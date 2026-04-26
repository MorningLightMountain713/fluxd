// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode/attestation.h"

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "fluxnode/fluxnode.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "tinyformat.h"
#include "util.h"

#include <algorithm>
#include <random>

AttestationManager g_attestationManager;

int GetRequiredAttestationCount()
{
    bool fTestNet = GetBoolArg("-testnet", false);
    return fTestNet ? FLUXNODE_ATTESTATION_THRESHOLD_TESTNET
                    : FLUXNODE_ATTESTATION_THRESHOLD_MAINNET;
}

int GetMinClearnetFluxnodePeers()
{
    bool fTestNet = GetBoolArg("-testnet", false);
    return fTestNet ? FLUXNODE_MIN_CLEARNET_PEERS_TESTNET
                    : FLUXNODE_MIN_CLEARNET_PEERS_MAINNET;
}

uint256 CFluxnodeAttestation::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << txid << attesterOutpoint;
    return ss.GetHash();
}

std::string CFluxnodeAttestation::ToString() const
{
    return strprintf("CFluxnodeAttestation(txid=%s, attester=%s)",
                     txid.ToString(), attesterOutpoint.ToString());
}

bool NeedsAttestation(const CTransaction& tx, int nHeight)
{
    if (!tx.IsFluxnodeTx())
        return false;
    if (!(tx.nType & FLUXNODE_CONFIRM_TX_TYPE))
        return false;

    bool fAttestationActive = NetworkUpgradeActive(
        nHeight, Params().GetConsensus(), Consensus::UPGRADE_IP_ATTESTATION);
    if (!fAttestationActive)
        return false;

    if (tx.nUpdateType == FluxnodeUpdateType::INITIAL_CONFIRM)
        return true;

    if (tx.nUpdateType == FluxnodeUpdateType::UPDATE_CONFIRM)
        return IsIpChanged(tx);

    return false;
}

bool IsIpChanged(const CTransaction& tx)
{
    LOCK(g_fluxnodeCache.cs);
    auto it = g_fluxnodeCache.mapConfirmedFluxnodeData.find(tx.collateralIn);
    if (it == g_fluxnodeCache.mapConfirmedFluxnodeData.end())
        return true;

    std::string txHost, dataHost;
    int txPort, dataPort;
    SplitHostPort(tx.ip, txPort, txHost);
    SplitHostPort(it->second.ip, dataPort, dataHost);
    return txHost != dataHost;
}

static std::set<std::string> BuildConfirmedFluxnodeIPSet()
{
    std::set<std::string> setIPs;
    for (const auto& [outpoint, data] : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        std::string host;
        int port;
        SplitHostPort(data.ip, port, host);
        if (!host.empty())
            setIPs.insert(host);
    }
    return setIPs;
}

int CountClearnetFluxnodePeers()
{
    int nCount = 0;
    LOCK2(cs_vNodes, g_fluxnodeCache.cs);
    std::set<std::string> setFluxnodeIPs = BuildConfirmedFluxnodeIPSet();
    for (CNode* pnode : vNodes) {
        if (!pnode->addr.IsRoutable() || pnode->addr.IsTor())
            continue;
        if (setFluxnodeIPs.count(pnode->addr.ToStringIP()))
            nCount++;
    }
    return nCount;
}

std::string GetFluxnodePeerToConnect(int nCurrentHeight)
{
    if (!fFluxnode)
        return "";

    bool fAttestationActive = NetworkUpgradeActive(
        nCurrentHeight, Params().GetConsensus(), Consensus::UPGRADE_IP_ATTESTATION);
    if (!fAttestationActive)
        return "";

    int nFluxnodePeers = 0;
    std::set<std::string> setConnectedIPs;
    std::vector<std::string> vCandidates;
    {
        LOCK2(cs_vNodes, g_fluxnodeCache.cs);

        std::set<std::string> setFluxnodeIPs = BuildConfirmedFluxnodeIPSet();

        for (CNode* pnode : vNodes) {
            if (pnode->fInbound || !pnode->addr.IsRoutable() || pnode->addr.IsTor())
                continue;
            std::string peerHost = pnode->addr.ToStringIP();
            if (setFluxnodeIPs.count(peerHost)) {
                nFluxnodePeers++;
                setConnectedIPs.insert(peerHost);
            }
        }

        if (nFluxnodePeers >= 2)
            return "";

        for (const std::string& ip : setFluxnodeIPs) {
            if (setConnectedIPs.count(ip))
                continue;
            CNetAddr netAddr(ip, false);
            if (!netAddr.IsValid() || !netAddr.IsRoutable() || netAddr.IsTor())
                continue;
            vCandidates.push_back(ip);
        }
    }

    if (vCandidates.empty())
        return "";

    static thread_local std::mt19937 rng(std::random_device{}());
    std::shuffle(vCandidates.begin(), vCandidates.end(), rng);

    LogPrint("attestation", "Connecting to fluxnode peer %s (have %d fluxnode peers)\n",
             vCandidates.front(), nFluxnodePeers);
    return vCandidates.front();
}

void RelayAttestation(const CFluxnodeAttestation& att)
{
    uint256 attHash = att.GetHash();
    CInv inv(MSG_FLUXNODE_ATTESTATION, attHash);
    {
        LOCK(cs_mapRelay);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << att;
        mapRelay.insert(std::make_pair(inv, ss));
        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv));
    }
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes) {
            pnode->PushInventory(inv);
        }
    }
}

// --- AttestationManager ---

void AttestationManager::SetNull()
{
    mapPendingConfirm.clear();
    setSeenAttestations.clear();
    mapAttesterCount.clear();
    nRateLimitWindowStart = 0;
    mapAttesterOrphans.clear();
    setBannedAttesters.clear();
    mapPeerInvCount.clear();
}

void AttestationManager::AddToStaging(const uint256& txid, const CTransaction& tx, int nHeight)
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it != mapPendingConfirm.end()) {
        it->second.tx = tx;
        if (it->second.nBlockFirstSeen == 0)
            it->second.nBlockFirstSeen = nHeight;
    } else {
        PendingConfirm entry;
        entry.tx = tx;
        entry.nBlockFirstSeen = nHeight;
        mapPendingConfirm[txid] = std::move(entry);
        EnforceCapLimit();
    }
}

void AttestationManager::AddAttestation(const uint256& txid, const COutPoint& attester,
                                        const std::vector<unsigned char>& sig, int nHeight)
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it != mapPendingConfirm.end()) {
        it->second.mapAttestations[attester] = sig;
    } else {
        PendingConfirm entry;
        entry.nBlockFirstSeen = nHeight;
        entry.mapAttestations[attester] = sig;
        mapPendingConfirm[txid] = std::move(entry);
        EnforceCapLimit();
    }
}

bool AttestationManager::IsReadyForPromotion(const uint256& txid) const
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it == mapPendingConfirm.end())
        return false;
    if (!it->second.tx.has_value())
        return false;

    int nRequired = GetRequiredAttestationCount();

    const COutPoint& collateral = it->second.tx->collateralIn;
    int nValid = 0;
    for (const auto& [attester, sig] : it->second.mapAttestations) {
        if (attester != collateral)
            nValid++;
    }
    return nValid >= nRequired;
}

std::optional<CTransaction> AttestationManager::GetPromotableTx(const uint256& txid) const
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it == mapPendingConfirm.end())
        return std::nullopt;
    return it->second.tx;
}

void AttestationManager::RemoveFromStaging(const uint256& txid)
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it != mapPendingConfirm.end()) {
        for (const auto& [attester, sig] : it->second.mapAttestations) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txid << attester;
            setSeenAttestations.erase(ss.GetHash());
        }
        mapPendingConfirm.erase(it);
    }
}

bool AttestationManager::HasTxInStaging(const uint256& txid) const
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it == mapPendingConfirm.end())
        return false;
    return it->second.tx.has_value();
}

bool AttestationManager::HasSeenAttestation(const uint256& attHash) const
{
    AssertLockHeld(cs);
    return setSeenAttestations.count(attHash) > 0;
}

void AttestationManager::MarkAttestationSeen(const uint256& attHash)
{
    AssertLockHeld(cs);
    setSeenAttestations.insert(attHash);
}

void AttestationManager::CleanupExpired(int nCurrentHeight)
{
    AssertLockHeld(cs);
    std::vector<uint256> vToRemove;
    for (const auto& [txid, entry] : mapPendingConfirm) {
        if (entry.nBlockFirstSeen > 0 &&
            (nCurrentHeight - entry.nBlockFirstSeen) >= FLUXNODE_ATTESTATION_EXPIRY_BLOCKS) {
            if (!entry.tx.has_value()) {
                for (const auto& [attester, sig] : entry.mapAttestations) {
                    mapAttesterOrphans[attester]++;
                    if (mapAttesterOrphans[attester] >= FLUXNODE_ATTESTATION_ORPHAN_BAN_THRESHOLD) {
                        setBannedAttesters.insert(attester);
                        LogPrint("attestation", "Banning attester %s for excessive orphans\n",
                                 attester.ToString());
                    }
                }
            }
            vToRemove.push_back(txid);
        }
    }
    for (const uint256& txid : vToRemove) {
        RemoveFromStaging(txid);
    }

    if (nRateLimitWindowStart > 0 &&
        (nCurrentHeight - nRateLimitWindowStart) >= FLUXNODE_ATTESTATION_RATE_LIMIT_WINDOW) {
        mapAttesterCount.clear();
        mapAttesterOrphans.clear();
        setBannedAttesters.clear();
        mapPeerInvCount.clear();
        nRateLimitWindowStart = nCurrentHeight;
    }

    // Cap setSeenAttestations to prevent unbounded growth from orphan attestations
    if (setSeenAttestations.size() > FLUXNODE_PENDING_CONFIRM_MAX_ENTRIES * 10)
        setSeenAttestations.clear();
}

void AttestationManager::CleanupOnBlockConnected(const uint256& txid)
{
    AssertLockHeld(cs);
    RemoveFromStaging(txid);
}

void AttestationManager::EnforceCapLimit()
{
    AssertLockHeld(cs);
    while (mapPendingConfirm.size() > FLUXNODE_PENDING_CONFIRM_MAX_ENTRIES) {
        int nOldestHeight = std::numeric_limits<int>::max();
        uint256 oldestTxid;
        for (const auto& [txid, entry] : mapPendingConfirm) {
            if (entry.nBlockFirstSeen < nOldestHeight) {
                nOldestHeight = entry.nBlockFirstSeen;
                oldestTxid = txid;
            }
        }
        RemoveFromStaging(oldestTxid);
    }
}

bool AttestationManager::CheckAttesterRateLimit(const COutPoint& attester, int nCurrentHeight)
{
    AssertLockHeld(cs);
    if (nRateLimitWindowStart == 0)
        nRateLimitWindowStart = nCurrentHeight;

    if ((nCurrentHeight - nRateLimitWindowStart) >= FLUXNODE_ATTESTATION_RATE_LIMIT_WINDOW) {
        mapAttesterCount.clear();
        nRateLimitWindowStart = nCurrentHeight;
    }

    int& count = mapAttesterCount[attester];
    if (count >= FLUXNODE_ATTESTATION_RATE_LIMIT_PER_ATTESTER)
        return false;
    count++;
    return true;
}

bool AttestationManager::IsAttesterBanned(const COutPoint& attester) const
{
    AssertLockHeld(cs);
    return setBannedAttesters.count(attester) > 0;
}

bool AttestationManager::CheckPeerInvLimit(int nodeId)
{
    AssertLockHeld(cs);
    int64_t nNow = GetTime();
    auto it = mapPeerInvCount.find(nodeId);
    if (it == mapPeerInvCount.end()) {
        mapPeerInvCount[nodeId] = {1, nNow};
        return true;
    }

    if ((nNow - it->second.second) >= FLUXNODE_ATTESTATION_PEER_INV_WINDOW) {
        it->second = {1, nNow};
        return true;
    }

    if (it->second.first >= FLUXNODE_ATTESTATION_PEER_INV_LIMIT)
        return false;
    it->second.first++;
    return true;
}
