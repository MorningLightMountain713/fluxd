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
    FluxnodeCacheData data = g_fluxnodeCache.GetFluxnodeData(tx.collateralIn);
    if (data.IsNull())
        return true;

    std::string txHost, dataHost;
    int txPort, dataPort;
    SplitHostPort(tx.ip, txPort, txHost);
    SplitHostPort(data.ip, dataPort, dataHost);
    return txHost != dataHost;
}

int CountClearnetFluxnodePeers()
{
    int nCount = 0;
    LOCK(cs_vNodes);
    LOCK(g_fluxnodeCache.cs);
    for (CNode* pnode : vNodes) {
        if (!pnode->addr.IsRoutable() || pnode->addr.IsTor())
            continue;
        std::string peerHost = pnode->addr.ToStringIP();
        for (const auto& [outpoint, data] : g_fluxnodeCache.mapConfirmedFluxnodeData) {
            std::string entryHost;
            int entryPort;
            SplitHostPort(data.ip, entryPort, entryHost);
            if (entryHost == peerHost) {
                nCount++;
                break;
            }
        }
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
    {
        LOCK(cs_vNodes);
        LOCK(g_fluxnodeCache.cs);
        for (CNode* pnode : vNodes) {
            if (pnode->fInbound || !pnode->addr.IsRoutable() || pnode->addr.IsTor())
                continue;
            std::string peerHost = pnode->addr.ToStringIP();
            for (const auto& [outpoint, data] : g_fluxnodeCache.mapConfirmedFluxnodeData) {
                std::string entryHost;
                int entryPort;
                SplitHostPort(data.ip, entryPort, entryHost);
                if (entryHost == peerHost) {
                    nFluxnodePeers++;
                    setConnectedIPs.insert(peerHost);
                    break;
                }
            }
        }
    }

    if (nFluxnodePeers >= 2)
        return "";

    LOCK(g_fluxnodeCache.cs);
    std::vector<std::string> vCandidates;
    for (const auto& [outpoint, data] : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        std::string entryHost;
        int entryPort;
        SplitHostPort(data.ip, entryPort, entryHost);
        if (setConnectedIPs.count(entryHost))
            continue;
        CNetAddr netAddr(entryHost, false);
        if (!netAddr.IsValid() || !netAddr.IsRoutable() || netAddr.IsTor())
            continue;
        vCandidates.push_back(entryHost);
    }

    if (vCandidates.empty())
        return "";

    std::shuffle(vCandidates.begin(), vCandidates.end(),
                 std::mt19937(std::random_device()()));

    LogPrint("attestation", "Connecting to fluxnode peer %s (have %d fluxnode peers)\n",
             vCandidates.front(), nFluxnodePeers);
    return vCandidates.front();
}

// --- AttestationManager ---

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

bool AttestationManager::HasInStaging(const uint256& txid) const
{
    AssertLockHeld(cs);
    return mapPendingConfirm.count(txid) > 0;
}

bool AttestationManager::HasTxInStaging(const uint256& txid) const
{
    AssertLockHeld(cs);
    auto it = mapPendingConfirm.find(txid);
    if (it == mapPendingConfirm.end())
        return false;
    return it->second.tx.has_value();
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
        nRateLimitWindowStart = nCurrentHeight;
    }
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
