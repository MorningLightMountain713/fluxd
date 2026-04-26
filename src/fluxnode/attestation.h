// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUXNODE_ATTESTATION_H
#define FLUXNODE_ATTESTATION_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

// Attestation thresholds
static const int FLUXNODE_ATTESTATION_THRESHOLD_MAINNET = 3;
static const int FLUXNODE_ATTESTATION_THRESHOLD_TESTNET = 1;
static const int FLUXNODE_MIN_CLEARNET_PEERS_MAINNET = 5;
static const int FLUXNODE_MIN_CLEARNET_PEERS_TESTNET = 1;

// Staging area limits
static const int FLUXNODE_ATTESTATION_EXPIRY_BLOCKS = 20;
static const size_t FLUXNODE_PENDING_CONFIRM_MAX_ENTRIES = 5000;

// Per-IP host limit
static const int FLUXNODE_MAX_NODES_PER_IP = 8;

// Spam defense
static const int FLUXNODE_ATTESTATION_RATE_LIMIT_WINDOW = 20;  // blocks
static const int FLUXNODE_ATTESTATION_RATE_LIMIT_PER_ATTESTER = 10;
static const int FLUXNODE_ATTESTATION_ORPHAN_BAN_THRESHOLD = 5;
static const int FLUXNODE_ATTESTATION_PEER_INV_LIMIT = 200;
static const int FLUXNODE_ATTESTATION_PEER_INV_WINDOW = 600;  // seconds

int GetRequiredAttestationCount();
int GetMinClearnetFluxnodePeers();

class CFluxnodeAttestation
{
public:
    uint256 txid;
    COutPoint attesterOutpoint;
    std::vector<unsigned char> vchSig;

    CFluxnodeAttestation() {}
    CFluxnodeAttestation(const uint256& txidIn, const COutPoint& attesterIn,
                         const std::vector<unsigned char>& sigIn)
        : txid(txidIn), attesterOutpoint(attesterIn), vchSig(sigIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(txid);
        READWRITE(attesterOutpoint);
        READWRITE(vchSig);
    }

    uint256 GetHash() const;
    std::string ToString() const;
};

struct PendingConfirm
{
    std::optional<CTransaction> tx;
    std::map<COutPoint, std::vector<unsigned char>> mapAttestations;
    int nBlockFirstSeen;

    PendingConfirm() : nBlockFirstSeen(0) {}
};

class AttestationManager
{
public:
    mutable CCriticalSection cs;

    std::map<uint256, PendingConfirm> mapPendingConfirm;
    std::set<uint256> setSeenAttestations;

    // Per-attester rate limiting: outpoint -> count in current window
    std::map<COutPoint, int> mapAttesterCount;
    int nRateLimitWindowStart = 0;

    // Per-attester orphan tracking: outpoint -> orphan count
    std::map<COutPoint, int> mapAttesterOrphans;
    std::set<COutPoint> setBannedAttesters;

    // Per-peer inv rate limiting: node id -> (count, window start time)
    std::map<int, std::pair<int, int64_t>> mapPeerInvCount;

    void AddToStaging(const uint256& txid, const CTransaction& tx, int nHeight);
    void AddAttestation(const uint256& txid, const COutPoint& attester,
                        const std::vector<unsigned char>& sig, int nHeight);
    bool IsReadyForPromotion(const uint256& txid) const;
    std::optional<CTransaction> GetPromotableTx(const uint256& txid) const;
    void RemoveFromStaging(const uint256& txid);
    bool HasInStaging(const uint256& txid) const;
    bool HasTxInStaging(const uint256& txid) const;

    void CleanupExpired(int nCurrentHeight);
    void CleanupOnBlockConnected(const uint256& txid);
    void EnforceCapLimit();

    bool CheckAttesterRateLimit(const COutPoint& attester, int nCurrentHeight);
    bool IsAttesterBanned(const COutPoint& attester) const;
    bool CheckPeerInvLimit(int nodeId);

    void SetNull()
    {
        mapPendingConfirm.clear();
        setSeenAttestations.clear();
        mapAttesterCount.clear();
        nRateLimitWindowStart = 0;
        mapAttesterOrphans.clear();
        setBannedAttesters.clear();
        mapPeerInvCount.clear();
    }
};

extern AttestationManager g_attestationManager;

bool NeedsAttestation(const CTransaction& tx, int nHeight);
bool IsIpChanged(const CTransaction& tx);

// Called from net.cpp — returns a fluxnode address to connect to if we need
// more fluxnode peers for attestation, or an empty string if no action needed.
// Encapsulates all fluxnode cache access so net.cpp doesn't need fluxnode headers.
std::string GetFluxnodePeerToConnect(int nCurrentHeight);

// Called from activefluxnode.cpp — counts clearnet fluxnode peers.
int CountClearnetFluxnodePeers();

#endif // FLUXNODE_ATTESTATION_H
