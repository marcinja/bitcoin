// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ADDRINDEX_H
#define BITCOIN_INDEX_ADDRINDEX_H

#include <chain.h>
#include <index/base.h>
#include <index/addrindexkeys.h>
#include <vector>
#include <tuple>
#include <random.h>
#include <txdb.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <script/script.h>

using DbValue = CScript;

/**
 * AddrIndex is used to look up transactions included in the blockchain by script.
 * The index is written to a LevelDB database and records the filesystem
 * location of transactions by script.
 */
class AddrIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    uint64_t m_hash_seed;

    // Returns part of key used to store information for this script.
    AddrId GetAddrID(const CScript& script);

 protected:
    /// Override base class init to set Siphash seeds.
    bool Init() override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "addrindex"; }

public:
    /// Constructs the index, which becomes available to be queried.
    explicit AddrIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~AddrIndex() override;

    /// Lookup outpoints by scriptPubKey.
    bool FindOutPointsByScript(const CScript& script, std::vector<COutPoint> &outpoints);


    bool FindTxsByScript(const CScript& dest, std::vector<CTransactionRef>
    &txs);

    // Get everything. 
    bool FindOutPointsAndTxsByScript(const CScript& dest, std::vector<std::pair<COutPoint, CTransactionRef>> &result);
};

/// The global address index, used in FindTxsByScript. May be null.
extern std::unique_ptr<AddrIndex> g_addrindex;

#endif // BITCOIN_INDEX_ADDRINDEX_H
 
