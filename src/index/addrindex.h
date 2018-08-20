// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ADDRINDEX_H
#define BITCOIN_INDEX_ADDRINDEX_H

#include <chain.h>
#include <index/base.h>
#include <vector>
#include <txdb.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <script/script.h>

/**
 * TxIndex is used to look up transactions included in the blockchain by hash.
 * The index is written to a LevelDB database and records the filesystem
 * location of each transaction by transaction hash.
 */

/**
 * AddrIndex
 */
class AddrIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

protected:
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "addrindex"; }

public:
    /// Constructs the index, which becomes available to be queried.
    explicit AddrIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~AddrIndex() override;

    /// Lookup transaction(s) by address.
    /// TODO: documentation once API is decided
    bool FindTransactionsByDestination(const CScript& dest, std::vector<std::pair<uint256, CTransactionRef>> &txs);
};

/// TODO decide on the RPC interface that will use this index.
/// The global address index, used in GetTransactionFromAddress. May be null.
extern std::unique_ptr<AddrIndex> g_addrindex;

#endif // BITCOIN_INDEX_ADDRINDEX_H
