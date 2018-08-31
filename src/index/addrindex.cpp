// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <index/addrindex.h>
#include <index/txindex.h>
#include <shutdown.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>
#include <vector>
#include <uint256.h>

#include <boost/thread.hpp>

constexpr char DB_ADDRINDEX = 'a';
std::unique_ptr<AddrIndex> g_addrindex;

/**
 * Access to the addrindex database (indexes/addrindex/)
 *
 * The database stores a block locator of the chain the database is synced to
 * so that the AddrIndex can efficiently determine the point it last stopped at.
 * A locator is used instead of a simple hash of the chain tip because blocks
 * and block index entries may not be flushed to disk until after this database
 * is updated.
 */
class AddrIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Find all entries in the index for addr_id.
    // If filter_by_value is true, only returns keys with values equal to value_wanted.
    bool ReadAddrIndex(const uint64_t addr_id,
                       std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> &keys_found,
                       const bool filter_by_value = false,
                       const uint64_t value_wanted = 0);

    bool WriteToIndex(const std::vector<std::pair<uint64_t, CDiskTxPos>> &positions, const uint256 block_hash);

    void RemoveKeys(const std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> &keys_to_remove);
};

AddrIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(GetDataDir() / "indexes" / "addrindex", n_cache_size, f_memory, f_wipe)
{}

BaseIndex::DB& AddrIndex::GetDB() const { return *m_db; }


/*

  key_prefix = DBADDRINDEX | S/R (spent/received), addr_id

  options:

  key: key_prefix, outpoint
  value:  CScript (to check key)

  cons: implicit dependency on txindex to do the full tx lookup

  key: key_prefix, outpoint
  value:  block_hash, CScript (to check key)

  pros: can getrawtransaction using this

  key

 */

bool AddrIndex::DB::ReadAddrIndex(const CScript& script) {
    bool found_tx = false; // return true only if at least one transaction was found
    const std::pair<char, AddrId> key_prefix = std::make_pair(DB_ADDRINDEX, addr_id);
    std::unique_ptr<CDBIterator> iter(NewIterator());

    iter->Seek(key_prefix);
    while (iter->Valid()) {
        DbKey key;
        DbValue value;
        if (!iter->GetKey(key) || key.first != key_prefix || !iter->GetValue(value)) break;

        if (value == script) {
            found_tx = true;
            keys_found.emplace_back(key);
        } else {
            break;
        }

        iter->Next();
    }

    return found_tx;
}

AddrIndex::AddrIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<AddrIndex::DB>(n_cache_size, f_memory, f_wipe)){}

AddrIndex::~AddrIndex() {}

// TODO: how to set siphasher seed?
// TODO: save in the database as key = "SIPHASHSEED", value = std:pair<seed0, seed1>
// initialize as randomness
static constexpr uint64_t seed0 = 1337;
static constexpr uint64_t seed1 = 1337 << 9;

AddrId AddrIndex::GetAddrID(const CScript& script) {
    return CSipHasher(seed0, seed1).Write(script).Finalize();
}

bool AddrIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    std::vector<std::pair<DbKey, DbValue> new_db_entries;
    for (const auto& tx : block.vtx) {
        const uint256 tx_hash = tx.GetHash();

        if (tx->vout.empty()) continue;

        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            const AddrId addr_id = GetAddrID(tx->vout[i].scriptPubKey);
            const COutPoint outpoint = COutPoint(tx_hash, static_cast<uint32_t>(i));
            const DbKey new_key = std::make_pair(std::make_pair(DB_ADDRINDEX, addr_id), outpoint);

            new_db_entries.emplace_back(new_key, tx->vout[i].scriptPubKey);
        }
    }

    // TODO: use block_undo to index spends in future commit

    return m_db->WriteToIndex(new_db_entries);
}


bool AddrIndex::DB::WriteToIndex(const std::vector<std::pair<DbKey, DbValue>>& entries) {
    CDBBatch batch(*this);
    for (const auto& kv : entries) {
        // Insert (address, position) pair with a part of the block hash.
        // Different transactions for the same address will be differentiated
        // in leveldb by their CDiskTxPos suffix.
        batch.Write(kv.first, kv.second);
    }
    return WriteBatch(batch);
}

bool AddrIndex::DB::WriteToIndex(const std::vector<std::pair<uint64_t, CDiskTxPos>>& positions, const uint256 block_hash)
{
    CDBBatch batch(*this);
    for (const auto& pos : positions) {
        // Insert (address, position) pair with a part of the block hash.
        // Different transactions for the same address will be differentiated
        // in leveldb by their CDiskTxPos suffix.
        batch.Write(std::make_pair(std::make_pair(DB_ADDRINDEX, pos.first), pos.second), block_hash.GetUint64(0));
    }
    return WriteBatch(batch);
}

bool AddrIndex::FindTxsByScript(const CScript& dest, std::vector<std::pair<uint256, CTransactionRef>> &txs)
{
    const uint64_t addr_id = GetAddrID(dest);
    std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> keys;
    if (!m_db->ReadAddrIndex(addr_id, keys)) {
        return false;
    }

    for (const auto& key : keys) {
        uint256 block_hash;
        CTransactionRef tx;

        CAutoFile file(OpenBlockFile(key.second, true), SER_DISK, CLIENT_VERSION);
        if (file.IsNull()) {
            return error("%s: OpenBlockFile failed", __func__);
        }
        CBlockHeader header;
        try {
            file >> header;
            if (fseek(file.Get(), key.second.nTxOffset, SEEK_CUR)) {
                return error("%s: fseek(...) failed", __func__);
            }
            file >> tx;
        } catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s", __func__, e.what());
        }

        txs.emplace_back(header.GetHash(), tx);
    }

    return true;
}
