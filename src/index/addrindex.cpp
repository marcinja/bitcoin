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

bool AddrIndex::DB::ReadAddrIndex(const uint64_t addr_id,
                                  std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> &keys_found,
                                  const bool filter_by_value,
                                  const uint64_t value_wanted){
    bool found_tx = false; // return true only if at least one transaction was found
    const std::pair<char, uint64_t> key_prefix = std::make_pair(DB_ADDRINDEX, addr_id);
    std::unique_ptr<CDBIterator> iter(NewIterator());

    iter->Seek(key_prefix);
    while (iter->Valid()) {
        std::pair<std::pair<char, uint64_t>, CDiskTxPos> key;
        uint64_t value;
        if (!iter->GetKey(key) || !iter->GetValue(value) || key.first != key_prefix) break;

        if  (!filter_by_value || (filter_by_value && value == value_wanted)) {
            found_tx = true;
            keys_found.emplace_back(key);
        }

        iter->Next();
    }

    return found_tx;
}

void AddrIndex::DB::RemoveKeys(const std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> &keys_to_remove) {
    CDBBatch batch(*this);
    for (const auto& key : keys_to_remove) {
        batch.Erase(key);
    }
    WriteBatch(batch);
}

AddrIndex::AddrIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<AddrIndex::DB>(n_cache_size, f_memory, f_wipe)){}

AddrIndex::~AddrIndex() {}

uint64_t AddrIndex::GetAddrID(const CScript& script) {
    uint256 hashed_script;

    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*script.begin()), script.end() - script.begin());
    hasher.Finalize(hashed_script.begin());

    return hashed_script.GetUint64(0);
}

bool AddrIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint64_t, CDiskTxPos>> positions;
    positions.reserve(2 * block.vtx.size());  // Most transactions have at least 1 input and 1 output.

    // Index addresses of spent outputs if txindex is enabled,
    for (const auto& tx : block.vtx) {
        for (const auto tx_out : tx->vout){
            positions.emplace_back(GetAddrID(tx_out.scriptPubKey), pos);
        }

        if (g_txindex && !tx->IsCoinBase()) {
            for (const auto tx_in : tx->vin) {
                CTransactionRef tx;
                uint256 block_hash;

                if (!g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx)) {
                    // Both addrindex and txindex may be syncing in parallel, and addrindex might
                    // be ahead of txindex. We let txindex sync first so that addrindex can continue
                    // after it.
                    while (!g_txindex->IsInSyncWithMainChain()) {
                        MilliSleep(1000); //TODO: find a less arbitrary sleep time.
                    }

                    // It's also possible we can't find the tx in txindex because it fell behind in
                    // the ValidationInterface queue. In this case we also let it finish before continuing.
                    g_txindex->BlockUntilSyncedToCurrentChain();

                    // If we still can't find the tx then a re-org may have happened.
                    if (!g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx)) return false;
                }

                CScript script_pub_key = tx->vout[tx_in.prevout.n].scriptPubKey;
                positions.emplace_back(GetAddrID(script_pub_key), pos);
            }
        }

        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }

    return m_db->WriteToIndex(positions, block.GetHash());
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

void AddrIndex::BlockDisconnected(const std::shared_ptr<const CBlock> &block) {
    const uint64_t block_hash_bits = block->GetHash().GetUint64(0);
    std::unordered_set<uint64_t> addr_ids_to_remove;

    {
        LOCK(cs_main);
        CCoinsViewCache view(pcoinsTip.get());

        // Collect all addr_ids from txs in this block.
        for (const auto& tx : block->vtx) {
            for (const auto tx_out : tx->vout){
                addr_ids_to_remove.emplace(GetAddrID(tx_out.scriptPubKey));
            }

            if (!tx->IsCoinBase()) {
                for (const auto tx_in : tx->vin){
                    Coin coin;
                    if (view.GetCoin(tx_in.prevout, coin)) {
                        addr_ids_to_remove.emplace(GetAddrID(coin.out.scriptPubKey));
                    }
                }
            }
        }
    }

    std::vector<std::pair<std::pair<char, uint64_t>, CDiskTxPos>> keys_to_remove;
    keys_to_remove.reserve(addr_ids_to_remove.size());

    // Find all keys in the addrindex that pertain to this block using the addr_ids found above.
    for (const auto addr_id : addr_ids_to_remove) {
        m_db->ReadAddrIndex(addr_id, keys_to_remove, true, block_hash_bits);
    }

    m_db->RemoveKeys(keys_to_remove);
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
