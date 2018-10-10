// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <index/addrindex.h>
#include <index/addrindexkeys.h>
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

    void SetupHashSeed(uint64_t &seed);

    bool ReadAddrIndex(const CScript &script, const AddrId addr_id, std::vector<AddrIndexKey> &result);

    bool WriteToIndex(const std::vector<std::pair<AddrIndexKey, DbValue>>& entries);
};

AddrIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(GetDataDir() / "indexes" / "addrindex", n_cache_size, f_memory, f_wipe)
{}

BaseIndex::DB& AddrIndex::GetDB() const { return *m_db; }

void AddrIndex::DB::SetupHashSeed(uint64_t& seed) {
    std::unique_ptr<CDBIterator> iter(NewIterator());
    const AddrIndexBaseKey seed_key = AddrIndexBaseKey(ADDR_INDEX_SEED_KEY);
    iter->Seek(seed_key);

    AddrIndexBaseKey key;
    uint64_t value;

    // If there aren't any seeds stored yet, generate new ones.
    if (!iter->GetKey(key) || !iter->GetValue(value) || key != seed_key){
        seed = GetRand(std::numeric_limits<uint64_t>::max());
        Write(seed_key, seed);
    } else {
        seed = value;
    }
}

// TODO search for created inputs in future commit.
bool AddrIndex::DB::ReadAddrIndex(const CScript &script, const AddrId addr_id,
std::vector<AddrIndexKey> &result) {
    bool found_tx = false; // return true only if at least one transaction was found
    const AddrIndexSearchKey search_key = AddrIndexSearchKey(ADDR_INDEX_SPENT_OUTPUT, addr_id);
    std::unique_ptr<CDBIterator> iter(NewIterator());

    iter->Seek(search_key);
    while (iter->Valid()) {
        AddrIndexKey key;
        DbValue value;
        if (!iter->GetKey(key) ||
            !key.MatchesSearchKey(search_key) ||
            !iter->GetValue(value)) break;

        if (value == script) {
            found_tx = true;
            result.push_back(key);
        }

        iter->Next();
    }

    return found_tx;
}

bool AddrIndex::DB::WriteToIndex(const std::vector<std::pair<AddrIndexKey, DbValue>>& entries) {
    CDBBatch batch(*this);
    for (const auto& kv : entries) {
        // Insert (address, position) pair with a part of the block hash.
        // Different transactions for the same address will be differentiated
        // in leveldb by their CDiskTxPos suffix.
        batch.Write(kv.first, kv.second);
    }
    return WriteBatch(batch);
}

AddrIndex::AddrIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<AddrIndex::DB>(n_cache_size, f_memory, f_wipe)){}

AddrIndex::~AddrIndex() {}

AddrId AddrIndex::GetAddrID(const CScript& script) {
    return MurmurHash3(m_hash_seed, ToByteVector(script));
}

bool AddrIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    std::vector<std::pair<AddrIndexKey, DbValue>> new_db_entries;
    
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<CDiskTxPos> positions;
    positions.reserve(2 * block.vtx.size()); 

    for (const auto& tx : block.vtx) {
        if (tx->vout.empty()) continue;

        const uint256 tx_hash = tx->GetHash();

        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            const AddrId addr_id = GetAddrID(tx->vout[i].scriptPubKey);
            const COutPoint outpoint = COutPoint(tx_hash, static_cast<uint32_t>(i));

            new_db_entries.emplace_back(AddrIndexKey(ADDR_INDEX_SPENT_OUTPUT,
            addr_id, outpoint, pos), tx->vout[i].scriptPubKey);
        }

        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION); 
    }

    // TODO: use block_undo to index spends in future commit

    return m_db->WriteToIndex(new_db_entries);
}

bool AddrIndex::Init() {
    // Get hasher seeds.
    uint64_t seed;
    m_db->SetupHashSeed(seed);
    m_hash_seed = seed;

    return BaseIndex::Init();
}

bool AddrIndex::FindOutPointsByScript(const CScript& dest, std::vector<COutPoint> &outpoints) {
    std::vector<AddrIndexKey> keys;
    const AddrId addr_id = GetAddrID(dest);

    bool ok = m_db->ReadAddrIndex(dest, addr_id, keys);
    if (ok) {
        for (const auto& key : keys) {
            outpoints.emplace_back(key.outpoint);
        }
    }

    return ok;
}

bool AddrIndex::FindTxsByScript(const CScript& dest, std::vector<CTransactionRef> &txs) {
    std::vector<AddrIndexKey> keys;
    const AddrId addr_id = GetAddrID(dest);
    
    bool ok = m_db->ReadAddrIndex(dest, addr_id, keys);
    if (ok) {
        for (const auto& key : keys) {
            CTransactionRef tx;

            CAutoFile file(OpenBlockFile(key.pos, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull()) {
                return error("%s: OpenBlockFile failed", __func__);
            }
            CBlockHeader header;
            try {
                file >> header;
                if (fseek(file.Get(), key.pos.nTxOffset, SEEK_CUR)) {
                    return error("%s: fseek(...) failed", __func__);
                }
                file >> tx;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what()); 
            }
    
            txs.emplace_back(tx);
        }
    }

    return ok;
}

bool AddrIndex::FindOutPointsAndTxsByScript(const CScript& dest, std::vector<std::pair<COutPoint, CTransactionRef>> &result) {
    std::vector<AddrIndexKey> keys;
    const AddrId addr_id = GetAddrID(dest);
    
    bool ok = m_db->ReadAddrIndex(dest, addr_id, keys);
    if (ok) {
        for (const auto& key : keys) {
            CTransactionRef tx;

            CAutoFile file(OpenBlockFile(key.pos, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull()) {
                return error("%s: OpenBlockFile failed", __func__);
            }
            CBlockHeader header;
            try {
                file >> header;
                if (fseek(file.Get(), key.pos.nTxOffset, SEEK_CUR)) {
                    return error("%s: fseek(...) failed", __func__);
                }
                file >> tx;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what()); 
            }
    
            result.emplace_back(key.outpoint, tx);
        }
    }

    return ok;
}
