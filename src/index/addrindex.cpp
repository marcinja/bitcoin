// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>
#include <hash.h>
#include <index/addrindex.h>
#include <index/disktxpos.h>
#include <shutdown.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/standard.h>
#include <txdb.h>
#include <ui_interface.h>
#include <validation.h>
#include <vector>
#include <uint256.h>

#include <boost/thread.hpp>

std::unique_ptr<AddrIndex> g_addrindex;

static constexpr char DB_ADDRINDEX = 'a';

// DbKeyType is used by the address index to distinguish between the 
// different kinds of values stored.
enum DbKeyType : char {
    SEED,    // Seed used for MurmurHash3 inside GetAddrId
    SPENT,   // Used for values in the index indicating a spend
    CREATED, // Used for values in the index indicating the creation of an input
};

// AddrId is used to identify each script. Instead of storing full CScript's
// in the index, we hash them and use AddrIds.
using AddrId = unsigned int;

// We include the COutPoint in the key so that we can add many values to the 
// index for the same script.
using DbKeyPrefix = std::pair</*DB_ADDRINDEX*/ char, AddrId>;
using DbKey = std::pair<std::pair<DbKeyPrefix, /*DbKeyType*/ char>, COutPoint>;

using DbValue = CDiskTxPos;

/** Access to the addrindex database (indexes/addrindex/)*/
class AddrIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /** ReadAddrIndex returns the set of entries stored in the index for this addr_id. */
    std::vector<std::pair<DbKey, DbValue>> ReadAddrIndex(const unsigned int addr_id);

    /** WriteToIndex writes the input vector of database entries into the index.  */
    bool WriteToIndex(const std::vector<std::pair<DbKey, DbValue>> &entries);

    /** SetupHashSeed is used to create/backup/restore the seed used by the index for hashing. */
    unsigned int SetupHashSeed();
};

AddrIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(GetDataDir() / "indexes" / "addrindex", n_cache_size, f_memory, f_wipe)
{}

BaseIndex::DB& AddrIndex::GetDB() const { return *m_db; }

std::vector<std::pair<DbKey, DbValue>> AddrIndex::DB::ReadAddrIndex(const unsigned int addr_id)
{
    std::vector<std::pair<DbKey, DbValue>> result;
    DbKeyPrefix search_key = std::make_pair(DB_ADDRINDEX, addr_id);

    std::unique_ptr<CDBIterator> iter(NewIterator());
    iter->Seek(search_key);
    while (iter->Valid()) {
        DbKey key;
        DbValue value;
        if (!iter->GetKey(key) || key.first.first != search_key || !iter->GetValue(value) ) break;

        result.emplace_back(std::make_pair(key, value));
        iter->Next();
    }

    return result;
}

AddrIndex::AddrIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<AddrIndex::DB>(n_cache_size, f_memory, f_wipe)) {
        m_hash_seed = m_db->SetupHashSeed();
}

unsigned int AddrIndex::DB::SetupHashSeed() {
    constexpr auto seed_key = std::make_pair(DB_ADDRINDEX, static_cast<char>(DbKeyType::SEED));
    unsigned int seed;

    std::unique_ptr<CDBIterator> iter(NewIterator());
    std::pair<char, char> key;

    // If key is in the index already, read it and return.
    iter->Seek(seed_key);
    if (iter->Valid() && iter->GetKey(key) && key == seed_key && iter->GetValue(seed)) {
        return seed;
    }

    // Generate a random key and write it to the index.
    seed = GetRandInt(std::numeric_limits<int>::max());
    Write(seed_key, seed);
    return seed;
}

AddrIndex::~AddrIndex() {}

unsigned int AddrIndex::GetAddrId(const CScript& script) {
    std::vector<unsigned char> script_data;
    for (auto it = script.begin(); it != script.end(); ++it) {
        script_data.push_back(*it);
    }
    return MurmurHash3(m_hash_seed, script_data);
}

bool AddrIndex::WriteBlock(const CBlock& block, const CBlockUndo& block_undo, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<DbKey, DbValue>> entries;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = *(block.vtx[i]);
        const uint256 tx_hash = tx.GetHash();
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            DbKeyPrefix key_prefix = std::make_pair(DB_ADDRINDEX, GetAddrId(tx.vout[j].scriptPubKey));
            DbKey key = std::make_pair(std::make_pair(key_prefix, static_cast<char>(DbKeyType::CREATED)), COutPoint(tx_hash, j));
            entries.emplace_back(key, pos);
        }

        // Skip coinbase inputs.
        if (i > 0) {
            const CTxUndo& tx_undo = block_undo.vtxundo[i-1];
            for (size_t k = 0; k < tx.vin.size(); ++k) {
                // Get the scriptPubKey of this spent output.
                CScript spent_outputs_scriptpubkey = tx_undo.vprevout[k].out.scriptPubKey;
               
                DbKeyPrefix key_prefix = std::make_pair(DB_ADDRINDEX, GetAddrId(spent_outputs_scriptpubkey));
                DbKey key = std::make_pair(std::make_pair(key_prefix, static_cast<char>(DbKeyType::SPENT)), tx.vin[k].prevout);
                
                entries.emplace_back(key, pos);
            }
        }
        pos.nTxOffset += ::GetSerializeSize(tx, CLIENT_VERSION);
    }

    return m_db->WriteToIndex(entries);
}

bool AddrIndex::DB::WriteToIndex(const std::vector<std::pair<DbKey, DbValue>> &entries)
{
    CDBBatch batch(*this);
    for (const auto& entry : entries) {
        batch.Write(entry.first, entry.second);
    }
    return WriteBatch(batch);
}

// FindTxsByScript fills the spends_result vector with outpoints corresponding 
// to the output spent with the given script, and the transaction it was spent 
// in. creations_result is filled with outpoints for outputs created with this
// script as their script pubkey, and the transactions they were created in.
bool AddrIndex::FindTxsByScript(const CScript& dest, 
                                std::vector<std::pair<COutPoint, std::pair<CTransactionRef, uint256>>> &spends_result,
                                std::vector<std::pair<COutPoint, std::pair<CTransactionRef, uint256>>> &creations_result)
{
    auto db_entries = m_db->ReadAddrIndex(GetAddrId(dest));
    if (db_entries.size() == 0) return false;

    for (const auto& entry : db_entries) {
        DbKey key = entry.first;
        DbValue value = entry.second;

        CAutoFile file(OpenBlockFile(value, true), SER_DISK, CLIENT_VERSION);
        if (file.IsNull()) {
            return error("%s: OpenBlockFile failed", __func__);
        }
        CBlockHeader header;
        CTransactionRef tx;
        try {
            file >> header;
            if (fseek(file.Get(), value.nTxOffset, SEEK_CUR)) {
                return error("%s: fseek(...) failed", __func__);
            }
            file >> tx;
        } catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s", __func__, e.what());
        }
        std::pair<CTransactionRef, uint256> result =  std::make_pair(tx, header.GetHash());

        // Place entry into correct vector depending on its type.
        switch (key.first.second) {
            case DbKeyType::SPENT:
                spends_result.emplace_back(std::make_pair(key.second, result));
                break;
            case DbKeyType::CREATED:
                creations_result.emplace_back(std::make_pair(key.second, result));
                break;
            default:
                LogPrintf("AddrIndex::DB returned value with unexpected key type.\n");
                return false;
        }
    }

    return true;
}
