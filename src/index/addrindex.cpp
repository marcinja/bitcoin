// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <index/addrindex.h>
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

    bool ReadAddrIndex(const uint64_t addr_id, std::vector<CDiskTxPos> &tx_positions);

    bool WriteToIndex(const std::vector<std::pair<uint64_t, CDiskTxPos>> &positions);
};

AddrIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(GetDataDir() / "indexes" / "addrindex", n_cache_size, f_memory, f_wipe)
{}


BaseIndex::DB& AddrIndex::GetDB() const { return *m_db; }

bool AddrIndex::DB::ReadAddrIndex(const uint64_t addr_id, std::vector<CDiskTxPos> &tx_positions) {
    bool found_tx = false; // return true only if at least one transaction was found
    std::unique_ptr<CDBIterator> iter(NewIterator());

    iter->Seek(std::make_pair(DB_ADDRINDEX, addr_id));
    while (iter->Valid()) {
        std::pair<std::pair<char, uint64_t>, CDiskTxPos> key;
        if (!iter->GetKey(key)) break;

        if (key.first.first == DB_ADDRINDEX && key.first.second == addr_id) {
            found_tx = true;
            tx_positions.emplace_back(key.second);
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

// called in BlockConnected (base.h/cpp validationinterface)
bool AddrIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint64_t, CDiskTxPos>> positions;
    positions.reserve(2 * block.vtx.size()); // NOTE: could profile how tweaking reservation change does anything, but only if vec inserts are more than a blip

    for (const auto& tx : block.vtx) {
        for (const auto tx_out : tx->vout){
            CSHA256 hasher;
            hasher.Write((unsigned char*)&(*tx_out.scriptPubKey.begin()), tx_out.scriptPubKey.end() - tx_out.scriptPubKey.begin());
            uint256 hashed_script;
            hasher.Finalize(hashed_script.begin());

            uint64_t addr_id = hashed_script.GetUint64(0);
            positions.emplace_back(addr_id, pos);
        }

        // TODO If tx_index is *also* enabled, look through spends from this address.
        if (false && !tx->IsCoinBase()) {
            for (const auto tx_in : tx->vin) {
                // sipa's original checked scriptPubKey from UTXO set here

                // NOTE: we have a lock on cs_main here from where GetMainsSignal is called
                // Get CCoinsView here.
            }
        }

        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }

    return m_db->WriteToIndex(positions);
}

// TODO implement block disconnected

bool AddrIndex::DB::WriteToIndex(const std::vector<std::pair<uint64_t, CDiskTxPos>>& positions)
{
    // TODO: Is there a way to insert with no key instead?
    constexpr unsigned char small_val = 0x00;

    CDBBatch batch(*this);
    for (const auto& pos : positions) {
        // Insert (address, position) pair with a small value.
        // Different transactions for the same address will be differentiated
        // in leveldb by their CDiskTxPos suffix.
        batch.Write(std::make_pair(std::make_pair(DB_ADDRINDEX, pos.first), pos.second), small_val);
    }
    return WriteBatch(batch);
}

bool AddrIndex::FindTransactionsByDestination(const CScript& dest, std::vector<std::pair<uint256, CTransactionRef>> &txs) 
{
    CScript scriptPubKey = dest;//GetScriptForDestination(dest);
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*scriptPubKey.begin()), scriptPubKey.end() - scriptPubKey.begin());
    uint256 hashed_script;
    hasher.Finalize(hashed_script.begin());
    const uint64_t addr_id = hashed_script.GetUint64(0);

    std::vector<CDiskTxPos> tx_positions;
    if (!m_db->ReadAddrIndex(addr_id, tx_positions)) {
        return false;
    }

    // NOTE: optimization: we don't need to keep opening the same file over and over again
    // sort tx_positions by CDiskBlockPos fields (as proxy for sorting by block number)
    // this way we can ensure each block file is only accessed once
    // Probably not necessary.

    for (const auto& tx_pos : tx_positions) {
        uint256 block_hash;
        CTransactionRef tx;

        CAutoFile file(OpenBlockFile(tx_pos, true), SER_DISK, CLIENT_VERSION);
        if (file.IsNull()) {
            return error("%s: OpenBlockFile failed", __func__);
        }
        CBlockHeader header;
        try {
            file >> header;
            if (fseek(file.Get(), tx_pos.nTxOffset, SEEK_CUR)) {
                return error("%s: fseek(...) failed", __func__);
            }
            file >> tx;
            // this way we can ensure each block file is only accessed once
        } catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s", __func__, e.what());
        }

        // NOTE: check scriptPubKeys
        /*
        if (tx->GetHash() != tx_hash) {
            return error("%s: txid mismatch", __func__);
        }
        */

        txs.emplace_back(header.GetHash(), tx);
    }

    return true;
}
