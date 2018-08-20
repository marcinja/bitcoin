// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/addrindex.h>
#include <script/standard.h>
#include <test/test_bitcoin.h>
#include <util.h>
#include <utiltime.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(addrindex_tests)

BOOST_FIXTURE_TEST_CASE(addrindex_initial_sync, TestChain100Setup)
{
    AddrIndex addr_index(1 << 20, true);

    CTransactionRef tx_disk;
    uint256 block_hash;

    // Transactions should not be found in the index before it is started.
    for (const auto& txn : m_coinbase_txns) {
        for (const auto& out : txn->vout) {
            std::vector<std::pair<uint256, CTransactionRef>> txs;
            BOOST_CHECK(!addr_index.FindTransactionsByDestination(out.scriptPubKey, txs));
        }
    }

    // BlockUntilSyncedToCurrentChain should return false before addrindex is started.
    BOOST_CHECK(!addr_index.BlockUntilSyncedToCurrentChain());

    addr_index.Start();

    // Allow addrindex to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!addr_index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    // Check that addrindex has all addresses sent to that were in the chain before it started.
    for (const auto& txn : m_coinbase_txns) {
        uint256 tx_hash = txn->GetHash();
        for (const auto& out : txn->vout) {
            std::vector<std::pair<uint256, CTransactionRef>> txs;
            if (!addr_index.FindTransactionsByDestination(out.scriptPubKey, txs)) {
                    BOOST_ERROR("FindTransactionsByDestination failed");
            }

            // Confirm that the transaction's destination is in the index.
            bool found_tx = false;
            for (const auto& tuple : txs) {
                if (tuple.second->GetHash() == tx_hash) {
                    found_tx = true;
                    break;
                }
            }

            if (!found_tx) {
                BOOST_ERROR("Transaction not found by destination");
            }
        }
    }

    // Check that new transactions in new blocks make it into the index.
    CScript coinbase_script_pub_key = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    for (int i = 0; i < 10; i++) {
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        const CTransaction& txn = *block.vtx[0];

        BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain());

        uint256 tx_hash = txn.GetHash();
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTransactionsByDestination(coinbase_script_pub_key, txs)) {
            BOOST_ERROR("FindTransactionsByDestionation failed");
        }

        // Every coinbase tx sends to the same address so we should expect the number of txs
        // for this address to increase with each tx we add.
        BOOST_CHECK_EQUAL(txs.size(), i + 1);

        // Confirm that the transaction's destination is in the index.
        bool found_tx = false;
        for (const auto& tuple : txs) {
            if (tuple.second->GetHash() == tx_hash) {
                found_tx = true;
                break;
            }
        }

        if (!found_tx) {
            BOOST_ERROR("Transaction not found by destination");
        }
    }
}

BOOST_FIXTURE_TEST_CASE(addrindex_many_spends, TestChain100Setup)
{
    AddrIndex addr_index(1 << 20, true);
    addr_index.Start();

    // Mine blocks for coinbase maturity.
    CScript coinbase_script_pub_key = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < 20; i++) {
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
    }

    // Allow addrindex to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!addr_index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    // Create several new key pairs to test sending to many different addresses in the same block.
    std::vector<CKey> priv_keys(10);
    std::vector<CScript> script_pub_keys(10);
    for (int i = 0; i < 10; i++) {
        priv_keys[i].MakeNewKey(true);
        script_pub_keys[i] = CScript() <<  ToByteVector(priv_keys[i].GetPubKey()) << OP_CHECKSIG;
    }

    // Create a transaction sending to each of the new addresses.
    std::vector<CMutableTransaction> spends(10);
    for (int i = 0; i < 10; i++) {
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = m_coinbase_txns[i]->GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = script_pub_keys[i];

        // Sign:
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(coinbase_script_pub_key, spends[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    const CBlock& block = CreateAndProcessBlock(spends, coinbase_script_pub_key);
    const uint256 block_hash = block.GetHash();
    BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain());
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block_hash);

    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTransactionsByDestination(script_pub_keys[i], txs)) {
            BOOST_ERROR("FindTransactionsByDestination failed");
        }

        // Expect exactly one transaction the result.
        BOOST_CHECK_EQUAL(txs.size(), 1);

        // Confirm that the transaction's destination is in the index.
        bool found_tx = false;
        for (const auto& tuple : txs) {
            if (tuple.second->GetHash() == spends[i].GetHash()) {
                found_tx = true;
                break;
            }
        }

        if (!found_tx) {
            BOOST_ERROR("Transaction not found by destination");
        }
    }

    // Now we'll create transaction that only send to the first 5 addresses we made.
    std::vector<CMutableTransaction> spends2(5);
    for (int i = 0; i < 5; i++) {
        spends2[i].nVersion = 1;
        spends2[i].vin.resize(1);
        spends2[i].vin[0].prevout.hash = m_coinbase_txns[i+10]->GetHash();
        spends2[i].vin[0].prevout.n = 0;
        spends2[i].vout.resize(1);
        spends2[i].vout[0].nValue = 11*CENT;
        spends2[i].vout[0].scriptPubKey = script_pub_keys[i];

        // Sign:
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(coinbase_script_pub_key, spends2[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends2[i].vin[0].scriptSig << vchSig;
    }

    const CBlock& block2 = CreateAndProcessBlock(spends2, coinbase_script_pub_key);
    const uint256 block_hash2 = block2.GetHash();
    BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain());
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block_hash2);

    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTransactionsByDestination(script_pub_keys[i], txs)) {
            BOOST_ERROR("FindTransactionsByDestination failed");
        }

        // Expect 2 transasctions for those sent to twice, 1 for the rest.
        if (i >= 5) {
            BOOST_CHECK_EQUAL(txs.size(), 1);
        } else {
            BOOST_CHECK_EQUAL(txs.size(), 2);
        }

        // Confirm that the transaction's destination is in the index.
        bool found_tx = false;
        for (const auto& tuple : txs) {
            if (i >= 5) {
                if (tuple.second->GetHash() == spends[i].GetHash()) {
                    found_tx = true;
                    break;
                }
            } else {
                if (tuple.second->GetHash() == spends2[i].GetHash()) {
                    found_tx = true;
                    break;
                }
            }
        }

        if (!found_tx) {
            BOOST_ERROR("Transaction not found by destination");
        }
    }
    // TODO: Same test but with every kind of transaction

}
BOOST_AUTO_TEST_SUITE_END()
