// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/addrindex.h>
#include <index/txindex.h>
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
            BOOST_CHECK(!addr_index.FindTxsByScript(out.scriptPubKey, txs));
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
            if (!addr_index.FindTxsByScript(out.scriptPubKey, txs)) {
                    BOOST_ERROR("FindTxsByScript failed");
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
        if (!addr_index.FindTxsByScript(coinbase_script_pub_key, txs)) {
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

// Tests for correctness in the event of BlockDisconnected events in the ValidationInterface queue.
// Creates a small reorg to generate them.
BOOST_FIXTURE_TEST_CASE(addrindex_many_spends, TestChain100Setup)
{
    AddrIndex addr_index(1 << 20, true);
    addr_index.Start();

    // Mine blocks for coinbase maturity, so we can spend some coinbase outputs in the test.
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
    CreateSpendingTxs(0, script_pub_keys, spends, coinbase_script_pub_key);

    const CBlock& block = CreateAndProcessBlock(spends, coinbase_script_pub_key);
    const uint256 block_hash = block.GetHash();
    BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain()); // Let the address index catch up.
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block_hash); // Sanity check to make sure this block is actually being used.

    // Now check that all the addresses we sent to are present in the index.
    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTxsByScript(script_pub_keys[i], txs)) {
            BOOST_ERROR("FindTxsByScript failed");
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

        if (!found_tx) BOOST_ERROR("Transaction not found by destination");
    }

    // Now we'll create transaction that only send to the first 5 addresses we made.
    // Then we can check that the number of txs for those addresses increases, while
    // the number of txs for the other address remains the same.
    std::vector<CMutableTransaction> spends2(5);
    CreateSpendingTxs(10, script_pub_keys, spends2, coinbase_script_pub_key);

    const CBlock& block2 = CreateAndProcessBlock(spends2, coinbase_script_pub_key);
    const uint256 block_hash2 = block2.GetHash();
    BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain());
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block_hash2);

    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTxsByScript(script_pub_keys[i], txs)) {
            BOOST_ERROR("FindTxsByScript failed");
        }

        // Expect 2 transactions for those sent to twice, 1 for the rest.
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
}

BOOST_FIXTURE_TEST_CASE(addrindex_reorgs, TestChain100Setup)
{
    AddrIndex addr_index(1 << 20, true);
    g_txindex = MakeUnique<TxIndex>(1 << 20, false, false); // tx_index enabled so that addr_index can index spent outputs.

    g_txindex->Start();

    uint256 prev_hash = chainActive.Tip()->GetBlockHash();
    uint32_t prev_time = chainActive.Tip()->nTime;;

    // Mine blocks for coinbase maturity.
    CScript coinbase_script_pub_key = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < 20; i++) {
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        prev_hash = block.GetHash();
        prev_time = block.nTime;
    }

    // Allow txindex to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!g_txindex->BlockUntilSyncedToCurrentChain()) { //TODO this was addr_index
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
    // Copies are made since BuildChain erases txs from its input.
    std::vector<CMutableTransaction> spends(10);
    CreateSpendingTxs(0, script_pub_keys, spends, coinbase_script_pub_key);

    std::vector<CMutableTransaction> fork_one_copy(10);
    std::vector<CMutableTransaction> fork_two_copy(5);

    // The initial chain gets all txns, and the fork will only have the first half of them.
    for (int i = 0; i < 10; i++) {
        fork_one_copy[i] = spends[i];
        if (i < 5) {
            fork_two_copy[i] = spends[i];
        }
    }

    // Now we'll make two forks from the same block.
    // The second will have 5 more blocks, so should be chosen over the first.
    std::vector<std::shared_ptr<const CBlock>> chain_one;
    std::vector<std::shared_ptr<const CBlock>> chain_two;
    BuildChain(prev_hash, prev_time, 10, fork_one_copy, coinbase_script_pub_key, chain_one);
    BuildChain(prev_hash, prev_time, 20, fork_two_copy, coinbase_script_pub_key, chain_two);
    BOOST_CHECK_EQUAL(chain_one.size(), 10);
    BOOST_CHECK_EQUAL(chain_two.size(), 20);

    // As we process the transactions from chain_one, we should accept them all.
    // This mostly tests that BuildChain gives a valid chain for the purposes of this test.
    for (int i = 0; i < 10; ++i) {
        uint256 expected_hash = chain_one[i]->GetHash();
        ProcessNewBlock(Params(), chain_one[i], true, nullptr);
        BOOST_CHECK_EQUAL(expected_hash, chainActive.Tip()->GetBlockHash());

        if (i > 0) {
            BOOST_CHECK_EQUAL(chain_one[i]->hashPrevBlock, chain_one[i-1]->GetHash());
            BOOST_CHECK(chain_one[i]->GetHash() != chain_one[i-1]->GetHash());
        }
    }

    BOOST_CHECK(fork_one_copy.size() == 0);

    addr_index.Start();
    while (!addr_index.BlockUntilSyncedToCurrentChain()) {
        MilliSleep(100);
    }

    // Let's check that spending from coinbase shows up in the index.
    std::vector<std::pair<uint256, CTransactionRef>> txs;
    if (!addr_index.FindTxsByScript(coinbase_script_pub_key, txs)) {
        BOOST_ERROR("FindTransactionsByDestionation failed");
    }

    // Every coinbase tx sends to the same address so we should expect the number of txs
    // for this address to increase with each tx we add.
    BOOST_CHECK_EQUAL(txs.size(), 130 + 10); // 130 blocks + 10 spends

    // Check that the transactions we created spending from the coinbase_script_pub_key
    // appear in the index.
    for (unsigned int i = 0; i < spends.size(); i++) {
        bool found_tx = false;
        for (const auto& tuple : txs) {
            for (unsigned int i = 0; i < spends.size(); i++) {
                if (tuple.second->GetHash() == spends[i].GetHash()) {
                    found_tx = true;
                    break;
                }
            }
        }
        BOOST_CHECK(found_tx);
    }

    // Now check that all the txs we made appear in the index by their output address.
    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;
        if (!addr_index.FindTxsByScript(script_pub_keys[i], txs)) {
            BOOST_ERROR("FindTxsByScript failed");
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

        if (!found_tx) BOOST_ERROR("Transaction not found by destination");
    }

    // Now process the fork.
    for (int i = 0; i < 20; ++i) {
        uint256 chain_two_hash = chain_two[i]->GetHash();
        ProcessNewBlock(Params(), chain_two[i], true, nullptr);

        // After 10 blocks have been processed, this should be the main chain.
        if (i > 9) {
            BOOST_CHECK_EQUAL(chain_two_hash, chainActive.Tip()->GetBlockHash());
            BOOST_CHECK_EQUAL(chain_two[i]->hashPrevBlock, chain_two[i-1]->GetHash());
            BOOST_CHECK(chain_two[i]->GetHash() != chain_two[i-1]->GetHash());
        } else {
            // Check that this chain isn't being used yet.
            BOOST_CHECK(chain_two_hash != chainActive.Tip()->GetBlockHash());
        }
    }

    BOOST_CHECK(fork_two_copy.size() == 0);
    BOOST_CHECK(addr_index.BlockUntilSyncedToCurrentChain());


    // Check that transactions from the previous fork have been removed from the index,
    // and that transactions that stayed in the chain are still in the index.
    for (int i = 0; i < 10; i++) {
        std::vector<std::pair<uint256, CTransactionRef>> txs;

        // We expect these txs to show up.
        if (i < 5) {
            if (!addr_index.FindTxsByScript(script_pub_keys[i], txs)) {
                BOOST_ERROR("FindTxsByScript failed");
            }

            // Expect exactly one transaction the result.
            BOOST_CHECK_EQUAL(txs.size(), 1);

            // Confirm that the transaction's destination is in the index.
            bool found_tx = false;
            for (const auto& tuple : txs) {
                BOOST_CHECK(true);
                if (tuple.second->GetHash() == spends[i].GetHash()) {
                    found_tx = true;
                    break;
                }
            }

            if (!found_tx) {
                BOOST_ERROR("Transaction not found by destination");
            }
        } else {
            if (addr_index.FindTxsByScript(script_pub_keys[i], txs)) {
                BOOST_ERROR("FindTxsByScript should not find this tx");
            }
        }
    }

    // Check by coinbase_script_pub_key.
    std::vector<std::pair<uint256, CTransactionRef>> txs2;
    if (!addr_index.FindTxsByScript(coinbase_script_pub_key, txs2)) {
        BOOST_ERROR("FindTransactionsByDestionation failed");
    }

    // 140 coinbase txs + 5 spends.
    BOOST_CHECK_EQUAL(txs2.size(), 140 + 5);

    for (unsigned int i = 0; i < spends.size(); i++) {
        bool found_tx = false;
        for (const auto& tuple : txs2) {
            for (unsigned int i = 0; i < spends.size(); i++) {
                if (tuple.second->GetHash() == spends[i].GetHash()) {
                    found_tx = true;
                    break;
                }
            }
        }
        BOOST_CHECK(found_tx);
    }

    g_txindex->Stop();
    g_txindex = nullptr;
}

BOOST_AUTO_TEST_SUITE_END()
