// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cassert>
#include "arith_uint256.h"

#include "chainparamsseeds.h"

// Far into the future.
static const std::string ANTI_REPLAY_COMMITMENT =
    "Bitcoin: A Peer-to-Peer Electronic Cash System";

static std::vector<uint8_t> GetAntiReplayCommitment() {
    return std::vector<uint8_t>(std::begin(ANTI_REPLAY_COMMITMENT),
                                std::end(ANTI_REPLAY_COMMITMENT));
}

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 28/Jan/2018 AICHAIN life forever...";
    const CScript genesisOutputScript =
        CScript() << ParseHex("039494a2b58d639eac9c79a6f0c8e02be71b0d0b98c639e8cfb87e886de1fb2c61") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
#include "arith_uint256.h"

static bool CheckProofOfWork(uint256 hash, uint32_t nBits,
                      const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

static void Get_nBits_fromPOWLimit(uint256 powlimit) {
    arith_uint256 bnTarget;

	bnTarget=UintToArith256(powlimit);
	uint256 targetbn = ArithToUint256(bnTarget.GetCompact(false));

	printf("get nBits=%s\n", targetbn.ToString().c_str());
}

static bool CheckPOWLIMIT_valid(uint32_t nBits,
                      const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {

		uint256 targetbn = ArithToUint256(bnTarget);
		printf("wrong bnTarget=%s\n", targetbn.ToString().c_str());
        return false;
    }

    return true;
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 0;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 0;
        consensus.antiReplayOpReturnSunsetHeight = 530000;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        // 95% of 2016
        consensus.nRuleChangeActivationThreshold = 1916;
        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            uint256S("0x00000000000000000553279251628c470a5b51de3bbbf336b208530"
                     "25ffbf270");

        // Aug, 1 hard fork
        consensus.uahfHeight = 0;

        // Nov, 13 hard fork
        consensus.cashHardForkActivationTime = 0;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb6;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0xbf;
        pchMessageStart[3] = 0xad;
        pchCashMessageStart[0] = 0xcd;
        pchCashMessageStart[1] = 0xf5;
        pchCashMessageStart[2] = 0xc9;
        pchCashMessageStart[3] = 0xbc;
        nDefaultPort = 9523;
        nPruneAfterHeight = 100000;
		nMinerThreads = 1;

#if 0
        uint32_t myTime=time(NULL);
        genesis = CreateGenesisBlock(myTime, 0, 0x1f00ffff, 1,
                                     50 * COIN);

		Get_nBits_fromPOWLimit(consensus.powLimit);
		if(!CheckPOWLIMIT_valid(genesis.nBits, consensus))
		{
			exit(1);
		}
		
		printf("MAINNET start to compute genesis block time=%d\n",myTime);
		while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, consensus)) {
		//	printf("nonce=%d hash=%s\n", genesis.nNonce, genesis.GetPoWHash().ToString().c_str());
			++genesis.nNonce;
		}

		printf("MAINNET Success create a genesis block! nonce=%d\n", genesis.nNonce);
		printf("MAINNET genesis POW hash = %s\n", genesis.GetPoWHash().ToString().c_str());
		printf("MAINNET genesis hash = %s\n", genesis.GetHash().ToString().c_str());
		printf("MAINNET genesis.hashMerkleRoot=%s\n", genesis.hashMerkleRoot.ToString().c_str());
		exit(1);
#endif
		genesis = CreateGenesisBlock(1519971762, 29168, 0x1f00ffff, 1,
                                     50 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("2b6d7868955c12134bef80a0d7509413483361faa7af7d3c1e1f2260b11af656"));
        assert(genesis.hashMerkleRoot ==
               uint256S("56b56c2b57e276da291084d8e3b1518ce2a406412e7d90910e02aa68c67eeaf3"));

        // Note that of those with the service bits flag, most only support a
        // subset of possible options.
        // for clement's test 
        vSeeds.push_back(CDNSSeedData("CLEMENT-MAINNET",
                                      "192.168.33.36", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 28);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 66);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x0C, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x0C, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "ait";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {.mapCheckpoints = {
                              {0, uint256S("2b6d7868955c12134bef80a0d7509413483361faa7af7d3c1e1f2260b11af656")},
                          }};

        chainTxData = ChainTxData{0, 0, 0};
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 0;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 0;
        consensus.antiReplayOpReturnSunsetHeight = 1250000;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 1512;
        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            uint256S("0x00000000ba37a638c096da8e1a843df68f4cc9754124f11034a0b61"
                     "3bbf4ca3e");

        // Aug, 1 hard fork
        consensus.uahfHeight = 0;

        // Nov, 13 hard fork
        consensus.cashHardForkActivationTime = 0;

		pchCashMessageStart[0] = 0xb6;
        pchCashMessageStart[1] = 0xce;
        pchCashMessageStart[2] = 0xbf;
        pchCashMessageStart[3] = 0xad;
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf5;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xbc;
		
        nDefaultPort = 19523;
        nPruneAfterHeight = 1000;
		nMinerThreads = 1;

#if 0
		uint32_t myTime=time(NULL);
        genesis =
            CreateGenesisBlock(myTime, 0, 0x1f00ffff, 1, 50 * COIN);

		Get_nBits_fromPOWLimit(consensus.powLimit);
		if(!CheckPOWLIMIT_valid(genesis.nBits, consensus))
		{
			exit(1);
		}
		
		printf("TESTNET start to compute genesis block time=%d\n",myTime);
		while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, consensus)) {
			++genesis.nNonce;
		}

		printf("TESTNET Success create a genesis block! nonce=%d\n", genesis.nNonce);
		printf("TESTNET genesis POW hash = %s\n", genesis.GetPoWHash().ToString().c_str());
		printf("TESTNET genesis hash = %s\n", genesis.GetHash().ToString().c_str());
		printf("TESTNET genesis.hashMerkleRoot=%s\n", genesis.hashMerkleRoot.ToString().c_str());
		exit(1);
#endif
		genesis =
            CreateGenesisBlock(1519972273, 125880, 0x1f00ffff, 1, 50 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("4bde424ae600ed26cd3417ce477bd165c441c6e90dceca50af69815bfb7edda7"));
        assert(genesis.hashMerkleRoot ==
               uint256S("56b56c2b57e276da291084d8e3b1518ce2a406412e7d90910e02aa68c67eeaf3"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // for clement's test 
        vSeeds.push_back(CDNSSeedData("CLEMENT-TESTNET",
                                      "192.168.33.36", true));
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 132);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 137);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 142);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x0C, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x0C, 0x35, 0x83, 0x94};
        cashaddrPrefix = "aittest";
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

		checkpointData = {.mapCheckpoints = {
                              {0, uint256S("4bde424ae600ed26cd3417ce477bd165c441c6e90dceca50af69815bfb7edda7")},
                          }};

        chainTxData = ChainTxData{0, 0, 0};
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        consensus.antiReplayOpReturnSunsetHeight = 530000;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 108;
        // Faster than normal for regtest (144 instead of 2016)
        consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =
            999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =
            999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // Hard fork is always enabled on regtest.
        consensus.uahfHeight = 0;

        // Nov, 13 hard fork is always on on regtest.
        consensus.cashHardForkActivationTime = 0;

        pchCashMessageStart[0] = 0xb6;
        pchCashMessageStart[1] = 0xce;
        pchCashMessageStart[2] = 0xbf;
        pchCashMessageStart[3] = 0xad;
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf5;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xbc;
        nDefaultPort = 19524;
        nPruneAfterHeight = 1000;
		nMinerThreads = 0;

#if 0
		uint32_t myTime=time(NULL);
        genesis = CreateGenesisBlock(myTime, 0, 0x207fffff, 1, 50 * COIN);
		Get_nBits_fromPOWLimit(consensus.powLimit);
		if(!CheckPOWLIMIT_valid(genesis.nBits, consensus))
		{
			exit(1);
		}
		
		printf("REGTEST start to compute genesis block time=%d\n",myTime);
		
		while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, consensus)) {
            ++genesis.nNonce;
        }

		printf("REGTEST Success create a genesis block! nonce=%d\n", genesis.nNonce);
		printf("REGTEST genesis POW hash = %s\n", genesis.GetPoWHash().ToString().c_str());
		printf("REGTEST genesis hash = %s\n", genesis.GetHash().ToString().c_str());
		printf("REGTEST genesis.hashMerkleRoot=%s\n", genesis.hashMerkleRoot.ToString().c_str());
		exit(1);
#endif
		genesis = CreateGenesisBlock(1519973022, 0, 0x207fffff, 1, 50 * COIN);
		consensus.hashGenesisBlock = genesis.GetHash();
		
        assert(consensus.hashGenesisBlock ==
               uint256S("3b3a8dca4654427042e5142ef7da37fc8963a38a0d4b34d222e364d92cc4e10c"));
        assert(genesis.hashMerkleRoot ==
               uint256S("56b56c2b57e276da291084d8e3b1518ce2a406412e7d90910e02aa68c67eeaf3"));

        //!< Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //!< Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {.mapCheckpoints = {
                              {0, uint256S("3b3a8dca4654427042e5142ef7da37fc8963a38a0d4b34d222e364d92cc4e10c")},
                          }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 132);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 137);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 142);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x0C, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x0C, 0x35, 0x83, 0x94};
        cashaddrPrefix = "aitreg";
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                              int64_t nTimeout) {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return mainParams;
    }

    if (chain == CBaseChainParams::TESTNET) {
        return testNetParams;
    }

    if (chain == CBaseChainParams::REGTEST) {
        return regTestParams;
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                                 int64_t nTimeout) {
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
