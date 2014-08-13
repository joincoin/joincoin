// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

//
// Main network
//

unsigned int pnSeed[] =
{
    0x12345678
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0x9e;
        vAlertPubKey = ParseHex("04afab92605200deff24c7d1bd64b4849600897b73feb25a69de757eade6893d043c40276ec1d84581b400288d0d312cd8037b7ab75a502b1e98e13fbacaacd671");
        nDefaultPort = 17941;
        nRPCPort = 17942;
	bnProofOfWorkLimit[ALGO_SHA]  = CBigNum(~uint256(0) >> 20);
	bnProofOfWorkLimit[ALGO_X11]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_X13]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_X15]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_SCRYPT]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_NIST5]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_GROESTLE]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_PENTABLAKE]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_WHIRLPOOL]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_LUFFA]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_KECCAK]  = CBigNum(~uint256(0) >> 26);
	bnProofOfWorkLimit[ALGO_QUARK]  = CBigNum(~uint256(0) >> 26);
        bnProofOfWorkLimit[ALGO_BASTION]  = CBigNum(~uint256(0) >> 26);
        nSubsidyHalvingInterval = 80000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
  
        const char* pszTimestamp = "FOXNEWS 04/08 Police arrest Washington mother suspected of killing toddler";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("044142d677eb339b60dc70c7c2adc77baf47699bf610b89da68caf664efdd1d69133921db64d65e08ff6873a935aba23778da80fa1d08a836a27fe76fa4401f389") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = BLOCK_VERSION_DEFAULT;
        genesis.nTime    = 1407162812;
        genesis.nBits    = 0x1e0fffff;
        genesis.nNonce   = 4119966442;
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        //while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA].getuint256()){
        //    if (++genesis.nNonce==0) break;
        //    hashGenesisBlock = genesis.GetHash();
        //}

        //printf("MAIN: %s\n", hashGenesisBlock.ToString().c_str());
        //printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("%x\n", bnProofOfWorkLimit[ALGO_SHA].GetCompact());
        //genesis.print();
        
        assert(hashGenesisBlock == uint256("0x00000cb6d04806bcc087902202a7e3ed33aea51319b2c896ab4acdd112690371"));
        assert(genesis.hashMerkleRoot == uint256("0x8a489c39885ac6f5beb68d32302ad4dcfa1df3abdd6226314a10e69c7134a513"));

        vSeeds.push_back(CDNSSeedData("seed1.joincoin.org", "seed1.joincoin.org"));
        vSeeds.push_back(CDNSSeedData("seed2.joincoin.org", "seed2.joincoin.org"));
        vSeeds.push_back(CDNSSeedData("seed3.joincoin.org", "seed3.joincoin.org"));
        vSeeds.push_back(CDNSSeedData("seed4.joincoin.org", "seed4.joincoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = 43;
        base58Prefixes[SCRIPT_ADDRESS] = 9;
        base58Prefixes[SECRET_KEY] = 178;

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' 
            const int64 nTwoDays = 2 * 24 * 60 * 60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nTwoDays) - nTwoDays;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        pchMessageStart[0] = 0x5a;
        pchMessageStart[1] = 0x7b;
        pchMessageStart[2] = 0xff;
        pchMessageStart[3] = 0xfa;
        vAlertPubKey = ParseHex("04afab92605200deff24c7d1bd64b4849600897b73feb25a69de757eade6893d043c40276ec1d84581b400288d0d312cd8037b7ab75a502b1e98e13fbacaacd671");
        nDefaultPort = 27941;
        nRPCPort = 27942;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1407163316;
        genesis.nNonce = 419605088;
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        /*while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA].getuint256()){
            if (++genesis.nNonce==0) break;
           hashGenesisBlock = genesis.GetHash();
        }

        printf("TEST: %s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        genesis.print(); */
        
        assert(hashGenesisBlock == uint256("0x00000f1ac866247e953a9afb34faa736f84f9e2c4f72010b608f3d34e15bfda5"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testseed1.joincoin.org", "testseed1.joincoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = 88;
        base58Prefixes[SCRIPT_ADDRESS] = 188;
        base58Prefixes[SECRET_KEY] = 239;

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0x77;
        pchMessageStart[1] = 0xea;
        pchMessageStart[2] = 0xe1;
        pchMessageStart[3] = 0x9f;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit[ALGO_SHA]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X11]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X13]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X15]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_SCRYPT]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_NIST5]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_GROESTLE]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_PENTABLAKE]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_WHIRLPOOL]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_LUFFA]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_KECCAK]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_QUARK]  = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1407163387;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 5;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 27943;
        strDataDir = "regtest";
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        /*while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA].getuint256()){
            if (++genesis.nNonce==0) break;
            hashGenesisBlock = genesis.GetHash();
        }

        printf("REG: %s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        genesis.print();*/

        assert(hashGenesisBlock == uint256("0x164a6df9af06b9226f5b184d1b1a7645f054b9fc21fe91f51c1143c00ec76d79"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = 0;
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
