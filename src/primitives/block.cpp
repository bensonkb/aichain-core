// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "crypto/common.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "streams.h"

#define USE_LYRA2DC
uint256 CBlockHeader::GetHash() const {
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
#ifndef USE_LYRA2DC
	return SerializeHash(*this);
#else
	uint256 thash;
	lyra2dc_hash(BEGIN(nVersion), BEGIN(thash));
	return thash;
#endif
}

uint256 CBlockHeader::ComputePowHash(uint32_t nNonce) const
{
	CBlockHeader tryBlockHeader = *this;
	tryBlockHeader.nNonce = nNonce;	// set new nonce value to try ...

	CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tryBlockHeader;
    assert(ss.size() == 80);

#ifndef USE_LYRA2DC
	return SerializeHash(tryBlockHeader);
#else
	uint256 powHash;
	lyra2dc_hash((const char*)&ss[0], BEGIN(powHash));
	return powHash;
#endif
}

std::string CBlock::ToString() const {
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, "
                   "hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, "
                   "vtx=%u)\n",
                   GetHash().ToString(), nVersion, hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++) {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}
