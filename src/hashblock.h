#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "uint256.h"
#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "sph_luffa.h"
#include "sph_cubehash.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_echo.h"
#include "sph_hamsi.h"
#include "sph_fugue.h"
#include "sph_shabal.h"
#include "sph_whirlpool.h"
#include "hefty1.h"



#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_blake512_context     z_blake;
GLOBAL sph_bmw512_context       z_bmw;
GLOBAL sph_groestl512_context   z_groestl;
GLOBAL sph_jh512_context        z_jh;
GLOBAL sph_keccak512_context    z_keccak;
GLOBAL sph_skein512_context     z_skein;
GLOBAL sph_luffa512_context     z_luffa;
GLOBAL sph_cubehash512_context  z_cubehash;
GLOBAL sph_shavite512_context   z_shavite;
GLOBAL sph_simd512_context      z_simd;
GLOBAL sph_echo512_context      z_echo;
GLOBAL sph_hamsi512_context      z_hamsi;
GLOBAL sph_fugue512_context      z_fugue;
GLOBAL sph_shabal512_context     z_shabal;
GLOBAL sph_whirlpool_context     z_whirlpool;
GLOBAL HEFTY1_CTX                ctx1;
GLOBAL SHA256_CTX                ctx2;

#define fillz() do { \
    sph_blake512_init(&z_blake); \
    sph_bmw512_init(&z_bmw); \
    sph_groestl512_init(&z_groestl); \
    sph_jh512_init(&z_jh); \
    sph_keccak512_init(&z_keccak); \
    sph_skein512_init(&z_skein); \
    sph_luffa512_init(&z_luffa); \
    sph_cubehash512_init(&z_cubehash); \
    sph_shavite512_init(&z_shavite); \
    sph_simd512_init(&z_simd); \
    sph_echo512_init(&z_echo); \
    sph_hamsi512_init(&z_hamsi); \
    sph_fugue512_init(&z_fugue); \
    sph_shabal512_init(&z_shabal); \
    sph_whirlpool_init(&z_whirlpool); \
    HEFTY1_Init(&ctx1); \
    SHA256_Init(&ctx2); \
} while (0) 


#define ZBLAKE (memcpy(&ctx_blake, &z_blake, sizeof(z_blake)))
#define ZBMW (memcpy(&ctx_bmw, &z_bmw, sizeof(z_bmw)))
#define ZGROESTL (memcpy(&ctx_groestl, &z_groestl, sizeof(z_groestl)))
#define ZJH (memcpy(&ctx_jh, &z_jh, sizeof(z_jh)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))
#define ZHAMSI (memcpy(&ctx_hamsi, &z_hamsi, sizeof(z_hamsi)))
#define ZFUGUE (memcpy(&ctx_fugue, &z_fugue, sizeof(z_fugue)))
#define ZSHABAL (memcpy(&ctx_shabal, &z_shabal, sizeof(z_shabal)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))

inline uint256 CombineHashes(uint256 hash1, uint512 hash2, uint512 hash3, uint512 hash4)
{
    uint256 mask = uint256("0x8000000000000000000000000000000000000000000000000000000000000000");
    uint256 hash[4] = { hash1, hash2.trim256(), hash3.trim256(), hash4.trim256() };

    /* Transpose first 64 bits of each hash into final */
    uint256 final = 0;
    for (unsigned int i = 0; i < 64; i++) {
        for (unsigned int j = 0; j < 4; j++) {
            final <<= 1;
            if ((hash[j] & mask) != 0)
                final |= 1;
        }
        mask >>= 1;
    }

    return final;
}

template<typename T1>
inline uint256 HashGROESTLE(const T1 pbegin, const T1 pend)

{
    sph_groestl512_context ctx_groestl;
    static unsigned char pblank[1];

    uint512 hash1;
    uint256 hash2;

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash1));

    SHA256((unsigned char*)&hash1, 64, (unsigned char*)&hash2);

    return hash2;
}

template<typename T1>
inline uint256 HashSKEIN(const T1 pbegin, const T1 pend)

{
    sph_skein512_context ctx_skein;
    static unsigned char pblank[1];

    uint512 hash1;
    uint256 hash2;

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash1));

    SHA256((unsigned char*)&hash1, 64, (unsigned char*)&hash2);

    return hash2;
}

template<typename T1>
inline uint256 HashPENTABLAKE(const T1 pbegin, const T1 pend)
{
    sph_blake512_context ctx_blake;
    static unsigned char pblank[1];
    uint512 hash[8];
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, static_cast<const void*>(&hash[0]), 64);
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[1]));

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, static_cast<const void*>(&hash[1]), 64);
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[2]));

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, static_cast<const void*>(&hash[2]), 64);
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[3]));

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, static_cast<const void*>(&hash[3]), 64);
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[4]));

    return hash[4].trim256();
}

template<typename T1>
inline uint256 HashNIST5(const T1 pbegin, const T1 pend)
{
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    static unsigned char pblank[1];
    uint512 hash;

    // Blake512
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, (pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, (unsigned char*)&hash);
    // Groestl512
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (unsigned char*)&hash, sizeof(hash));
    sph_groestl512_close(&ctx_groestl, (unsigned char*)&hash);
    // Jh512
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, (unsigned char*)&hash, sizeof(hash));
    sph_jh512_close(&ctx_jh, (unsigned char*)&hash);
    // Keccak512
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, (unsigned char*)&hash, sizeof(hash));
    sph_keccak512_close(&ctx_keccak, (unsigned char*)&hash);
    // Skein512
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, (unsigned char*)&hash, sizeof(hash));
    sph_skein512_close(&ctx_skein, (unsigned char*)&hash);

    return hash.trim256();
}

template<typename T1>
inline uint256 HashWHIRLPOOL(const T1 pbegin, const T1 pend)
{
    sph_whirlpool1_context whirlpool;
    static unsigned char pblank[1];
    uint512 hash[4];

    sph_whirlpool1_init(&whirlpool);
    sph_whirlpool1 (&whirlpool, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_whirlpool1_close(&whirlpool, static_cast<void*>(&hash[0]));

sph_whirlpool1_init(&whirlpool);
sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[0]),64);
sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[1]));

sph_whirlpool1_init(&whirlpool);
sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[1]),64);
sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[2]));

sph_whirlpool1_init(&whirlpool);
sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[2]),64);
sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[3]));

    return hash[3].trim256();
}

template<typename T1>
inline uint256 HashLUFFA(const T1 pbegin, const T1 pend)

{
    sph_luffa512_context ctx_luffa;
    static unsigned char pblank[1];

    uint512 hash;
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash));

    return hash.trim256();
}

template<typename T1>
inline uint256 HashKECCAK(const T1 pbegin, const T1 pend)
{
    sph_keccak256_context ctx_keccak;
    static unsigned char pblank[1];
    uint256 hash;

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak256_close(&ctx_keccak, static_cast<void*>(&hash));

    return hash;
}

template<typename T1>
inline uint256 HashX11(const T1 pbegin, const T1 pend)

{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    static unsigned char pblank[1];

#ifndef QT_NO_DEBUG
    //std::string strhash;
    //strhash = "";
#endif

    uint512 hash[17];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));

    return hash[10].trim256();
}

template<typename T1>
inline uint256 HashX13(const T1 pbegin, const T1 pend)

{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    static unsigned char pblank[1];

    uint512 hash[17];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));


    return hash[12].trim256();



}

template<typename T1>
inline uint256 HashX15(const T1 pbegin, const T1 pend)

{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    static unsigned char pblank[1];

#ifndef QT_NO_DEBUG
    //std::string strhash;
    //strhash = "";
#endif
    
    uint512 hash[17];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
        
    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));


    return hash[14].trim256();
}

template<typename T1>
inline uint256 HashQUARK(const T1 pbegin, const T1 pend)

{
    sph_blake512_context ctx_blake;
    sph_bmw512_context ctx_bmw;
    sph_groestl512_context ctx_groestl;
    sph_jh512_context ctx_jh;
    sph_keccak512_context ctx_keccak;
    sph_skein512_context ctx_skein;
    static unsigned char pblank[1];

    uint512 mask = 8;
    uint512 zero = 0;
    
    uint512 hash[9];

    sph_blake512_init(&ctx_blake);
    // ZBLAKE;
    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
    
    sph_bmw512_init(&ctx_bmw);
    // ZBMW;
    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));

    if ((hash[1] & mask) != zero)
    {
        sph_groestl512_init(&ctx_groestl);
        // ZGROESTL;
        sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
        sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        // ZSKEIN;
        sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[1]), 64);
        sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[2]));
    }
    
    sph_groestl512_init(&ctx_groestl);
    // ZGROESTL;
    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[2]), 64);
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[3]));

    sph_jh512_init(&ctx_jh);
    // ZJH;
    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));

    if ((hash[4] & mask) != zero)
    {
        sph_blake512_init(&ctx_blake);
        // ZBLAKE;
        sph_blake512 (&ctx_blake, static_cast<const void*>(&hash[4]), 64);
        sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[5]));
    }
    else
    {
        sph_bmw512_init(&ctx_bmw);
        // ZBMW;
        sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[4]), 64);
        sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[5]));
    }
    
    sph_keccak512_init(&ctx_keccak);
    // ZKECCAK;
    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[5]), 64);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[6]));

    sph_skein512_init(&ctx_skein);
    // SKEIN;
    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[6]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[7]));

    if ((hash[7] & mask) != zero)
    {
        sph_keccak512_init(&ctx_keccak);
        // ZKECCAK;
        sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[7]), 64);
        sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[8]));
    }
    else
    {
        sph_jh512_init(&ctx_jh);
        // ZJH;
        sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[7]), 64);
        sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[8]));
    }

    return hash[8].trim256();
}

template<typename T1>
inline uint256 HashBASTION(const T1 pbegin, const T1 pend)

{
    sph_echo512_context ctx_echo;
    sph_luffa512_context ctx_luffa;
    sph_fugue512_context ctx_fugue;
    sph_whirlpool_context ctx_whirlpool;
    sph_shabal512_context ctx_shabal;
    sph_skein512_context ctx_skein;
    sph_hamsi512_context ctx_hamsi;
    static unsigned char pblank[1];

    uint512 mask = 8;
    uint512 zero = 0;

    uint512 hash[11];

    HEFTY1((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
    (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash[0]);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, static_cast<const void*>(&hash[0]), 64);
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[1]));

    if ((hash[1] & mask) != zero)
    {
        sph_fugue512_init(&ctx_fugue);
        sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[1]), 64);
        sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[2]));
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[1]), 64);
        sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[2]));
    }


    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[2]), 64);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[3]));
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[3]), 64);
    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[4]));

    if ((hash[4] & mask) != zero)
    {
        sph_echo512_init(&ctx_echo);
        sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[4]), 64);
        sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[5]));
    }
    else
    {
        sph_luffa512_init(&ctx_luffa);
        sph_luffa512 (&ctx_luffa, static_cast<const void*>(&hash[4]), 64);
        sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[5]));
    }

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[5]), 64);
    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[6]));

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[6]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[7]));

    if ((hash[7] & mask) != zero)
    {
        sph_shabal512_init(&ctx_shabal);
        sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[7]), 64);
        sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[8]));
    }
    else
    {
        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[7]), 64);
        sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[8]));
    }

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[8]), 64);
    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[9]));
    
    if ((hash[9] & mask) != zero)
    {
        sph_hamsi512_init(&ctx_hamsi);
        sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[9]), 64);
        sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[10]));
    }
    else
    {
        sph_luffa512_init(&ctx_luffa);
        sph_luffa512 (&ctx_luffa, static_cast<const void*>(&hash[9]), 64);
        sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[10]));
    }
    
    return hash[10].trim256();
}


template<typename T1>
inline uint256 HashHEFTY(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    HEFTY1((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
           (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);

    uint256 hash2;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx,
                  (pbegin == pend ? pblank : (unsigned char *)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    SHA256_Update(&ctx, (unsigned char *)&hash1, sizeof(hash1));
    SHA256_Final((unsigned char *)&hash2, &ctx);

    uint512 hash3;
    sph_keccak512_context keccakCtx;
    sph_keccak512_init(&keccakCtx);
    sph_keccak512(&keccakCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak512(&keccakCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_keccak512_close(&keccakCtx, (void *)&hash3);

    uint512 hash4;
    sph_groestl512_context groestlCtx;
    sph_groestl512_init(&groestlCtx);
    sph_groestl512(&groestlCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                   (pend - pbegin) * sizeof(pbegin[0]));
    sph_groestl512(&groestlCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_groestl512_close(&groestlCtx, (void *)&hash4);

    uint512 hash5;
    sph_blake512_context blakeCtx;
    sph_blake512_init(&blakeCtx);
    sph_blake512(&blakeCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512(&blakeCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_blake512_close(&blakeCtx, (void *)&hash5);

    uint256 final = CombineHashes(hash2, hash3, hash4, hash5);

    return final;
}


#endif // HASHBLOCK_H
