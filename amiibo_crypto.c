// Amiibo crypto
// -- plutoo 2015

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>

typedef unsigned long long int u64;
typedef unsigned int  uint;
typedef unsigned char u8;

#define DEBUG_KEYS

u8 random_key[16] = {
    0xC1, /* Censored. */
};

u8 random_iv[16] = {
    0x4F, /* Censored. */
};

u8 amiibo_constant0[14] = {
#ifdef DEBUG_KEYS
    0xDB, /* Censored. */
#else
    0x52, /* Censored. */
#endif
};

u8 amiibo_constant1[16] = {
#ifdef DEBUG_KEYS
    0xFD, /* Censored. */
#else
    0x4C, /* Censored. */
#endif
};

u8 hmac_key0[16] = {
#ifdef DEBUG_KEYS
    0x1D, /* Censored. */
#else
    0xED, /* Censored. */
#endif
};

u8 hmac_key1[16] = {
#ifdef DEBUG_KEYS
    0x7F, /* Censored. */
#else
    0x83, /* Censored. */
#endif
};

u8 type_string0[] = "unfixed infos\x00";
u8 type_string1[] = "locked secret\x00";


void sha256_hmac(u8* key, uint keylen, u8* in, uint inlen, u8* out) {
    HMAC_CTX ctx, *c=&ctx;
    uint outlen = 0x20;
    HMAC_CTX_init(c);
    HMAC_Init(c, key, keylen, EVP_sha256());
    HMAC_Update(c, in, inlen);
    HMAC_Final(c, out, &outlen);
    HMAC_CTX_cleanup(c);
}

void sha256(u8* in, uint inlen, u8* out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out, &ctx);
}

void aes128(u8* key, u8* in, u8* out) {
    u8 iv[16];
    AES_KEY aes_key;
    memset(iv, 0, 16);
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_cbc_encrypt(in, out, 16, &aes_key, iv, AES_ENCRYPT);
}

void aes128_ctr(u8* key, u8* iv, u8* in_out, uint len) {
    u8 buf[16], out[16];
    memcpy(buf, iv, 16);

    uint i;
    for(i=0; i<len/16; i++) {
        aes128(key, buf, out);

        uint j;
        for(j=0; j<16; j++)
            in_out[i*16 + j] ^= out[j];

        for(j=0; j<16; j++) {
            uint old = buf[15-j] + 1;
            buf[15-j] = old;
            if(old < 0x100)
                break;
        }
    }
}

void amiibo_hmac_scramble(u8* hmac_key, u8* type_str/*len=0xE*/, u8* seeds/*len=0x40*/, u8* out) {
    u8 data[0x50];
    memcpy(data+2,    type_str, 14);
    memcpy(data+2+14, seeds, 0x40);
    data[0] = 0; data[1] = 0;
    sha256_hmac(hmac_key, 0x10, data, 0x50, out);
    data[0] = 0; data[1] = 1;
    sha256_hmac(hmac_key, 0x10, data, 0x50, out+0x20);
}

void generate_seeds1(int type, u8* seed1/*len=0x10 or 8*/, u8* randomseed, u8* out/*len=0x40*/) {
    memcpy(out, amiibo_constant1, 16);
    if(type == 0)
        memcpy(out+16, seed1, 16);
    else {
        memcpy(out+16,   seed1, 8);
        memcpy(out+16+8, seed1, 8);
    }
    memcpy(out+32, randomseed, 32);
}

void generate_seeds0(int type, u8* seed0/*len=2*/, u8* seed1, u8* randomseed, u8* out/*len=0x40*/) {
    memcpy(out, seed0, 2);
    memcpy(out+2, amiibo_constant0, 14);
    if(type == 0)
        memcpy(out+16, seed1, 16);
    else {
        memcpy(out+16,   seed1, 8);
        memcpy(out+16+8, seed1, 8);
    }
    memcpy(out+32, randomseed, 32);
}

void hexdump(u8* a, uint len) {
    uint i;
    for(i=0; i<len; i++) {
        printf("%02x", a[i]);
        if(((i+1) % 16) == 0)
            printf("\n");
    }
}

void encrypt_zeroes(u8* key, u8* iv) {
    u8 out[16];
    memset(out, 0, 0x10);
    aes128_ctr(key, iv, out, 16);
    hexdump(out, 0x10);
}

int main() {
    u8 randomseed[0x20];
    u8 seed0[2];
    u8 seed1[0x10]; // For type2, this is 8-bytes.

    memset(randomseed, 0, 0x20);
    memset(seed0, 0, 2);
    memset(seed1, 0, 0x10);

    #define TYPE 2
    aes128_ctr(random_key, random_iv, randomseed, 0x20);
    //hexdump(randomseed, 0x20);

    u8 seeds[0x40];
    u8 hmac[0x20];
    generate_seeds0(TYPE, seed0, seed1, randomseed, seeds);
    amiibo_hmac_scramble(hmac_key0, type_string0, seeds, hmac);

    printf("Per-key0:      ");
    hexdump(hmac, 0x10);
    printf("Per-iv0:       ");
    hexdump(hmac+0x10, 0x10);
    printf("(Zeroes:)      ");
    encrypt_zeroes(hmac, hmac+0x10);
    printf("Per-hmac-key0: ");
    hexdump(hmac+0x20, 0x10);

    generate_seeds1(TYPE, seed1, randomseed, seeds);
    amiibo_hmac_scramble(hmac_key1, type_string1, seeds, hmac);
    
    printf("Per-key1:      ");
    hexdump(hmac, 0x10);
    printf("Per-iv1:       ");
    hexdump(hmac+0x10, 0x10);
    printf("(Zeroes:)      ");
    encrypt_zeroes(hmac, hmac+0x10);
    printf("Per-hmac-key1: ");
    hexdump(hmac+0x20, 0x10);

    return 0;
}

// __ Keychunk: __
// type_str = "unfixed infos" (flag != 0)
// type_str = "locked secret" (flag == 0)
// offset 0x0E size 0x0E    (amiibo_constant flag != 0)
// offset 0x1C size 0x10    (hmac-key flag != 0)
// offset 0x3A size 0x10    (amiibo_constant flag == 0)
// offset 0x4A size 0x10    (hmac-key flag == 0)
