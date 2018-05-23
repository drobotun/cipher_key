#include "cipher_key.h"

static void
add_xor_64(const uint8_t *a, const uint8_t *b, uint8_t *c)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        c[i] = a[i]^b[i];
}

static void
GetHashString(uint8_t *str, uint8_t *hash, int hash_size, size_t size_str)
{
    TGOSTHashContext *CTX;
    CTX = (TGOSTHashContext*)(malloc(sizeof(TGOSTHashContext)));
    uint8_t *buffer;
    buffer = malloc(size_str);
    memcpy(buffer, str, size_str);
    GOSTHashInit(CTX, hash_size);
    GOSTHashUpdate(CTX, buffer, size_str);
    GOSTHashFinal(CTX);
    memcpy(hash, CTX->hash, BLOCK_SIZE);
    free(buffer);
    free(CTX);
}

static void
HMAC_GOSTR3411(const uint8_t *K, size_t size_K, const uint8_t *T, size_t size_T, uint8_t *HMAC)
{
    uint8_t i_pad[BLOCK_SIZE] = {
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
    };

    uint8_t o_pad[BLOCK_SIZE] = {
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
    };

    uint8_t internal_1 [2 * BLOCK_SIZE];
    uint8_t *internal_2;
    uint8_t hash[BLOCK_SIZE];
    internal_2 = malloc(BLOCK_SIZE + size_T);
    uint8_t K_[BLOCK_SIZE];
    memset(K_, 0x00, BLOCK_SIZE);
    memcpy(K_, K, size_K);
    add_xor_64(K_, i_pad, internal_2);
    memcpy(internal_2 + BLOCK_SIZE, T, size_T);
    GetHashString(internal_2, hash, 512, BLOCK_SIZE + size_T);
    add_xor_64(K_, o_pad, internal_1);
    memcpy(internal_1 + BLOCK_SIZE, hash, BLOCK_SIZE);
    GetHashString(internal_1, HMAC, 512, 2 * BLOCK_SIZE);
    free(internal_2);
}

static void
U_first(const uint8_t *password, size_t size_pass, const uint8_t *salt, size_t size_salt,
        uint32_t i, uint8_t *U_first_res)
{
    uint8_t *internal;
    internal = malloc(size_salt + 4);
    memcpy(internal, salt, size_salt);
    internal[size_salt] = (uint8_t)((i >> 24) & 0xff);
    internal[size_salt + 1] = (uint8_t)((i >> 16) & 0xff);
    internal[size_salt + 2] = (uint8_t)((i >> 8) & 0xff);
    internal[size_salt + 3] = (uint8_t)(i & 0xff);
    HMAC_GOSTR3411(password, size_pass, internal, size_salt + 4, U_first_res);
}

static void
U_iter(const uint8_t *password, size_t size_pass, const uint8_t *U_prev, uint8_t *U_iter_res)
{
    HMAC_GOSTR3411(password, size_pass, U_prev, BLOCK_SIZE, U_iter_res);
}

static void
F(const uint8_t *password, size_t size_pass, const uint8_t *salt,
  size_t size_salt, uint64_t num_iter, uint32_t block_number, uint8_t *F_res)
{
    uint8_t T[BLOCK_SIZE];
    uint8_t T_[BLOCK_SIZE];
    uint8_t internal[BLOCK_SIZE];
    U_first(password, size_pass, salt, size_salt, block_number, T);
    memcpy(internal, T, BLOCK_SIZE);
    uint64_t i;
    for (i = 1; i < num_iter; i++)
    {
        U_iter(password, size_pass, internal, internal);
        add_xor_64(internal, T, T_);
        memcpy(T, T_, BLOCK_SIZE);
    }
    memcpy(F_res, T, BLOCK_SIZE);
}

void
PBKDF_2(const uint8_t *password, size_t size_pass, const uint8_t *salt, size_t size_salt,
        uint64_t num_iter, uint64_t key_length, uint8_t *key)
{
    uint32_t num_block = key_length / BLOCK_SIZE;
    if ((key_length % BLOCK_SIZE) != 0)
        num_block += 1;
    uint32_t i;
    uint8_t F_res[BLOCK_SIZE];
    uint8_t *DK;
    DK = malloc(num_block * BLOCK_SIZE);
    for (i = 0; i < num_block; i++)
    {
        F(password, size_pass, salt, size_salt, num_iter, i + 1, F_res);
        memcpy(DK + (i * BLOCK_SIZE), F_res, BLOCK_SIZE);
    }
    memcpy(key, DK, key_length);
}
