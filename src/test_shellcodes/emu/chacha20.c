#include "../shellcode.h"
#include "../utils/my_std.h"

// a shellcode which uses a chacha cipher. the implementation was copied from the internet.

struct chacha20_context {
    uint32_t keystream32[16];
    size_t position;

    uint8_t key[32];
    uint8_t nonce[12];
    uint64_t counter;

    uint32_t state[16];
};

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t* a) {
    uint32_t res = 0;
    res |= (uint32_t) a[0] << 0 * 8;
    res |= (uint32_t) a[1] << 1 * 8;
    res |= (uint32_t) a[2] << 2 * 8;
    res |= (uint32_t) a[3] << 3 * 8;
    return res;
}

static void chacha20_init_block(struct chacha20_context* ctx, uint8_t key[], uint8_t nonce[]) {
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    const uint8_t* magic_constant = (uint8_t*) "expand 32-byte k";
    ctx->state[0] = pack4(magic_constant + 0 * 4);
    ctx->state[1] = pack4(magic_constant + 1 * 4);
    ctx->state[2] = pack4(magic_constant + 2 * 4);
    ctx->state[3] = pack4(magic_constant + 3 * 4);
    ctx->state[4] = pack4(key + 0 * 4);
    ctx->state[5] = pack4(key + 1 * 4);
    ctx->state[6] = pack4(key + 2 * 4);
    ctx->state[7] = pack4(key + 3 * 4);
    ctx->state[8] = pack4(key + 4 * 4);
    ctx->state[9] = pack4(key + 5 * 4);
    ctx->state[10] = pack4(key + 6 * 4);
    ctx->state[11] = pack4(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = pack4(nonce + 0 * 4);
    ctx->state[14] = pack4(nonce + 1 * 4);
    ctx->state[15] = pack4(nonce + 2 * 4);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context* ctx, uint64_t counter) {
    ctx->state[12] = (uint32_t) counter;
    ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t) (counter >> 32);
}

static void chacha20_block_next(struct chacha20_context* ctx) {
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++)
        ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d)                                                       \
    x[a] += x[b];                                                                                  \
    x[d] = rotl32(x[d] ^ x[a], 16);                                                                \
    x[c] += x[d];                                                                                  \
    x[b] = rotl32(x[b] ^ x[c], 12);                                                                \
    x[a] += x[b];                                                                                  \
    x[d] = rotl32(x[d] ^ x[a], 8);                                                                 \
    x[c] += x[d];                                                                                  \
    x[b] = rotl32(x[b] ^ x[c], 7);

    for (int i = 0; i < 10; i++) {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
    }

    for (int i = 0; i < 16; i++)
        ctx->keystream32[i] += ctx->state[i];

    uint32_t* counter = ctx->state + 12;
    // increment counter
    counter[0]++;
    if (0 == counter[0]) {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        assert(0 != counter[1]);
    }
}

static void chacha20_init_context(
    struct chacha20_context* ctx, uint8_t key[], uint8_t nonce[], uint64_t counter
) {
    memset(ctx, 0, sizeof(struct chacha20_context));

    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

static void chacha20_xor(struct chacha20_context* ctx, uint8_t* bytes, size_t n_bytes) {
    for (size_t i = 0; i < n_bytes; i++) {
        if (ctx->position >= 64) {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        uint32_t val = ctx->keystream32[i / 4];
        size_t byte_index = i % 4;
        size_t shift_amount = 8 * byte_index;
        bytes[i] ^= ((val >> shift_amount) & 0xff);
        ctx->position++;
    }
}

static void expand_u32(u32 input, u8* output, size_t output_len) {
    for (size_t i = 0; i < output_len; i++) {
        size_t byte_index_in_u32 = i % 4;
        size_t bit_index_in_u32 = byte_index_in_u32 * 8;
        output[i] = (input >> bit_index_in_u32) & 0xff;
    }
}

size_t SHELLCODE_ENTRY _start(u32 key_seed, u32 nonce_seed, u32 counter, u32 plaintext_seed) {
    struct chacha20_context ctx = {};

    // generate the key
    u8 key[32] = {};
    expand_u32(key_seed, key, sizeof(key));

    // generate the nonce
    u8 nonce[12] = {};
    expand_u32(nonce_seed, nonce, sizeof(nonce));

    // initialize the cipher
    chacha20_init_context(&ctx, key, nonce, counter);

    // encrypt a bunch of data
    u8 plaintext[32] = {};
    expand_u32(plaintext_seed, plaintext, sizeof(plaintext));
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    // generate a checksum of the data
    u32 sum = 0;
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        sum += plaintext[i];
    }

    return sum;
}
