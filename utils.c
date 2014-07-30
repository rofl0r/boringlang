#include <string.h>
#include <assert.h>

#include "utils.h"

void *talloc_from_(void *ctx, size_t size, void *data)
{
    void *res = talloc_size(ctx, size);
    memcpy(res, data, size);
    return res;
}

static int log2_u32(uint32_t v)
{
    for (int n = 31; n >= 0; n--) {
        if (v & (1 << n))
            return n;
    }
    return 0;
}

int log2_u64(uint64_t v)
{
    uint32_t hi = v >> 32;
    uint32_t lo = v;
    return hi ? log2_u32(hi) + 32 : log2_u32(lo);
}

int log2_up_u64(uint64_t v)
{
    int res = log2_u64(v);
    if (res && (1ULL << res) != v)
        res++;
    return res;
}

bool bitv_get(uint8_t *b, int index)
{
    assert(index >= 0);
    return b[index >> 3] & (1 << (index & 7));
}

void bitv_set(uint8_t *b, int index)
{
    assert(index >= 0);
    b[index >> 3] |= (1 << (index & 7));
}

void bitv_clear(uint8_t *b, int index)
{
    assert(index >= 0);
    b[index >> 3] &= ~(1 << (index & 7));
}

// Return size of a bit vector with "size" bits in bytes.
size_t bitv_size(int size)
{
    return (size + 7) / 8;
}

uint8_t *bitv_new(void *tctx, int bit_count)
{
    return talloc_zero_array(tctx, uint8_t, bitv_size(bit_count));
}
