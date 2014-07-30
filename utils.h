#ifndef BL_UTILS_H
#define BL_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "talloc.h"

#define BL_MIN(a, b) ((a) <= (b) ? (a) : (b))
#define BL_MAX(a, b) ((a) >= (b) ? (a) : (b))

#define assert_msg(x, ...) \
    ((x) || (fprintf(stderr, "ABORT: "), \
             fprintf(stderr, __VA_ARGS__), \
             fprintf(stderr, "\n"), \
             assert(false), 1))

// xxx replace (type*) cast by something that will make gcc warn on mismatch
#define talloc_from(ctx, type, ptr) \
    ( (type*)talloc_from_((ctx), sizeof(type), (type*) (ptr)) )
void *talloc_from_(void *ctx, size_t size, void *data);

#define BL_EXPAND_ARGS(...) __VA_ARGS__
#define BL_CONCAT(a, b) a ## b

#define talloc_struct(ctx, type, ...) \
    talloc_from(ctx, type, &(type) BL_EXPAND_ARGS(__VA_ARGS__) )

#define t_steal talloc_steal

#define BL_TARRAY_ELEMS(p) (talloc_get_size(p) / sizeof((p)[0]))

#define BL_TARRAY_GROW(ctx, p, nextidx)             \
    do {                                            \
        size_t nextidx_ = (nextidx);                \
        size_t nelems_ = BL_TARRAY_ELEMS(p);        \
        if (nextidx_ >= nelems_)                    \
            p = talloc_realloc_size((ctx), p,       \
               (nextidx_ + 1) * sizeof((p)[0]) * 2);\
    } while (0)

#define BL_TARRAY_APPEND(ctx, p, idxvar, val)       \
    do {                                            \
        BL_TARRAY_GROW(ctx, p, idxvar);             \
        p[idxvar] = (val);                          \
        idxvar++;                                   \
    } while (0)

#define BL_TARRAY_INSERT_AT(ctx, p, idxvar, at, val)\
    do {                                            \
        size_t at_ = (at);                          \
        assert(at_ <= idxvar);                      \
        BL_TARRAY_GROW(ctx, p, idxvar);             \
        memmove(p + at_ + 1, p + at_,               \
                (idxvar - at_) * sizeof(p[0]));     \
        idxvar++;                                   \
        p[at_] = (val);                             \
    } while (0)

// Doesn't actually free any memory.
#define BL_TARRAY_REMOVE_AT(p, idxvar, at)          \
    do {                                            \
        size_t at_ = (at);                          \
        assert(at_ <= idxvar);                      \
        memmove(p + at_, p + at_ + 1,               \
                (idxvar - at_) * sizeof(p[0]));     \
        idxvar--;                                   \
    } while (0)

#define BL_PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (printf, a1, a2)))

int log2_up_u64(uint64_t v);
int log2_u64(uint64_t v);
uint8_t *bitv_new(void *tctx, int bit_count);
bool bitv_get(uint8_t *b, int index);
void bitv_set(uint8_t *b, int index);
void bitv_clear(uint8_t *b, int index);
size_t bitv_size(int size);

#endif
