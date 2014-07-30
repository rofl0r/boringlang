#ifndef BL_HASHTABLE_H_
#define BL_HASHTABLE_H_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "bstr.h"

enum {
    HASH_INVALID = 0u, // hash value used to mark deleted entries

    HASH_FNV_INIT = 2166136261u, // also called "offset"
    HASH_FNV_PRIME = 16777619u,
};

static inline void hash_chain(uint32_t *hash, uint32_t value)
{
    *hash = (*hash ^ value) * HASH_FNV_PRIME;
}

static inline void hash_int(uint32_t *hash, int value)
{
    hash_chain(hash, value);
}

static inline void hash_int64(uint32_t *hash, int64_t value)
{
    hash_chain(hash, value);
    hash_chain(hash, value >> 32);
}

static inline void hash_ptr(uint32_t *hash, void *ptr)
{
    if (sizeof(ptr) > 4) {
        hash_int64(hash, (intptr_t)ptr);
    } else {
        hash_int(hash, (intptr_t)ptr);
    }
}

static inline void hash_bstr(uint32_t *hash, bstr str)
{
    // just something lame
    for (size_t n = 0; n < str.len; n++)
        *hash = ((*hash << 3) | (*hash >> 29)) ^ str.start[n];
}

static inline void hash_string(uint32_t *hash, const char *str)
{
    hash_bstr(hash, bstr0(str));
}

static inline void hash_double_bit(uint32_t *hash, double v)
{
    hash_bstr(hash, (struct bstr) { (char*)&v, sizeof(v) });
}

enum hashdata_type {
    HT_DATA_dempty,
    HT_DATA_dint,       // type int (we assume intptr_t is big enough)
    HT_DATA_dptr,       // pointer, and the raw pointer value is hashed
    HT_DATA_dstr,       // const char*
    HT_DATA_dbstr,      // bstr
    HT_DATA_dcustomptr, // pointer, subject to custom_key_* functions
    HT_DATA_dcustom,    // anything, must fit into hashdata
};

union hashdata {
    void *dempty;
    int dint;
    void *dptr;
    char *dstr;
    bstr dbstr;
    void *dcustomptr;
    char dcustom;
};

struct hashnode {
    struct hashnode *next;
    uint32_t hash;              // value 0 is magic for "unused"
    union hashdata key;
    union hashdata value;
};

/*
 * This is heavily inspired by Lua's implementation of hash tables. We use
 * exactly the same algorithm. The lack of an array part and support for
 * multiple types makes our code a bit simpler, having to support deleted
 * elements (insteads of just storing a "nil" value) complicates slightly.
 *
 * Citing the Lua source (ltable.c):
 * "A main invariant of these tables is that, if an element is not
 * in its main position [...], then the colliding element is in its own
 * main position."
 *
 * main position = array position a key's hash gives (cf. ht_main_position())
 */
struct hashtable {
    struct hashnode *table;
    enum hashdata_type key_type;
    enum hashdata_type value_type;
    uint32_t mask;                      // (size-1), but 0 if size==0
    size_t length;
    struct hashnode *free;

    size_t key_size, value_size;

    void *custom_key_ctx;
    uint32_t (*custom_key_hash)(void *ctx, void *k);
    bool (*custom_key_equals)(void *ctx, void *k1, void *k2);
};

struct hashtable *ht_create(void *talloc_ctx, enum hashdata_type key_type,
                            enum hashdata_type value_type);

// Recreate the hash table, and make sure at least reserve additional
// elements are free for use.
void ht_rehash(struct hashtable *ht, size_t reserve);
void *ht_find_or_insert_raw(struct hashtable *ht, void *key, void *init_value);
void ht_insert_raw(struct hashtable *ht, void *key, void *value);
void *ht_remove_raw(struct hashtable *ht, void *key);

// modified hash function: never returns 0 (as hash==0 has special meaning)
static inline uint32_t ht_key_hash(struct hashtable *ht, void *key)
{
    uint32_t hash = HASH_FNV_INIT;
    switch (ht->key_type) {
        case HT_DATA_dint:
            hash_int(&hash, *(int*)key);
            break;
        case HT_DATA_dptr:
            hash_ptr(&hash, *(void**)key);
            break;
        case HT_DATA_dstr:
            hash_string(&hash, *(char**)key);
            break;
        case HT_DATA_dbstr:
            hash_bstr(&hash, *(bstr*)key);
            break;
        case HT_DATA_dcustomptr:
            hash = ht->custom_key_hash(ht->custom_key_ctx, *(void**)key);
            break;
        case HT_DATA_dcustom:
            hash = ht->custom_key_hash(ht->custom_key_ctx, key);
            break;
        default:
            assert(false);
    }
    if (hash == HASH_INVALID)
        hash += 1;
    return hash;
}

static inline bool ht_key_equals(struct hashtable *ht, void *key1, void *key2)
{
    switch (ht->key_type) {
        case HT_DATA_dint:
            return *(int*)key1 == *(int*)key2;
        case HT_DATA_dptr:
            return *(void**)key1 == *(void**)key2;
        case HT_DATA_dstr:
            return strcmp(*(char**)key1, *(char**)key2) == 0;
        case HT_DATA_dbstr:
            return bstrcmp(*(bstr*)key1, *(bstr*)key2) == 0;
        case HT_DATA_dcustomptr:
            return ht->custom_key_equals(ht->custom_key_ctx, *(void**)key1,
                                         *(void**)key2);
        case HT_DATA_dcustom:
            return ht->custom_key_equals(ht->custom_key_ctx, key1, key2);
        default:
            assert(false);
    }
}

static inline struct hashnode *ht_main_position(struct hashtable *ht,
                                                uint32_t hash)
{
    return ht->table + (hash & ht->mask);
}

static inline struct hashnode *ht_lookup_node(struct hashtable *ht, void *key)
{
    uint32_t hash = ht_key_hash(ht, key);
    struct hashnode *cur = ht_main_position(ht, hash);
    while (cur) {
        if (cur->hash == hash && ht_key_equals(ht, key, &cur->key))
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static inline void *ht_find_raw(struct hashtable *ht, void *key)
{
    struct hashnode *node = ht_lookup_node(ht, key);
    return node ? &node->value : NULL;
}

static inline void *ht_find_raw_def(struct hashtable *ht, void *key,
                                    void *def_value)
{
    void *res = ht_find_raw(ht, key);
    return res ? res : def_value;
}

// Number of total allocated entries. (Basically size of ht->table.)
static inline size_t ht_capacity(struct hashtable *ht)
{
    return ht->mask ? ht->mask + 1 : 0;
}

static inline struct hashnode *ht_next_node(struct hashtable *ht,
                                            struct hashnode *node)
{
    struct hashnode *end = ht->table + ht_capacity(ht);
    assert(node);
    // This check will fail if the hashtable got rehashed during iteration,
    //  e.g. because the user added new elements while iterating.
    assert(node >= ht->table && node < end);
    node++;
    while (node < end) {
        if (node->hash)
            return node;
        node++;
    }
    return NULL;
}

static inline struct hashnode *ht_first_node(struct hashtable *ht)
{
    struct hashnode *node = ht->table;
    return node ? (node->hash ? node : ht_next_node(ht, ht->table)) : NULL;
}

// Create HT_DATA_dint out of t==dint etc.
#define HT_T_(t) HT_DATA_ ## t
// These macros make sure the data has the type corresponding to the one
// represented by HT_DATA_ ## t. As long as usage by the user is concerned,
// this avoids hard casts and makes sure the compiler warns on bogus implicit
// conversions.
// xxx HT_FROM_HD_ assumes t is always at offset 0 (so that d=NULL works)
#define HT_TO_HD_(t, d) (&(union hashdata) { . t = (d) })
#define HT_FROM_HD_(t, d) (&((union hashdata *) (d))-> t )

// For all these macros, key, value, def_value and node are guaranteed to be
// evaluated exactly once. (Unlike ht.)

#define HT_GET(key_t, value_t, ht, key)                 \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     assert((ht)->value_type == HT_T_(value_t)),        \
     HT_FROM_HD_(value_t,                               \
        ht_find_raw((ht), HT_TO_HD_(key_t, (key)))))

#define HT_GET_DEF(key_t, value_t, ht, key, def_value)  \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     assert((ht)->value_type == HT_T_(value_t)),        \
     *HT_FROM_HD_(value_t,                              \
        ht_find_raw_def((ht), HT_TO_HD_(key_t, (key)),  \
                        HT_TO_HD_(value_t, (def_value)))))

#define HT_INSERT(key_t, value_t, ht, key, value)       \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     assert((ht)->value_type == HT_T_(value_t)),        \
     ht_insert_raw((ht), HT_TO_HD_(key_t, (key)),       \
                   HT_TO_HD_(value_t, (value))))

#define HT_REMOVE(key_t, ht, key)                       \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     hd_remove_raw((ht), HT_TO_HD_(key_t, (key))))

#define HT_GET_NODE(key_t, ht, key)                     \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     ht_lookup_node((ht), HT_TO_HD_(key_t, (key))))

#define HT_NODE_KEY(key_t, ht, node)                    \
    (assert((ht)->key_type == HT_T_(key_t)),            \
     *HT_FROM_HD_(key_t, &(node)->key))                 \

// This one is a lvalue.
#define HT_NODE_VALUE(value_t, ht, node)                \
    (*(assert((ht)->value_type == HT_T_(value_t)),      \
     HT_FROM_HD_(value_t, &(node)->value)))

#endif
