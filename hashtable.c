#include "talloc.h"
#include "hashtable.h"
#include "utils.h"

static size_t hashdata_size(enum hashdata_type type)
{
    switch (type) {
        case HT_DATA_dempty: return 0;
        case HT_DATA_dint: return sizeof(int);
        case HT_DATA_dptr: return sizeof(void*);
        case HT_DATA_dstr: return sizeof(char*);
        case HT_DATA_dbstr: return sizeof(bstr);
        case HT_DATA_dcustomptr: return sizeof(void*);
        case HT_DATA_dcustom: return sizeof(union hashdata);
        default: assert(false);
    }
}

struct hashtable *ht_create(void *talloc_ctx, enum hashdata_type key_type,
                            enum hashdata_type value_type)
{
    return talloc_struct(talloc_ctx, struct hashtable, {
        .key_type = key_type,
        .key_size = hashdata_size(key_type),
        .value_type = value_type,
        .value_size = hashdata_size(value_type),
    });
}

static size_t ht_size(size_t size)
{
    if (size >= 1) {
        // get next power of two >= size, starting with 4 (= 1 << 2)
        for (size_t np = 2; np < 31; np++) {
            if ((1u << np) >= size) {
                size = (1u << np);
                break;
            }
        }
        assert(((size - 1) & size) == 0);
    }
    return size;
}

static struct hashnode *ht_find_free_node(struct hashtable *ht)
{
    while (ht->free > ht->table) {
        ht->free--;
        // NOTE: insertion code can't deal with ->next != NULL (this can
        //  happen with deleted elements).
        if (!ht->free->hash && !ht->free->next)
            return ht->free;
    }
    return NULL;
}

static void *ht_find_or_insert_raw_prehashed(struct hashtable *ht, void *key,
                                             uint32_t hash, void *init_value)
{
    assert(hash != 0);
    assert(hash == ht_key_hash(ht, key));

    struct hashnode *node = ht_main_position(ht, hash);

    // Key already inserted?
    struct hashnode *cur = node;
    while (cur) {
        if (cur->hash == hash && ht_key_equals(ht, key, &cur->key)) {
            return &cur->value;
        }
        cur = cur->next;
    }

    // Is it already in use? (also code path for empty table)
    if (!node || node->hash) {
        struct hashnode *free = ht_find_free_node(ht);
        if (!free) {
            ht_rehash(ht, 1);
            // There must be enough space now.
            return ht_find_or_insert_raw_prehashed(ht, key, hash, init_value);
        }

        assert(free->hash == 0);
        assert(free->next == NULL);

        struct hashnode *other = ht_main_position(ht, node->hash);
        if (other == node) {
            // Simply insert a new node.
            free->next = node->next;
            node->next = free;
            node = free;
        } else {
            // $node is not in natural main position. It's better to give
            //  that Node to the new entry, so move $node out of the way.
            //  Move $node to $free, and make sure it's still reachable
            //  through $other. After that, $node is free and we can use it.
            *free = *node;
            node->next = NULL;
            // $other leads to $node (because $other is in $node's main
            //  position). Walk down the chain to find the exact
            //  predecessor Node, and fix the reference.
            while (other->next != node)
                other = other->next;
            assert(other->next == node);
            other->next = free;
            // node->hash/key will be overwritten
        }
    }

    ht->length++;
    node->hash = hash;
    memcpy(&node->key, key, ht->key_size);
    if (init_value)
        memcpy(&node->value, init_value, ht->value_size);
    return &node->value;
}

// Warning: for internal uses, allocating enough elements for reserve is an
//          absolute requirement. It can't be skipped on low memory and such.
void ht_rehash(struct hashtable *ht, size_t reserve)
{
    struct hashnode *old_table = ht->table;
    size_t old_size = ht_capacity(ht);

    size_t request_size = ht_size(ht->length + reserve);

    ht->table = talloc_zero_array(ht, struct hashnode, request_size);
    ht->free = ht->table + request_size;
    ht->mask = request_size ? request_size - 1 : 0;
    ht->length = 0;

    for (size_t n = 0; n < old_size; n++) {
        struct hashnode *cur = old_table + n;
        if (cur->hash)
            ht_find_or_insert_raw_prehashed(ht, &cur->key, cur->hash,
                                            &cur->value);
    }

    talloc_free(old_table);
}

// Remove the key. Return pointer to old value (if it's NULL, the entry
//  didn't exist). The returned value is valid until the hashtable is
//  changed in any other way.
void *ht_remove_raw(struct hashtable *ht, void *key)
{
    struct hashnode *node = ht_lookup_node(ht, key);
    if (!node)
        return NULL;
    // It might be nice to "move up" any node->next elements to speed up
    //  future lookups, but unfortunately that would mess with iteration
    //  order (although maybe we could cheat and do it anyway if the next
    //  element is below this one in the Node array).
    ht->length--;
    node->hash = 0;
    return &node->value;
}

// If the key exists, return its value. Otherwise, insert and return init_value.
void *ht_find_or_insert_raw(struct hashtable *ht, void *key, void *init_value)
{
    return ht_find_or_insert_raw_prehashed(ht, key, ht_key_hash(ht, key),
                                           init_value);
}

// Insert a value into the hashtable. If the key already exists, overwrite it.
void ht_insert_raw(struct hashtable *ht, void *key, void *value)
{
    memcpy(ht_find_or_insert_raw(ht, key, NULL), value, ht->value_size);
}
