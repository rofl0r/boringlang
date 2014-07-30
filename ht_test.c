#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include "hashtable.h"
#include "talloc.h"

static uint32_t hash(void *ctx, void *key)
{
    int h = HASH_FNV_INIT;
    hash_int(&h, *(int*)key);
    return h;
}

static bool equals(void *ctx, void *k1, void *k2)
{
    return *(int*)k1 == *(int*)k2;
}

int main(int argc, char **argv)
{
    unsigned int sum = 0;
    srandom(1);
    /*
    struct hashtable *ht = ht_create(NULL, HT_DATA_dcustom, HT_DATA_dcustom);
    ht->value_size = ht->key_size = sizeof(int);
    ht->custom_key_hash = hash;
    ht->custom_key_equals = equals;
    */
    struct hashtable *ht = ht_create(NULL, HT_DATA_dint, HT_DATA_dint);
    for (int n = 0; n < 50000; n++) {
        int k = (random() % 45455);
        int d = 4;
        //ht_insert_raw(ht, &k, &d);
        HT_INSERT(dint, dint, ht, k, d);
        //ht_remove_raw(ht, (void*)(random() % 45453));
    }
    for (int n = 0; n < 5000000; n++) {
        int k = n; //(random() % 45455);
        //sum += HT_GET_DEF(dint, dint, ht, n, 0);
        /*
        void **p = ht_find_raw(ht, &k);
        if (p)
            sum += *(int*)p;
        */
        int *p = HT_GET(dint, dint, ht, n);
        if (p)
            sum += *p;
    }
    for (int n = 0; n < 2000; n++) {
        for (struct hashnode *node = ht_first_node(ht);
             node;
             node = ht_next_node(ht, node))
        {
            //sum += node->key.dint + (int)node->value.dint;
            sum += HT_NODE_KEY(dint, ht, node) + HT_NODE_VALUE(dint, ht, node);
        }
    }
    talloc_free(ht);
    printf("%d\n", sum);
    return 0;
}
