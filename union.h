// Helper macro for typesafe disjoint unions.
// It doesn't actually check that much, but mainly serves to enforce a good
// coding convention.

#ifndef BL_UNION_H
#define BL_UNION_H

#include <assert.h>
#include "talloc.h"
#include "utils.h"

#define CONCAT3(a, b, c) a ## b ## c

#define GET_UNION(prefix, name, ptr) \
    (assert((ptr)->type == CONCAT3(prefix, _, name)), (&(ptr)->u.name))

#define TEST_UNION0(prefix, name, ptr) \
    ((ptr)->type == CONCAT3(prefix, _, name))

#define TEST_UNION(prefix, name, ptr) \
    (TEST_UNION0(prefix, name, ptr) ? (&(ptr)->u.name) : NULL)

#define MAKE_UNION(prefix, name, ...) \
    {.type = CONCAT3(prefix, _, name), .u. name = __VA_ARGS__}

#define MAKE_UNION0(prefix, name) \
    {.type = CONCAT3(prefix, _, name)}

#define NEW_UNION(ctx, type, prefix, name, ...) \
    talloc_from(ctx, type, &(type) MAKE_UNION(prefix, name, __VA_ARGS__))

#endif
