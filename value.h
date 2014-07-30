#ifndef BL_VARIANT_H
#define BL_VARIANT_H

#include <stdint.h>
#include <stdbool.h>
#include "bstr.h"
#include "types.h"

// @ALL value_type
enum value_type {
    VALUE_vempty,
    VALUE_vuint64,
    VALUE_vdouble,
    VALUE_vstring,
    VALUE_vstruct,
    VALUE_vptr,
    VALUE_varray,
};

// Untyped constant value. The only reason why this is tagged with a type is
// to make debugging easier. ir_const_val is for properly typed values.
struct value {
    enum value_type type;
    union {
        uint64_t vuint64;
        double vdouble;
        bstr vstring;
        struct ir_struct_const *vstruct;
        void *vptr;
        struct ir_array_const *varray;
    } u;
};

// On the representation of integers:
// - both signed and unsigned integers are stored as unsigned
// - integers of a type != uint64 are stored as uint64
// - the excess bytes of unsigned ints must be 0
// - the excess bytes of signed ints correspond to the sign (i.e. to store a
//   smaller type in uint64, it's sign extended)

// Typed constant value.
struct ir_const_val {
    struct ir_type type;
    struct value value;
};

struct ir_struct_const {
    struct ir_struct_type *type;
    // Array of values, one entry for each struct member.
    // Ordered like the type->members array.
    struct value *data;
};

struct ir_array_const {
    struct ir_array_type *type;
    // Array of values, type->dimension count.
    struct value *data;
};

bool int_convertible(bool src_sign, int src_bits, bool dst_sign, int dst_bits);

char *string_unparse(void *talloc, bstr s);

struct ir_const_val type_init_value(struct ir_type t);
struct ir_const_val const_from_int_lit(struct lex_const c, bool negate);
struct ir_const_val const_from_lit(struct ir_types *ctx, struct lex_const c);
bool const_bit_equals(struct ir_const_val v1, struct ir_const_val v2);
void const_hash(uint32_t *hash, struct ir_const_val v);
char *const_unparse(void *tctx, struct ir_const_val v);

#endif
