#include <inttypes.h>
#include <assert.h>

#include "talloc.h"
#include "hashtable.h"
#include "value.h"
#include "union.h"
#include "utils.h"
#include "types.h"

static char *vstruct_to_string(void *talloc, struct ir_type t,
                               struct ir_struct_const *vstruct)
{
    struct ir_struct_type *type = vstruct->type;
    char *res = talloc_strdup(talloc, "{");
    for (int n = 0; n < type->members_count; n++) {
        struct ir_const_val c = { type->members[n]->type, vstruct->data[n] };
        char *v = const_unparse(NULL, c);
        res = talloc_asprintf_append(res, "%s%s", n ? "," : "", v);
        talloc_free(v);
    }
    res = talloc_asprintf_append(res, "}");
    return res;
}

static char *varray_to_string(void *talloc, struct ir_array_const *varray)
{
    struct ir_array_type *type = varray->type;
    char *res = talloc_strdup(talloc, "{");
    for (int n = 0; n < type->dimension; n++) {
        struct ir_const_val c = { type->item_type, varray->data[n] };
        char *v = const_unparse(NULL, c);
        res = talloc_asprintf_append(res, "%s%s", n ? "," : "", v);
        talloc_free(v);
    }
    res = talloc_asprintf_append(res, "}");
    return res;
}

static const char hex[] = "0123456789ABCDEF";

char *string_unparse(void *talloc, bstr s)
{
    char *res = NULL;
    int count = 0;
#define APPEND(c) BL_TARRAY_APPEND(talloc, res, count, (c))
    APPEND('"');
    for (int n = 0; n < s.len; n++) {
        unsigned char c = s.start[n];
        if (c < 32 || c > 127) {
            APPEND('\\');
            // Use octal, because '\xNN' is ambiguous with '\xNNNN' in C.
            // (Also, emitting bytes with \x might be questionable.)
            APPEND(hex[c >> 6]);
            APPEND(hex[(c >> 3) & 7]);
            APPEND(hex[c & 7]);
        } else {
            APPEND(c);
        }
    }
    APPEND('"');
    APPEND('\0');
    return res;
#undef APPEND
}

// In such a representation, that the value can be read back exactly. Numbers
// are in a format parseable by strto[[ull|ll]|d], strings quoted and escaped
// as in C, and structs/arrays are comma-separated, enclosed in { }.
// Pointers are formatted as %p.
char *const_unparse(void *tctx, struct ir_const_val v)
{
    struct value *rv = &v.value;
    // @ALL ir_type_type
    switch (v.type.type) {
    case IR_TYPE_error:
    case IR_TYPE_any:
        return talloc_asprintf(tctx, "<invalid>");
    case IR_TYPE_tuntyped:
        return talloc_asprintf(tctx, "<untyped>");
    case IR_TYPE_tbool: {
        uint64_t c = *GET_UNION(VALUE, vuint64, rv);
        assert(c == !!c);
        return talloc_asprintf(tctx, c ? "true" : "false");
    }
    case IR_TYPE_tint: {
        uint64_t u = *GET_UNION(VALUE, vuint64, rv);
        if (type_get_sign(v.type)) {
            return talloc_asprintf(tctx, "%"PRId64, u);
        } else {
            return talloc_asprintf(tctx, "%"PRIu64, u);
        }
    }
    case IR_TYPE_tdouble:
        return talloc_asprintf(tctx, "%a", *GET_UNION(VALUE, vdouble, rv));
    case IR_TYPE_tptr:
        if (rv->type == VALUE_vempty)
            return "(empty)";
        return talloc_asprintf(tctx, "%p", *GET_UNION(VALUE, vptr, rv));
    case IR_TYPE_tstruct:
    case IR_TYPE_ttuple:
    case IR_TYPE_tcompound:
        return vstruct_to_string(tctx, v.type, *GET_UNION(VALUE, vstruct, rv));
    case IR_TYPE_tarray:
        return varray_to_string(tctx, *GET_UNION(VALUE, varray, rv));
    case IR_TYPE_tfn:
    case IR_TYPE_tstackclosure:
    case IR_TYPE_tslice:
        if (rv->type == VALUE_vstring)
            return string_unparse(tctx, *GET_UNION(VALUE, vstring, rv));
        assert(rv->type == VALUE_vempty);
        return talloc_asprintf(tctx, "0"); // xxx: unknown representation
    default: assert(false);
    }
}

static bool vstruct_bit_equals(struct ir_struct_const *v1,
                               struct ir_struct_const *v2)
{
    if (v1 == v2)
        return true;
    struct ir_struct_type *type = v1->type;
    assert(type->members_count == v2->type->members_count);
    for (int n = 0; n < type->members_count; n++) {
        struct ir_type t = type->members[n]->type;
        struct ir_const_val c1 = { t, v1->data[n] };
        struct ir_const_val c2 = { t, v2->data[n] };
        if (!const_bit_equals(c1, c2))
            return false;
    }
    return true;
}

static bool varray_bit_equals(struct ir_array_const *v1,
                              struct ir_array_const *v2)
{
    if (v1 == v2)
        return true;
    struct ir_array_type *type = v1->type;
    struct ir_type t = type->item_type;
    assert(type->dimension == v2->type->dimension);
    for (int n = 0; n < type->dimension; n++) {
        struct ir_const_val c1 = { t, v1->data[n] };
        struct ir_const_val c2 = { t, v2->data[n] };
        if (!const_bit_equals(c1, c2))
            return false;
    }
    return true;
}

// nan == nan, 0 != -0, ...
static bool double_bit_equals(double v1, double v2)
{
    return memcmp(&v1, &v2, sizeof(double)) == 0;
}

// The "bit" means we strictly compare the bits in case several different values
// can equal with each other.
// NOTE: the types of both values must equal exactly. If the type has an extra
//       type object associated, but is structurally types (like arrays and
//       tuples), the type objects pointers don't need to be the same, but
//       must be guaranteed to be of the same contents.
bool const_bit_equals(struct ir_const_val v1, struct ir_const_val v2)
{
    assert(type_equals(v1.type, v2.type));
    assert(v1.value.type == v2.value.type);
    struct value *val1 = &v1.value;
    struct value *val2 = &v2.value;
    // @ALL ir_type_type
    switch (v1.type.type) {
    case IR_TYPE_error:
    case IR_TYPE_any:
    case IR_TYPE_tuntyped:
        assert(false);
    case IR_TYPE_tbool:
    case IR_TYPE_tint:
        return *GET_UNION(VALUE, vuint64, val1)
            == *GET_UNION(VALUE, vuint64, val2);
    case IR_TYPE_tdouble:
        return double_bit_equals(*GET_UNION(VALUE, vdouble, val1),
                                 *GET_UNION(VALUE, vdouble, val2));
    case IR_TYPE_tptr:
        return *GET_UNION(VALUE, vptr, val1) == *GET_UNION(VALUE, vptr, val2);
    case IR_TYPE_tstruct:
    case IR_TYPE_ttuple:
    case IR_TYPE_tcompound:
        return vstruct_bit_equals(*GET_UNION(VALUE, vstruct, val1),
                                  *GET_UNION(VALUE, vstruct, val2));
    case IR_TYPE_tarray:
        return varray_bit_equals(*GET_UNION(VALUE, varray, val1),
                                 *GET_UNION(VALUE, varray, val2));
    case IR_TYPE_tfn:
    case IR_TYPE_tstackclosure:
    case IR_TYPE_tslice:
        if (val1->type == VALUE_vstring)
            return bstrcmp(*GET_UNION(VALUE, vstring, val1),
                           *GET_UNION(VALUE, vstring, val2)) == 0;
        // xxx: unknown representation
        assert(val1->type == VALUE_vempty);
        return true;
    default: assert(false);
    }
}

// const_bit_equals(a, b) => const_hash(a) == const_hash(b)
void const_hash(uint32_t *hash, struct ir_const_val v)
{
    hash_int(hash, v.type.type); // xxx very broad
    struct value *val = &v.value;
    // @ALL ir_type_type
    switch (v.type.type) {
    case IR_TYPE_error:
    case IR_TYPE_any:
    case IR_TYPE_tuntyped:
        assert(false);
    case IR_TYPE_tbool:
    case IR_TYPE_tint:
        hash_int64(hash, *GET_UNION(VALUE, vuint64, val));
        return;
    case IR_TYPE_tdouble:
        hash_double_bit(hash, *GET_UNION(VALUE, vdouble, val));
        return;
    case IR_TYPE_tptr:
        hash_ptr(hash, *GET_UNION(VALUE, vptr, val));
        return;
    case IR_TYPE_tstruct:
    case IR_TYPE_ttuple:
    case IR_TYPE_tcompound:
        //*GET_UNION(VALUE, vstruct, val)
        return; // xxx very broad
    case IR_TYPE_tarray:
        return; // xxx very broad
    case IR_TYPE_tfn:
    case IR_TYPE_tstackclosure:
    case IR_TYPE_tslice:
        if (val->type == VALUE_vstring) {
            hash_bstr(hash, *GET_UNION(VALUE, vstring, val));
            return;
        }
        assert(val->type == VALUE_vempty);
        // xxx: unknown representation
        return;
    default: assert(false);
    }
}

static int int_implied_bits_u(uint64_t v)
{
    if (v <= UINT8_MAX)
        return 8;
    if (v <= UINT16_MAX)
        return 16;
    if (v <= UINT32_MAX)
        return 32;
    return 64;
}

static int int_implied_bits_i(int64_t v)
{
    if (v >= INT8_MIN && v <= INT8_MAX)
        return 8;
    if (v >= INT16_MIN && v <= INT16_MAX)
        return 16;
    if (v >= INT32_MIN && v <= INT32_MAX)
        return 32;
    return 64;
}

bool int_convertible(bool src_sign, int src_bits, bool dst_sign, int dst_bits)
{
    if (src_bits == dst_bits && src_sign == dst_sign)
        return true;
    return ((dst_sign == src_sign) || (!src_sign && dst_sign))
           && src_bits < dst_bits;
}


static struct value basic_init_value(struct ir_type t)
{
    // Caller has to deal with this. Not an assert for error paths.
    if (!type_is_complete(t))
        return (struct value) {0};
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error:
        case IR_TYPE_any:
        case IR_TYPE_tuntyped:
        case IR_TYPE_tslice:
        case IR_TYPE_tptr:
        case IR_TYPE_tfn:
        case IR_TYPE_tstackclosure:
            return (struct value) MAKE_UNION0(VALUE, vempty);
        case IR_TYPE_tbool:
        case IR_TYPE_tint:
            return (struct value) MAKE_UNION(VALUE, vuint64, 0);
        case IR_TYPE_tdouble:
            return (struct value) MAKE_UNION(VALUE, vdouble, 0.0);
        case IR_TYPE_tstruct: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tstruct, &t);
            return (struct value) MAKE_UNION(VALUE, vstruct, st->init);
        }
        case IR_TYPE_ttuple: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, ttuple, &t);
            return (struct value) MAKE_UNION(VALUE, vstruct, st->init);
        }
        case IR_TYPE_tcompound: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tcompound, &t);
            return (struct value) MAKE_UNION(VALUE, vstruct, st->init);
        }
        case IR_TYPE_tarray: {
            struct ir_array_type *at = *GET_UNION(IR_TYPE, tarray, &t);
            return (struct value) MAKE_UNION(VALUE, varray, at->init);
        }
        default:
            assert(false);
    }
}

// return whatever the default initializer is
struct ir_const_val type_init_value(struct ir_type t)
{
    return (struct ir_const_val) { t, basic_init_value(t) };
}

// On error (overflow), a value with type error is returned.
struct ir_const_val const_from_int_lit(struct lex_const c, bool negate)
{
    struct lex_int li = *GET_UNION(LEX_CONST, cint, &c);
    uint64_t v = li.val;
    if (li.type) {
        // type is specified in the constant's token (e.g. 128i8)
        bool sign = li.type < 0;
        int bits = abs(li.type);
        struct ir_type t = type_integer(sign, bits);
        uint64_t tmax = bits == 64 ? UINT64_MAX : ((UINT64_C(1) << bits) - 1);
        uint64_t imax = tmax / 2; // largest positive integer value
        if (!sign) {
            if (v > tmax)
                goto error;
            if (negate) {
                // negating an integer of explicit unsigned type
                v = ((uint64_t)-v) & tmax;
            }
            return (struct ir_const_val) {t, MAKE_UNION(VALUE, vuint64, v)};
        }
        if (negate) {
            if (v > imax + 1)
                goto error;
            v = -v;
            return (struct ir_const_val) {t, MAKE_UNION(VALUE, vuint64, v)};
        } else {
            if (v > imax)
                goto error;
        }
        return (struct ir_const_val)
            {t, MAKE_UNION(VALUE, vuint64, v)};
    } else {
        // type is unspecified by the constant's token
        if (negate) {
            if (v > (((uint64_t)INT64_MAX) + 1))
                goto error;
            int64_t v2 = -v;
            return (struct ir_const_val)
                {type_integer_min(true, int_implied_bits_i(v2)),
                 MAKE_UNION(VALUE, vuint64, v2)};
        } else {
            return (struct ir_const_val)
                {type_integer_min(false, int_implied_bits_u(v)),
                 MAKE_UNION(VALUE, vuint64, v)};
        }
    }
error:
    return (struct ir_const_val) {{0}};
}

// On error, return a value with type error.
struct ir_const_val const_from_lit(struct ir_types *ctx, struct lex_const c)
{
    //@ALL lex_const_type
    switch (c.type) {
        case LEX_CONST_cempty:
            assert(false);
        case LEX_CONST_cint: {
            return const_from_int_lit(c, false);
        }
        case LEX_CONST_cdouble:
            return (struct ir_const_val) {
                MAKE_IR_TYPE0(tdouble),
                MAKE_UNION(VALUE, vdouble, *GET_UNION(LEX_CONST, cdouble, &c)),
            };
        case LEX_CONST_cchar:
            return (struct ir_const_val) {
                TYPE_CHAR,
                MAKE_UNION(VALUE, vuint64, *GET_UNION(LEX_CONST, cchar, &c)),
            };
        case LEX_CONST_cstring:
            return (struct ir_const_val) {
                TYPE_STRING,
                MAKE_UNION(VALUE, vstring, *GET_UNION(LEX_CONST, cstring, &c)),
            };
        default:
            assert(false);
    }
}
