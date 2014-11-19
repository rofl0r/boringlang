#include "talloc.h"
#include "types.h"
#include "ir.h"
#include "value.h"

const struct ir_type TYPE_G_PTR = {
    .type = IR_TYPE_tptr,
    .u.tptr = &(struct ir_type) MAKE_IR_TYPE0(tuntyped),
};

// Maybe change to a special char type (but who cares?)
const struct ir_type TYPE_CHAR = MAKE_UNION(IR_TYPE, tint, IR_INTT_8);

const struct ir_type TYPE_STRING
    = MAKE_UNION(IR_TYPE, tslice, (struct ir_type*)&TYPE_CHAR);

// (don't confuse this with IR_TYPE_tstruct semantics, see type_equals())
// compare_metadata:
//      false => only compare member types
//      true => names and default values (and possibly more) is important too
static bool struct_equals(struct ir_struct_type *s1, struct ir_struct_type *s2,
                          bool compare_metadata)
{
    if (s1 == s2)
        return true;
    if (!s1->defined || !s2->defined)
        return false;
    if (s1->members_count != s2->members_count)
        return false;
    for (int n = 0; n < s1->members_count; n++) {
        struct ir_struct_member *m1 = s1->members[n], *m2 = s2->members[n];
        assert(m1->index == n && m2->index == n);
        if (!type_equals(m1->type, m2->type))
            return false;
        if (compare_metadata) {
            if (strcmp(m1->name, m2->name) != 0)
                return false;
            if (!!m1->init != !!m2->init)
                return false;
            if (m1->init && !const_bit_equals(*m1->init, *m2->init))
                return false;
        }
    }
    return true;
}

// Used to decide whether:
// - forwared declaration / function definitions asre compatible
// - function pointer variables can be assigned to each other
// Does not include in comparison:
// - default arguments
// - parameter names
bool fn_type_equals(struct ir_fn_type *fn1, struct ir_fn_type *fn2)
{
    if (fn1 == fn2)
        return true;
    return struct_equals(fn1->args, fn2->args, false)
        && type_equals(fn1->ret_type, fn2->ret_type)
        && fn1->vararg == fn2->vararg;
}

static bool array_type_equals(struct ir_array_type *arr1,
                              struct ir_array_type *arr2)
{
    if (arr1 == arr2)
        return true;
    return type_equals(arr1->item_type, arr2->item_type)
        && arr1->dimension == arr2->dimension;
}

// Equality as in t1 and t2 mean the same type, even if some decorations might
// be different. In particular, see fn_type_equals().
// The allowed differences between equal types shall only matter for high level
// code (such as the semantic analysis parts of the compiler), not the IR.
bool type_equals(struct ir_type t1, struct ir_type t2)
{
    if (t1.type != t2.type)
        return false;
    // @ALL ir_type_type
    switch (t1.type) {
        case IR_TYPE_error:
            return false;
        case IR_TYPE_any:
            return false;       // not a real type
        case IR_TYPE_tuntyped:
            return true;
        case IR_TYPE_tbool:
            return true;
        case IR_TYPE_tint:
            return *GET_UNION(IR_TYPE, tint, &t1)
                    == *GET_UNION(IR_TYPE, tint, &t2);
        case IR_TYPE_tdouble:
            return true;
        case IR_TYPE_tptr:
            return type_equals(**GET_UNION(IR_TYPE, tptr, &t1),
                               **GET_UNION(IR_TYPE, tptr, &t2));
        case IR_TYPE_tstruct:
            return *GET_UNION(IR_TYPE, tstruct, &t1)
                == *GET_UNION(IR_TYPE, tstruct, &t2);
        case IR_TYPE_ttuple:
            return struct_equals(*GET_UNION(IR_TYPE, ttuple, &t1),
                                 *GET_UNION(IR_TYPE, ttuple, &t2),
                                 true);
        case IR_TYPE_tcompound:
            return struct_equals(*GET_UNION(IR_TYPE, tcompound, &t1),
                                 *GET_UNION(IR_TYPE, tcompound, &t2),
                                 true);
        case IR_TYPE_tfn:
            return fn_type_equals(*GET_UNION(IR_TYPE, tfn, &t1),
                                  *GET_UNION(IR_TYPE, tfn, &t2));
        case IR_TYPE_tstackclosure:
            return fn_type_equals(*GET_UNION(IR_TYPE, tstackclosure, &t1),
                                  *GET_UNION(IR_TYPE, tstackclosure, &t2));
        case IR_TYPE_tarray:
            return array_type_equals(*GET_UNION(IR_TYPE, tarray, &t1),
                                     *GET_UNION(IR_TYPE, tarray, &t2));
        case IR_TYPE_tslice:
            return type_equals(**GET_UNION(IR_TYPE, tslice, &t1),
                               **GET_UNION(IR_TYPE, tslice, &t2));
        default:
            assert(false);
    }
}

bool type_is_complete(struct ir_type t)
{
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error:
            return true;        // consider complete for sake of error handling
        case IR_TYPE_any:
            return false;       // not a real type
        case IR_TYPE_tuntyped:
            return false;       // like void in C
        case IR_TYPE_tbool:
        case IR_TYPE_tint:
        case IR_TYPE_tdouble:
        case IR_TYPE_tptr:
            return true;
        case IR_TYPE_tslice:
            // xxx not sure; declaring the slice is ok, indexing it isn't
            return true;
        case IR_TYPE_tstruct: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tstruct, &t);
            // xxx check all members?
            return st->defined;
        }
        case IR_TYPE_tfn:
        case IR_TYPE_tstackclosure:
        case IR_TYPE_ttuple:
        case IR_TYPE_tcompound:
        case IR_TYPE_tarray:
        {
            // xxx check all members / connected types?
            return true;
        }
        default:
            assert(false);
    }
}

bool type_is_integer(struct ir_type t)
{
    return t.type == IR_TYPE_tint;
}

bool type_is_fp(struct ir_type t)
{
    // might add float
    return t.type == IR_TYPE_tdouble;
}

bool type_is_ptr(struct ir_type t)
{
    return t.type == IR_TYPE_tptr;
}

bool type_is_bool(struct ir_type t)
{
    return t.type == IR_TYPE_tbool;
}

bool type_is_void(struct ir_type t)
{
    // Same as type_equals(t, global_types->tvoid)
    struct ir_struct_type void_type = {
        .defined = true
    };
    return type_equals(t, MAKE_IR_TYPE(ttuple, &void_type));
}

bool type_is_untyped(struct ir_type t)
{
    return t.type == IR_TYPE_tuntyped;
}

bool type_is_untyped_ptr(struct ir_type t)
{
    return type_is_ptr(t) && type_is_untyped(**GET_UNION(IR_TYPE, tptr, &t));
}

bool type_is_typed_ptr(struct ir_type t)
{
    return type_is_ptr(t) && !type_is_untyped(**GET_UNION(IR_TYPE, tptr, &t));
}

static enum ir_intt bits_to_rank(int bits)
{
    switch (bits) {
        case 8:  return IR_INTT_8;
        case 16: return IR_INTT_16;
        case 32: return IR_INTT_32;
        case 64: return IR_INTT_64;
    }
    assert(false);
}

struct ir_type type_integer(bool sign, int bits)
{
    return MAKE_IR_TYPE(tint, bits_to_rank(bits) | (sign ? IR_INTT_SIGNED : 0));
}

// Integer type that has at least the given number of bits.
struct ir_type type_integer_min(bool sign, int bits)
{
    int bt = 8;
    while (bt <= 64 && bits > bt)
        bt *= 2;
    if (bt > 64)
        return TYPE_ERROR;
    return type_integer(sign, bt);
}

struct ir_type type_unptr(struct ir_type t)
{
    struct ir_type **pt = TEST_UNION(IR_TYPE, tptr, &t);
    if (pt)
        return **pt;
    return TYPE_ERROR;
}

struct ir_type type_ptr_to(struct ir_types *ctx, struct ir_type t)
{
    return MAKE_IR_TYPE(tptr, talloc_from(ctx, struct ir_type, &t));
}

struct ir_type type_array(struct ir_types *ctx, struct ir_type t, int dim)
{
    assert(dim >= 0);
    struct ir_array_type *at = talloc_struct(ctx, struct ir_array_type,
                                             {t, dim});
    at->init = talloc_struct(at, struct ir_array_const, {at});
    at->init->data = talloc_array(at, struct value, dim);
    struct value v = type_init_value(t).value;
    for (int n = 0; n < dim; n++)
        at->init->data[n] = v;
    return MAKE_IR_TYPE(tarray, at);
}

struct ir_type type_slice_to(struct ir_types *ctx, struct ir_type t)
{
    return MAKE_IR_TYPE(tslice, talloc_from(ctx, struct ir_type, &t));
}

struct ir_type type_item_type(struct ir_type t)
{
    switch (t.type) {
        case IR_TYPE_tarray:
            return (*GET_UNION(IR_TYPE, tarray, &t))->item_type;
        case IR_TYPE_tslice:
            return **GET_UNION(IR_TYPE, tslice, &t);
        default:
            return TYPE_ERROR;
    }
}

int type_array_get_dimension(struct ir_type t)
{
    struct ir_array_type **tarr = TEST_UNION(IR_TYPE, tarray, &t);
    if (tarr)
        return (*tarr)->dimension;
    return 0;
}

bool type_get_sign(struct ir_type t)
{
    return *GET_UNION(IR_TYPE, tint, &t) & IR_INTT_SIGNED;
}

int type_get_bits(struct ir_type t)
{
    return INTT_BITS(*GET_UNION(IR_TYPE, tint, &t));
}

// return 0-3 for 8/16/32/64
// xxx rename
int type_int_order(struct ir_type t)
{
    return INTT_RANK(*GET_UNION(IR_TYPE, tint, &t));
}

bool type_is_structlike(struct ir_type t)
{
    switch (t.type) {
        case IR_TYPE_tstruct: return true;
        case IR_TYPE_ttuple: return true;
        case IR_TYPE_tcompound: return true;
        default: return false;
    }
}

struct ir_struct_type *type_get_structlike(struct ir_type t)
{
    switch (t.type) {
        case IR_TYPE_tstruct: return *GET_UNION(IR_TYPE, tstruct, &t);
        case IR_TYPE_ttuple: return *GET_UNION(IR_TYPE, ttuple, &t);
        case IR_TYPE_tcompound: return *GET_UNION(IR_TYPE, tcompound, &t);
        default: assert(false);
    }
}

static char *struct_vararg_mangle(struct ir_types *ctx, char *prefix,
                                  struct ir_struct_type *st)
{
    char *s = talloc_asprintf(ctx, "%s%d_", prefix, st->members_count);
    for (int n = 0; n < st->members_count; n++) {
        struct ir_struct_member *m = st->members[n];
        s = talloc_strdup_append_buffer(s, type_vararg_mangle(ctx, m->type));
    }
    return s;
}

char *type_vararg_mangle(struct ir_types *ctx, struct ir_type t)
{
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error:
        case IR_TYPE_any:
            return "?";
        case IR_TYPE_tuntyped:
            return "t";
        case IR_TYPE_tbool:
            return "b";
        case IR_TYPE_tint: {
            int ti = *GET_UNION(IR_TYPE, tint, &t);
            return talloc_asprintf(ctx, "%s%d", INTT_SIGN(ti) ? "i" : "u",
                                   INTT_BITS(ti));
        }
        case IR_TYPE_tdouble:
            return "d";
        case IR_TYPE_tptr:
            return talloc_asprintf(ctx, "*%s",
                    type_vararg_mangle(ctx, **GET_UNION(IR_TYPE, tptr, &t)));
        case IR_TYPE_tstruct: {
            // This is obviously not always unambiguous, and we don't care.
            // If we want "absolute" type-safety, we could append the item-wise
            // mangle, as it is done with tuples.
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tstruct, &t);
            return talloc_asprintf(ctx, "t'%s'", st->name);
        }
        case IR_TYPE_ttuple:
            return struct_vararg_mangle(ctx, "p",
                                        *GET_UNION(IR_TYPE, ttuple, &t));
        case IR_TYPE_tcompound:
            return struct_vararg_mangle(ctx, "P",
                                        *GET_UNION(IR_TYPE, tcompound, &t));
        case IR_TYPE_tfn: {
            struct ir_fn_type *fn = *GET_UNION(IR_TYPE, tfn, &t);
            return talloc_asprintf(ctx, "fn%s%s",
                                   type_vararg_mangle(ctx, fn->ret_type),
                                   struct_vararg_mangle(ctx, "", fn->args));
        }
        case IR_TYPE_tstackclosure: {
            struct ir_fn_type *fn = *GET_UNION(IR_TYPE, tfn, &t);
            return talloc_asprintf(ctx, "^%s%s",
                                   type_vararg_mangle(ctx, fn->ret_type),
                                   struct_vararg_mangle(ctx, "", fn->args));
        }
        case IR_TYPE_tarray: {
            struct ir_array_type *a = *GET_UNION(IR_TYPE, tarray, &t);
            return talloc_asprintf(ctx, "a%d_%s", a->dimension,
                                   type_vararg_mangle(ctx, a->item_type));
        }
        case IR_TYPE_tslice:
            return talloc_asprintf(ctx, "s%s",
                    type_vararg_mangle(ctx, **GET_UNION(IR_TYPE, tslice, &t)));
        default:
            assert(false);
    }
}

struct ir_struct_type *struct_start(struct ir_types *ctx, LOC loc)
{
    struct ir_struct_type *st = talloc_struct(ctx, struct ir_struct_type, {
        .loc = loc,
        .defined = false,
    });
    st->scope = talloc_struct(st, struct ir_scope, {0});
    return st;
}

struct ir_struct_member *struct_add(struct ir_struct_type *st, LOC m_loc,
                                    char *m_name, struct ir_type m_type,
                                    struct ir_const_val *m_init)
{
    assert(!st->defined);
    assert(!st->init);
    assert(!scope_lookup(st->scope, m_name));
    assert(type_is_complete(m_type));
    struct ir_struct_member *sm =
        talloc_struct(st, struct ir_struct_member, {
            .loc = m_loc,
            .name = m_name,
            .index = st->members_count,
            .type = m_type,
            .init = m_init,
        });
    talloc_steal(sm, m_init);
    BL_TARRAY_APPEND(st, st->members, st->members_count, sm);
    if (m_name && m_name[0]) {
        scope_add(st->scope, m_name,
                    (struct ast_sym) MAKE_UNION(AST_SYM, struct_member, sm));
    }
    return sm;
}

void struct_end(struct ir_struct_type *st, bool add_init)
{
    assert(!st->defined);
    assert(!st->init);
    if (add_init) {
        st->init = talloc_struct(st, struct ir_struct_const, {.type = st});
        st->init->data = talloc_array(st->init, struct value,
                                      st->members_count);
        for (int n = 0; n < st->members_count; n++) {
            struct ir_struct_member *member = st->members[n];
            if (!member->init) {
                struct ir_const_val c = type_init_value(member->type);
                member->init = talloc_from(st, struct ir_const_val, &c);
            }
            st->init->data[n] = member->init->value;
        }
    }
    st->defined = true;
}

struct ir_struct_member *struct_find_member(struct ir_struct_type *t, char *name)
{
    struct ast_sym *sym = scope_lookup(t->scope, name);
    return sym ? *GET_UNION(AST_SYM, struct_member, sym) : NULL;
}

static struct ir_type create_vararg_struct(struct ir_types *t)
{
    LOC loc = {0};
    struct ir_struct_type *st = struct_start(t, loc);
    // The order, types, and count of these struct fields are hardcoded
    // somewhere else in the compiler (have fun finding them).
    struct_add(st, loc, "ptr", TYPE_G_PTR, NULL);
    struct_add(st, loc, "name", TYPE_STRING, NULL);
    struct_add(st, loc, "type", TYPE_STRING, NULL);
    struct_end(st, true);
    st->name = "vararg";
    return MAKE_IR_TYPE(tstruct, st);
}

static struct ir_fn_type *create_c_main_fntype(struct ir_types *t)
{
    struct ir_fn_type *m = talloc_zero(t, struct ir_fn_type);
    m->args = struct_start(t, m->loc);
    struct ir_type c_int = MAKE_IR_TYPE(tint, IR_INTT_32 | IR_INTT_SIGNED);
    struct_add(m->args, m->loc, "argc", c_int, NULL);
    struct_add(m->args, m->loc, "argv",
               type_ptr_to(t, type_ptr_to(t, TYPE_CHAR)), NULL);
    struct_end(m->args, false);
    talloc_steal(m, m->args);
    m->ret_type = c_int;
    return m;
}

/*
static struct ir_type create_closure_struct(struct ir_types *t)
{
    LOC loc = {0};
    struct ir_struct_type *st = struct_start(t, loc);
    struct_add(st, loc, bstr0("ptr"), TYPE_G_PTR, NULL);
    struct_add(st, loc, bstr0("name"), TYPE_STRING, NULL);
    struct_add(st, loc, bstr0("type"), TYPE_STRING, NULL);
    struct_end(st, true);
    st->name = bstr0("vararg");
    return MAKE_IR_TYPE(tstruct, st);
}
*/

static struct ir_type create_void(struct ir_types *t)
{
    LOC loc = {0};
    struct ir_struct_type *st = struct_start(t, loc);
    struct_end(st, true);
    return MAKE_IR_TYPE(ttuple, st);
}

struct ir_types *types_new(void)
{
    struct ir_types *t = talloc_zero(NULL, struct ir_types);
    t->word_size = sizeof(void*) * 8; // xxx what about cross compiling?
    t->tvoid = create_void(t);
    assert(type_is_void(t->tvoid));
    t->index = type_integer(false, t->word_size);
    // The order, types, and count of these struct fields are hardcoded
    // somewhere else in the compiler (have fun finding them).
    t->vararg = create_vararg_struct(t);
    t->varargs = type_slice_to(t, t->vararg);
    //t->closure = create_closure_struct(t);
    t->c_main = create_c_main_fntype(t);
    return t;
}

bool type_implicitly_convertible(struct ir_type from, struct ir_type to)
{
    if (type_equals(from, to))
        return true;

    // untyped* -> T* and T* -> untyped* are allowed, but not T1* -> T2*
    if (type_is_ptr(from) && type_is_ptr(to))
        return type_is_untyped_ptr(from) || type_is_untyped_ptr(to);

    if (!(type_is_integer(from) && type_is_integer(to)))
        return false;

    bool from_sign = type_get_sign(from);
    bool to_sign = type_get_sign(to);
    int from_bits = type_get_bits(from);
    int to_bits = type_get_bits(to);
    return int_convertible(from_sign, from_bits, to_sign, to_bits);
}

// Return a common type both t1 and t2 can be implicitly converted to, or an
// error (IR_TYPE_error).
// On success, both t1 and t2 must be implicitly convertible to the result type.
struct ir_type type_common(struct ir_type t1, struct ir_type t2)
{
    if (type_equals(t1, t2))
        return t1;
    if (type_is_ptr(t1) && type_is_ptr(t2))
        return TYPE_G_PTR;
    // For now, always assume that the common type is one of t1 or t2 (and not
    // a third type) - normalize such that the common type will be t2.
    if (type_implicitly_convertible(t1, t2))
        return t2;
    if (type_implicitly_convertible(t2, t1))
        return t1;
    if (type_is_integer(t1) && type_is_integer(t2)) {
        // Since implicit conversion failed, these types must be of different
        // signedness. Two possibilities:
        // - Both types have the same size.
        // - The signed type is smaller. (If the unsigned type were smaller,
        //   it could have been implicitly converted to the larger one.)
        // => Get the next largest signed type.
        int minbits = BL_MAX(type_get_bits(t1), type_get_bits(t2));
        return type_integer_min(true, minbits + 1);
    }
    return TYPE_ERROR;
}

#define TYPE_SYM(t) (struct ast_sym) MAKE_UNION(AST_SYM, type, t)
#define CONST_SYM(tctx, t, v) \
    (struct ast_sym) MAKE_UNION(AST_SYM, const_, \
        talloc_struct(tctx, struct ir_const_val, {t, v}))

#define ADD(name, sym) scope_add(scope, name, sym);

void add_predefined_types(struct ir_scope *scope, struct ir_types *t)
{
    ADD("i8", TYPE_SYM(type_integer(true, 8)));
    ADD("u8", TYPE_SYM(type_integer(false, 8)));
    ADD("i16", TYPE_SYM(type_integer(true, 16)));
    ADD("u16", TYPE_SYM(type_integer(false, 16)));
    ADD("i32", TYPE_SYM(type_integer(true, 32)));
    ADD("u32", TYPE_SYM(type_integer(false, 32)));
    ADD("i64", TYPE_SYM(type_integer(true, 64)));
    ADD("u64", TYPE_SYM(type_integer(false, 64)));
    ADD("double", TYPE_SYM(MAKE_IR_TYPE0(tdouble)));
    ADD("iword", TYPE_SYM(type_integer(true, t->word_size)));
    ADD("uword", TYPE_SYM(type_integer(false, t->word_size)));
    ADD("bool", TYPE_SYM(TYPE_BOOL));
    ADD("void", TYPE_SYM(t->tvoid));
    ADD("untyped", TYPE_SYM(MAKE_IR_TYPE0(tuntyped)));
    ADD("string", TYPE_SYM(TYPE_STRING));
    ADD("false", CONST_SYM(scope, TYPE_BOOL, MAKE_UNION(VALUE, vuint64, 0)));
    ADD("true", CONST_SYM(scope, TYPE_BOOL, MAKE_UNION(VALUE, vuint64, 1)));
    ADD("NULL", CONST_SYM(scope, TYPE_G_PTR, MAKE_UNION(VALUE, vuint64, 0)));
    ADD("vararg", TYPE_SYM(t->vararg));
    ADD("varargs", TYPE_SYM(t->varargs));
    // C compatibility crap
    ADD("c_int", TYPE_SYM(type_integer(true, 32)));
    ADD("c_uint", TYPE_SYM(type_integer(false, 32)));
    ADD("c_size_t", TYPE_SYM(type_integer(false, t->word_size)));
    // Not exactly the same, but since i8/u8 map to signed/unsigned char, and
    // C's char is a separate 3rd type, we can't get it right anyway (as far
    // as the C backend is concerned).
    struct ir_type c_char = TYPE_CHAR;
    ADD("c_char", TYPE_SYM(c_char));
    ADD("c_string", TYPE_SYM(type_ptr_to(t, c_char)));
}

