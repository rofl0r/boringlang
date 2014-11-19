#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "hashtable.h"
#include "utils.h"
#include "ir.h"

// NOTE:
// The generated C code is probably invalid whenever it uses "{}" as initializer
// strictly speaking.
// Some structs contain no members, which according to C99 is undefined, but
// works fine with gcc.
// In theory using void* for function pointers is a problem (closures do).

// Output #line preprocessor statements.
static const bool write_loc = false;
// Write nested C expressions.
static const bool write_inline = true;
// Make tuple mangles shorter for the sake of readability.
// The downside is that it violates C aliasing rules if multiple translation
// units are used (equal tuple types must map to structs of the same name).
static const bool use_anon_mangle_for_tuples = true;

struct context {
    FILE *f;
    int next_type_id;
    int indentation;
    source_pos last_loc;
    bool writing_types;
    struct hashtable *type_mangle;
    struct hashtable *redef;
    struct hashtable *tuple_abbrev;
    // lame cache for T0, T1, ... (seriously)
    int tempnames_count;
    char **tempnames;
    // temp during code output
    void *tmp;
    int reg;
};

typedef struct context CTX;

#define MANGLE_PREFIX "BL_"

#define SLICE_MANGLE MANGLE_PREFIX "slice"
#define CLOSURE_MANGLE MANGLE_PREFIX "closure"
#define VPTR_MANGLE MANGLE_PREFIX "vptr"
#define VOID_MANGLE MANGLE_PREFIX "void"
#define VOID_VAL MANGLE_PREFIX "VOID_VAL"

#define INDENT 4

static void indent(CTX *ctx)
{
    fprintf(ctx->f, "%*s", ctx->indentation * INDENT, "");
}

static void indent_in(CTX *ctx)
{
    ctx->indentation++;
}

static void indent_out(CTX *ctx)
{
    ctx->indentation--;
    assert(ctx->indentation>= 0);
}

BL_PRINTF_ATTRIBUTE(2, 3)
static void wf(CTX *ctx, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    indent(ctx);
    vfprintf(ctx->f, fmt, va);
    fprintf(ctx->f, "\n");
    va_end(va);
}

static void set_loc(CTX *ctx, source_pos loc)
{
    if (loc.byte != ctx->last_loc.byte) {
        char *l = source_pos_string(loc);
        wf(ctx, "// loc: %s", l);
        talloc_free(l);
    }
    if (write_loc) {
        if (loc.line != ctx->last_loc.line) {
            fprintf(ctx->f, "#line %d\n", loc.line);
        }
    }
    ctx->last_loc = loc;
}

static void set_no_loc(CTX *ctx)
{
}

// Use this if special variables (starting with one of T, B, A, V) need to be
// renamed into something longer (less ambiguous), and you can't be bothered to
// update the strings in gen_inst(). (Then we'd search & replace on fmt.)
BL_PRINTF_ATTRIBUTE(2, 3)
static void P(CTX *ctx, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vfprintf(ctx->f, fmt, va);
    va_end(va);
}

static char* def_type(CTX *ctx, struct ir_type t);

static char *type(CTX *ctx, struct ir_type t)
{
    return def_type(ctx, t);
}

static char *ret_type(CTX *ctx, struct ir_type t)
{
    // for C ABI compatibility
    return type_is_void(t) ? "void" : def_type(ctx, t);
}

static void add_mangle(CTX *ctx, void *key, char *val)
{
    assert(!HT_GET(dptr, dstr, ctx->type_mangle, key));
    HT_INSERT(dptr, dstr, ctx->type_mangle, key, val);
}

static char *get_mangle(CTX *ctx, void *key)
{
    char **res = HT_GET(dptr, dstr, ctx->type_mangle, key);
    assert(!res || *res);
    return res ? *res : NULL;
}

static char *gen_anon_mangle(CTX *ctx, char *prefix)
{
    return talloc_asprintf(ctx, "%s%s_a%d", MANGLE_PREFIX, prefix,
                           ctx->next_type_id++);
}

// If 's' was already defined, return true.
// Otherwise, define 's' and return false.
static bool check_redef(CTX *ctx, char *s)
{
    if (HT_GET(dstr, dempty, ctx->redef, s))
        return true;
    HT_INSERT(dstr, dempty, ctx->redef, s, NULL);
    return false;
}

static void mangle_append_sub(char **s, char *m)
{
    void *p = talloc_parent(*s);
    assert(p);
    // Kill prefix, for not making type names not ridiculous long.
    if (strncmp(m, MANGLE_PREFIX, strlen(MANGLE_PREFIX)) == 0)
        m = m + strlen(MANGLE_PREFIX);
    *s = talloc_asprintf_append_buffer(*s, "%zd_%s_", strlen(m), m);
}

static char *def_array_type(CTX *ctx, struct ir_array_type *at)
{
    char *m = get_mangle(ctx, at);
    if (m)
        return m;
    assert(ctx->writing_types);
    m = talloc_strdup(ctx, MANGLE_PREFIX "arr_");
    m = talloc_asprintf_append_buffer(m, "%d_", at->dimension);
    mangle_append_sub(&m, def_type(ctx, at->item_type));
    add_mangle(ctx, at, m);
    if (!check_redef(ctx, m)) {
        wf(ctx, "typedef struct %s {", m);
        indent_in(ctx);
        wf(ctx, "%s a[%d];", def_type(ctx, at->item_type), at->dimension);
        indent_out(ctx);
        wf(ctx, "} %s;", m);
    }
    return m;
}

static void write_fn_type(CTX *ctx, struct ir_fn_type *fnt, bool as_ptr,
                          char *name)
{
    fprintf(ctx->f, "%s ", ret_type(ctx, fnt->ret_type));
    if (as_ptr) {
        fprintf(ctx->f, "(*%s)", name);
    } else {
        fprintf(ctx->f, "%s", name);
    }
    fprintf(ctx->f, "(");
    for (int n = 0; n < fnt->args->members_count; n++) {
        struct ir_struct_member *m = fnt->args->members[n];
        if (n > 0)
            fprintf(ctx->f, ", ");
        P(ctx, "%s A%d", def_type(ctx, m->type), n);
    }
    if (fnt->vararg == IR_VARARG_C) {
        if (fnt->args->members_count)
            fprintf(ctx->f, ", ");
        fprintf(ctx->f, "...");
    } else if (fnt->args->members_count == 0) {
        fprintf(ctx->f, "void");
    }
    fprintf(ctx->f, ")");
}

static char *def_fn_type(CTX *ctx, struct ir_fn_type *fnt)
{
    char *m = get_mangle(ctx, fnt);
    if (m)
        return m;
    assert(ctx->writing_types);
    m = talloc_strdup(ctx, MANGLE_PREFIX "fn_");
    mangle_append_sub(&m, def_type(ctx, fnt->ret_type));
    for (int n = 0; n < fnt->args->members_count; n++) {
        struct ir_struct_member *sm = fnt->args->members[n];
        mangle_append_sub(&m, def_type(ctx, sm->type));
    }
    switch (fnt->vararg) {
        case IR_VARARG_NONE: break;
        case IR_VARARG_NATIVE: mangle_append_sub(&m, "vararg"); break;
        case IR_VARARG_C: mangle_append_sub(&m, "cvararg"); break;
        default: assert(false);
    }
    add_mangle(ctx, fnt, m);
    fprintf(ctx->f, "typedef ");
    write_fn_type(ctx, fnt, true, m);
    fprintf(ctx->f, ";\n");
    return m;
}

struct name_temp {
    char tmp[20];
};

static char *member_name(struct ir_struct_member *m, struct name_temp *t)
{
    if (m->name && m->name[0])
        return m->name;
    snprintf(t->tmp, sizeof(t->tmp), "m%d", m->index);
    return t->tmp;
}

static void write_struct(CTX *ctx, struct ir_struct_type *st, char *name)
{
    assert(ctx->writing_types);
    wf(ctx, "struct %s;", name);
    wf(ctx, "typedef struct %s %s;", name, name);
    // Make sure all types are written out first.
    for (int n = 0; n < st->members_count; n++) {
        struct ir_struct_member *m = st->members[n];
        def_type(ctx, m->type);
    }
    set_loc(ctx, st->loc);
    wf(ctx, "struct %s {", name);
    indent_in(ctx);
    for (int n = 0; n < st->members_count; n++) {
        struct ir_struct_member *m = st->members[n];
        struct name_temp t;
        char *mname = member_name(m, &t);
        set_loc(ctx, m->loc);
        wf(ctx, "%s %s;", def_type(ctx, m->type), mname);
    }
    indent_out(ctx);
    wf(ctx, "};");
    set_no_loc(ctx);
}

static char *def_tuple(CTX *ctx, struct ir_struct_type *st, bool add_names)
{
    // NOTE: we use the same C type for empty tuples and compounds; should be ok
    if (st->members_count == 0)
        return VOID_MANGLE;
    char *m = get_mangle(ctx, st);
    if (m)
        return m;
    assert(ctx->writing_types);
    m = talloc_strdup(ctx, MANGLE_PREFIX "tuple_");
    for (int n = 0; n < st->members_count; n++) {
        struct ir_struct_member *sm = st->members[n];
        mangle_append_sub(&m, def_type(ctx, sm->type));
        assert(add_names == (sm->name[0]));
        if (sm->name)
            m = talloc_asprintf_append_buffer(m, "n%zd_%s_", strlen(sm->name),
                                              sm->name);
    }
    if (use_anon_mangle_for_tuples) {
        char *new_mangle = HT_GET_DEF(dstr, dstr, ctx->tuple_abbrev, m, NULL);
        if (!new_mangle) {
            new_mangle = gen_anon_mangle(ctx, "tuple");
            HT_INSERT(dstr, dstr, ctx->tuple_abbrev, m, new_mangle);
        }
        m = new_mangle;
    }
    add_mangle(ctx, st, m);
    if (!check_redef(ctx, m))
        write_struct(ctx, st, m);
    return m;
}

static char *def_struct(CTX *ctx, struct ir_struct_type *st)
{
    char *m = get_mangle(ctx, st);
    if (m)
        return m;
    assert(ctx->writing_types);
    // In theory we must not mangle at all. If there is C code that
    // uses the same struct, they must use the same name (and have
    // the same members and so on).
    // xxx handle structs nested inside functions
    m = talloc_strdup(ctx, st->name);
    add_mangle(ctx, st, m);
    write_struct(ctx, st, m);
    return m;
}

static char *def_ptr(CTX *ctx, struct ir_type *pt)
{
    if (type_is_untyped(*pt))
        return VPTR_MANGLE;
    char *m = get_mangle(ctx, pt);
    if (m)
        return m;
    assert(ctx->writing_types);
    char *sub = def_type(ctx, *pt);
    m = talloc_strdup(ctx, MANGLE_PREFIX "p_");
    mangle_append_sub(&m, sub);
    add_mangle(ctx, pt, m);
    if (!check_redef(ctx, m))
        wf(ctx, "typedef %s *%s;", sub, m);
    return m;
}

static const char *int_types[] = {
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
};

static char *def_int(struct ir_type t)
{
    return (char *)int_types[type_int_order(t) + (type_get_sign(t) ? 4 : 0)];
}

// Write a definition for a type and return its name (possibly a typedef).
// If the type was already written, return mangle only.
// Note about mangling:
// - The main issue is making anonymous, structural types like tuples work. To
//   get proper defined C behavior, we must use the same struct for the same
//   types across all translation units. For example, (int, bool) must always
//   be backed by the same C struct. That is, the C struct must consist of the
//   same members (name and type) and have the same name.
// - Some types must be disambiguated. (Consider different structs nested in
//   different functions, but with the same name.)
// - This is no "public" mangling, as it's needed e.g. for C++ symbols. It's
//   merely needed for accomplishing the above goals.
// - This function also returns a valid C type name. This is a misguided attempt
//   to stuff everything into one function, instead of requiring one function
//   to get the typename, and one to get the mangle, or maybe even just having
//   a bool parameter telling whether to return a type or a mangle.
static char* def_type(CTX *ctx, struct ir_type t)
{
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error:
            abort();
        case IR_TYPE_any:
            return NULL;
        case IR_TYPE_tuntyped:
            return (char *)"void";
        case IR_TYPE_tbool:
            return (char *)"bool";
        case IR_TYPE_tint:
            return def_int(t);
        case IR_TYPE_tdouble:
            return (char *)"double";
        case IR_TYPE_tptr:
            return def_ptr(ctx, *GET_UNION(IR_TYPE, tptr, &t));
        case IR_TYPE_tstruct:
            return def_struct(ctx, *GET_UNION(IR_TYPE, tstruct, &t));
        case IR_TYPE_ttuple:
            return def_tuple(ctx, *GET_UNION(IR_TYPE, ttuple, &t), false);
        case IR_TYPE_tcompound:
            return def_tuple(ctx, *GET_UNION(IR_TYPE, tcompound, &t), true);
        case IR_TYPE_tfn:
            return def_fn_type(ctx, *GET_UNION(IR_TYPE, tfn, &t));
        case IR_TYPE_tstackclosure:
            return (char *)CLOSURE_MANGLE;
        case IR_TYPE_tarray:
            return def_array_type(ctx, *GET_UNION(IR_TYPE, tarray, &t));
        case IR_TYPE_tslice:
            return (char *)SLICE_MANGLE;
        default:
            assert(false);
    }
}

// Define all referenced function types.
static void do_fn_types(CTX *ctx, struct ir_fn_type *fnt)
{
    def_type(ctx, fnt->ret_type);
    for (int n = 0; n < fnt->args->members_count; n++)
        def_type(ctx, fnt->args->members[n]->type);
}

static char *def_nested_fn(CTX *ctx, struct ir_function *fn)
{
    char *m = get_mangle(ctx, fn);
    if (m)
        return m;
    assert(ctx->writing_types);
    m = gen_anon_mangle(ctx, "nested_fn");
    add_mangle(ctx, fn, m);
    do_fn_types(ctx, fn->type);
    fprintf(ctx->f, "static ");
    write_fn_type(ctx, fn->type, false, m);
    fprintf(ctx->f, ";\n");
    return m;
}

static char *link_name(CTX *ctx, struct ir_link_name name)
{
    return talloc_asprintf(ctx, "%s%s%s",
                           // For now, out all functions not meant to be
                           // visible by C code into their own namespace.
                           name.is_c ? "" : (MANGLE_PREFIX "f_"),
                           // invisible => make name different from possible
                           //              same-named global functions?
                           name.visible ? "" : "inv_",
                           name.name);
}

static char *def_fn(CTX *ctx, struct ir_fn_decl *fn)
{
    if (fn->body && fn->body->parent)
        return def_nested_fn(ctx, fn->body);
    char *m = get_mangle(ctx, fn);
    if (m)
        return m;
    assert(ctx->writing_types);
    m = link_name(ctx, fn->name);
    add_mangle(ctx, fn, m);
    do_fn_types(ctx, fn->type);
    if (!fn->name.visible)
        fprintf(ctx->f, "static ");
    write_fn_type(ctx, fn->type, false, m);
    fprintf(ctx->f, ";\n");
    return m;
}

static const char *int_consts[] = {
    "UINT8_C", "UINT16_C", "UINT32_C", "UINT64_C",
    "INT8_C", "INT16_C", "INT32_C", "INT64_C",
};

static char *int_const(struct ir_type t)
{
    return (char *)int_consts[type_int_order(t) + (type_get_sign(t) ? 4 : 0)];
}

static void write_const(CTX *ctx, struct ir_const_val v)
{
    char *s = const_unparse(NULL, v);
    if (TEST_UNION(IR_TYPE, tarray, &v.type)) {
        fprintf(ctx->f, "{%s}", s);
    } else if (type_is_integer(v.type)) {
        // Get rid of annoying-but-correct gcc warning. This happens because we
        // negate a value not representable in intmax_t, even though the result
        // is representable, i.e. the only case is INT64_MIN.
        if (type_equals(v.type, type_integer(true, 64))
            && *GET_UNION(VALUE, vuint64, &v.value) == INT64_MIN)
        {
            fprintf(ctx->f, "INT64_MIN");
        } else {
            fprintf(ctx->f, "%s(%s)", int_const(v.type), s);
        }
    } else if (TEST_UNION(IR_TYPE, tslice, &v.type)) {
        if (TEST_UNION0(VALUE, vempty, &v.value)) {
            fprintf(ctx->f, "{0}");
        } else if (type_equals(v.type, TYPE_STRING)) {
            char *raw = *GET_UNION(VALUE, vstring, &v.value);
            fprintf(ctx->f, "{ %s, %zd }", s, raw ? strlen(raw) : 0);
        } else {
            assert(false);
        }
    } else {
        fprintf(ctx->f, "%s", s);
    }
    talloc_free(s);
}

static const char *optable[] = {
    [IR_OP_ADD] = "+",
    [IR_OP_SUB] = "-",
    [IR_OP_MUL] = "*",
    [IR_OP_DIV] = "/",
    [IR_OP_MOD] = "%",
    [IR_OP_AND] = "&",
    [IR_OP_OR] = "|",
    [IR_OP_XOR] = "^",
    [IR_OP_SHIFT_R] = ">>",
    [IR_OP_SHIFT_L] = "<<",
    [IR_OP_EQ] = "==",
    [IR_OP_NOT_EQ] = "!=",
    [IR_OP_CMP_LT] = "<",
    [IR_OP_CMP_GT] = ">",
    [IR_OP_CMP_LT_EQ] = "<=",
    [IR_OP_CMP_GT_EQ] = ">=",
};

static char *get_temp(CTX *ctx, int n)
{
    assert(n >= 0);
    while (n >= ctx->tempnames_count) {
        char *s = talloc_asprintf(ctx, "T%d", ctx->tempnames_count);
        BL_TARRAY_APPEND(ctx, ctx->tempnames, ctx->tempnames_count, s);
    }
    return ctx->tempnames[n];
}

static char *gen_inst_inline(CTX *ctx, struct ir_inst *in);

static char *R(CTX *ctx, struct ir_inst *in, int i)
{
    struct ir_inst *r = inst_getuse(in, i);
    if (type_is_void(r->result_type))
        return VOID_VAL;
    if (r->scratch1_i < 0) {
        return gen_inst_inline(ctx, r);
    } else {
        return get_temp(ctx, r->scratch1_i);
    }
}

static int BR(struct ir_inst *in, int i)
{
    return in->branch[i]->index;
}

static void print_reads(CTX *ctx, struct ir_inst *in, int first)
{
    for (int n = first; n < in->read_count; n++) {
        if (n > first)
            P(ctx, ", ");
        P(ctx, "%s", R(ctx, in, n));
    }
}

#define R0 R(ctx, in, 0)
#define R1 R(ctx, in, 1)
static void write_inst(CTX *ctx, struct ir_inst *in, bool inner)
{
    if (in->comment)
        P(ctx, " /* COMMENT: %s */ ", in->comment);
    // @ALL ir_opcode
    switch (in->op) {
        case IR_OP_NOP:
            break;
        case IR_OP_COPY:
            P(ctx, "%s", R0);
            break;
        case IR_OP_GOTO:
            P(ctx, "goto B%d", BR(in, 0));
            break;
        case IR_OP_BRANCH:
            P(ctx, "if (%s) goto B%d; else goto B%d", R0, BR(in, 1), BR(in, 0));
            break;
        case IR_OP_RET:
            if (type_is_void(inst_getuse(in, 0)->result_type)) {
                P(ctx, "return");
            } else {
                P(ctx, "return %s", R0);
            }
            break;
        case IR_OP_ABORT:
            P(ctx, "abort()");
            break;
        case IR_OP_GETARG:
            P(ctx, "A%d", in->struct_member->index);
            break;
        case IR_OP_READ_VAR:
            P(ctx, "V%d", in->var->index);
            break;
        case IR_OP_WRITE_VAR:
            P(ctx, "V%d = %s", in->var->index, R0);
            break;
        case IR_OP_VAR_PTR:
            P(ctx, "&V%d", in->var->index);
            break;
        case IR_OP_GET_STRUCT_MEMBER_PTR: {
            struct name_temp t;
            P(ctx, "&(%s->%s)", R0, member_name(in->struct_member, &t));
            break;
        }
        case IR_OP_CONSTRUCT_STRUCT: {
            if (inner)
                P(ctx, "(%s)", type(ctx, in->result_type));
            P(ctx, "{");
            print_reads(ctx, in, 0);
            P(ctx, "}");
            break;
        }
        case IR_OP_GET_STRUCT_MEMBER: {
            struct name_temp t;
            P(ctx, "%s.%s", R0, member_name(in->struct_member, &t));
            break;
        }
        case IR_OP_SET_STRUCT_MEMBER: {
            //struct name_temp t;
            //bstr name = member_name(in->struct_member, &t);
            //P(ctx, "%s; %s.%.*s = %s", R0, in->write, BSTR_P(name), R1);
            abort();
            break;
        }
        case IR_OP_MAKE_CLOSURE:
            if (inner)
                P(ctx, "(%s)", type(ctx, in->result_type));
            P(ctx, "{ (void*)%s, %s }", R0, R1);
            break;
        case IR_OP_GET_CLOSURE_FN:
            P(ctx, "(%s) %s.fn", type(ctx, in->result_type), R0);
            break;
        case IR_OP_GET_CLOSURE_CTX:
            P(ctx, "%s.ctx", R0);
            break;
        case IR_OP_CONSTRUCT_SLICE:
        case IR_OP_SLICE:
        case IR_OP_SLICE_COPY:
        case IR_OP_SLICE_SET:
            assert(false); //TODO
        case IR_OP_GET_SLICE_LENGTH:
            P(ctx, "%s.len", R0);
            break;
        case IR_OP_GET_SLICE_PTR:
            P(ctx, "(%s)%s.ptr", type(ctx, in->result_type), R0);
            break;
        case IR_OP_GET_SLICE_ITEM_PTR:
            P(ctx, "(assert(%s < %s.len), ((%s)%s.ptr) + %s)", R1, R0,
              type(ctx, in->result_type), R0, R1);
            break;
        case IR_OP_CONSTRUCT_ARRAY:
            if (inner)
                P(ctx, "(%s)", type(ctx, in->result_type));
            P(ctx, "{ {");
            print_reads(ctx, in, 0);
            P(ctx, "} }");
            break;
        case IR_OP_ARRAY_TO_SLICE:
            if (inner)
                P(ctx, "(%s)", type(ctx, in->result_type));
            P(ctx, "{ &%s->a[0], %d }", R0, type_array_get_dimension
                                (type_unptr(inst_getuse(in, 0)->result_type)));
            break;
        case IR_OP_READ_PTR:
            P(ctx, "*%s", R0);
            break;
        case IR_OP_WRITE_PTR:
            P(ctx, "*%s = %s", R0, R1);
            break;
        case IR_OP_LOAD_CONST:
            if (inner)
                P(ctx, "(%s)", type(ctx, in->result_type));
            write_const(ctx, *in->const_value);
            break;
        case IR_OP_FN_PTR:
            P(ctx, "%s", def_fn(ctx, in->fn));
            break;
        case IR_OP_CALL: {
            P(ctx, "%s(", def_fn(ctx, in->fn));
            print_reads(ctx, in, 0);
            P(ctx, ")");
            break;
        }
        case IR_OP_CALL_PTR: {
            P(ctx, "%s(", R0);
            print_reads(ctx, in, 1);
            P(ctx, ")");
            break;
        }
        case IR_OP_NEG:
            P(ctx, "-%s", R0);
            break;
        case IR_OP_NOT:
            if (in->result_type.type == IR_TYPE_tbool) {
                // C promotes the bool to a larger integer, "~" won't work.
                P(ctx, "!%s", R0);
            } else {
                P(ctx, "~%s", R0);
            }
            break;
        case IR_OP_CONV_INT_SIGN:
        case IR_OP_CONV_INT_EXT:
        case IR_OP_CONV_INT_TRUNC:
        case IR_OP_CONV_TO_G_PTR:
        case IR_OP_CONV_FROM_G_PTR:
            P(ctx, "(%s)%s", type(ctx, in->result_type), R0);
            break;
        case IR_OP_ADD:
        case IR_OP_SUB:
        case IR_OP_MUL:
        case IR_OP_DIV:
        case IR_OP_MOD:
        case IR_OP_AND:
        case IR_OP_OR:
        case IR_OP_XOR:
        case IR_OP_SHIFT_R:
        case IR_OP_SHIFT_L:
        case IR_OP_EQ:
        case IR_OP_NOT_EQ:
        case IR_OP_CMP_LT:
        case IR_OP_CMP_GT:
        case IR_OP_CMP_LT_EQ:
        case IR_OP_CMP_GT_EQ:
        {
            // C integer promotion makes it hard to avoid the cast here.
            P(ctx, "(%s)(%s %s %s)", type(ctx, in->result_type), R0,
              optable[in->op], R1);
            break;
        }
        // not applicable
        case IR_OP_UPVAL_PTR:
        case IR_OP_UPVAL_CONTEXT:
        case IR_OP_PHI:
            assert(false);
        default:
            assert(false);
    }
}
#undef R0
#undef R1

static char *gen_inst_inline(CTX *ctx, struct ir_inst *in)
{
    assert(!ir_op_writes_side_effects(in->op) && !ir_op_is_branch(in->op)
           && !type_is_void(in->result_type) && in->users_count == 1);

    size_t sz = 0;
    char *data = NULL;

    FILE *oldf = ctx->f;
    ctx->f = open_memstream(&data, &sz);

    P(ctx, "(");
    write_inst(ctx, in, true);
    P(ctx, ")");

    int res = fclose(ctx->f);
    assert(res == 0);
    ctx->f = oldf;

    char *r = talloc_strdup(ctx->tmp, data);
    free(data);
    return r;
}

// Whether there are not yet generated read side-effects.
// (A more efficient implementation would mark all users of an instruction as
// having read side-effects if generation of the instruction is delayed.)
static bool has_outstanding_sideffect_reads(struct ir_inst *in)
{
    if (in->scratch1_i >= 0)
        return false;
    if (ir_op_reads_side_effects(in->op))
        return true;
    for (int n = 0; n < in->read_count; n++) {
        if (has_outstanding_sideffect_reads(inst_getuse(in, n)))
            return true;
    }
    return false;
}

static void gen_inst(CTX *ctx, struct ir_inst *in)
{
    struct ir_type res_t = in->result_type;
    bool is_void = type_is_void(res_t);
    // Don't write anything not needed. Note that void values are never actually
    // "used" by the generated C code, and instead are replaced with VOID_VAL.
    if (!ir_op_writes_side_effects(in->op) && !ir_op_is_branch(in->op)) {
        if (is_void)
            return;
        if (in->users_count == 0)
            return;
        // If it has 1 use, it can be generated inline.
        if (write_inline && in->users_count == 1) {
            // But if it crosses side effects, it must be generated earlier.
            // NOTE: if there are any not yet generated instructions with read
            //       side-effects, we must generate the code before crossing
            //       write side-effects as well.
            // Consider: t1=read; t2=neg(t1); call a(); call b(t2);
            // Mustn't turn into: call a(); call b(neg(read));
            bool crosses_sideffects = false;
            if (has_outstanding_sideffect_reads(in)) {
                struct ir_inst *user= in->users[0];
                for (struct ir_inst *cur = in; cur; cur = cur->next) {
                    if (cur == user)
                        break;
                    if (ir_op_writes_side_effects(cur->op)) {
                        crosses_sideffects = true;
                        break;
                    }
                }
            }
            if (!crosses_sideffects)
                return;
        }
    }

    set_loc(ctx, in->loc);
    indent(ctx);
    if (!TEST_UNION0(IR_TYPE, any, &res_t) && !is_void && in->users_count > 0)
    {
        if (in->scratch1_i == -1)
            in->scratch1_i = ctx->reg++;
        P(ctx, "%s %s = ", type(ctx, res_t), get_temp(ctx, in->scratch1_i));
    }

    write_inst(ctx, in, false);

    fprintf(ctx->f, ";\n");

    talloc_free_children(ctx->tmp);
}

static void gen_fn(CTX *ctx, struct ir_function *fn, char *name, bool visible)
{
    assert(!ctx->writing_types);

    if (!fn->parent)
        fn_complete_nested_calls(fn);

    for (int n = 0; n < fn->nested_functions_count; n++) {
        struct ir_function *nfn = fn->nested_functions[n];
        ctx->writing_types = true;
        char *nname = def_nested_fn(ctx, nfn);
        ctx->writing_types = false;
        gen_fn(ctx, nfn, nname, false);
    }

    fn_remove_global_ssa(fn);
    fn_verify(fn);
    //dump_fn(stderr, fn);

    for (int b = 0; b < fn->blocks_count; b++) {
        for (struct ir_inst *in = fn->blocks[b]->first; in; in = in->next)
            in->scratch1_i = -1;
    }

    // add all C types and function declarations needed for this function
    ctx->writing_types = true;
    do_fn_types(ctx, fn->type);
    for (int n = 0; n < fn->vars_count; n++)
        def_type(ctx, fn->vars[n]->type);
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            def_type(ctx, in->result_type);
            if (in->op == IR_OP_CALL || in->op == IR_OP_FN_PTR) {
                def_fn(ctx, in->fn);
            }
        }
    }
    ctx->writing_types = false;

    set_loc(ctx, fn->loc);
    if (!visible)
        fprintf(ctx->f, "static ");
    write_fn_type(ctx, fn->type, false, name);
    wf(ctx, " {");
    indent_in(ctx);
    for (int n = 0; n < fn->vars_count; n++) {
        struct ir_var *v = fn->vars[n];
        set_loc(ctx, v->loc);
        indent(ctx);
        P(ctx, "%s V%d", type(ctx, v->type), n);
        // void values are never assigned to (to avoid clashes with C's void);
        // since they have only one value, there's no need to. Initialize them
        // to avoid C warnings, though.
        if (type_is_void(v->type))
            P(ctx, " = {0}");
        P(ctx, ";\n");
    }
    indent(ctx);
    P(ctx, "goto B%d;\n", fn->entry->index);
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        indent(ctx);
        P(ctx, "B%d: {\n", b);
        indent_in(ctx);
        ctx->reg = 0;
        for (struct ir_inst *in = bb->first; in; in = in->next)
            gen_inst(ctx, in);
        indent_out(ctx);
        wf(ctx, "}");
    }
    indent_out(ctx);
    wf(ctx, "}");
}

static void prelude(CTX *ctx)
{
    wf(ctx, "#include <stddef.h>");
    wf(ctx, "#include <stdlib.h>");
    wf(ctx, "#include <stdbool.h>");
    wf(ctx, "#include <stdint.h>");
    wf(ctx, "#include <assert.h>");
    wf(ctx, "typedef struct { void *ptr; size_t len; } " SLICE_MANGLE ";");
    wf(ctx, "typedef struct { void *fn; void *ctx; } " CLOSURE_MANGLE ";");
    wf(ctx, "typedef void *" VPTR_MANGLE ";");
    wf(ctx, "typedef struct { char dummy; } " VOID_MANGLE ";");
    wf(ctx, "#define " VOID_VAL " ((" VOID_MANGLE ") {0})");
}

void generate_c(FILE *f, struct ir_unit *unit)
{
    CTX *ctx = talloc_struct(NULL, CTX, { f, 0 });
    ctx->type_mangle = ht_create(ctx, HT_DATA_dptr, HT_DATA_dstr);
    ctx->redef = ht_create(ctx, HT_DATA_dstr, HT_DATA_dempty);
    ctx->tuple_abbrev = ht_create(ctx, HT_DATA_dstr, HT_DATA_dstr);
    ctx->tmp = talloc_new(ctx);
    prelude(ctx);
    struct optimize_settings opt = OPTIMIZE_DEFAULT;
    opt.opt_inline = true;
    unit_optimize(unit, &opt);
    for (int n = 0; n < unit->fn_decls_count; n++) {
        struct ir_fn_decl *fn = unit->fn_decls[n];
        gen_fn(ctx, fn->body, link_name(ctx, fn->name), fn->name.visible);
    }
    talloc_free(ctx);
}
