// type checking and codegen

#include <stdbool.h>
#include <assert.h>
#include "talloc.h"
#include "union.h"
#include "ast.h"
#include "ir.h"

enum CR_type {
    CR_error,
    CR_cvoid,
    CR_val,
    CR_val_lvalue,
    CR_var,
    CR_fn,
    CR_compound_lit,
};

struct comp_result {
    enum CR_type type;
    union {
        struct ir_inst *val;
        struct ir_inst *val_lvalue;     // val contains a ptr, *ptr is lvalue
        struct ir_var *var;             // direct reference to a local var
        struct ir_type type;
        struct ir_fn_decl *fn;
        struct compound_lit *compound_lit;      // {...} literal/initializer
    } u;
};

typedef struct comp_result CR;

#define MAKE_CR(name, ...) \
    (CR) MAKE_UNION(CR, name, __VA_ARGS__)

#define MAKE_CR_ERROR \
    (CR) MAKE_UNION0(CR, error)

#define MAKE_CR_VOID \
    (CR) MAKE_UNION0(CR, cvoid)

struct ir_context {
    bool error_flag;
    struct ir_unit *unit;
    struct ir_types *types;
    // Current function being compiled. (NULL if not in function.)
    struct ir_function *fn;
    // Currently available local variables (variables going out of scope are
    // removed).
    struct ir_scope *local_scope;
    // Namespace for labels (a global namespace for each function).
    struct ir_scope *label_scope;
    // Where to append instructions. If the callee branches, it must change it
    // to the new BB.
    struct ir_bb *bb;
    // Basically whether return can be used. Expressions have an implicit
    // return, while non-void functions require an explicit return.
    bool compiling_expression;
};

typedef struct ir_context CTX;

// only temporary during compilation
struct ir_label {
    source_pos loc;
    char *name;
    bool defined;       // is false while it's being forward-referenced
    struct ir_bb *bb;
};

static struct ir_function *compile_function(struct ir_unit *unit,
                                            struct ir_function *parent,
                                            struct ir_fn_type *type,
                                            struct ir_scope *base_scope,
                                            struct ast_node *ast);
static CR cg_assign_to(CTX *ctx, LOC loc, struct ast_node *assign_to,
                       CR assign_from);
static struct ir_type cg_type_expression(CTX *ctx, struct ast_node *ast);

static struct ir_inst *bb_add_error(struct ir_bb *bb)
{
    return BB_ADD_INST(bb, (source_pos) {0}, IR_OP_ERROR, TYPE_ERROR);
}

static void cg_compile_error(CTX *ctx, LOC loc, const char *msg, ...)
{
    va_list va;
    va_start(va, msg);

    char *sloc = source_pos_string(loc);
    fprintf(stderr, "Error at %s: ", sloc);
    talloc_free(sloc);
    vfprintf(stderr, msg, va);
    fprintf(stderr, "\n");

    va_end(va);

    ctx->error_flag = true;
}

static struct ir_type common_type(CTX *ctx, LOC loc, struct ir_type t1,
                                  struct ir_type t2)
{
    struct ir_type t = type_common(t1, t2);
    if (t.type == IR_TYPE_error)
        cg_compile_error(ctx, loc, "no common type");
    return t;
}

static struct ir_inst *cg_cast(CTX *ctx, LOC loc, struct ir_inst *val,
                               struct ir_type to)
{
    if (type_equals(val->result_type, to))
        return val;
    if (type_is_typed_ptr(val->result_type))
        val = bb_add_unop(ctx->bb, loc, IR_OP_CONV_TO_G_PTR, TYPE_G_PTR, val);
    if (type_is_integer(val->result_type) && type_is_integer(to)) {
        bool from_sign = type_get_sign(val->result_type);
        bool to_sign = type_get_sign(to);
        int from_bits = type_get_bits(val->result_type);
        int to_bits = type_get_bits(to);
        if (from_bits > to_bits) {
            val = bb_add_unop(ctx->bb, loc, IR_OP_CONV_INT_TRUNC,
                              type_integer(from_sign, to_bits), val);
        } else if (from_bits < to_bits) {
            val = bb_add_unop(ctx->bb, loc, IR_OP_CONV_INT_EXT,
                              type_integer(from_sign, to_bits), val);
        }
        if (from_sign != to_sign)
            val = bb_add_unop(ctx->bb, loc, IR_OP_CONV_INT_SIGN, to, val);
    }
    if (type_is_ptr(to) && type_is_untyped_ptr(val->result_type))
        val = bb_add_unop(ctx->bb, loc, IR_OP_CONV_FROM_G_PTR, to, val);
    assert(type_equals(val->result_type, to));
    return val;
}

static struct ir_inst *cg_implicit_conversion(CTX *ctx, LOC loc,
                                              struct ir_inst *val,
                                              struct ir_type to)
{
    if (!type_implicitly_convertible(val->result_type, to)) {
        cg_compile_error(ctx, loc, "conversion not possible from %s to %s",
                         type_str(ctx, val->result_type),
                         type_str(ctx, to));
        return bb_add_error(ctx->bb);
    }
    return cg_cast(ctx, loc, val, to);
}

static void cg_push_scope(CTX *ctx)
{
    struct ir_scope *nscope = talloc_zero(NULL, struct ir_scope);
    nscope->next = ctx->local_scope;
    ctx->local_scope = nscope;
}

static void cg_pop_scope(CTX *ctx)
{
    struct ir_scope *oldscope = ctx->local_scope;
    ctx->local_scope = oldscope->next;
    talloc_free(oldscope);
}

static struct ir_inst *cg_const(CTX *ctx, LOC loc, struct ir_const_val c)
{
    return BB_ADD_INST(ctx->bb, loc, IR_OP_LOAD_CONST, c.type,
                       .const_value = &c);
}

static struct ir_inst *cg_init(CTX *ctx, LOC loc, struct ir_type t)
{
    return cg_const(ctx, loc, type_init_value(t));
}

static struct ir_inst *cg_void(CTX *ctx, LOC loc)
{
    return cg_init(ctx, loc, ctx->types->tvoid);
}

static struct ir_inst *cg_string(CTX *ctx, LOC loc, char *s)
{
    assert(s);
    return cg_const(ctx, loc, (struct ir_const_val) {
        .type = TYPE_STRING,
        .value = MAKE_UNION(VALUE, vstring, s),
    });
}

static bool cg_require_complete_type(CTX *ctx, LOC loc, struct ir_type type)
{
    if (type_is_complete(type))
        return true;
    cg_compile_error(ctx, loc, "incomplete type");
    return false;
}

static CR cg_expression(CTX *ctx, struct ast_node *ast);

// A return value of NULL means a void value is returned.
static struct ir_inst *cg_cr_to_val_maybe(CTX *ctx, LOC loc, CR cr,
                                          struct ir_type type_hint)
{
    switch (cr.type) {
        case CR_val: return *GET_UNION(CR, val, &cr);
        case CR_val_lvalue: {
            struct ir_inst *ptr = *GET_UNION(CR, val_lvalue, &cr);
            return bb_add_unop(ctx->bb, loc, IR_OP_READ_PTR,
                               type_unptr(ptr->result_type), ptr);
        }
        case CR_var: {
            struct ir_var *var = *GET_UNION(CR, var, &cr);
            return bb_add_unop(ctx->bb, loc, IR_OP_READ_PTR, var->type,
                               BB_ADD_INST(ctx->bb, loc, IR_OP_VAR_PTR,
                                           var->ptr_type, .var = var));
        }
        case CR_cvoid:
            return NULL;
        default:
            cg_compile_error(ctx, loc, "expression expected");
            return bb_add_error(ctx->bb);
    }
}

static struct ir_inst *cg_cr_to_val(CTX *ctx, LOC loc, CR cr,
                                    struct ir_type type_hint)
{
    struct ir_inst *in = cg_cr_to_val_maybe(ctx, loc, cr, type_hint);
    return in ? in : cg_void(ctx, loc);
}

static struct ir_inst *cg_to_val(CTX *ctx, struct ast_node *ast,
                                 struct ir_type type_hint)
{
    return cg_cr_to_val(ctx, ast_get_loc(ast), cg_expression(ctx, ast),
                        type_hint);
}

static struct ir_inst *cg_cr_to_lvalue_ptr(CTX *ctx, LOC loc, CR cr)
{
    switch (cr.type) {
        case CR_val_lvalue: return *GET_UNION(CR, val_lvalue, &cr);
        case CR_var: {
            struct ir_var *var = *GET_UNION(CR, var, &cr);
            return BB_ADD_INST(ctx->bb, loc, IR_OP_VAR_PTR, var->ptr_type,
                               .var = var);
        }
        default:
            cg_compile_error(ctx, loc, "lvalue expected");
            return bb_add_error(ctx->bb);
    }
}

static struct ir_inst *cg_to_lvalue_ptr(CTX *ctx, struct ast_node *ast)
{
    return cg_cr_to_lvalue_ptr(ctx, ast_get_loc(ast), cg_expression(ctx, ast));
}

static struct ir_const_val *cg_to_const(CTX *ctx, struct ir_type t,
                                        struct ast_node *ast)
{
    // xxx this is a hack to be able to use certain things before the
    //     interpreter is done (which is a piece of work)
    if (!TEST_UNION(AST, lit, ast)) {
        // implement and use interpreter
        assert(false);
    }
    // extremely hacky and semantically incomplete code, perhaps incorrect
    struct ast_lit *ast_lit = GET_UNION(AST, lit, ast);
    struct lex_const lit = ast_lit->lit;
    assert(lit.type == LEX_CONST_cint);
    //struct ir_type lit_t = type_from_value(val);
    // fuck the police
    return talloc_struct(NULL, struct ir_const_val, {
        .type = t,
        .value = MAKE_UNION(VALUE, vuint64, lit.u.cint.val),
    });
}

static int cg_to_const_idx(CTX *ctx, struct ast_node *ast)
{
    struct ir_const_val *v = cg_to_const(ctx, ctx->types->index, ast);
    // xxx maybe do bounds check
    int res = *GET_UNION(VALUE, vuint64, &v->value);
    talloc_free(v);
    return res;
}

static struct ir_inst *cg_coerce_bool(CTX *ctx, LOC loc, struct ir_inst *in)
{
    // we compare with the init value to convert to bool
    struct ir_type t = in->result_type;
    if (t.type != IR_TYPE_tbool) {
        // NOTE: must also match what IR_OP_NOT_EQ supports
        // See @COMPARABLE
        if (!type_is_integer(t) && !type_is_fp(t) && !type_is_ptr(t))
            cg_compile_error(ctx, loc, "bool coercion not supported for '%s'",
                             type_str(ctx, t));
        return bb_add_binop(ctx->bb, loc, IR_OP_NOT_EQ, TYPE_BOOL, in,
                            cg_init(ctx, loc, t));
    }
    return in;
}

static struct ir_inst *cg_to_bool_coerce(CTX *ctx, struct ast_node *e)
{
    return cg_coerce_bool(ctx, ast_get_loc(e), cg_to_val(ctx, e, TYPE_ANY));
}

static CR cg_scope_expr(CTX *ctx, struct ast_node *e)
{
    CR cr;
    cg_push_scope(ctx);
    cr = cg_expression(ctx, e);
    cg_pop_scope(ctx);
    return cr;
}

static struct ir_label *lookup_label(CTX *ctx, char *label)
{
    struct ast_sym *sym = scope_lookup(ctx->label_scope, label);
    if (!sym)
        return NULL;
    // only labels can be in this NS
    return *GET_UNION(AST_SYM, label, sym);
}

static struct ir_bb *cg_ref_label(CTX *ctx, LOC loc, char *label)
{
    struct ir_label *l = lookup_label(ctx, label);
    if (!l) {
        l = talloc_struct(ctx->label_scope, struct ir_label, {
            .name = label, .loc = loc, .defined = false,
            .bb = fn_add_bb(ctx->fn)
        });
        scope_add(ctx->label_scope, label,
                  (struct ast_sym) MAKE_UNION(AST_SYM, label, l));
    }
    return l->bb;
}

static void cg_goto_label(CTX *ctx, LOC loc, char *label)
{
    bb_add_jump(ctx->bb, loc, cg_ref_label(ctx, loc, label));
    ctx->bb = fn_add_bb(ctx->fn);
}

static void cg_label(CTX *ctx, LOC loc, char *label)
{
    struct ir_bb *bb = fn_add_bb(ctx->fn);
    struct ir_label *l = lookup_label(ctx, label);
    if (l) {
        if (l->defined) {
            cg_compile_error(ctx, loc, "label '%s' already defined", label);
            return;
        }
        // This was a forward reference - fix it.
        bb_add_jump(l->bb, loc, bb);
    } else {
        l = talloc_zero(ctx->label_scope, struct ir_label);
        scope_add(ctx->label_scope, label,
                  (struct ast_sym) MAKE_UNION(AST_SYM, label, l));
    }
    *l = (struct ir_label) {
        .name = label,
        .loc = loc,
        .bb = bb,
        .defined = true,
    };
    // Split current bb such that the label jumps inside the instruction stream.
    bb_add_jump(ctx->bb, loc, l->bb);
    ctx->bb = l->bb;
}

// Verifies that all referenced labels have actually been defined.
static void cg_finalize_labels(CTX *ctx)
{
    struct ir_scope *scope = ctx->label_scope;
    for (int n = 0; n < scope->entries_count; n++) {
        struct ir_label *l = *GET_UNION(AST_SYM, label, &scope->entries[n].sym);
        if (!l->defined)
            cg_compile_error(ctx, l->loc, "label '%s' referenced, but not "
                             "defined", l->name);
    }
}

// Caller is responsible for possibly splitting the BB.
static void cg_insert_return(CTX *ctx, LOC loc, struct ir_inst *ex)
{
    struct ir_type fn_res = ctx->fn->type->ret_type;
    ex = cg_implicit_conversion(ctx, loc, ex, fn_res);
    bb_add_nt_unop(ctx->bb, loc, IR_OP_RET, ex);
}

static CR cg_if(CTX *ctx, LOC loc, struct ast_node *cond, struct ast_node *yes,
                struct ast_node *no)
{
    struct ir_inst *cond_var = cg_to_bool_coerce(ctx, cond);
    struct ir_bb *yes_code = fn_add_bb(ctx->fn);
    struct ir_bb *no_code = no ? fn_add_bb(ctx->fn) : NULL;
    struct ir_bb *past_code = fn_add_bb(ctx->fn);
    bb_add_branch(ctx->bb, loc, cond_var, no_code ? no_code : past_code,
                  yes_code);
    ctx->bb = yes_code;
    cg_scope_expr(ctx, yes);
    bb_add_jump(ctx->bb, loc, past_code);
    if (no_code) {
        ctx->bb = no_code;
        cg_scope_expr(ctx, no);
        bb_add_jump(ctx->bb, loc, past_code);
    }
    ctx->bb = past_code;
    return MAKE_CR_VOID;
}

static CR cg_functional_if(CTX *ctx, LOC loc, struct ast_node *cond,
                           struct ast_node *yes, struct ast_node *no)
{
    struct ir_inst *cond_val = cg_to_bool_coerce(ctx, cond);
    struct ir_bb *yes_code = fn_add_bb(ctx->fn);
    struct ir_bb *no_code = no ? fn_add_bb(ctx->fn) : NULL;
    struct ir_bb *past_code = fn_add_bb(ctx->fn);
    bb_add_branch(ctx->bb, loc, cond_val, no_code, yes_code);
    // Very annoying: since semantics and codegen are done at the same time,
    // we must do this in 2 phases: 1. generate code, 2. do type conversions
    // yes:
    ctx->bb = yes_code;
    struct ir_inst *yes_v = cg_cr_to_val(ctx, loc, cg_scope_expr(ctx, yes),
                                         TYPE_ANY);
    // no:
    ctx->bb = no_code;
    struct ir_inst *no_v = cg_cr_to_val(ctx, loc, cg_scope_expr(ctx, no),
                                        TYPE_ANY);
    // common type:
    struct ir_type t = common_type(ctx, loc, yes_v->result_type,
                                   no_v->result_type);
    // yes:
    ctx->bb = yes_v->bb;
    yes_v = cg_implicit_conversion(ctx, loc, yes_v, t);
    bb_add_jump(ctx->bb, loc, past_code);
    // no:
    ctx->bb = no_v->bb;
    no_v = cg_implicit_conversion(ctx, loc, no_v, t);
    bb_add_jump(ctx->bb, loc, past_code);
    // done
    ctx->bb = past_code;
    return MAKE_CR(val, bb_add_binop(ctx->bb, loc, IR_OP_PHI, t, yes_v, no_v));
}

static CR cg_logical_shortcut_op(CTX *ctx, LOC loc, struct ast_node *e1,
                                 struct ast_node *e2, bool is_and)
{
    struct ir_inst *cond1 = cg_to_bool_coerce(ctx, e1);
    struct ir_bb *more_code = fn_add_bb(ctx->fn);
    struct ir_bb *end_code = fn_add_bb(ctx->fn);
    bb_add_branch(ctx->bb, loc, cond1,
                 is_and ? end_code : more_code,
                 is_and ? more_code : end_code);
    ctx->bb = more_code;
    // new scope in case expr2 contains var definitions etc.
    cg_push_scope(ctx);
    struct ir_inst *cond2 = cg_to_bool_coerce(ctx, e2);
    cg_pop_scope(ctx);
    bb_add_jump(ctx->bb, loc, end_code);
    ctx->bb = end_code;
    struct ir_inst *res = bb_add_binop(ctx->bb, loc, IR_OP_PHI,
                                       cond1->result_type, cond1, cond2);
    return MAKE_CR(val, res);
}

static CR cg_while(CTX *ctx, LOC loc, struct ast_node *cond,
                   struct ast_node *body)
{
    cg_push_scope(ctx);
    struct ir_bb *entry_code = fn_add_bb(ctx->fn);
    bb_add_jump(ctx->bb, loc, entry_code);
    ctx->bb = entry_code;
    struct ir_inst *cond_val = cg_to_bool_coerce(ctx, cond);
    struct ir_bb *body_code = fn_add_bb(ctx->fn);
    struct ir_bb *exit_code = fn_add_bb(ctx->fn);
    bb_add_branch(ctx->bb, loc, cond_val, exit_code, body_code);
    ctx->bb = body_code;
    cg_scope_expr(ctx, body);
    bb_add_jump(ctx->bb, loc, entry_code);
    ctx->bb = exit_code;
    cg_pop_scope(ctx);
    return MAKE_CR_VOID;
}

static CR cg_int_literal(CTX *ctx, LOC loc, struct lex_const lc, bool negate)
{
    struct ir_const_val c = const_from_int_lit(lc, negate);
    if (c.type.type != IR_TYPE_error) {
        return MAKE_CR(val, cg_const(ctx, loc, c));
    } else {
        cg_compile_error(ctx, loc, "numeric overflow");
        return MAKE_CR_ERROR;
    }
}

enum {
    BINOP_INT = 1,
    BINOP_BOOL = 2,
    BINOP_FP = 4,
    BINOP_PTR = 8,
    BINOP_BOOLRES = 16,
    // @COMPARABLE
    BINOP_COMPARABLE = BINOP_FP | BINOP_INT | BINOP_BOOL | BINOP_PTR,
    BINOP_NUM = BINOP_FP | BINOP_INT,
};

static bool binop_test_type(struct ir_type t, int flags)
{
    return ((flags & BINOP_INT) && type_is_integer(t))
        || ((flags & BINOP_BOOL) && t.type == IR_TYPE_tbool)
        || ((flags & BINOP_FP) && type_is_fp(t))
        || ((flags & BINOP_PTR) && type_is_ptr(t));
}

static void binop_check_type(CTX *ctx, LOC loc, struct ir_type t, int flags)
{
    if (!binop_test_type(t, flags))
        cg_compile_error(ctx, loc, "unexpected type");
}

static const int un_op_to_ir[UN_OP_END][2] = {
    [UN_OP_NEG] = {IR_OP_NEG, BINOP_NUM},
    [UN_OP_BIN_NOT] = {IR_OP_NOT, BINOP_INT | BINOP_BOOL},
};

static struct ir_inst *cg_to_array(CTX *ctx, LOC loc, CR ex);

static CR cg_unop(CTX *ctx, struct ast_un_op *op)
{
    LOC loc = op->loc;

    switch (op->op) {
        case UN_OP_ADDR: {
            // Dirty hack (or actually the proper way?) to implement "&a[]".
            struct ast_un_op *unop = TEST_UNION(AST, un_op, op->expr);
            if (unop && unop->op == UN_OP_ARRAY) {
                struct ir_inst *slice = cg_to_array(ctx, loc,
                                            cg_expression(ctx, unop->expr));
                struct ir_type item_ptr = type_ptr_to(ctx->types,
                                            type_item_type(slice->result_type));
                return MAKE_CR(val,
                    bb_add_unop(ctx->bb, loc, IR_OP_GET_SLICE_PTR, item_ptr,
                                slice));
            }
            CR crex = cg_expression(ctx, op->expr);
            if (TEST_UNION(CR, fn, &crex)) {
                struct ir_fn_decl *fn = *GET_UNION(CR, fn, &crex);
                struct ir_inst *res = BB_ADD_INST(ctx->bb, loc, IR_OP_FN_PTR,
                                                  MAKE_IR_TYPE(tfn, fn->type),
                                                  .fn = fn);
                if (fn->nested) {
                    struct ir_inst *c =
                        BB_ADD_INST(ctx->bb, loc, IR_OP_UPVAL_CONTEXT,
                                    TYPE_G_PTR, .fn = fn);
                    res = BB_ADD_INST(ctx->bb, loc, IR_OP_MAKE_CLOSURE,
                                      MAKE_IR_TYPE(tstackclosure, fn->type),
                                      INST_R2(res, c));
                }
                return MAKE_CR(val, res);
            }
            // We could allow non-lvalues here, but it would allow taking the
            // address of temporaries. Since there's a danger that this happens
            // unintended, and since C doesn't support that, we don't either.
            struct ir_inst *ex = cg_cr_to_lvalue_ptr(ctx, loc, crex);
            return MAKE_CR(val, ex);
        }
        case UN_OP_PTR: {
            struct ir_inst *ex = cg_to_val(ctx, op->expr, TYPE_ANY);
            if (!type_is_ptr(ex->result_type))
                cg_compile_error(ctx, loc, "pointer expected");
            if (!type_is_complete(type_unptr(ex->result_type)))
                cg_compile_error(ctx, loc, "dereferencing incomplete type");
            return MAKE_CR(val_lvalue, ex);
        }
        case UN_OP_ARRAY: {
            CR ex = cg_expression(ctx, op->expr);
            // xxx must support lvalues, though those work differently
            return MAKE_CR(val, cg_to_array(ctx, loc, ex));
        }
        // These are checked manually elsewhere, in the specific contexts they
        // are allowed to appear.
        case UN_OP_INIT:
        case UN_OP_VARARG:
        case UN_OP_MACRO_UNQUOTE:
        {
            cg_compile_error(ctx, loc, "can't use this here");
            return MAKE_CR_ERROR;
        }
        case UN_OP_ARRAY_LENGTH: {
            struct ir_inst *slice = cg_to_array(ctx, loc,
                                            cg_expression(ctx, op->expr));
            return MAKE_CR(val, bb_add_unop(ctx->bb, loc,
                            IR_OP_GET_SLICE_LENGTH, ctx->types->index, slice));
        }
        case UN_OP_NOT: {
            struct ir_inst *ex = cg_to_bool_coerce(ctx, op->expr);
            return MAKE_CR(val, bb_add_unop(ctx->bb, loc, IR_OP_NOT,
                                            ex->result_type, ex));
        }
    }

    // Some very primitive const-folding. Actually I don't want any AST-level
    // const-folding, but in this case it seems like an absolute necessity.
    if (op->op == UN_OP_NEG && TEST_UNION(AST, lit, op->expr)) {
        struct lex_const lc = GET_UNION(AST, lit, op->expr)->lit;
        if (lc.type == LEX_CONST_cint)
            return cg_int_literal(ctx, op->loc, lc, true);
    }

    if (un_op_to_ir[op->op][0]) {
        int ir_op = un_op_to_ir[op->op][0];
        int flags = un_op_to_ir[op->op][1];

        struct ir_inst *ex = cg_to_val(ctx, op->expr, TYPE_ANY);

        binop_check_type(ctx, loc, ex->result_type, flags);

        struct ir_type res_type = ex->result_type;
        if (flags & BINOP_BOOLRES)
            res_type = TYPE_BOOL;

        return MAKE_CR(val, bb_add_unop(ctx->bb, loc, ir_op, res_type, ex));
    }

    // not reached
    assert(false);
}


// operand type and result type are the same
static const int bin_op_to_ir[BIN_OP_END][2] = {
    // input type == result type, input type always numeric
    [BIN_OP_ADD] = {IR_OP_ADD, BINOP_NUM},
    [BIN_OP_SUB] = {IR_OP_SUB, BINOP_NUM},
    [BIN_OP_MUL] = {IR_OP_MUL, BINOP_NUM},
    [BIN_OP_DIV] = {IR_OP_DIV, BINOP_NUM},
    [BIN_OP_MOD] = {IR_OP_MOD, BINOP_NUM},
    // no floats
    [BIN_OP_SHIFT_R] = {IR_OP_SHIFT_R, BINOP_INT},
    [BIN_OP_SHIFT_L] = {IR_OP_SHIFT_L, BINOP_INT},

    // input type == result type, input type integer or bool
    [BIN_OP_BIT_AND] = {IR_OP_AND, BINOP_INT | BINOP_BOOL},
    [BIN_OP_BIT_OR] = {IR_OP_OR, BINOP_INT | BINOP_BOOL},
    [BIN_OP_BIT_XOR] = {IR_OP_XOR, BINOP_INT | BINOP_BOOL},

    // numeric input types, bool result type
    [BIN_OP_LT] = {IR_OP_CMP_LT, BINOP_NUM | BINOP_BOOLRES},
    [BIN_OP_GT] = {IR_OP_CMP_GT, BINOP_NUM | BINOP_BOOLRES},
    [BIN_OP_LT_EQ] = {IR_OP_CMP_LT_EQ, BINOP_NUM | BINOP_BOOLRES},
    [BIN_OP_GT_EQ] = {IR_OP_CMP_GT_EQ, BINOP_NUM | BINOP_BOOLRES},

    // any input type (except structs, some other complex types), bool result
    [BIN_OP_EQUAL] = {IR_OP_EQ, BINOP_COMPARABLE | BINOP_BOOLRES},
    [BIN_OP_UNEQUAL] = {IR_OP_NOT_EQ, BINOP_COMPARABLE | BINOP_BOOLRES},
};

static bool two_exprs_to_same_type(CTX *ctx, LOC loc,
                                   struct ast_node *e1, struct ast_node *e2,
                                   struct ir_inst **o_ex1,
                                   struct ir_inst **o_ex2)
{
    struct ir_inst *ex1 = cg_to_val(ctx, e1, TYPE_ANY);
    struct ir_inst *ex2 = cg_to_val(ctx, e2, TYPE_ANY);
    struct ir_type t = common_type(ctx, loc, ex1->result_type, ex2->result_type);
    ex1 = cg_implicit_conversion(ctx, loc, ex1, t);
    ex2 = cg_implicit_conversion(ctx, loc, ex2, t);
    *o_ex1 = ex1;
    *o_ex2 = ex2;
    return t.type == IR_TYPE_error;
}

static struct ir_inst *cg_to_array(CTX *ctx, LOC loc, CR ex)
{
    struct ir_inst *v = NULL;
    switch (ex.type) {
        case CR_val: {
            v = cg_cr_to_val(ctx, loc, ex, TYPE_ANY);
            if (TEST_UNION(IR_TYPE, tarray, &v->result_type)) {
                struct ir_array_type *a = *GET_UNION(IR_TYPE, tarray,
                                                     &v->result_type);
                // arrays are value types
                v = inst_spill_to_temp(v);
                v = bb_add_unop(ctx->bb, loc, IR_OP_ARRAY_TO_SLICE,
                                type_slice_to(ctx->types, a->item_type), v);
            }
            break;
        }
        case CR_var:
        case CR_val_lvalue: {
            v = cg_cr_to_lvalue_ptr(ctx, loc, ex);
            struct ir_type t = type_unptr(v->result_type);
            if (TEST_UNION(IR_TYPE, tarray, &t)) {
                struct ir_array_type *a = *GET_UNION(IR_TYPE, tarray, &t);
                v = bb_add_unop(ctx->bb, loc, IR_OP_ARRAY_TO_SLICE,
                                type_slice_to(ctx->types, a->item_type), v);
            } else if (TEST_UNION(IR_TYPE, tslice, &t)) {
                v = bb_add_unop(ctx->bb, loc, IR_OP_READ_PTR, t, v);
            }
            break;
        }
        default:
            break;
    }
    if (!v || !TEST_UNION(IR_TYPE, tslice, &v->result_type)) {
        cg_compile_error(ctx, loc, "array or slice expected");
        return cg_void(ctx, loc);
    }
    return v;
}

static CR cg_binop(CTX *ctx, struct ast_bin_op *op)
{
    LOC loc = op->loc;

    switch (op->op) {
        case BIN_OP_ARRAY: {
            CR ex = cg_expression(ctx, op->expr1);
            // Note that we don't distinguish between rvalues and
            // lvalues, because slices are pointers anyway. Actually
            // we should add something to distinguish rvalue/lvalue for
            // things that are always pointers.
            struct ir_inst *index = cg_to_val(ctx, op->expr2,
                                                TYPE_ANY);
            index = cg_implicit_conversion(ctx, loc, index, ctx->types->index);
            struct ir_inst *v = cg_to_array(ctx, loc, ex);
            struct ir_type elemt = type_item_type(v->result_type);
            return MAKE_CR(val_lvalue,
                bb_add_binop(ctx->bb, loc, IR_OP_GET_SLICE_ITEM_PTR,
                                type_ptr_to(ctx->types, elemt), v, index));
        }
        case BIN_OP_DOT: {
            CR ex = cg_expression(ctx, op->expr1);
            struct ast_id *id = TEST_UNION(AST, id, op->expr2);
            if (!id) {
                cg_compile_error(ctx, loc, "need a name on RHS of '.'");
                return MAKE_CR_ERROR;
            }
            char *member_name = id->id;
            // xxx maybe types should work too; for now restrict to values
            //     (types could be useful for sizeof/offsetof/nested stuff)
            struct ir_inst *v = NULL;
            struct ir_type struct_type = {0};
            bool is_lvalue = false;
            switch (ex.type) {
                case CR_val:
                    v = cg_cr_to_val(ctx, loc, ex, TYPE_ANY);
                    struct_type = v->result_type;
                    break;
                case CR_var:
                case CR_val_lvalue:
                    v = cg_cr_to_lvalue_ptr(ctx, loc, ex);
                    struct_type = type_unptr(v->result_type);
                    is_lvalue = true;
                    break;
                default:
                    cg_compile_error(ctx, loc, "value expected");
                    return MAKE_CR_ERROR;
            }
            struct ir_struct_type **pst = TEST_UNION(IR_TYPE, tstruct,
                                                     &struct_type);
            if (!pst) {
                cg_compile_error(ctx, loc, "need struct type for '.'");
                return MAKE_CR_ERROR;
            }
            struct ir_struct_type *st = *pst;
            if (!st->defined) {
                cg_compile_error(ctx, loc, "accessing incomplete type");
                return MAKE_CR_ERROR;
            }
            struct ast_sym *sym = scope_lookup(st->scope, member_name);
            if (!sym) {
                cg_compile_error(ctx, loc, "member '%s' doesn't exist",
                                 member_name);
                return MAKE_CR_ERROR;
            }
            // (must always succeed, because it's the only symbol type allowed)
            struct ir_struct_member *member
                = *GET_UNION(AST_SYM, struct_member, sym);
            struct ir_type member_type = is_lvalue
                ? type_ptr_to(ctx->types, member->type)
                : member->type;
            int s_op = is_lvalue
                ? IR_OP_GET_STRUCT_MEMBER_PTR
                : IR_OP_GET_STRUCT_MEMBER;
            struct ir_inst *res
                = bb_add_unop(ctx->bb, loc, s_op, member_type, v);
            res->struct_member = member;
            return is_lvalue ? MAKE_CR(val_lvalue, res) : MAKE_CR(val, res);
        }
        case BIN_OP_ASSIGN: {
            return cg_assign_to(ctx, loc, op->expr1,
                                cg_expression(ctx, op->expr2));
        }
        case BIN_OP_INIT: {
            // The code dealing with initializer expressions checks for
            // BIN_OP_INIT manually (makes code simpler).
            cg_compile_error(ctx, loc, "can't use this here");
            return MAKE_CR_ERROR;
        }
        case BIN_OP_AND:
        case BIN_OP_OR:
        {
            return cg_logical_shortcut_op(ctx, loc, op->expr1, op->expr2,
                                          op->op == BIN_OP_AND);
        }
    }

    if (bin_op_to_ir[op->op][0]) {
        int ir_op = bin_op_to_ir[op->op][0];
        int flags = bin_op_to_ir[op->op][1];

        struct ir_inst *ex1, *ex2;
        two_exprs_to_same_type(ctx, loc, op->expr1, op->expr2, &ex1, &ex2);

        struct ir_type arg_type = ex1->result_type;
        binop_check_type(ctx, loc, arg_type, flags);

        struct ir_type res_type = arg_type;
        if (flags & BINOP_BOOLRES)
            res_type = TYPE_BOOL;

        return MAKE_CR(val, bb_add_binop(ctx->bb, loc, ir_op, res_type, ex1,
                                         ex2));
    }

    // not reached
    assert(false);
}

struct compound_lit {
    LOC loc;
    int items_count;
    struct compound_item *items;
    // Number of initial positional arguments, and also the offset for named
    // arguments (items[positional_count] is the first named arg, if existent).
    int positional_count;
};

struct compound_item {
    char *name;
    // may be NULL for skipped items, instead of pointing to a proper "{}"
    struct ir_inst *val;
};

static int lit_find_name(struct compound_lit *lit, char *name)
{
    for (int n = lit->positional_count; n < lit->items_count; n++) {
        if (strcmp(lit->items[n].name, name) == 0)
            return n;
    }
    return -1;
}

static void lit_add_item(CTX *ctx, LOC loc, struct compound_lit *lit, int pos,
                         char *name, struct ir_inst *val)
{
    if (name[0]) {
        int i = lit_find_name(lit, name);
        if (i >= 0) {
            lit->items[i].val = val;
        } else {
            struct compound_item nitem = {name, val};
            BL_TARRAY_APPEND(lit, lit->items, lit->items_count, nitem);
        }
    } else {
        if (pos < 0)
            pos = lit->positional_count;
        // Possibly skip entries. In that case, we must be in an array literal,
        // and all entries have the same type. This means the currently added
        // value's type can be used to retrieve a default value to initialize
        // the skipped parts. (Implies implicitly convertible types have equal
        // default values.)
        // xxx this create useless instructions to get default values, even if
        //     they are not used
        struct ir_inst *init = NULL;
        while (pos + 1 > lit->positional_count) {
            if (!init)
                init = cg_init(ctx, loc, val->result_type);
            struct compound_item skip = {"", init};
            BL_TARRAY_INSERT_AT(lit, lit->items, lit->items_count,
                                lit->positional_count, skip);
            lit->positional_count++;
        }
        lit->items[pos].val = val;
    }
}

static void lit_expand_value(CTX *ctx, LOC exloc, struct compound_lit *lit,
                             struct ir_inst *v)
{
    LOC loc = v->loc;
    struct ir_type vt = v->result_type;
    struct ir_struct_type **pst = TEST_UNION(IR_TYPE, tstruct, &vt);
    if (!pst)
        pst = TEST_UNION(IR_TYPE, ttuple, &vt);
    if (!pst)
        pst = TEST_UNION(IR_TYPE, tcompound, &vt);
    // xxx also allow expansion of arrays
    if (!pst) {
        cg_compile_error(ctx, loc, "struct expected");
        return;
    }
    struct ir_struct_type *st = *pst;
    for (int n = 0; n < st->members_count; n++) {
        struct ir_struct_member *m = st->members[n];
        struct ir_inst *mv = bb_add_unop(ctx->bb, loc, IR_OP_GET_STRUCT_MEMBER,
                                         m->type, v);
        mv->struct_member = m;
        lit_add_item(ctx, exloc, lit, -1, m->name, mv);
    }
}

// Basically generates {<exprs>}, which then can be used for function calls,
// struct/array initializers, tuples, etc.
static struct compound_lit *cg_gen_lit(CTX *ctx, LOC loc, int exprs_count,
                                       struct ast_node **exprs)
{
    struct compound_lit *res = talloc_struct(ctx, struct compound_lit, {loc});

    for (int n = 0; n < exprs_count; n++) {
        struct ast_node *arg = exprs[n];
        char *name = "";
        int pos = -1;
        LOC exloc = ast_get_loc(arg);

        struct ast_un_op *unop = TEST_UNION(AST, un_op, arg);
        if (unop && unop->op == UN_OP_INIT) {
            lit_expand_value(ctx, exloc, res, cg_to_val(ctx, unop->expr, TYPE_ANY));
            continue;
        }

        struct ast_bin_op *binop = TEST_UNION(AST, bin_op, arg);
        if (binop && binop->op == BIN_OP_INIT) {
            struct ast_id *id = TEST_UNION(AST, id, binop->expr1);
            if (!id) {
                cg_compile_error(ctx, ast_get_loc(binop->expr1), "id expected");
                break;
            }
            name = id->id;
            arg = binop->expr2;
        }
        if (binop && binop->op == BIN_OP_INIT_ARRAY) {
            pos = cg_to_const_idx(ctx, binop->expr1);
            arg = binop->expr2;
        }

        lit_add_item(ctx, exloc, res, pos, name,  cg_to_val(ctx, arg, TYPE_ANY));
    }

    return res;
}

// Copy values from lit into params. Generate default values and do error
// checking. The struct is sliced by st_start and st_end. The first struct
// member that counts is st_start, and the last is (st_end - 1).
// That means params must have the length (st_end - st_start).
// If out_remainder is NULL, an error is raised if unused elements are left in
// lit. Otherwise, *out_remainder is set to the index of the first unused
// element. (This is used for varargs.)
static bool lit_fill_for_struct(CTX *ctx, LOC loc, struct compound_lit *lit,
                                struct ir_struct_type *st,
                                int st_start, int st_end,
                                struct ir_use *params,
                                int *out_remainder)
{
    assert(st_end - st_start <= st->members_count);
    struct ir_struct_member **members = st->members + st_start;
    int members_count = st_end - st_start;
    int remainder = -1;
    memset(params, 0, sizeof(struct ir_use) * (st_end - st_start));
    for (int n = 0; n < lit->items_count; n++) {
        struct compound_item *item = &lit->items[n];
        int assign_to = -1;
        if (n < lit->positional_count) {
            assign_to = n;
        } else {
            struct ir_struct_member *m = struct_find_member(st, item->name);
            if (m && m->index >= st_start && m->index < st_end)
                assign_to = m->index - st_start;
        }
        if (assign_to < 0 || assign_to >= members_count) {
            remainder = n;
            break;
        }
        params[assign_to].def = cg_implicit_conversion(ctx, loc, item->val,
                                                      members[assign_to]->type);
    }

    // Set default arguments.
    for (int n = 0; n < members_count; n++) {
        struct ir_struct_member *m = members[n];
        if (!params[n].def) {
            struct ir_inst *val;
            if (m->init) {
                // @LOC_ISSUE
                val = cg_const(ctx, loc, *m->init);
            } else {
                cg_compile_error(ctx, loc, "arg skipped, no default value");
                // xxx should be cg_error or so
                val = cg_void(ctx, loc);
            }
            params[n].def = val;
        }
    }

    if (remainder >= 0) {
        if (out_remainder) {
            *out_remainder = remainder;
        } else {
            // @LOC_ISSUE
            cg_compile_error(ctx, loc, "too many arguments");
        }
    }

    return true;
}

static struct ir_inst *gen_varargs(CTX *ctx, LOC loc, int args_count,
                                   struct compound_item *args)
{
    struct ir_type vt = ctx->types->vararg;
    struct ir_inst *va = INST_NEW(loc, IR_OP_CONSTRUCT_ARRAY,
                                  type_array(ctx->types, vt, args_count),
                                  .read_count = args_count);
    for (int n = 0; n < args_count; n++) {
        struct compound_item *item = &args[n];
        struct ir_inst *ptr = inst_spill_to_temp(item->val);
        ptr = bb_add_unop(ctx->bb, loc, IR_OP_CONV_TO_G_PTR, TYPE_G_PTR, ptr);
        struct ir_inst *name = cg_string(ctx, loc, item->name);
        struct ir_inst *type = cg_string(ctx, loc,
                type_vararg_mangle(ctx->types, item->val->result_type));
        va->read[n].def = BB_ADD_INST(ctx->bb, loc, IR_OP_CONSTRUCT_STRUCT, vt,
                                      INST_R3(ptr, name, type));
    }
    bb_add_inst(ctx->bb, va);
    // Construct the va array on the stack, and return the slice to it.
    return cg_to_array(ctx, loc, MAKE_CR(val, va));
}

static struct ir_inst *gen_call(CTX *ctx, LOC loc, struct ir_fn_type *fn,
                                int args_count, struct ast_node **args,
                                struct ir_inst *read_0, struct ir_inst *arg_0,
                                struct ir_inst call)
{
    bool vararg = fn->vararg != IR_VARARG_NONE;
    bool n_vararg = fn->vararg == IR_VARARG_NATIVE;
    // detect vararg expansion
    struct ast_node *expand_vararg_node = NULL;
    if (n_vararg && args_count) {
        struct ast_node *last = args[args_count - 1];
        if (TEST_UNION(AST, un_op, last)) {
            struct ast_un_op *op = GET_UNION(AST, un_op, last);
            if (op->op == UN_OP_VARARG) {
                args_count--;
                expand_vararg_node = op->expr;
            }
        }
    }
    struct ir_struct_type *st = fn->args;
    struct compound_lit *list = cg_gen_lit(ctx, loc, args_count, args);
    struct ir_inst *expand_vararg = NULL;
    if (expand_vararg_node)
        expand_vararg = cg_to_val(ctx, expand_vararg_node, TYPE_ANY);
    assert(call.read_count == 0);
    struct ir_inst *ncall = inst_dup(&call);
    int offset = read_0 ? 1 : 0;
    int m_offset = offset + (arg_0 ? 1 : 0);
    ncall->read_count = st->members_count + offset;
    ncall->read = talloc_zero_array(ncall, struct ir_use, ncall->read_count);
    if (read_0)
        ncall->read[0].def = read_0;
    if (arg_0)
        ncall->read[offset].def = arg_0;
    int remainder = -1;
    lit_fill_for_struct(ctx, loc, list, st, arg_0 ? 1 : 0,
                        st->members_count - (n_vararg ? 1 : 0),
                        &ncall->read[m_offset], vararg ? &remainder : NULL);
    if (fn->vararg == IR_VARARG_C) {
        if (remainder >= 0) {
            if (remainder < list->items_count - list->positional_count)
                // @LOC_ISSUE
                cg_compile_error(ctx, loc, "can't pass named args to C vararg");
            for (int n = remainder; n < list->items_count; n++) {
                struct ir_inst *val = list->items[n].val;
                if (!val) {
                    cg_compile_error(ctx, loc, "arg skipped or something");
                    break;
                }
                struct ir_use use = {val};
                BL_TARRAY_APPEND(ctx, ncall->read, ncall->read_count, use);
            }
        }
    }
    if (n_vararg) {
        struct ir_inst *vargs = expand_vararg;
        int varargs = remainder >= 0 ? list->items_count - remainder : 0;
        if (vargs) {
            if (varargs)
                cg_compile_error(ctx, loc, "both expanded and normal varargs");
        } else {
            vargs = gen_varargs(ctx, loc, varargs, list->items + remainder);
        }
        ncall->read[ncall->read_count - 1].def = vargs;
    }
    talloc_free(list);
    bb_add_inst(ctx->bb, ncall);
    return ncall;
}

static CR cg_call(CTX *ctx, struct ast_call *call)
{
    LOC loc = call->loc;

    CR crfn = cg_expression(ctx, call->expr);
    if (TEST_UNION(CR, fn, &crfn)) {
        // Direct call (including nested functions).
        struct ir_fn_decl *fn_decl = *GET_UNION(CR, fn, &crfn);
        struct ir_fn_type *fn = fn_decl->type;
        struct ir_inst in = {loc, IR_OP_CALL, fn->ret_type, .fn = fn_decl};
        struct ir_inst *arg_0 = NULL;
        if (fn_decl->nested) {
            arg_0 = BB_ADD_INST(ctx->bb, loc, IR_OP_UPVAL_CONTEXT, TYPE_G_PTR,
                                .fn = fn_decl);
        }
        return MAKE_CR(val, gen_call(ctx, loc, fn, call->args_count, call->args,
                                     NULL, arg_0, in));
    } else {
        // Indirect calls, funcion and closure types.
        struct ir_inst *fn_val = cg_cr_to_val(ctx, loc, crfn, TYPE_ANY);
        struct ir_type t = fn_val->result_type;
        struct ir_inst *arg_0 = NULL;
        struct ir_fn_type *fn;
        if (TEST_UNION(IR_TYPE, tstackclosure, &t)) {
            fn = *GET_UNION(IR_TYPE, tstackclosure, &t);
            arg_0 = BB_ADD_INST(ctx->bb, loc, IR_OP_GET_CLOSURE_CTX, TYPE_G_PTR,
                                INST_R1(fn_val));
            fn_val = BB_ADD_INST(ctx->bb, loc, IR_OP_GET_CLOSURE_FN,
                                 MAKE_IR_TYPE(tfn, fn), INST_R1(fn_val));
        } else if (TEST_UNION(IR_TYPE, tfn, &t)) {
            fn = *GET_UNION(IR_TYPE, tfn, &t);
        } else {
            cg_compile_error(ctx, loc, "function expected");
            return MAKE_CR_ERROR;
        }
        struct ir_inst in = {loc, IR_OP_CALL_PTR, fn->ret_type};
        return MAKE_CR(val, gen_call(ctx, loc, fn, call->args_count, call->args,
                                     fn_val, arg_0, in));
    }
    assert(false);
}

static struct ir_inst *gen_struct_lit(CTX *ctx, struct ir_struct_type *st,
                                      struct compound_lit *list)
{
    LOC loc = list->loc;
    struct ir_type type = MAKE_IR_TYPE(tstruct, st);
    struct ir_inst *in = INST_NEW(loc, IR_OP_CONSTRUCT_STRUCT, type,
                                  .read_count = st->members_count);
    lit_fill_for_struct(ctx, loc, list, st, 0, in->read_count, in->read, NULL);
    bb_add_inst(ctx->bb, in);
    return in;
}

// dimension == -1 means it's unlimited, and will result in a slice type
// (also means the semantics are slightly different from C, and maybe confusing)
static struct ir_inst *gen_array_lit(CTX *ctx, struct ir_type item_type,
                                     int dimension, struct compound_lit *list)
{
    LOC loc = list->loc;
    if (list->positional_count < list->items_count) {
        cg_compile_error(ctx, loc, "array literals can't contain named items");
        return bb_add_error(ctx->bb);
    }
    bool is_slice = dimension < 0;
    if (!is_slice && list->items_count > dimension) {
        cg_compile_error(ctx, loc, "array type has %d elements, but "
            "initializer provides %d items", dimension, list->items_count);
        return bb_add_error(ctx->bb);
    }
    if (is_slice)
        dimension = list->items_count;
    struct ir_type arr_type = type_array(ctx->types, item_type, dimension);
    struct ir_inst *in = INST_NEW(loc, IR_OP_CONSTRUCT_ARRAY, arr_type,
                                  .read_count = dimension);
    for (int n = 0; n < list->items_count; n++) {
        struct ir_inst *v = list->items[n].val;
        in->read[n].def = cg_implicit_conversion(ctx, v->loc, v, item_type);
    }
    for (int n = list->items_count; n < dimension; n++) {
        in->read[n].def = cg_init(ctx, loc, item_type);
    }
    bb_add_inst(ctx->bb, in);
    if (is_slice) {
        // Against C semantics: result is not an array, but a slice.
        struct ir_inst *p = inst_spill_to_temp(in);
        in = bb_add_unop(ctx->bb, in->loc, IR_OP_ARRAY_TO_SLICE,
                         type_slice_to(ctx->types, item_type), p);
    }
    return in;
}

static CR cg_struct_lit(CTX *ctx, struct ast_struct_lit *lit)
{
    LOC loc = lit->loc;
    struct compound_lit *list = cg_gen_lit(ctx, loc, lit->exprs_count,
                                           lit->exprs);
    struct ir_type type = cg_type_expression(ctx, lit->type);
    if (!cg_require_complete_type(ctx, loc, type))
        return MAKE_CR_ERROR;
    struct ir_inst *val = NULL;
    if (TEST_UNION(IR_TYPE, tstruct, &type)) {
        val = gen_struct_lit(ctx, *GET_UNION(IR_TYPE, tstruct, &type), list);
    } else if (TEST_UNION(IR_TYPE, tarray, &type)) {
        val = gen_array_lit(ctx, type_item_type(type),
                            type_array_get_dimension(type), list);
    } else if (TEST_UNION(IR_TYPE, tslice, &type)) {
        val = gen_array_lit(ctx, type_item_type(type), -1, list);
    }
    talloc_free(list);
    if (!val) {
        cg_compile_error(ctx, ast_get_loc(lit->type),
                         "not a type that can be in a something-literal");
        return MAKE_CR_ERROR;
    }
    // These literals are lvalues in C, so we do the same.
    return MAKE_CR(val_lvalue, inst_spill_to_temp(val));
}

static CR cg_tuple(CTX *ctx, LOC loc, int exprs_count, struct ast_node **exprs)
{
    struct compound_lit *list = cg_gen_lit(ctx, loc, exprs_count, exprs);
    if (list->positional_count < list->items_count) {
        cg_compile_error(ctx, loc, "tuple literals can't contain named items");
        return MAKE_CR_ERROR;
    }
    struct ir_inst *in = INST_NEW(loc, IR_OP_CONSTRUCT_STRUCT,
                                  .read_count = list->items_count);
    struct ir_struct_type *st = struct_start(ctx->types, loc);
    for (int n = 0; n < list->items_count; n++) {
        struct ir_inst *val = list->items[n].val;
        cg_require_complete_type(ctx, val->loc, val->result_type);
        struct_add(st, val->loc, "", val->result_type, NULL);
        in->read[n].def = val;
    }
    struct_end(st, true);
    in->result_type = MAKE_IR_TYPE(ttuple, st);
    bb_add_inst(ctx->bb, in);
    return MAKE_CR(val, in);
}

static struct ir_type cg_type_tuple(CTX *ctx, LOC loc, int exprs_count,
                                    struct ast_node **exprs)
{
    // xxx: add tuple expansion
    struct ir_struct_type *st = struct_start(ctx->types, loc);
    for (int n = 0; n < exprs_count; n++) {
        LOC tloc = ast_get_loc(exprs[n]);
        struct ir_type t = cg_type_expression(ctx, exprs[n]);
        cg_require_complete_type(ctx, tloc, t);
        struct_add(st, tloc, "", t, NULL);
    }
    struct_end(st, true);
    return MAKE_IR_TYPE(ttuple, st);
}

static void set_struct_members(CTX *ctx, struct ir_struct_type *st,
                               struct ast_struct_body *body)
{
    assert(!st->defined);
    assert(!st->init);
    for (int n = 0; n < body->members_count; n++) {
        struct ast_struct_member m = body->members[n];
        if (m.name && m.name[0] && scope_lookup(st->scope, m.name)) {
            cg_compile_error(ctx, m.loc, "member already defined");
            return;
        }
        struct ir_type t = cg_type_expression(ctx, m.type);
        struct ir_const_val *init = NULL;
        if (m.init)
            init = cg_to_const(ctx, t, m.init);
        cg_require_complete_type(ctx, m.loc, t);
        struct_add(st, m.loc, m.name, t, init);
    }
}

static void cg_struct(CTX *ctx, struct ast_struct_ *struct_)
{
    LOC loc = struct_->loc;
    struct ast_sym *prev_sym = scope_lookup(ctx->local_scope, struct_->name);
    struct ir_struct_type *def = NULL;
    if (prev_sym) {
        if (!TEST_UNION(AST_SYM, type, prev_sym)) {
            cg_compile_error(ctx, loc, "identifier '%s' already "
                             "defined", struct_->name);
            return;
        }
        struct ir_type *prev_struct_type = GET_UNION(AST_SYM, type, prev_sym);
        if (!TEST_UNION(IR_TYPE, tstruct, prev_struct_type)) {
            cg_compile_error(ctx, loc, "identifier '%s' redefined "
                             "as different type", struct_->name);
            return;
        }
        def = *GET_UNION(IR_TYPE, tstruct, prev_struct_type);
    } else {
        def = talloc_struct(ctx->types, struct ir_struct_type, {
            .loc = loc,
            .name = struct_->name,
            .defined = false,
        });
        scope_add(ctx->local_scope, def->name,
            (struct ast_sym) MAKE_UNION(AST_SYM, type,
                MAKE_UNION(IR_TYPE, tstruct, def)));
    }
    // forward-declaration
    if (!struct_->body)
        return;
    if (def->defined) {
        cg_compile_error(ctx, loc, "struct already defined");
        return;
    }
    // proper definition
    def->loc = loc;
    assert(!def->scope);
    def->scope = talloc_struct(def, struct ir_scope, {0});
    set_struct_members(ctx, def, struct_->body);
    struct_end(def, true);
}

static struct ir_fn_type *fn_signature_to_type(CTX *ctx, bool nested,
                                               struct ast_fn_signature sig)
{
    struct ir_fn_type *fn = talloc_struct(ctx->types, struct ir_fn_type,
                                          { .loc = sig.loc });
    fn->args = struct_start(ctx->types, sig.loc);
    if (nested)
        struct_add(fn->args, sig.loc, "", TYPE_G_PTR, NULL);
    set_struct_members(ctx, fn->args, &sig.params);
    if (sig.is_vararg)
        fn->vararg = sig.is_c ? IR_VARARG_C : IR_VARARG_NATIVE;
    if (fn->vararg == IR_VARARG_NATIVE)
        struct_add(fn->args, sig.loc, "_varargs_", ctx->types->varargs,
                   NULL);
    struct_end(fn->args, false);
    talloc_steal(fn, fn->args); //???
    fn->ret_type = cg_type_expression(ctx, sig.ret_type);
    return fn;
}

static void cg_fn(CTX *ctx, struct ast_fn *fn)
{
    LOC loc = fn->loc;
    struct ast_sym *prev_sym = scope_lookup(ctx->local_scope, fn->name);
    bool nested = !fn->sig.is_c;
    struct ir_fn_type *fnt = fn_signature_to_type(ctx, nested, fn->sig);
    struct ir_fn_decl *def = NULL;
    if (prev_sym) {
        if (!TEST_UNION(AST_SYM, fn_decl, prev_sym)) {
            cg_compile_error(ctx, loc, "identifier '%s' already "
                             "defined", fn->name);
            return;
        }
        def = *GET_UNION(AST_SYM, fn_decl, prev_sym);
        // xxx check other aspects, like linkage, nestedness, and C-ness
        //     also, check scope of redefinition
        if (!fn_type_equals(def->type, fnt) || def->nested != nested)
        {
            cg_compile_error(ctx, loc, "incompatible redeclaration");
            return;
        }
    } else {
        def = talloc_struct(ctx->types, struct ir_fn_decl, {
            .loc = loc,
            .nested = nested,
            .name = {fn->name, .visible = true, .is_c = fn->sig.is_c},
        });
        scope_add(ctx->local_scope, fn->name,
            (struct ast_sym) MAKE_UNION(AST_SYM, fn_decl, def));
    }
    // Use the parameter names and default arguments of the last declaration
    // before the proper definition.
    if (!def->body)
        def->type = fnt;
    assert(def->type);
    // forward-declaration
    if (!fn->body)
        return;
    if (def->body) {
        cg_compile_error(ctx, loc, "function already defined");
        return;
    }

    def->body = compile_function(ctx->unit, ctx->fn, fnt, ctx->local_scope,
                                 fn->body);
    if (!def->body)
        cg_compile_error(ctx, loc, "nested function failed");
    // xxx
    //dump_fn(stdout, def->body);
}

static void cg_assign_var(CTX *ctx, LOC loc, struct ir_var *var,
                          struct ir_inst *value)
{
    struct ir_inst *ptr = cg_cr_to_lvalue_ptr(ctx, loc, MAKE_CR(var, var));
    bb_add_nt_binop(ctx->bb, loc, IR_OP_WRITE_PTR, ptr, value);
}

static CR cg_get_upvalue(CTX *ctx, LOC loc, struct ir_var *v)
{
    assert(v->fn != ctx->fn);
    if (!fn_can_access_upval(ctx->fn, v)) {
        // when does this happen anyway?
        cg_compile_error(ctx, loc, "can't access upvalue");
        return MAKE_CR_ERROR;
    }
    return MAKE_CR(val_lvalue, BB_ADD_INST(ctx->bb, loc, IR_OP_UPVAL_PTR,
                                           v->ptr_type, .var = v));
}

static CR cg_assign_to(CTX *ctx, LOC loc, struct ast_node *assign_to,
                       CR assign_from)
{
    // xxx convert to rvalue only
    struct ir_inst *value = cg_cr_to_val(ctx, loc, assign_from, TYPE_ANY);
    switch (assign_to->type) {
        case AST_tuple: {
            //- flatten
            //- cross-check with assign_from type
            assert(false);
        }
        default: {
            // normal assign
            struct ir_inst *lval = cg_to_lvalue_ptr(ctx, assign_to);
            value = cg_implicit_conversion(ctx, loc, value,
                                           type_unptr(lval->result_type));
            bb_add_nt_binop(ctx->bb, loc, IR_OP_WRITE_PTR, lval, value);
            return MAKE_CR(val_lvalue, lval);
        }
    }
}

static struct ir_type cg_type_expression(CTX *ctx, struct ast_node *ast)
{
    LOC loc = ast_get_loc(ast);

    switch (ast->type) {
        case AST_id: {
            struct ast_id *id = GET_UNION(AST, id, ast);
            struct ast_sym *sym = scope_lookup(ctx->local_scope, id->id);
            if (!sym) {
                cg_compile_error(ctx, loc, "identifier '%s' not defined",
                                 id->id);
                return TYPE_ERROR;
            }
            switch (sym->type) {
                case AST_SYM_type:
                    return *GET_UNION(AST_SYM, type, sym);
                default:
                    goto type_expected;
            }
        }
        case AST_tuple: {
            struct ast_tuple *tp = GET_UNION(AST, tuple, ast);
            return cg_type_tuple(ctx, loc, tp->exprs_count, tp->exprs);
        }
        case AST_un_op: {
            struct ast_un_op *op = GET_UNION(AST, un_op, ast);
            switch (op->op) {
                case UN_OP_PTR:
                    return type_ptr_to(ctx->types,
                                       cg_type_expression(ctx, op->expr));
                case UN_OP_ARRAY:
                    return type_slice_to(ctx->types,
                                         cg_type_expression(ctx, op->expr));
                default:
                    goto type_expected;
            }
        }
        case AST_bin_op: {
            struct ast_bin_op *op = GET_UNION(AST, bin_op, ast);
            switch (op->op) {
                case BIN_OP_ARRAY: {
                    struct ir_type t = cg_type_expression(ctx, op->expr1);
                    int dim = cg_to_const_idx(ctx, op->expr2);
                    return type_array(ctx->types, t, dim);
                }
                default:
                    goto type_expected;
            }
        }
        case AST_fn_type: {
            struct ast_fn_type *fn = GET_UNION(AST, fn_type, ast);
            struct ir_fn_type *fnt = fn_signature_to_type(ctx, false, fn->sig);
            return MAKE_IR_TYPE(tfn, fnt);
        }
        case AST_stackclosure_type: {
            struct ast_stackclosure_type *sc
                = GET_UNION(AST, stackclosure_type, ast);
            struct ir_fn_type *fnt = fn_signature_to_type(ctx, true, sc->sig);
            return MAKE_IR_TYPE(tstackclosure, fnt);
        }
        default:
            goto type_expected;
    }

type_expected:
    cg_compile_error(ctx, loc, "type expected, got value or other");
    return TYPE_ERROR;
}

static CR cg_expression(CTX *ctx, struct ast_node *ast)
{
    LOC loc = ast_get_loc(ast);

    switch (ast->type) {
        case AST_id: {
            struct ast_id *id = GET_UNION(AST, id, ast);
            // xxx: global variables
            //      in case of CTFE: const stuff?
            struct ast_sym *sym = scope_lookup(ctx->local_scope, id->id);
            if (!sym) {
                cg_compile_error(ctx, loc, "identifier '%s' not defined",
                                 id->id);
                return MAKE_CR_ERROR;
            }
            // @ALL ast_sym_type
            switch (sym->type) {
                case AST_SYM_var: {
                    struct ir_var *v = *GET_UNION(AST_SYM, var, sym);
                    if (v->fn == ctx->fn) {
                        return MAKE_CR(var, v);
                    } else {
                        return cg_get_upvalue(ctx, loc, v);
                    }
                }
                case AST_SYM_type:
                    cg_compile_error(ctx, loc, "value, not type expected");
                    return MAKE_CR_ERROR;
                case AST_SYM_const_:
                    return MAKE_CR(val, cg_const(ctx, loc,
                              **GET_UNION(AST_SYM, const_, sym)));
                case AST_SYM_label:
                case AST_SYM_struct_member:
                    // these are in different namespaces
                    assert(false);
                case AST_SYM_fn_decl:
                    return MAKE_CR(fn, *GET_UNION(AST_SYM, fn_decl, sym));
                default: assert(false);
            }
        }
        case AST_var: {
            struct ast_var *var = GET_UNION(AST, var, ast);
            // xxx allow shadowing out-of-function stuff (e.g. global variables)
            if (scope_lookup(ctx->local_scope, var->name)) {
                cg_compile_error(ctx, loc,
                        "variable '%s' already defined", var->name);
                return MAKE_CR_ERROR;
            }
            if (!var->type && !var->init) {
                cg_compile_error(ctx, loc, "need type or init expression");
                return MAKE_CR_ERROR;
            }
            struct ir_type type = TYPE_ANY;
            if (var->type)
                type = cg_type_expression(ctx, var->type);
            struct ir_inst *init = NULL;
            if (var->init)
                init = cg_to_val(ctx, var->init, type);
            // (lol type inferrence, D/C++11 "auto" is so great)
            if (!var->type)
                type = init->result_type;
            cg_require_complete_type(ctx, loc, type);
            struct ir_var *nvar = fn_add_var(ctx->fn, loc, type);
            nvar->name = var->name;
            if (var->init) {
                init = cg_implicit_conversion(ctx, loc, init, type);
            } else {
                // Default initialization.
                init = cg_init(ctx, loc, type);
            }
            if (init)
                cg_assign_var(ctx, loc, nvar, init);
            scope_add(ctx->local_scope, var->name,
                      (struct ast_sym) MAKE_UNION(AST_SYM, var, nvar));
            return MAKE_CR_VOID;
        }
        case AST_lit: {
            struct ast_lit *lit = GET_UNION(AST, lit, ast);
            struct ir_const_val c = const_from_lit(ctx->unit->global_types,
                                                   lit->lit);
            if (c.type.type == IR_TYPE_error) {
                cg_compile_error(ctx, loc, "numeric overflow");
                return MAKE_CR_ERROR;
            }
            return MAKE_CR(val, cg_const(ctx, loc, c));
        }
        case AST_struct_lit: {
            struct ast_struct_lit *lit = GET_UNION(AST, struct_lit, ast);
            return cg_struct_lit(ctx, lit);
        }
        case AST_tuple: {
            struct ast_tuple *tp = GET_UNION(AST, tuple, ast);
            return cg_tuple(ctx, loc, tp->exprs_count, tp->exprs);
        }
        case AST_un_op:
            return cg_unop(ctx, GET_UNION(AST, un_op, ast));
        case AST_bin_op:
            return cg_binop(ctx, GET_UNION(AST, bin_op, ast));
        case AST_tern_op: {
            struct ast_tern_op *op = GET_UNION(AST, tern_op, ast);
            switch (op->op) {
                case TERN_OP_COND: {
                    return cg_functional_if(ctx, loc, op->expr1, op->expr2,
                                            op->expr3);
                }
                case TERN_OP_SLICE: {
                    assert(false);
                }
                default:
                    assert(false);
            }
        }
        case AST_call:
            return cg_call(ctx, GET_UNION(AST, call, ast));
        case AST_fn_type:
            cg_compile_error(ctx, loc, "value, not type expected");
            return MAKE_CR_ERROR;
        case AST_fn: {
            struct ast_fn *fn = GET_UNION(AST, fn, ast);
            cg_fn(ctx, fn);
            return MAKE_CR_VOID;
        }
        case AST_struct_: {
            struct ast_struct_ *struct_ = GET_UNION(AST, struct_, ast);
            cg_struct(ctx, struct_);
            return MAKE_CR_VOID;
        }
        case AST_ret: {
            struct ast_ret *ret = GET_UNION(AST, ret, ast);
            if (ctx->compiling_expression) {
                cg_compile_error(ctx, loc, "can't return from here");
                return MAKE_CR_ERROR;
            }
            struct ir_inst *ex = ret->expr
                ? cg_to_val(ctx, ret->expr, ctx->fn->type->ret_type)
                : cg_void(ctx, loc);
            cg_insert_return(ctx, loc, ex);
            ctx->bb = fn_add_bb(ctx->fn);
            return MAKE_CR_VOID;
        }
        case AST_if_: {
            struct ast_if_ *if_ = GET_UNION(AST, if_, ast);
            return cg_if(ctx, loc, if_->cond, if_->yes, if_->no);
        }
        case AST_while_: {
            struct ast_while_ *while_ = GET_UNION(AST, while_, ast);
            return cg_while(ctx, loc, while_->cond, while_->body);
        }
        case AST_block: {
            struct ast_block *block = GET_UNION(AST, block, ast);
            CR last = MAKE_CR_VOID;
            for (int n = 0; n < block->stmts_count; n++)
                last = cg_expression(ctx, block->stmts[n]);
            return last;
        }
        case AST_label: {
            struct ast_label *label = GET_UNION(AST, label, ast);
            cg_label(ctx, loc, label->name);
            return MAKE_CR_VOID;
        }
        case AST_goto_: {
            struct ast_goto_ *goto_ = GET_UNION(AST, goto_, ast);
            cg_goto_label(ctx, loc, goto_->label);
            return MAKE_CR_VOID;
        }
        default:
            assert(false);
    }
}

static void cg_finalize_nested_fns(CTX *ctx)
{
    struct ir_function *fn = ctx->fn;
    for (int n = 0; n < fn->blocks_count; n++) {
        struct ir_bb *bb = fn->blocks[n];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            if (in->op == IR_OP_UPVAL_CONTEXT) {
                struct ir_function *callee = in->fn->body;
                if (!callee) {
                    cg_compile_error(ctx, in->loc,
                                     "unresolved nested function");
                    return;
                }
                // not sure when this happens, or if at all?
                if (!fn_can_call_nested(fn, callee)) {
                    cg_compile_error(ctx, in->loc,
                                     "can't call nested function");
                    return;
                }
            }
        }
    }
}

// Finishes the function compilation, frees ctx, and returns the function.
// Returns NULL if there was an error during compilation.
static struct ir_function *finalize_function(struct ir_context *ctx)
{
    struct ir_function *fn = ctx->fn;

    cg_finalize_labels(ctx);

    LOC loc = ctx->fn->loc;

    // Check for missing return statement.
    if (!ctx->compiling_expression) {
        struct ir_bb *bb = ctx->bb;
        if (!bb->last || !ir_op_is_branch(bb->last->op)) {
            // The BB is unterminated.
            if (type_is_void(fn->type->ret_type)) {
                cg_insert_return(ctx, loc, cg_void(ctx, loc));
            } else if (!bb->first) {
                // This must be the stray block inserted after the last return
                // statement, or junk code after that statement.
                // The block should be unreachable, and is never executed.
                bb_add_nt_inst(ctx->bb, loc, IR_OP_ABORT);
            } else {
                cg_compile_error(ctx, loc, "missing return statement");
            }
        }
    }

    // Since we have to deal with recursive and forward referenced calls, only
    // do this on the root function.
    if (!ctx->fn->parent)
        cg_finalize_nested_fns(ctx);

    bool ok = !ctx->error_flag;
    talloc_free(ctx);
    if (!ok) {
        talloc_free(fn);
        return NULL;
    }

    if (fn->parent) {
        struct ir_function *p = fn->parent;
        BL_TARRAY_APPEND(p, p->nested_functions, p->nested_functions_count, fn);
    }

    fn_verify(fn);
    return fn;
}

static void cg_function_prologue(CTX *ctx)
{
    struct ir_fn_type *type = ctx->fn->type;
    for (int n = 0; n < type->args->members_count; n++) {
        struct ir_struct_member *m = type->args->members[n];
        // Obviously only named arguments can be accessed.
        if (m->name && m->name[0]) {
            cg_require_complete_type(ctx, m->loc, m->type);
            struct ir_var *v = fn_add_var(ctx->fn, m->loc, m->type);
            struct ir_inst *val = BB_ADD_INST(ctx->bb, m->loc, IR_OP_GETARG,
                                              m->type, .struct_member = m);
            cg_assign_var(ctx, m->loc, v, val);
            scope_add(ctx->local_scope, m->name,
                      (struct ast_sym) MAKE_UNION(AST_SYM, var, v));
        }
    }
}

static struct ir_context *alloc_ctx(struct ir_unit *unit,
                                    struct ir_scope *scope)
{
    struct ir_function *fn
        = talloc_struct(unit->global_types, struct ir_function, {.unit = unit});
    fn->entry = fn_add_bb(fn);
    struct ir_context *ctx = talloc_struct(NULL, struct ir_context, {
        .fn = fn,
        .bb = fn->entry,
        .types = unit->global_types,
        .unit = unit,
    });
    ctx->label_scope = talloc_zero(ctx, struct ir_scope);
    ctx->local_scope = talloc_zero(ctx, struct ir_scope);
    ctx->local_scope->next = scope;
    return ctx;
}

static struct ir_function *compile_function(struct ir_unit *unit,
                                            struct ir_function *parent,
                                            struct ir_fn_type *type,
                                            struct ir_scope *base_scope,
                                            struct ast_node *ast)
{
    struct ir_context *ctx = alloc_ctx(unit, base_scope);
    ctx->fn->loc = ast_get_loc(ast);
    ctx->fn->parent = parent;
    ctx->fn->type = type;
    cg_function_prologue(ctx);
    cg_expression(ctx, ast);
    return finalize_function(ctx);
}

static struct ir_function *compile_expression(struct ir_unit *unit,
                                              struct ir_type res_type,
                                              struct ir_scope *scope,
                                              struct ast_node *ast)
{
    struct ir_context *ctx = alloc_ctx(unit, scope);
    ctx->compiling_expression = true;
    ctx->fn->loc = ast_get_loc(ast);
    struct ir_inst *res = cg_to_val(ctx, ast, res_type);
    if (TEST_UNION0(IR_TYPE, any, &res_type)) {
        res_type = res->result_type;
    } else {
        res = cg_implicit_conversion(ctx, ctx->fn->loc, res, res_type);
    }

    struct ir_fn_type *type = talloc_zero(unit->global_types,
                                          struct ir_fn_type);
    type->ret_type = res->result_type;
    type->args = struct_start(ctx->types, ctx->fn->loc);
    struct_end(type->args, false);
    talloc_steal(type, type->args);
    ctx->fn->type = type;

    cg_insert_return(ctx, ctx->fn->loc, res);

    return finalize_function(ctx);
}

static struct ir_fn_decl *unit_define_function(struct ir_unit *unit,
                                               struct ir_function *fn,
                                               struct ir_link_name name)
{
    if (scope_lookup(unit->symbols, name.name))
        assert(false);
    struct ir_fn_decl *fnd = talloc_struct(unit, struct ir_fn_decl, {
        .loc = fn->loc,
        .name = name,
        .type = fn->type,
        .body = fn,
    });
    scope_add(unit->symbols, name.name,
              (struct ast_sym) MAKE_UNION(AST_SYM, fn_decl, fnd));
    BL_TARRAY_APPEND(unit, unit->fn_decls, unit->fn_decls_count, fnd);
    return fnd;
}

struct ir_unit *bl_cg_expr(struct ast_node *ast)
{
    struct ir_unit *unit = unit_new();

    struct ir_function *fn
        = compile_expression(unit, MAKE_IR_TYPE0(any), unit->symbols, ast);

    if (!fn) {
        talloc_free(unit);
        return NULL;
    }

    // Turn it into something that can be compiled as program.
    // Add the expression as function, and call it from main().
    struct ir_fn_decl *fnd =
        unit_define_function(unit, fn, (struct ir_link_name) { "expr" });
    CTX *ctx = alloc_ctx(unit, unit->symbols);
    ctx->fn->type = ctx->types->c_main;
    cg_function_prologue(ctx);
    BB_ADD_INST(ctx->bb, fn->loc, IR_OP_CALL, fn->type->ret_type, .fn = fnd);
    struct ir_inst *i0 = cg_init(ctx, fn->loc, ctx->fn->type->ret_type);
    bb_add_nt_unop(ctx->bb, fn->loc, IR_OP_RET, i0);
    struct ir_function *main_fn = finalize_function(ctx);
    unit_define_function(unit, main_fn,
        (struct ir_link_name) { "main", .visible = true, .is_c = true });

    return unit;
}

struct ast_sym *scope_lookup(struct ir_scope *scope, char *name)
{
    for (int n = 0; n < scope->entries_count; n++) {
        if (strcmp(scope->entries[n].name, name) == 0)
            return &scope->entries[n].sym;
    }
    if (scope->next)
        return scope_lookup(scope->next, name);
    return NULL;
}

void scope_add(struct ir_scope *scope, char *name, struct ast_sym entry)
{
    struct scope_entry e = { name, entry };
    BL_TARRAY_APPEND(scope, scope->entries, scope->entries_count, e);
}

