#include "talloc.h"
#include "hashtable.h"
#include "ir.h"
#include "value.h"

// Remove all IR_OP_PHI instructions. Remove read-references across basic block
// boundaries and turn them into variables.
void fn_remove_global_ssa(struct ir_function *fn)
{
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            if (in->op != IR_OP_PHI) {
                for (int r = 0; r < in->read_count; r++) {
                    struct ir_inst *t = in->read[r].def;
                    if (t->bb != bb) {
                        struct ir_var *v =
                            fn_add_var(fn, t->loc, t->result_type);
                        struct ir_inst *vw =
                            INST_NEW(t->loc, IR_OP_WRITE_VAR, IR_INST_NO_TYPE,
                                     INST_R1(t), .var = v);
                        bb_add_inst_after(t->bb, t, vw);
                        struct ir_inst *vr =
                            INST_NEW(t->loc, IR_OP_READ_VAR, v->type, .var = v);
                        bb_add_inst_before(in->bb, in, vr);
                        inst_use(in, r, vr);
                    }
                }
            } else {
                // v is shared across all instructions that are read
                struct ir_var *v = fn_add_var(fn, in->loc, in->result_type);
                for (int r = 0; r < in->read_count; r++) {
                    struct ir_inst *t = in->read[r].def;
                    struct ir_inst *vw =
                        INST_NEW(t->loc, IR_OP_WRITE_VAR, IR_INST_NO_TYPE,
                                 INST_R1(t), .var = v);
                    bb_add_inst_after(t->bb, t, vw);
                }
                in = bb_replace_inst_dup(in,
                            INST(in->loc, IR_OP_READ_VAR, v->type, .var = v));
            }
        }
    }
}

static uint64_t sign_ext(uint64_t x, unsigned int b)
{
    if (b == 64)
        return x;
    // http://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend
    uint64_t m = UINT64_C(1) << (b - 1);
    x = x & ((UINT64_C(1) << b) - 1);
    return (x ^ m) - m;
}

static uint64_t mask(uint64_t x, unsigned int b)
{
    return b < 64 ? (x & ((UINT64_C(1) << b) - 1)) : x;
}

static uint64_t fixval(struct ir_type t, uint64_t v)
{
    if (type_is_bool(t))
        return v & 1;
    int bits = type_get_bits(t);
    int sign = type_get_sign(t);
    return sign ? sign_ext(v, bits) : mask(v, bits);
}

// Fold binary and unary operations on integers and bools.
static bool const_fold_int(enum ir_opcode op, struct ir_type source_type,
                           struct ir_type dest_type, uint64_t a, uint64_t b,
                           uint64_t *out_val)
{
    assert(type_is_integer(source_type) || type_is_bool(source_type));
    assert(type_is_integer(dest_type) || type_is_bool(dest_type));
    uint64_t r;
    //int bits = type_is_bool(t) ? 1 : type_get_bits(t);
    int sign = type_is_bool(source_type) ? 0 : type_get_sign(source_type);
#define SIGNED_OP(op, a, b) (sign ? (((int64_t)a) op ((int64_t)b)) : (a) op (b))
    switch (op) {
        case IR_OP_ADD: r = a + b; break;
        case IR_OP_SUB: r = a - b; break;
        case IR_OP_MUL: r = SIGNED_OP(*, a, b); break;
        case IR_OP_DIV: {
            if (b == 0)
                return false;
            r = SIGNED_OP(/, a, b);
            break;
        }
        case IR_OP_MOD: {
            if (b == 0)
                return false;
            r = SIGNED_OP(%, a, b);
            break;
        }
        case IR_OP_AND: r = a & b; break;
        case IR_OP_OR: r = a | b; break;
        case IR_OP_XOR: r = a ^ b; break;
        // xxx there's some undefined behavior lurking
        case IR_OP_SHIFT_R: r = SIGNED_OP(>>, a, b); break;
        case IR_OP_SHIFT_L: r = a << b; break;
        case IR_OP_EQ: r = (a == b); break;
        case IR_OP_NOT_EQ: r = (a != b); break;
        case IR_OP_CMP_LT: r = SIGNED_OP(<, a, b); break;
        case IR_OP_CMP_GT: r = SIGNED_OP(>, a, b); break;
        case IR_OP_CMP_LT_EQ: r = SIGNED_OP(<=, a, b); break;
        case IR_OP_CMP_GT_EQ: r = SIGNED_OP(>=, a, b); break;
        // unary
        case IR_OP_CONV_INT_TRUNC: r = a; break;
        case IR_OP_CONV_INT_SIGN: r = a; break;
        case IR_OP_CONV_INT_EXT: r = a; break;
        case IR_OP_NEG: r = -(int64_t)a; break;
        case IR_OP_NOT: r = ~a; break;
        default:
            return false;
    }
#undef SIGNED_OP
    *out_val = fixval(dest_type, r);
    //printf("foldbin %s %llu %llu -> %llu\n", ir_op_name(op), a, b, *out_val);
    return true;
}

// whether the operation is commutative (and has two operands)
static bool arith_op_is_commutative(enum ir_opcode op)
{
    switch (op) {
        case IR_OP_ADD:
        case IR_OP_MUL:
        case IR_OP_AND:
        case IR_OP_OR:
        case IR_OP_XOR:
        case IR_OP_EQ:
        case IR_OP_NOT_EQ:
            return true;
        default:
            return false;
    }
}

static bool arith_op_is_associative(enum ir_opcode op)
{
    switch (op) {
        case IR_OP_ADD:
        case IR_OP_MUL:
        case IR_OP_AND:
        case IR_OP_OR:
        case IR_OP_XOR:
            return true;
        default:
            return false;
    }
}

static struct ir_inst *fold_arith(struct ir_inst *in)
{
    if (!(in->op >= IR_OP_ARITH_START && in->op < IR_OP_ARITH_END))
        return NULL;
    for (int n = 0; n < in->read_count; n++) {
        if (inst_getuse(in, n)->op != IR_OP_LOAD_CONST)
            return NULL;
    }
    if (!type_is_integer(in->result_type) && !type_is_bool(in->result_type))
        return NULL;
    struct ir_inst *r0 = inst_getuse(in, 0);
    struct ir_inst *r1 = in->read_count > 1 ? inst_getuse(in, 1) : NULL;
    uint64_t a = *GET_UNION(VALUE, vuint64, &r0->const_value->value);
    uint64_t b = r1 ? *GET_UNION(VALUE, vuint64, &r1->const_value->value) : 0;
    uint64_t r;
    if (!const_fold_int(in->op, r0->result_type, in->result_type, a, b, &r))
        return NULL;
    return INST_NEW(in->loc, IR_OP_LOAD_CONST, in->result_type,
                    .const_value = &(struct ir_const_val) {
                        in->result_type, MAKE_UNION(VALUE, vuint64, r) });
}

// It seems this rule helps with associative const folding of mixed +/- ops.
// e.g. 3+(a-1) => 3+(a+(-1)) => (3+(-1))+a => 2+a
// xxx: handle 3+(1-a) as well
static struct ir_inst *fold_subc(struct ir_inst *in)
{
    struct ir_inst *k = inst_getuse(in, 1);
    struct ir_type t = k->result_type;
    uint64_t r;
    if (!const_fold_int(IR_OP_NEG, t, t,
        *GET_UNION(VALUE, vuint64, &k->const_value->value), 0, &r))
        return NULL;
    k->const_value->value = (struct value) MAKE_UNION(VALUE, vuint64, r);
    in->op = IR_OP_ADD;
    return in;
}

#define SWAP_INST(a, b) \
    do { struct ir_inst *tmp = (a); (a) = (b); (b) = tmp; } while (0)

// (b op k1) op k2 => b op (k1 op k2)
// Normal const folding (i.e. fold_arith) will do the rest.
static struct ir_inst *fold_const_assoc(struct ir_inst *in)
{
    struct ir_inst *k2 = inst_getuse(in, 0);
    struct ir_inst *r = inst_getuse(in, 1);
    if (k2->op != IR_OP_LOAD_CONST)
        SWAP_INST(k2, r);
    if (in->op != r->op || !arith_op_is_associative(in->op))
        return NULL;
    struct ir_inst *b = inst_getuse(r, 0);
    struct ir_inst *k1 = inst_getuse(r, 1);
    if (k1->op != IR_OP_LOAD_CONST)
        SWAP_INST(k1, b);
    // Don't do anything if we don't reach a stable state.
    if (b->op == IR_OP_LOAD_CONST)
        return NULL;
    inst_rewire_uses(in, k2, b);
    inst_rewire_uses(r, b, k2);
    return in;
}

// CALL_PTR(a0, ...) -> CALL(...)
static struct ir_inst *fold_call_ptr(struct ir_inst *in)
{
    struct ir_inst *r0 = inst_getuse(in, 0);
    assert(r0->op == IR_OP_FN_PTR);
    return INST_NEW(in->loc, IR_OP_CALL, in->result_type,
                    .read_count = in->read_count - 1, .read = &in->read[1],
                    .fn = r0->fn);
}

static struct ir_inst *fold_phi(struct ir_inst *in)
{
    //assert(in->read_count > 0);
    // Might be slightly unkosher, and cause trouble in the future.
    // Note that the inliner likes to create such nodes.
    return in->read_count == 1 ? inst_getuse(in, 0) : NULL;
}

static struct ir_inst *fold_struct(struct ir_inst *in)
{
    assert(false); //untested, should be fine
    return inst_getuse(inst_getuse(in, 0), in->struct_member->index);
}

static struct ir_inst *fold_branch(struct ir_inst *in)
{
    struct ir_inst *r = inst_getuse(in, 0);
    struct ir_bb *dest = NULL;
    if (r->op == IR_OP_LOAD_CONST) {
        dest = in->branch[*GET_UNION(VALUE, vuint64, &r->const_value->value)];
    } else if (in->branch[0] == in->branch[1]) {
        dest = in->branch[0];
    }
    if (!dest)
        return NULL;
    return INST_NEW(in->loc, IR_OP_GOTO, IR_INST_NO_TYPE, .branch = {dest});
}

static struct ir_inst *fold_var_ptr(struct ir_inst *in)
{
    struct ir_inst *r = inst_getuse(in, 0);
    if (in->op == IR_OP_READ_PTR) {
        return INST_NEW(in->loc, IR_OP_READ_VAR, r->var->type, .var = r->var);
    } else {
        return INST_NEW(in->loc, IR_OP_WRITE_VAR, IR_INST_NO_TYPE,
                        INST_R1(inst_getuse(in, 1)), .var = r->var);
    }
}

struct fold_rule {
    // Pattern match the IR code with the rule, given by this tree.
    struct fold_tree *match;
    // If non-NULL, replace the matched IR code with new IR generated by tree.
    struct fold_tree *replace;
    // If non-NULL, replace the matched IR code with the function return.
    // "in" is the root of the matched tree.
    // Return value:
    // - == NULL: do nothing, operation couldn't be completed.
    // - == "in": "in" was mutated. Set the change flag.
    // - not added instruction (result->bb == NULL): replace "in" with this
    //   instruction. "in" is removed and destroyed.
    // - any other instruction: it is assumed it's one of the readers in the
    //   matched tree. All uses of "in" are replaced with the returned
    //   instruction. "in" is removed and destroyed.
    struct ir_inst *(*handler)(struct ir_inst *in);
};

#define MAX_FOLD_READS 3

struct fold_tree {
    int op;
    struct fold_tree *sub[MAX_FOLD_READS];
    int flags;
    uint64_t v;
};

#define FOLD_FLAG_INT 1
#define FOLD_FLAG_CONST 2

#define FOLD_PSEUDO_INT -1
#define FOLD_PSEUDO_BOOL -2
#define FOLD_PSEUDO_R -3
#define FOLD_PSEUDO_ANY -4
#define FOLD_PSEUDO_CONST -5
#define FOLD_PSEUDO_ARITH -6

#define MAX_SAVED_READS 2

// Shoehorn the rules declarations into C.
// NOTE about types:
// - we never fold floats, because floats are scary
// - for folding, bools are treated as 1-bit integer types
// Think of F(...) as {...}, except it returns a pointer to the new struct.
#define F(...) &(struct fold_tree) {__VA_ARGS__}
// Match instruction, and a number of reads (in order).
#define S(op, ...) F(op, {__VA_ARGS__})
// Like S(), but only match integer/bool types.
#define SI(op, ...) F(op, {__VA_ARGS__}, FOLD_FLAG_INT)
// Match integer/bool IR_OP_LOAD_CONST instructions containing the given value.
#define I(i) F(FOLD_PSEUDO_INT, .v = (i))
#define I0 I(0)
// All bits of the target type are set (whether it's signed or unsigned).
#define I_ALLBITS I(-1)
// Match booleans.
#define BT F(FOLD_PSEUDO_BOOL, .v = 1)
#define BF F(FOLD_PSEUDO_BOOL, .v = 0)
// Match a constant, and save for the replace part (can use with R(x)).
#define C(x) F(FOLD_PSEUDO_CONST, .v = x)
// Pattern matching: remember this as read x.
// If used in the replace part, use a previously saved pattern.
// x is bounded by MAX_SAVED_READS.
#define R(x) F(FOLD_PSEUDO_R, .v = x)
#define R0 R(0)
// Ignore this read.
#define R_ F(FOLD_PSEUDO_ANY)
const struct fold_rule fold_simplify_rules[] = {
    // -- algebraic simplifications
    // neutral element
    {SI(IR_OP_ADD, R0, I0), R0},
    {SI(IR_OP_SUB, R0, I0), R0},
    {SI(IR_OP_MUL, R0, I(1)), R0},
    {SI(IR_OP_DIV, R0, I(1)), R0},
    {SI(IR_OP_OR, R0, I0), R0},
    {SI(IR_OP_XOR, R0, I0), R0},
    {SI(IR_OP_AND, R0, I_ALLBITS), R0},
    {SI(IR_OP_EQ, BT, R0), R0},
    {SI(IR_OP_NOT_EQ, BF, R0), R0},
    // idempotence
    {SI(IR_OP_OR, R0, R0), R0},
    {SI(IR_OP_AND, R0, R0), R0},
    {SI(IR_OP_NOT, SI(IR_OP_NOT, R0)), R0},
    {SI(IR_OP_NEG, SI(IR_OP_NEG, R0)), R0},
    // idempotence (association)
    {SI(IR_OP_AND, SI(IR_OP_AND, R0, R(1)), R0),
     SI(IR_OP_AND, R0, R(1))}, // (a & b) & a = (a & b)
    {SI(IR_OP_OR, SI(IR_OP_OR, R0, R(1)), R0),
     SI(IR_OP_OR, R0, R(1))}, // (a | b) | a = (a | b)
    // cancellation (neutral element)
    {SI(IR_OP_OR, R0, I_ALLBITS), I_ALLBITS},
    {SI(IR_OP_AND, R_, I0), I0},
    {SI(IR_OP_MUL, R_, I0), I0},
    // cancellation (algebraic)
    {SI(IR_OP_SUB, R0, R0), I0},
    {SI(IR_OP_XOR, R0, R0), I0},
    // cancellation (association)
    {SI(IR_OP_XOR, SI(IR_OP_XOR, R0, R(1)), R0), R(1)}, // (a ^ b) ^ a = b
    // simplification
    {SI(IR_OP_SUB, I0, R0), SI(IR_OP_NEG, R0)}, // 0 - a = -a
    {SI(IR_OP_SUB, R0, C(1)), NULL, fold_subc}, // a - k = a + (-k)
    {SI(IR_OP_EQ, BF, R0), SI(IR_OP_NOT, R0)}, // (false == a) = ~a
    {SI(IR_OP_NOT_EQ, BT, R0), SI(IR_OP_NOT, R0)}, // (true != a) = ~a
    {SI(IR_OP_XOR, R0, I_ALLBITS), SI(IR_OP_NOT, R0)}, // a ^ 1..1 = ~a
    // (a-b)-a = -b
    {SI(IR_OP_SUB, SI(IR_OP_SUB, R(1), R0), R(1)), SI(IR_OP_NEG, R0)},
    // a-(a-b) = b
    {SI(IR_OP_SUB, R(1), SI(IR_OP_SUB, R(1), R0)), R0},
    // (a+b)-b = a
    {SI(IR_OP_SUB, SI(IR_OP_ADD, R0, R(1)), R(1)), R0},
    // b-(a+b) = -a
    {SI(IR_OP_SUB, R(1), SI(IR_OP_ADD, R0, R(1))), SI(IR_OP_NEG, R0)},
    // -- const folding entry points
    // xxx crappiness: we could match both operands with C(), but then we
    //                 couldn't fold NOT/NEG
    {F(FOLD_PSEUDO_ARITH, {0}, FOLD_FLAG_INT | FOLD_FLAG_CONST),
     NULL, fold_arith},
    {S(IR_OP_BRANCH), NULL, fold_branch}, // also simplify pointless branches
    // assisting const. folding through association
    {SI(FOLD_PSEUDO_ARITH, SI(FOLD_PSEUDO_ARITH, R_, C(0)), C(1)), NULL,
     fold_const_assoc}, // (b op k1) op k2 = b op (k1 op k2)
    // -- simplistic scalar replacement of struct members
    {S(IR_OP_GET_CLOSURE_FN, S(IR_OP_MAKE_CLOSURE, R0, R_)), R0},
    {S(IR_OP_GET_CLOSURE_CTX, S(IR_OP_MAKE_CLOSURE, R_, R0)), R0},
    {S(IR_OP_GET_STRUCT_MEMBER, S(IR_OP_CONSTRUCT_STRUCT)), NULL, fold_struct},
    // -- other
    {S(IR_OP_COPY, R0), R0},
    {S(IR_OP_PHI), NULL, fold_phi},
    {S(IR_OP_CALL_PTR, S(IR_OP_FN_PTR)), NULL, fold_call_ptr},
    {S(IR_OP_READ_PTR, S(IR_OP_VAR_PTR)), NULL, fold_var_ptr},
    {S(IR_OP_WRITE_PTR, S(IR_OP_VAR_PTR)), NULL, fold_var_ptr},
    // --
    {0}
};
#undef S
#undef S_COM
#undef I
#undef I0
#undef I_ALLBITS
#undef BT
#undef BF
#undef C
#undef R
#undef R0
#undef R_

static uint64_t int_mask_uint64(uint64_t val, struct ir_type t)
{
    if (type_is_bool(t))
        return val & 1;
    int bits = type_get_bits(t);
    return bits < 64 ? (val & ((UINT64_C(1) << bits) - 1)) : val;
}

static void reset_reads(struct ir_inst **saved_reads)
{
    memset(saved_reads, 0, sizeof(saved_reads[0]) * MAX_SAVED_READS);
}

static bool save_read(struct ir_inst *in, int r, struct ir_inst **saved_reads)
{
    assert(r >= 0 && r < MAX_SAVED_READS);
    struct ir_inst *saved = saved_reads[r];
    if (saved && saved != in)
        return false;
    saved_reads[r] = in;
    return true;
}

static bool tree_match(struct fold_tree *match, struct ir_inst *in,
                       struct ir_inst **saved_reads)
{
    // check instruction itself
    if(match->op == in->op || match->op == FOLD_PSEUDO_ANY) {
        //pass
    } else if (match->op == FOLD_PSEUDO_R ||
               (match->op == FOLD_PSEUDO_CONST && in->op == IR_OP_LOAD_CONST))
    {
        if (!save_read(in, match->v, saved_reads))
            return false;
    } else if (match->op == FOLD_PSEUDO_INT || match->op == FOLD_PSEUDO_BOOL) {
        if (in->op != IR_OP_LOAD_CONST)
            return false;
        struct ir_type t = in->result_type;
        if (match->op == FOLD_PSEUDO_INT) {
            if (!(type_is_integer(t) || type_is_bool(t)))
                return false;
        } else {
            if (!type_is_bool(t))
                return false;
        }
        if (*GET_UNION(VALUE, vuint64, &in->const_value->value)
            != int_mask_uint64(match->v, t))
            return false;
    } else if (match->op == FOLD_PSEUDO_ARITH) {
        if (!(in->op >= IR_OP_ARITH_START && in->op < IR_OP_ARITH_END))
            return false;
    } else {
        return false;
    }

    if (in->read_count && (match->flags & FOLD_FLAG_INT)) {
        struct ir_type t = inst_getuse(in, 0)->result_type;
        if (!type_is_integer(t) && !type_is_bool(t))
            return false;
    }

    if (match->flags & FOLD_FLAG_INT) {
        for (int n = 0; n < in->read_count; n++) {
            if (inst_getuse(in, n)->op != IR_OP_LOAD_CONST)
                return false;
        }
    }

    if (arith_op_is_commutative(in->op) && match->sub[0] && match->sub[1]) {
        // Commutative - must have two sub-trees, and match them in both ways.
        assert(in->read_count == 2);
        struct ir_inst *r0 = inst_getuse(in, 0), *r1 = inst_getuse(in, 1);
        struct fold_tree *t0 = match->sub[0], *t1 = match->sub[1];
        if (!(tree_match(t0, r0, saved_reads)
            && tree_match(t1, r1, saved_reads)))
        {
            reset_reads(saved_reads);
            if (!(tree_match(t0, r1, saved_reads)
                && tree_match(t1, r0, saved_reads)))
                return false;
        }
    } else {
        // normal case
        for (int n = 0; n < MAX_FOLD_READS; n++) {
            if (!match->sub[n])
                break;
            if (!(n < in->read_count))
                return false;
            if (!tree_match(match->sub[n], inst_getuse(in, n), saved_reads))
                return false;
        }
    }

    return true;
}

static struct ir_inst *tree_replace(struct fold_tree *tree, struct ir_inst *in,
                                    struct ir_inst **saved_reads)
{
    if (tree->op == FOLD_PSEUDO_R) {
        assert(tree->v >= 0 && tree->v < MAX_SAVED_READS);
        in = saved_reads[tree->v];
        assert(in);
        return in;
    } else if (tree->op == FOLD_PSEUDO_INT) {
        struct ir_type t = in->result_type;
        assert(type_is_integer(t) || type_is_bool(t));
        uint64_t iv = (int64_t)tree->v; // make sure it's sign-extended
        if (type_is_bool(t))
            iv = !!iv;
        struct value v = MAKE_UNION(VALUE, vuint64, iv);
        return INST_NEW(in->loc, IR_OP_LOAD_CONST, t,
                        .const_value = &(struct ir_const_val) {t, v});
    } else if (tree->op > 0) {
        // NOTE: we support creation of only one instruction. No tree.
        struct ir_inst new = {in->loc, tree->op, in->result_type};
        struct ir_use reads[MAX_FOLD_READS];
        new.read = &reads[0];
        for (int n = 0; n < MAX_FOLD_READS; n++) {
            if (tree->sub[n]) {
                new.read_count += 1;
                reads[n].def = tree_replace(tree->sub[n], in, saved_reads);
            }
        }
        return inst_dup(&new);
    }
    assert(false);
}

// This matches the IR against the rules in fold_rules.
// This idea is stolen from LuaJIT's "FOLD engine".
// NOTE: doesn't necessarily remove instructions that aren't needed anymore,
//       running fn_remove_neutral_code() may help.
static bool fn_fold_insts(struct ir_function *fn, const struct fold_rule *rules)
{
    bool change = false;
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        struct ir_inst *in = bb->first;
    inst_done:
        while (in) {
            assert(in->bb == bb);
            // NOTE: if we were clever, we would use a hashtable for searching.
            for (const struct fold_rule *rule = rules; rule->match; rule++) {
                struct ir_inst *saved_reads[MAX_SAVED_READS];
                reset_reads(saved_reads);
                if (!tree_match(rule->match, in, saved_reads))
                    continue;
                assert((!!rule->replace) != (!!rule->handler));
                struct ir_inst *result = rule->handler
                    ? rule->handler(in)
                    : tree_replace(rule->replace, in, saved_reads);
                if (result == NULL)
                    continue;
                change = true;
                if (result == in)
                    continue;
                struct ir_inst *next = result->bb ? in->next : result;
                bb_replace_inst(in, result);
                in = next;
                goto inst_done;
            }
            in = in->next;
        }
    }
    return change;
}

static bool fn_simplify_insts(struct ir_function *fn)
{
    return fn_fold_insts(fn, fold_simplify_rules);
}

static void cse_inst_hash(struct ir_inst *in)
{
    assert(in->scratch1_i == 0);
    uint32_t *hash = &(uint32_t) { HASH_FNV_INIT };

    hash_int(hash, in->op);
    // xxx not all these fields are relevant for all instructions
    //     doing this is ok, but possibly slightly slower than required
    hash_ptr(hash, in->var);
    hash_ptr(hash, in->struct_member);
    hash_ptr(hash, in->fn);
    if (in->const_value)
        const_hash(hash, *in->const_value);

    for (int n = 0; n < in->read_count; n++) {
        struct ir_inst *r = inst_getuse(in, n);
        if (r->bb == in->bb && r->scratch1_i != 0) {
            hash_chain(hash, r->scratch1_i);
        } else {
            hash_ptr(hash, in);
        }
    }

    in->scratch1_i = *hash | 1;
}

static bool cse_inst_equals(struct ir_bb *bb, struct ir_inst *in1,
                            struct ir_inst *in2)
{
    if (in1 == in2)
        return true;
    if (in1->bb != in2->bb || in1->bb != bb)
        return false;

    if (in1->op != in2->op || in1->read_count != in2->read_count)
        return false;

    if (in1->var != in2->var
        || in1->struct_member != in2->struct_member
        || in1->fn != in2->fn)
        return false;

    if (!type_equals(in1->result_type, in2->result_type))
        return false;

    if (in1->const_value) {
        if (!const_bit_equals(*in1->const_value, *in2->const_value))
            return false;
    }

    for (int n = 0; n < in1->read_count; n++) {
        if (cse_inst_equals(bb, inst_getuse(in1, n), inst_getuse(in2, n)))
            return false;
    }

    return true;
}

static uint32_t ht_cse_inst_hash(void *ctx, void *k)
{
    struct ir_inst *in = k;
    assert(in->scratch1_i != 0);
    return in->scratch1_i;
}

static bool ht_cse_inst_equals(void *ctx, void *k1, void *k2)
{
    return cse_inst_equals(ctx, k1, k2);
}

static bool cse_block(struct ir_bb *bb)
{
    bool change = false;
    // The hashtable key is the "contents" of an instruction (i.e. what it
    // does), the value is the instruction itself. Since we have the instruction
    // via the key, don't bother with the actual hashtable value.
    struct hashtable *ht = ht_create(NULL, HT_DATA_dcustomptr, HT_DATA_dempty);
    ht->custom_key_hash = ht_cse_inst_hash;
    ht->custom_key_equals = ht_cse_inst_equals;
    ht->custom_key_ctx = bb;
    for (struct ir_inst *in = bb->first; in; in = in->next)
        in->scratch1_i = 0;
    for (struct ir_inst *in = bb->first; in; in = in->next) {
        // NOTE: could CSE read side effects, as long as they don't get
        //       reordered with any write side effects.
        if (ir_op_reads_side_effects(in->op)
            || ir_op_writes_side_effects(in->op) || ir_op_is_branch(in->op))
            continue;
        cse_inst_hash(in);
        struct hashnode *node = HT_GET_NODE(dcustomptr, ht, in);
        if (!node) {
            HT_INSERT(dcustomptr, dempty, ht, in, NULL);
        } else {
            struct ir_inst *new_in = HT_NODE_KEY(dcustomptr, ht, node);
            assert(cse_inst_equals(bb, in, new_in));
            assert(type_equals(in->result_type, new_in->result_type));
            inst_replace_all_uses(in, new_in);
            change = true;
            // leave removal of "in" to fn_remove_neutral_code()
        }
    }
    talloc_free(ht);
    return change;
}

// Do common subexpression elemination (strictly block-local).
static bool fn_local_cse(struct ir_function *fn)
{
    bool change = false;
    for (int b = 0; b < fn->blocks_count; b++)
        change |= cse_block(fn->blocks[b]);
    return change;
}

static bool fn_remove_neutral_code_step(struct ir_function *fn)
{
    bool change = false;
    // Iterating backwards makes it converge faster, because unused instructions
    // depending on later unused instructions get eliminated immediately.
    // (Assumes later blocks tend to be dominated by earlier blocks.)
    for (int b = fn->blocks_count - 1; b >= 0; b--) {
        struct ir_bb *bb = fn->blocks[b];
        struct ir_inst *in = bb->last;
        while (in) {
            if (!ir_op_is_branch(in->op) && !ir_op_writes_side_effects(in->op)
                && !inst_has_users(in))
            {
                struct ir_inst *n = in->prev;
                bb_kill_inst(bb, in);
                in = n;
                change = true;
            } else {
                in = in->prev;
            }
        }
    }
    return change;
}

// Remove instructions that have no effect.
static bool fn_remove_neutral_code(struct ir_function *fn)
{
    bool change = false;
    while (fn_remove_neutral_code_step(fn))
        change = true;
    return change;
}

static void check_reachable(struct ir_bb *bb, uint8_t *b)
{
    if (bitv_get(b, bb->index))
        return;
    bitv_set(b, bb->index);
    for (int n = 0; n < bb->jump_to_count; n++)
        check_reachable(bb->jump_to[n], b);
}

static bool fn_remove_unreachable_blocks(struct ir_function *fn)
{
    bool change = false;
    uint8_t *b = bitv_new(NULL, fn->blocks_count);
    check_reachable(fn->entry, b);
    // Clean up PHI nodes. They might have uses from dead blocks. This can
    // happen with PHI ops only, as they connect data flow and control flow.
    for (int n = 0; n < fn->blocks_count; n++) {
        if (!bitv_get(b, n))
            continue;
        for (struct ir_inst *in = fn->blocks[n]->first; in; in = in->next) {
            // PHIs are the only instructions at the beginning of a block.
            if (in->op != IR_OP_PHI)
                break;
            for (int i = in->read_count - 1; i >= 0; i--) {
                struct ir_inst *r = inst_getuse(in, i);
                // Remove the read; don't bother to update the users-info.
                if (!bitv_get(b, r->bb->index))
                    BL_TARRAY_REMOVE_AT(in->read, in->read_count, i);
            }
        }
    }
    for (int n = fn->blocks_count - 1; n >= 0; n--) {
        if (!bitv_get(b, n)) {
            struct ir_bb *bb = fn->blocks[n];
            fn_remove_bb(fn, bb);
            talloc_free(bb);
            change = true;
        }
    }
    talloc_free(b);
    return change;
}

static bool fn_shortcut_jumps(struct ir_function *fn)
{
    bool change = false;
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        if (bb->first->op == IR_OP_GOTO) {
            struct ir_bb *dest = bb->jump_to[0];
            // Note: try to get in a stable state, i.e. avoid switching back and
            //       forth between two gotos on each iteration.
            //       Also, the entry is not a jump target.
            if (dest != bb && dest != fn->entry
                && dest->first->op != IR_OP_GOTO)
            {
                while (bb->jump_from_count) {
                    bb_rewire_jump(bb->jump_from[0], bb, dest);
                    change = true;
                }
                if (fn->entry == bb)
                    fn->entry = dest;
            }
        }
    }
    return change;
}

// Merge head and tail, head is deleted.
static void bb_merge_blocks(struct ir_function *fn, struct ir_bb *head,
                            struct ir_bb *tail)
{
    assert(head->jump_to_count == 1);
    assert(head->jump_to[0] == tail);
    assert(tail->jump_from_count == 1);
    assert(tail->first);
    assert(tail->first->op != IR_OP_PHI);
    while (head->jump_from_count)
        bb_rewire_jump(head->jump_from[0], head, tail);
    // Remove the jump
    bb_kill_inst(head, head->last);
    while (head->last)
        inst_move_to(head->last, tail, NULL);
    if (fn->entry == head)
        fn->entry = tail;
    fn_remove_bb(fn, head);
    talloc_free(head);
}

static bool fn_merge_adjacent_blocks(struct ir_function *fn)
{
    bool change = false;
    for (int b = fn->blocks_count - 1; b >= 0; b--) {
        struct ir_bb *bb = fn->blocks[b];
        if (bb->jump_to_count == 1) {
            struct ir_bb *dest = bb->jump_to[0];
            if (dest->jump_from_count == 1 && dest->first->op != IR_OP_PHI) {
                bb_merge_blocks(fn, bb, dest);
                change = true;
            }
        }
    }
    return change;
}

// A retarded method of converting variables to registers. It's exceedingly
// naive and never creates PHI nodes.
// The only advantage of this is that it's quite fast.
// Requires simplify pass to be effective.
static bool fn_dumbass_to_ssa(struct ir_function *fn)
{
    bool change = false;
    struct ir_inst **last_def = talloc_array(NULL, struct ir_inst*,
                                             fn->vars_count);
    for (int n = 0; n < fn->blocks_count; n++) {
        memset(last_def, 0, sizeof(last_def[0]) * fn->vars_count);
        for (struct ir_inst *in = fn->blocks[n]->first; in; in = in->next) {
            if (in->op == IR_OP_READ_VAR) {
                if (last_def[in->var->index]) {
                    inst_replace_all_uses(in, last_def[in->var->index]);
                    change = true;
                }
            } else if (in->op == IR_OP_WRITE_VAR) {
                last_def[in->var->index] = inst_getuse(in, 0);
            } else if (ir_op_writes_side_effects(in->op)) {
                // NOTE: we could check which vars can be aliased at all (if
                //       IR_OP_VAR_PTR was run on them), but for now wipe all.
                memset(last_def, 0, sizeof(last_def[0]) * fn->vars_count);
            }
        }
    }
    talloc_free(last_def);
    return change;
}

static void mark_upvars(struct ir_function *parent, uint8_t *b,
                        struct ir_function *fn)
{
    for (int n = 0; n < fn->blocks_count; n++) {
        for (struct ir_inst *in = fn->blocks[n]->first; in; in = in->next) {
            if (in->op == IR_OP_UPVAL_PTR && in->var->fn == parent)
                bitv_set(b, in->var->index);
        }
    }
    for (int n = 0; n < fn->nested_functions_count; n++)
        mark_upvars(parent, b, fn->nested_functions[n]);
}

// This can be arbitrarily complex (because it has to do with pointers), so we
// do something naive.
// Requires fn_remove_neutral_code() to be effective (think about chained
// VAR_PTR + READ_PTR calls).
static bool fn_remove_unused_vars(struct ir_function *fn)
{
    uint8_t *b = bitv_new(NULL, fn->vars_count);
    for (int n = 0; n < fn->nested_functions_count; n++)
        mark_upvars(fn, b, fn->nested_functions[n]);
    for (int n = 0; n < fn->blocks_count; n++) {
        for (struct ir_inst *in = fn->blocks[n]->first; in; in = in->next) {
            if (in->op == IR_OP_VAR_PTR || in->op == IR_OP_READ_VAR) {
                if (inst_has_users(in))
                    bitv_set(b, in->var->index);
            }
        }
    }
    for (int n = 0; n < fn->blocks_count; n++) {
        struct ir_inst *in = fn->blocks[n]->first;
        while (in) {
            if (in->op == IR_OP_READ_VAR || in->op == IR_OP_WRITE_VAR
                || in->op == IR_OP_VAR_PTR)
            {
                if (!bitv_get(b, in->var->index)) {
                    struct ir_inst *next = in->next;
                    bb_kill_inst(in->bb, in);
                    in = next;
                    continue;
                }
            }
            in = in->next;
        }
    }
    bool change = false;
    for (int n = fn->vars_count - 1; n >= 0; n--) {
        if (!bitv_get(b, n)) {
            struct ir_var *var = fn->vars[n];
            fn_remove_var(fn, var);
            talloc_free(var);
            change = true;
        }
    }
    talloc_free(b);
    return change;
}

// Do a bunch of relatively cheap optimizations.
bool fn_simplify(struct ir_function *fn)
{
    bool any_change = false;
    for (;;) {
        bool change = false;
        change |= fn_simplify_insts(fn);
        change |= fn_remove_neutral_code(fn);
        change |= fn_shortcut_jumps(fn);
        change |= fn_remove_unreachable_blocks(fn);
        change |= fn_merge_adjacent_blocks(fn);
        change |= fn_dumbass_to_ssa(fn);
        change |= fn_remove_unused_vars(fn);
        change |= fn_local_cse(fn);
        any_change |= change;
        if (!change)
            break;
    }
    return any_change;
}

static int index_of_fn(struct ir_function *parent, struct ir_function *fn)
{
    if (fn->parent != parent)
        return -1;
    for (int n = 0; n < parent->nested_functions_count; n++) {
        if (parent->nested_functions[n] == fn)
            return n;
    }
    assert(false);
}

// Nested function calls form a dependency graph. Maybe it's a bit simpler, but
// at least it's not a simple tree.
static bool mark_nested_fn_use(struct ir_function *parent,
                               struct ir_function *fn,
                               uint8_t *b)
{
    bool change = false;
    for (int n = 0; n < fn->blocks_count; n++) {
        for (struct ir_inst *in = fn->blocks[n]->first; in; in = in->next) {
            if (in->fn) {
                struct ir_function *f = in->fn->body;
                if (f && f->parent == parent) {
                    int i = index_of_fn(parent, f);
                    if (!bitv_get(b, i)) {
                        bitv_set(b, i);
                        change = true;
                    }
                }
            }
        }
    }
    for (int n = 0; n < fn->nested_functions_count; n++) {
        if (fn->parent != parent || bitv_get(b, n))
            change |= mark_nested_fn_use(fn, fn->nested_functions[n], b);
    }
    return change;
}

static bool fn_remove_unused_nested_fns(struct ir_function *fn)
{
    if (!fn->nested_functions_count)
        return false;
    bool change = false;
    for (int n = 0; n < fn->nested_functions_count; n++)
        change |= fn_remove_unused_nested_fns(fn->nested_functions[n]);
    uint8_t *b = talloc_zero_array(NULL, uint8_t,
                                   bitv_size(fn->nested_functions_count));
    while (mark_nested_fn_use(fn, fn, b)) {
    }
    for (int n = fn->nested_functions_count - 1; n >= 0; n--) {
        if (!bitv_get(b, n)) {
            talloc_free(fn->nested_functions[n]);
            BL_TARRAY_REMOVE_AT(fn->nested_functions,
                                fn->nested_functions_count, n);
            change = true;
        }
    }
    talloc_free(b);
    return change;
}

bool fn_simplify_harder(struct ir_function *fn)
{
    bool any_change = false;
    for (;;) {
        bool change = false;
        change |= fn_simplify(fn);
        for (int n = 0; n < fn->nested_functions_count; n++)
            change |= fn_simplify_harder(fn->nested_functions[n]);
        change |= fn_remove_unused_nested_fns(fn);
        any_change |= change;
        if (!change)
            break;
    }
    return any_change;
}

// Split the block at "in". All instructions after in will be moved to a new
// block. A jump to the new block is added after in. The new block is returned.
static struct ir_bb *bb_split(struct ir_inst *in)
{
    assert(!ir_op_is_branch(in->op));
    struct ir_bb *old = in->bb;
    struct ir_bb *new = fn_add_bb(old->fn);
    while (in->next) {
        inst_move_to(in->next, new, new->last);
    }
    bb_add_jump(old, in->loc, new);
    return new;
}

// Return the function that could be inlined for this instruction.
// Also checks basic inlining requirements.
static struct ir_function *inst_get_fn_for_inline(struct ir_inst *call)
{
    if (call->op == IR_OP_CALL) {
        struct ir_function *fn = call->fn->body;
        // Supporting nested functions require complicated logic to fix up
        // nested function calls and upvalues.
        if (fn && fn->nested_functions_count == 0)
            return fn;
    }
    return NULL;
}

// Inline the given call, remove & deallocate the call instruction, and return
// the instruction that replaced the call at the end of the inlined IR.
static struct ir_inst *fn_inline_call(struct ir_inst *call)
{
    struct ir_function *fn = call->bb->fn;
    struct ir_function *infn = inst_get_fn_for_inline(call);
    assert(infn);
    struct ir_bb *tail = bb_split(call);
    int b_0 = fn->blocks_count;
    struct ir_bb *entry = fn_inline_code(fn, infn);
    struct ir_inst **results = NULL;
    int results_count = 0;
    // Turn the call into a jump to the entry block, and turn all returns into
    // jumps to the code after the call. Also rewrite IR_OP_GETARG into
    // IR_OP_COPY of the call instruction arguments.
    // fn_simplify() can take care of unsplitting the blocks again if the
    // inlined code was simple.
    bb_rewire_jump(call->bb, tail, entry);
    for (int b = b_0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            if (in->op == IR_OP_RET) {
                BL_TARRAY_APPEND(NULL, results, results_count,
                                 inst_getuse(in, 0));
                //in = bb_replace_inst_dup(in, &(struct ir_inst)
                //    {in->loc, IR_OP_GOTO, IR_INST_NO_TYPE, .branch = {tail}});
                bb_remove_inst(bb, in);
                bb_add_inst_dup(bb, INST(in->loc, IR_OP_GOTO, IR_INST_NO_TYPE,
                                         .branch = {tail}));
            } else if (in->op == IR_OP_GETARG) {
                int arg = in->struct_member->index;
                struct ir_inst *r = inst_getuse(call, arg);
                in = bb_replace_inst_dup(in, INST(in->loc, IR_OP_COPY,
                                                  in->result_type, INST_R1(r)));
            } else if (in->op == IR_OP_UPVAL_PTR) {
                if (in->var->fn == fn)
                    in->op = IR_OP_VAR_PTR;
            }
        }
    }
    struct ir_inst *result = INST_NEW(call->loc, IR_OP_PHI, call->result_type,
                                      .read_count = results_count);
    for (int n = 0; n < results_count; n++)
        result->read[n].def = results[n];
    talloc_free(results);
    bb_add_inst_after(tail, NULL, result);
    bb_replace_inst(call, result);
    //printf("post inline:\n");
    //dump_fn(stdout, fn);
    return result;
}

// The hardest part about inlining is finding a good metric (code size vs.
// number of calls, and also making the inlining algorithm reach a stable
// state).
// This function disregards this and tries to inline everything.
bool fn_inline_all(struct ir_function *fn)
{
    bool change = false;

    for (int n = 0; n < fn->nested_functions_count; n++) {
        change |= fn_inline_all(fn->nested_functions[n]);
    }

    int old_block_count = fn->blocks_count;
    for (int b = 0; b < old_block_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            struct ir_function *inl = inst_get_fn_for_inline(in);
            if (inl && inl != fn) {
                in = fn_inline_call(in);
                change = true;
            }
        }
    }

    fn_remove_unused_nested_fns(fn);
    return change;
}

void unit_optimize(struct ir_unit *unit, struct optimize_settings *opt)
{
    for (int n = 0; n < unit->fn_decls_count; n++) {
        struct ir_fn_decl *fnd = unit->fn_decls[n];
        struct ir_function *fn = fnd->body;

        if (fn) {
            int passes = opt->opt_inline ? 2 : 1;
            for (int i = 0; i < passes; i++) {
                if (opt->opt_inline)
                    fn_inline_all(fn);
                fn_simplify_harder(fn);
            }
        }
    }
}
