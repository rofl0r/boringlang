// this is some butt-ugly, but strictly debugging-only code
// => hide it away from the rest

#include "talloc.h"
#include "hashtable.h"
#include "ir.h"
#include "value.h"

static int index_of_block(struct ir_function *fn, struct ir_bb *bb)
{
    for (int n = 0; n < fn->blocks_count; n++)
        if (fn->blocks[n] == bb)
            return n;
    return -1;
}

static int index_of_inst(struct ir_bb *bb, struct ir_inst *s_inst)
{
    int n = 0;
    for (struct ir_inst *inst = bb->first; inst; inst = inst->next) {
        if (inst == s_inst)
            return n;
        n++;
    }
    return -1;
}

static void verify_type(struct ir_types *types, struct ir_type t);

static void verify_struct_type(struct ir_types *types,
                               struct ir_struct_type *st)
{
    assert(st);
    if (st->defined) {
        assert(st->init);
        assert(st->init->type == st);
        for (int n = 0; n < st->members_count; n++) {
            struct ir_struct_member *m = st->members[n];
            verify_type(types, m->type);
            assert(m->index == n);
            assert(m->init);
            assert(type_equals(m->init->type, m->type));
        }
    } else {
        assert(st->members_count == 0);
        assert(!st->init);
    }
}

static void verify_type(struct ir_types *types, struct ir_type t)
{
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error: assert_msg(false, "error type"); break;
        // only allow "discrete" types in final code, no placeholder types
        case IR_TYPE_any: assert_msg(false, "any type"); break;
        case IR_TYPE_tuntyped: break;
        case IR_TYPE_tbool: break;
        case IR_TYPE_tint:
            assert(((unsigned)*GET_UNION(IR_TYPE, tint, &t)) <= 7);
            break;
        case IR_TYPE_tdouble: break;
        case IR_TYPE_tptr:
            verify_type(types, **GET_UNION(IR_TYPE, tptr, &t));
            break;
        case IR_TYPE_tstruct: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tstruct, &t);
            verify_struct_type(types, st);
            break;
        }
        case IR_TYPE_ttuple: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, ttuple, &t);
            assert(st);
            assert(st->defined);
            verify_struct_type(types, st);
            break;
        }
        case IR_TYPE_tcompound: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tcompound, &t);
            assert(st);
            assert(st->defined);
            verify_struct_type(types, st);
            break;
        }
        case IR_TYPE_tfn: {
            struct ir_fn_type *fn = *GET_UNION(IR_TYPE, tfn, &t);
            verify_type(types, fn->ret_type);
            assert(!fn->args->init);
            assert(fn->args->defined);
            for (int n = 0; n < fn->args->members_count; n++) {
                struct ir_struct_member *m = fn->args->members[n];
                verify_type(types, m->type);
                assert(m->index == n);
                if (m->init)
                    assert(type_equals(m->init->type, m->type));
            }
            // xxx check last argument for proper vararg type
            //     until then, we can't allow them
            if (fn->vararg == IR_VARARG_NATIVE) {
                assert(fn->args->members_count > 0);
                assert(type_equals(
                    fn->args->members[fn->args->members_count-1]->type,
                    types->varargs));
            }
            break;
        }
        case IR_TYPE_tstackclosure: {
            struct ir_fn_type *fn = *GET_UNION(IR_TYPE, tstackclosure, &t);
            assert(fn->args->members_count > 0);
            assert(type_equals(fn->args->members[0]->type, TYPE_G_PTR));
            verify_type(types, MAKE_IR_TYPE(tfn, fn));
            break;
        }
        case IR_TYPE_tarray: {
            struct ir_array_type *tarr = *GET_UNION(IR_TYPE, tarray, &t);
            verify_type(types, tarr->item_type);
            // xxx should probably check whether size exceeds address space
            assert(tarr->dimension >= 0);
            break;
        }
        case IR_TYPE_tslice:
            verify_type(types, **GET_UNION(IR_TYPE, tslice, &t));
            break;
        default:
            assert(false);
    }
}

static void verify_const(struct ir_types *types, struct ir_const_val c)
{
    verify_type(types, c.type);
    struct value *rv = &c.value;
    // @ALL ir_type_type
    switch (c.type.type) {
    case IR_TYPE_error:
    case IR_TYPE_any:
    case IR_TYPE_tuntyped:
        assert(false);
    case IR_TYPE_tbool: {
        uint64_t b = *GET_UNION(VALUE, vuint64, rv);
        assert(b == !!b);
        return;
    }
    case IR_TYPE_tint: {
        uint64_t u = *GET_UNION(VALUE, vuint64, rv);
        int bits = type_get_bits(c.type);
        uint64_t mask = bits == 64 ? (uint64_t)-1 : (UINT64_C(1) << bits) - 1;
        if (!type_get_sign(c.type)) {
            assert((u & ~mask) == 0);
        } else {
            bool sign = ((int64_t)u) < 0;
            if (sign) {
                assert(((u | mask) == (uint64_t)-1));
            } else {
                assert((u & ~mask) == 0);
            }
        }
        return;
    }
    case IR_TYPE_tdouble:
        (void)*GET_UNION(VALUE, vdouble, rv);
        return;
    case IR_TYPE_tptr:
        assert(rv->type == VALUE_vptr || rv->type == VALUE_vempty);
        return;
    case IR_TYPE_tstruct:
    case IR_TYPE_ttuple:
    case IR_TYPE_tcompound:
        (void)*GET_UNION(VALUE, vstruct, rv);
        return;
    case IR_TYPE_tarray:
        (void)*GET_UNION(VALUE, varray, rv);
        return;
    case IR_TYPE_tfn:
    case IR_TYPE_tstackclosure:
    case IR_TYPE_tslice:
        assert(rv->type == VALUE_vstring || rv->type == VALUE_vempty);
        if (rv->type == VALUE_vstring)
            assert(*GET_UNION(VALUE, vstring, rv));
        return;
    default: assert(false);
    }
}

// Check that in is really a part of fn.
static void verify_inst_ref(struct ir_function *fn, struct ir_inst *in)
{
    assert(in);
    assert(in->bb);
    assert(index_of_block(fn, in->bb) >= 0);
    assert(index_of_inst(in->bb, in) >= 0);
}

static void verify_var_ref(struct ir_function *fn, struct ir_var *v)
{
    assert(v->fn == fn);
    for (int n = 0; n < fn->vars_count; n++) {
        if (fn->vars[n] == v)
            return;
    }
    assert(false);
}

static void verify_is_struct_member(struct ir_struct_type *st,
                                    struct ir_struct_member *m)
{
    bool found = false;
    for (int n = 0; n < st->members_count; n++) {
        if (st->members[n] == m) {
            found = true;
            break;
        }
    }
    assert(found);
}

struct verify_inst_data {
    int reads, writes;
    int branches;
    bool read_same_type;
    bool all_same_type;
    bool has_var, has_const, has_struct_member, has_fn;
};

// @ALL ir_opcode
static const struct verify_inst_data verify_insts[IR_OP_END] = {
    [IR_OP_NOP] = { 0 },
    [IR_OP_COPY] = { 1, 1, .all_same_type = true },
    [IR_OP_PHI] = { -1, 1, .all_same_type = true },
    [IR_OP_GOTO] = { .branches = 1 },
    [IR_OP_BRANCH] = { 1, .branches = 2 },
    [IR_OP_RET] = { 1 },
    [IR_OP_ABORT] = { 0 },
    [IR_OP_GETARG] = { 0, 1, .has_struct_member = true },
    [IR_OP_READ_VAR] = { 0, 1, .has_var = true },
    [IR_OP_WRITE_VAR] = { 1, 0, .has_var = true },
    [IR_OP_VAR_PTR] = { 0, 1, .has_var = true },
    [IR_OP_UPVAL_PTR] = { 0, 1, .has_var = true },
    [IR_OP_UPVAL_CONTEXT] = { 0, 1, .has_fn = true },
    [IR_OP_MAKE_CLOSURE] = { 2, 1 },
    [IR_OP_GET_CLOSURE_FN] = { 1, 1 },
    [IR_OP_GET_CLOSURE_CTX] = { 1, 1 },
    [IR_OP_GET_STRUCT_MEMBER_PTR] = { 1, 1, .has_struct_member = true },
    [IR_OP_CONSTRUCT_STRUCT] = { -1, 1 },
    [IR_OP_GET_STRUCT_MEMBER] = { 1, 1, .has_struct_member = true },
    [IR_OP_SET_STRUCT_MEMBER] = { 2, 1, .has_struct_member = true },
    [IR_OP_CONSTRUCT_SLICE] = { 2, 1 },
    [IR_OP_SLICE] = { 3, 1 },
    [IR_OP_SLICE_COPY] = { 2, 0, .read_same_type = true },
    [IR_OP_SLICE_SET] = { 2, 0 },
    [IR_OP_GET_SLICE_LENGTH] = { 1, 1 },
    [IR_OP_GET_SLICE_PTR] = { 1, 1 },
    [IR_OP_GET_SLICE_ITEM_PTR] = { 2, 1 },
    [IR_OP_CONSTRUCT_ARRAY] = { -1, 1, .read_same_type = true },
    [IR_OP_ARRAY_TO_SLICE] = { 1, 1},
    [IR_OP_READ_PTR] = { 1, 1 },
    [IR_OP_WRITE_PTR] = { 2, 0 },
    [IR_OP_LOAD_CONST] = { 0, 1, .has_const = true },
    [IR_OP_FN_PTR] = { 0, 1, .has_fn = true },
    [IR_OP_CALL] = { -1, 1, .has_fn = true },
    [IR_OP_CALL_PTR] = { -1, 1 },
    [IR_OP_NEG] = { 1, 1, .all_same_type = true },
    [IR_OP_NOT] = { 1, 1, .all_same_type = true },
    [IR_OP_CONV_INT_TRUNC] = { 1, 1 },
    [IR_OP_CONV_INT_SIGN] = { 1, 1 },
    [IR_OP_CONV_INT_EXT] = { 1, 1 },
    [IR_OP_CONV_TO_G_PTR] = { 1, 1 },
    [IR_OP_CONV_FROM_G_PTR] = { 1, 1 },
    [IR_OP_ADD] = { 2, 1, .all_same_type = true },
    [IR_OP_SUB] = { 2, 1, .all_same_type = true },
    [IR_OP_MUL] = { 2, 1, .all_same_type = true },
    [IR_OP_DIV] = { 2, 1, .all_same_type = true },
    [IR_OP_MOD] = { 2, 1, .all_same_type = true },
    [IR_OP_AND] = { 2, 1, .all_same_type = true },
    [IR_OP_OR] = { 2, 1, .all_same_type = true },
    [IR_OP_XOR] = { 2, 1, .all_same_type = true },
    [IR_OP_SHIFT_R] = { 2, 1, .all_same_type = true },
    [IR_OP_SHIFT_L] = { 2, 1, .all_same_type = true },
    [IR_OP_EQ] = { 2, 1, .read_same_type = true },
    [IR_OP_NOT_EQ] = { 2, 1, .read_same_type = true },
    [IR_OP_CMP_LT] = { 2, 1, .read_same_type = true },
    [IR_OP_CMP_GT] = { 2, 1, .read_same_type = true },
    [IR_OP_CMP_LT_EQ] = { 2, 1, .read_same_type = true },
    [IR_OP_CMP_GT_EQ] = { 2, 1, .read_same_type = true },
};

// Check invariants. This is strictly for debugging only.
void fn_verify(struct ir_function *fn)
{
    assert(fn->unit);
    struct ir_types *types = fn->unit->global_types;
    for (int n = 0; n < fn->nested_functions_count; n++) {
        struct ir_function *nfn = fn->nested_functions[n];
        assert(nfn->parent == fn);
        fn_verify(nfn);
    }
    //dump_fn(stderr, fn);
    void *tctx = talloc_new(NULL);
    assert(fn->type);
    verify_type(types, MAKE_IR_TYPE(tfn, fn->type));
    for (int n = 0; n < fn->vars_count; n++) {
        assert(fn->vars[n]->index == n);
        assert(fn->vars[n]->fn == fn);
        struct ir_type t = fn->vars[n]->type;
        struct ir_type pt = fn->vars[n]->ptr_type;
        verify_type(types, t);
        assert(type_is_complete(t));
        verify_type(types, pt);
        assert(type_equals(type_unptr(pt), t));
    }
    assert(fn->entry);
    assert(index_of_block(fn, fn->entry) >= 0);
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *block = fn->blocks[b];
        assert(block->index == b);
        assert(block->first);
        for (int n = 0; n < block->jump_from_count; n++) {
            struct ir_bb *from = block->jump_from[n];
            assert(index_of_block(fn, from) >= 0);
            bool found = false;
            for (int i = 0; i < from->jump_to_count; i++) {
                if (from->jump_to[i] == block) {
                    found = true;
                    break;
                }
            }
            assert(found);
        }
        for (int n = 0; n < block->jump_to_count; n++) {
            struct ir_bb *to = block->jump_to[n];
            assert(index_of_block(fn, to) >= 0);
            bool found = false;
            for (int i = 0; i < to->jump_from_count; i++) {
                if (to->jump_from[i] == block) {
                    found = true;
                    break;
                }
            }
            assert(found);
        }
        if (fn->entry == block)
            assert(block->jump_from_count == 0);
        struct hashtable *idef = ht_create(NULL, HT_DATA_dptr, HT_DATA_dint);
        bool in_phi = true;
        for (struct ir_inst *in = block->first; in; in = in->next) {
            assert(in->bb == block);
            assert(!HT_GET_DEF(dptr, dint, idef, in, 0));
            HT_INSERT(dptr, dint, idef, in, 1);
            int writes = 0;
            if (in->result_type.type != IR_TYPE_any) {
                writes = 1;
                verify_type(types, in->result_type);
            }
            // xxx doesn't check that
            //          number of entries == number of uses
            // when another inst. reads "in" more than once
            for (int n = 0; n < in->users_count; n++) {
                struct ir_inst *other = in->users[n];
                bool found = false;
                for (int i = 0; i < other->read_count; i++) {
                    if (other->read[i].def == in) {
                        found = true;
                        break;
                    }
                }
                assert(found);
            }
            bool is_last_inst = in == block->last;
            bool is_phi = in->op == IR_OP_PHI;
            if (in_phi) {
                in_phi = is_phi;
            } else {
                assert(!is_phi);
            }
            int reads = in->read_count;
            if (is_phi) {
                assert(reads == block->jump_from_count);
                assert(block != fn->entry);
            }
            for (int n = 0; n < reads; n++)
                verify_type(types, in->read[n].def->result_type);
            const struct verify_inst_data *v = &verify_insts[in->op];
            if (v->reads >= 0) assert(v->reads == reads);
            if (v->writes >= 0) assert(v->writes == writes);
            assert(writes < 2);
            for (int x = 0; x < reads; x++) {
                struct ir_inst *r = in->read[x].def;
                assert(r != in);
                verify_inst_ref(fn, r);
                if (r->bb == block)
                    assert(HT_GET_DEF(dptr, dint, idef, r, 0));
                bool found = false;
                for (int n = 0; n < r->users_count; n++) {
                    if (r->users[n] == in) {
                        found = true;
                        break;
                    }
                }
                assert(found);
                // xxx verify that the read is dominated by the source
            }
            if ((v->read_same_type || v->all_same_type) && reads > 0) {
                struct ir_inst *v1 = in->read[0].def;
                for (int x = 1; x < reads; x++)
                    assert(type_equals(v1->result_type,
                                       in->read[x].def->result_type));
                if (v->all_same_type && v1 && writes > 0)
                    assert(type_equals(v1->result_type, in->result_type));
            }
            assert(!!in->const_value == v->has_const);
            if (in->const_value)
                verify_const(types, *in->const_value);
            assert(!!in->struct_member == v->has_struct_member);
            assert(!!in->var == v->has_var);
            if (v->has_var) {
                if (in->op != IR_OP_UPVAL_PTR) {
                    verify_var_ref(fn, in->var);
                } else {
                    assert(fn_can_access_upval(fn, in->var));
                    verify_var_ref(in->var->fn, in->var);
                }
            }
            assert(!!in->fn == v->has_fn);
            int branches = !!in->branch[0] + !!in->branch[1];
            if (v->branches >= 0)
                assert(v->branches == branches);
            // this is always decomposed in basic blocks
            bool is_jump_inst = ir_op_is_branch(in->op);
            if (branches > 0)
                assert(is_jump_inst);
            assert(is_last_inst == is_jump_inst);
            if (is_jump_inst)
                assert(block->jump_to_count == v->branches);
            for (int x = 0; x < v->branches; x++)
                assert(block->jump_to[x] == in->branch[x]);
            struct ir_type t_w = in->result_type;
            if (writes)
                assert(type_is_complete(t_w));
            struct ir_type t_r1 =
                reads > 0 ? in->read[0].def->result_type : TYPE_ERROR;
            struct ir_type t_r2 =
                reads > 1 ? in->read[1].def->result_type : TYPE_ERROR;
            struct ir_type t_r3 =
                reads > 2 ? in->read[2].def->result_type : TYPE_ERROR;
            // @ALL ir_opcode
            switch (in->op) {
                case IR_OP_NOP: break;
                case IR_OP_COPY: break;
                case IR_OP_PHI:
                    assert(reads > 0);  // at least 1
                    break;
                case IR_OP_GOTO: break;
                case IR_OP_BRANCH:
                    assert(type_equals(t_r1, TYPE_BOOL));
                    break;
                case IR_OP_RET:
                    assert(type_equals(t_r1, fn->type->ret_type));
                    break;
                case IR_OP_ABORT: break;
                case IR_OP_GETARG: {
                    verify_is_struct_member(fn->type->args, in->struct_member);
                    assert(type_equals(in->struct_member->type,
                                       in->result_type));
                    break;
                }
                case IR_OP_READ_VAR:
                    assert(type_equals(t_w, in->var->type));
                    break;
                case IR_OP_WRITE_VAR:
                    assert(type_equals(t_r1, in->var->type));
                    break;
                case IR_OP_VAR_PTR:
                case IR_OP_UPVAL_PTR:
                    assert(type_is_ptr(t_w));
                    assert(type_equals(type_unptr(t_w), in->var->type));
                    break;
                case IR_OP_UPVAL_CONTEXT:
                    assert(type_equals(t_w, TYPE_G_PTR));
                    break;
                case IR_OP_MAKE_CLOSURE:
                    assert(TEST_UNION(IR_TYPE, tstackclosure, &t_w));
                    assert(type_equals(t_r1, MAKE_IR_TYPE(tfn,
                                    *GET_UNION(IR_TYPE, tstackclosure, &t_w))));
                    assert(type_equals(t_r2, TYPE_G_PTR));
                    break;
                case IR_OP_GET_CLOSURE_FN:
                    assert(TEST_UNION(IR_TYPE, tstackclosure, &t_r1));
                    assert(type_equals(t_w, MAKE_IR_TYPE(tfn,
                                   *GET_UNION(IR_TYPE, tstackclosure, &t_r1))));
                    break;
                case IR_OP_GET_CLOSURE_CTX:
                    assert(TEST_UNION(IR_TYPE, tstackclosure, &t_r1));
                    assert(type_equals(t_w, TYPE_G_PTR));
                    break;
                case IR_OP_GET_STRUCT_MEMBER_PTR: {
                    assert(type_is_ptr(t_r1));
                    struct ir_type st_t = type_unptr(t_r1);
                    assert(type_is_structlike(st_t));
                    struct ir_struct_type *st = type_get_structlike(st_t);
                    verify_is_struct_member(st, in->struct_member);
                    assert(type_is_ptr(t_w));
                    assert(type_equals(type_unptr(t_w),
                                       in->struct_member->type));
                    break;
                }
                case IR_OP_CONSTRUCT_STRUCT: {
                    assert(type_is_structlike(t_w));
                    struct ir_struct_type *st = type_get_structlike(t_w);
                    assert(st->members_count == reads);
                    for (int n = 0; n < st->members_count; n++)
                        assert(type_equals(st->members[n]->type,
                                           in->read[n].def->result_type));
                    break;
                }
                case IR_OP_GET_STRUCT_MEMBER: {
                    assert(type_is_structlike(t_r1));
                    struct ir_struct_type *st = type_get_structlike(t_r1);
                    verify_is_struct_member(st, in->struct_member);
                    assert(type_equals(in->struct_member->type,
                                       in->result_type));
                    break;
                }
                case IR_OP_SET_STRUCT_MEMBER: {
                    assert(type_equals(t_r1, t_w));
                    assert(type_is_structlike(t_r1));
                    struct ir_struct_type *st = type_get_structlike(t_r1);
                    verify_is_struct_member(st, in->struct_member);
                    assert(type_equals(in->struct_member->type, t_r2));
                    break;
                }
                case IR_OP_CONSTRUCT_SLICE: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_w));
                    struct ir_type itemt = type_item_type(t_w);
                    assert(type_equals(type_unptr(t_r1), itemt));
                    assert(type_equals(t_r2, types->index));
                    break;
                }
                case IR_OP_SLICE: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    assert(type_equals(t_w, t_r1));
                    assert(type_equals(t_r2, types->index));
                    assert(type_equals(t_r3, types->index));
                    break;
                }
                case IR_OP_SLICE_COPY: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    assert(type_equals(t_r1, t_r2));
                    break;
                }
                case IR_OP_SLICE_SET: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    struct ir_type itemt = type_item_type(t_r1);
                    assert(type_equals(itemt, type_unptr(t_w)));
                    break;
                }
                case IR_OP_GET_SLICE_LENGTH: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    assert(type_equals(t_w, types->index));
                    break;
                }
                case IR_OP_GET_SLICE_PTR: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    struct ir_type itemt = type_item_type(t_r1);
                    assert(type_equals(type_unptr(t_w), itemt));
                    break;
                }
                case IR_OP_GET_SLICE_ITEM_PTR: {
                    assert(TEST_UNION(IR_TYPE, tslice, &t_r1));
                    struct ir_type itemt = type_item_type(t_r1);
                    assert(type_equals(t_r2, types->index));
                    assert(type_equals(type_unptr(t_w), itemt));
                    break;
                }
                case IR_OP_CONSTRUCT_ARRAY: {
                    struct ir_array_type *a = *GET_UNION(IR_TYPE, tarray, &t_w);
                    assert(reads == a->dimension);
                    if (reads > 0)
                        assert(type_equals(t_r1, a->item_type));
                    break;
                }
                case IR_OP_ARRAY_TO_SLICE: {
                    struct ir_type unp = type_unptr(t_r1);
                    struct ir_array_type *a = *GET_UNION(IR_TYPE, tarray, &unp);
                    assert(TEST_UNION(IR_TYPE, tslice, &t_w));
                    struct ir_type itemt = type_item_type(t_w);
                    assert(type_equals(itemt, a->item_type));
                    break;
                }
                case IR_OP_READ_PTR:
                    assert(type_is_ptr(t_r1));
                    assert(type_equals(type_unptr(t_r1), t_w));
                    assert(type_is_complete(t_w));
                    break;
                case IR_OP_WRITE_PTR:
                    assert(type_is_ptr(t_r1));
                    assert(type_equals(type_unptr(t_r1), t_r2));
                    assert(type_is_complete(t_r1));
                    break;
                case IR_OP_LOAD_CONST:
                    assert(type_equals(t_w, in->const_value->type));
                    break;
                case IR_OP_FN_PTR:
                    assert(type_equals(in->result_type,
                                       MAKE_IR_TYPE(tfn, in->fn->type)));
                    break;
                case IR_OP_CALL: {
                    struct ir_fn_type *t = in->fn->type;
                    int fn_args = t->args->members_count;
                    if (t->vararg != IR_VARARG_C) {
                        assert(fn_args == reads);
                    } else {
                        assert(fn_args <= reads);
                    }
                    for (int n = 0; n < fn_args; n++)
                        assert(type_equals(in->read[n].def->result_type,
                                           t->args->members[n]->type));
                    assert(type_equals(in->result_type, t->ret_type));
                    break;
                }
                case IR_OP_CALL_PTR: {
                    assert(in->read_count >= 1);
                    struct ir_inst *fnv = in->read[0].def;
                    struct ir_fn_type **pfn = TEST_UNION(IR_TYPE, tfn,
                                                         &fnv->result_type);
                    assert(pfn);
                    struct ir_fn_type *t = *pfn;
                    if (t->vararg != IR_VARARG_C) {
                        assert(t->args->members_count == in->read_count - 1);
                    } else {
                        assert(t->args->members_count <= in->read_count - 1);
                    }
                    for (int n = 1; n < in->read_count; n++)
                        assert(type_equals(in->read[n].def->result_type,
                                           t->args->members[n - 1]->type));
                    assert(type_equals(in->result_type, t->ret_type));
                    break;
                }
                case IR_OP_NEG:
                    assert(type_is_integer(t_r1) || type_is_fp(t_r1));
                    break;
                case IR_OP_NOT:
                    assert(type_is_integer(t_r1) || t_r1.type == IR_TYPE_tbool);
                    break;
                case IR_OP_CONV_INT_TRUNC:
                    assert(type_is_integer(t_r1) && type_is_integer(t_w));
                    assert(type_get_bits(t_r1) > type_get_bits(t_w));
                    assert(type_get_sign(t_r1) == type_get_sign(t_w));
                    break;
                case IR_OP_CONV_INT_SIGN:
                    assert(type_is_integer(t_r1) && type_is_integer(t_w));
                    assert(type_get_bits(t_r1) == type_get_bits(t_w));
                    assert(type_get_sign(t_r1) != type_get_sign(t_w));
                    break;
                case IR_OP_CONV_INT_EXT:
                    assert(type_is_integer(t_r1) && type_is_integer(t_w));
                    assert(type_get_bits(t_r1) < type_get_bits(t_w));
                    assert(type_get_sign(t_r1) == type_get_sign(t_w));
                    break;
                case IR_OP_CONV_TO_G_PTR:
                    assert(type_is_ptr(t_r1) && type_is_untyped_ptr(t_w));
                    break;
                case IR_OP_CONV_FROM_G_PTR:
                    assert(type_is_untyped_ptr(t_r1) && type_is_ptr(t_w));
                    break;
                case IR_OP_ADD:
                case IR_OP_SUB:
                case IR_OP_MUL:
                case IR_OP_DIV:
                case IR_OP_MOD:
                    assert(type_is_integer(t_r1) || type_is_fp(t_r1));
                    break;
                case IR_OP_AND:
                case IR_OP_OR:
                case IR_OP_XOR:
                    assert(type_is_integer(t_r1) || t_r1.type == IR_TYPE_tbool);
                    break;
                case IR_OP_SHIFT_R:
                case IR_OP_SHIFT_L:
                    assert(type_is_integer(t_r1));
                    break;
                case IR_OP_EQ:
                case IR_OP_NOT_EQ:
                    // See @COMPARABLE
                    assert(type_is_integer(t_r1) || type_is_fp(t_r1)
                           || type_is_ptr(t_r1) || t_r1.type == IR_TYPE_tbool);
                    assert(t_w.type == IR_TYPE_tbool);
                    break;
                case IR_OP_CMP_LT:
                case IR_OP_CMP_GT:
                case IR_OP_CMP_LT_EQ:
                case IR_OP_CMP_GT_EQ:
                    assert(type_is_integer(t_r1) || type_is_fp(t_r1));
                    assert(t_w.type == IR_TYPE_tbool);
                    break;
                default:
                    assert(false);
            }
        }
        talloc_free(idef);
    } //blocks
    talloc_free(tctx);
}
