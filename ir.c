#include "talloc.h"
#include "hashtable.h"
#include "ir.h"
#include "value.h"

struct inst_info {
    const char *name;
    bool read_se;
    bool write_se;
    bool is_branch;
};

// @ALL ir_opcode
static const struct inst_info inst_infos[IR_OP_END] = {
    [IR_OP_NOP] =               { "nop" },
    [IR_OP_COPY] =              { "copy" },
    [IR_OP_PHI] =               { "phi" },
    [IR_OP_GOTO] =              { "goto",
                                  .is_branch = true },
    [IR_OP_BRANCH] =            { "branch",
                                  .is_branch = true },
    [IR_OP_RET] =               { "ret",
                                  .is_branch = true },
    [IR_OP_ABORT] =             { "abort",
                                  .is_branch = true },
    [IR_OP_GETARG] =            { "getarg" },
    [IR_OP_READ_VAR] =          { "read_var",
                                  .read_se = true },
    [IR_OP_WRITE_VAR] =         { "write_var",
                                  .write_se = true },
    [IR_OP_VAR_PTR] =           { "var_ptr" },
    [IR_OP_UPVAL_PTR] =         { "upval_ptr" },
    [IR_OP_UPVAL_CONTEXT] =     { "upval_context" },
    [IR_OP_MAKE_CLOSURE] =      { "make_closure" },
    [IR_OP_GET_CLOSURE_FN] =    { "get_closure_fn" },
    [IR_OP_GET_CLOSURE_CTX] =   { "get_closure_ctx" },
    [IR_OP_GET_STRUCT_MEMBER_PTR] = { "get_struct_member_ptr" },
    [IR_OP_CONSTRUCT_STRUCT] =  { "construct_struct" },
    [IR_OP_GET_STRUCT_MEMBER] = { "get_struct_member" },
    [IR_OP_SET_STRUCT_MEMBER] = { "set_struct_member" },
    [IR_OP_CONSTRUCT_SLICE] =   { "construct_slice" },
    [IR_OP_SLICE] =             { "slice" },
    [IR_OP_SLICE_COPY] =        { "slice_copy",
                                  .read_se = true, .write_se = true },
    [IR_OP_SLICE_SET] =         { "slice_set",
                                  .write_se = true },
    [IR_OP_GET_SLICE_LENGTH] =  { "get_slice_length" },
    [IR_OP_GET_SLICE_PTR] =     { "get_slice_ptr" },
    [IR_OP_GET_SLICE_ITEM_PTR] = { "get_slice_item_ptr" },
    [IR_OP_CONSTRUCT_ARRAY] =   { "construct_array" },
    [IR_OP_ARRAY_TO_SLICE] =    { "array_to_slice" },
    [IR_OP_READ_PTR] =          { "read_ptr",
                                  .read_se = true },
    [IR_OP_WRITE_PTR] =         { "write_ptr",
                                  .write_se = true },
    [IR_OP_LOAD_CONST] =        { "load_const" },
    [IR_OP_FN_PTR] =            { "fn_ptr" },
    // Some imnstances of call instructions may have less side-effects.
    [IR_OP_CALL] =              { "call",
                                  .read_se = true, .write_se = true },
    [IR_OP_CALL_PTR] =          { "call_ptr",
                                  .read_se = true, .write_se = true },
    [IR_OP_NEG] =               { "neg" },
    [IR_OP_NOT] =               { "not" },
    [IR_OP_CONV_INT_TRUNC] =    { "conv_int_trunc" },
    [IR_OP_CONV_INT_SIGN] =     { "conv_int_sign" },
    [IR_OP_CONV_INT_EXT] =      { "conv_int_ext" },
    [IR_OP_CONV_TO_G_PTR] =     { "conv_to_g_ptr" },
    [IR_OP_CONV_FROM_G_PTR] =   { "conv_from_g_ptr" },
    [IR_OP_ADD] =               { "add" },
    [IR_OP_SUB] =               { "sub" },
    [IR_OP_MUL] =               { "mul" },
    [IR_OP_DIV] =               { "div" },
    [IR_OP_MOD] =               { "mod" },
    [IR_OP_AND] =               { "and" },
    [IR_OP_OR] =                { "or" },
    [IR_OP_XOR] =               { "xor" },
    [IR_OP_SHIFT_R] =           { "shift_r" },
    [IR_OP_SHIFT_L] =           { "shift_l" },
    [IR_OP_EQ] =                { "eq" },
    [IR_OP_NOT_EQ] =            { "not_eq" },
    [IR_OP_CMP_LT] =            { "cmp_lt" },
    [IR_OP_CMP_GT] =            { "cmp_gt" },
    [IR_OP_CMP_LT_EQ] =         { "cmp_lt_eq" },
    [IR_OP_CMP_GT_EQ] =         { "cmp_gt_eq" },
};

const char *ir_op_name(enum ir_opcode op)
{
    return inst_infos[op].name;
}

bool ir_op_is_branch(enum ir_opcode op)
{
    return inst_infos[op].is_branch;
}

// Return true if the instruction observes side-effects.
// e.g. IR_OP_READ_PTR
bool ir_op_reads_side_effects(enum ir_opcode op)
{
    return inst_infos[op].read_se;
}

// Return true if the instruction causes side-effects.
// e.g. IR_OP_WRITE_PTR
bool ir_op_writes_side_effects(enum ir_opcode op)
{
    return inst_infos[op].write_se;
}

bool ir_op_has_side_effects(enum ir_opcode op)
{
    return ir_op_reads_side_effects(op) || ir_op_writes_side_effects(op);
}

struct ir_var *fn_add_var(struct ir_function *fn, LOC loc, struct ir_type t)
{
    struct ir_var *res = talloc_struct(fn, struct ir_var, {
        .index = fn->vars_count,
        .loc = loc,
        .fn = fn,
        .type = t,
        .ptr_type = type_ptr_to(fn->unit->global_types, t),
    });
    BL_TARRAY_APPEND(fn, fn->vars, fn->vars_count, res);
    return res;
}

struct ir_inst *inst_dup(const struct ir_inst *orig)
{
    if (!orig) {
        static const struct ir_inst orig0 = {{0}};
        orig = &orig0;
    }
    struct ir_inst *r = talloc_size(NULL, sizeof(struct ir_inst) +
                                    orig->read_count * sizeof(struct ir_use));
    *r = *orig;
    r->read = (void*)(r + 1);
    if (orig->read) {
        // xxx: should clear use info, if any
        memcpy(r->read, orig->read, sizeof(struct ir_use) * r->read_count);
    } else {
        memset(r->read, 0, sizeof(struct ir_use) * r->read_count);
    }
    if (r->const_value)
        r->const_value = talloc_from(r, struct ir_const_val, r->const_value);
    r->users_count = 0;
    r->users = NULL;
    return r;
}

static void inst_add_user(struct ir_inst *in, struct ir_inst *user)
{
    assert(in->bb && user->bb);
    BL_TARRAY_APPEND(in, in->users, in->users_count, user);
}

// Removes exactly one user from the users multiset.
static void inst_remove_user(struct ir_inst *in, struct ir_inst *user)
{
    assert(in->bb && user->bb);
    for (int n = 0; n < in->users_count; n++) {
        if (in->users[n] == user) {
            if (n + 1 < in->users_count)
                in->users[n] = in->users[in->users_count - 1];
            in->users_count--;
            return;
        }
    }
    assert(false);
}

// for debugging
static int inst_index_of_user(struct ir_inst *in, struct ir_inst *user)
{
    for (int n = 0; n < in->users_count; n++)
        if (in->users[n] == user)
            return n;
    return -1;
}

// Make in->read[read_n] == use
// This deals with keeping track of users.
void inst_use(struct ir_inst *in, int read_n, struct ir_inst *use)
{
    assert(read_n >= 0 && read_n < in->read_count);
    assert(in != use);
    struct ir_inst **p = &in->read[read_n].def;
    if (*p == use)
        return;
    if (use && *p)
        assert(type_equals((*p)->result_type, use->result_type));
    if (*p)
        inst_remove_user(*p, in);
    *p = use;
    if (use)
        inst_add_user(use, in);
}

struct ir_inst *inst_getuse(struct ir_inst *in, int read_n)
{
    assert(read_n >= 0 && read_n < in->read_count);
    return in->read[read_n].def;
}

bool inst_has_users(struct ir_inst *in)
{
    return in->users_count > 0;
}

// "in" reads "use", from any operand, say: in->read[r] == use
// Replace the use such that: in->read[r] == new_use
// May replace more than one use.
void inst_rewire_uses(struct ir_inst *in, struct ir_inst *use,
                      struct ir_inst *new_use)
{
    assert(inst_index_of_user(use, in) >= 0);
    if (use == new_use)
        return;
    for (int r = 0; r < in->read_count; r++) {
        if (in->read[r].def == use)
            inst_use(in, r, new_use);
    }
}

// Change anything that reads from "old" to read "new"
void inst_replace_all_uses(struct ir_inst *old, struct ir_inst *new)
{
    if (old == new)
        return;
    while (old->users_count)
        inst_rewire_uses(old->users[0], old, new);
}

struct ir_bb *fn_add_bb(struct ir_function *fn)
{
    struct ir_bb *bb = talloc_struct(fn, struct ir_bb, {
        .index = fn->blocks_count,
        .fn = fn,
    });
    BL_TARRAY_APPEND(fn, fn->blocks, fn->blocks_count, bb);
    return bb;
}

static void bb_add_jump_from(struct ir_bb *bb, struct ir_bb *src)
{
    BL_TARRAY_APPEND(bb, bb->jump_from, bb->jump_from_count, src);
}

static void bb_remove_jump_from(struct ir_bb *bb, struct ir_bb *src)
{
    for (int n = 0; n < bb->jump_from_count; n++) {
        if (bb->jump_from[n] == src) {
            if (n + 1 < bb->jump_from_count)
                bb->jump_from[n] = bb->jump_from[bb->jump_from_count - 1];
            bb->jump_from_count--;
            return;
        }
    }
    assert(false);
}

void fn_remove_bb(struct ir_function *fn, struct ir_bb *bb)
{
    assert(bb->index >= 0 && bb->index < fn->blocks_count);
    assert(fn->blocks[bb->index] == bb);
    assert(fn->entry != bb);
    for (int n = 0; n < bb->jump_to_count; n++)
        bb_remove_jump_from(bb->jump_to[n], bb);
    BL_TARRAY_REMOVE_AT(fn->blocks, fn->blocks_count, bb->index);
    for (int b = bb->index; b < fn->blocks_count; b++)
        fn->blocks[b]->index = b;
    for (int b = 0; b < fn->blocks_count; b++)
        assert(fn->blocks[b]->index == b);
    bb->index = -1;
}

void fn_remove_var(struct ir_function *fn, struct ir_var *var)
{
    assert(var->fn == fn);
    assert(var->index >= 0 && var->index < fn->vars_count);
    assert(fn->vars[var->index] == var);
    BL_TARRAY_REMOVE_AT(fn->vars, fn->vars_count, var->index);
    for (int n = var->index; n < fn->vars_count; n++)
        fn->vars[n]->index = n;
    for (int n = 0; n < fn->vars_count; n++)
        assert(fn->vars[n]->index == n);
    var->index = -1;
}

// In the given bb, replace jumps from "from" to "to".
// Fixes the jump instruction as well.
void bb_rewire_jump(struct ir_bb *bb, struct ir_bb *from, struct ir_bb *to)
{
    assert(to != bb->fn->entry);
    if (from == to)
        return;
    for (int n = 0; n < bb->jump_to_count; n++) {
        if (bb->jump_to[n] == from) {
            bb->jump_to[n] = to;
            assert(bb->last->branch[n] == from);
            bb->last->branch[n] = to;
            if (from)
                bb_remove_jump_from(from, bb);
            if (to)
                bb_add_jump_from(to, bb);
        }
    }
}

static void branch_account(struct ir_inst *in)
{
    struct ir_bb *bb = in->bb;
    if (ir_op_is_branch(in->op)) {
        // Never allow more than one jump instruction added, because that makes
        // trouble with the jump_to_count field, even with IR_OP_RET etc.
        assert(bb->last == in || !bb->last || !ir_op_is_branch(bb->last->op));
        assert(!bb->jump_to_count);
        for (int n = 0; n < BRANCH_MAX; n++) {
            struct ir_bb *b = in->branch[n];
            if (b) {
                BL_TARRAY_APPEND(bb, bb->jump_to, bb->jump_to_count, b);
                bb_add_jump_from(b, bb);
            }
        }
    }
}

static void branch_unaccount(struct ir_inst *in)
{
    struct ir_bb *bb = in->bb;
    if (ir_op_is_branch(in->op)) {
        for (int n = 0; n < BRANCH_MAX; n++) {
            struct ir_bb *b = in->branch[n];
            if (b)
                bb_remove_jump_from(b, bb);
        }
        bb->jump_to_count = 0;
    }
}

static void uses_account(struct ir_inst *in)
{
    for (int n = 0; n < in->read_count; n++) {
        struct ir_inst *r = in->read[n].def;
        in->read[n].def = NULL;
        inst_use(in, n, r);
    }
}

static void uses_unaccount(struct ir_inst *in)
{
    // Remove use-info, but leave the read entries untouched.
    for (int n = 0; n < in->read_count; n++) {
        struct ir_inst *r = in->read[n].def;
        if (r)
            inst_remove_user(r, in);
    }
}

// If "after" is NULL, add to the beginning.
// Invariant: add->prev == after
static void inst_list_add(struct ir_bb *bb, struct ir_inst *after,
                          struct ir_inst *add)
{
    assert(bb && add->bb == NULL && add->next == NULL && add->prev == NULL);
    if (after) {
        assert(after->bb == bb);
        assert(bb->first && bb->last);
    }
    add->prev = after;
    if (after) {
        add->next = after->next;
        after->next = add;
    } else {
        add->next = bb->first;
        bb->first = add;
    }
    if (add->next) {
        add->next->prev = add;
    } else {
        bb->last = add;
    }
    add->bb = bb;
    talloc_steal(bb, add);
}

static void inst_list_unlink(struct ir_inst *inst)
{
    assert(inst->bb);
    if (inst->next) {
        inst->next->prev = inst->prev;
    } else {
        inst->bb->last = inst->prev;
    }
    if (inst->prev) {
        inst->prev->next = inst->next;
    } else {
        inst->bb->first = inst->next;
    }
    inst->next = inst->prev = NULL;
    inst->bb = NULL;
    // xxx: we'd want to reset the talloc parent of inst
}

// Add "add" so that the final list will look like "after" -> "add"
// If "after" is NULL, add it as first item.
void bb_add_inst_after(struct ir_bb *bb, struct ir_inst *after,
                       struct ir_inst *add)
{
    assert(add->users_count == 0);
    inst_list_add(bb, after, add);
    uses_account(add);
    branch_account(add);
}

// Add "add" so that the final list will look like "add" -> "before"
// If "before" is NULL, add it as first item.
void bb_add_inst_before(struct ir_bb *bb, struct ir_inst *before,
                        struct ir_inst *add)
{
    bb_add_inst_after(bb, before ? before->prev : NULL, add);
}

void bb_remove_inst(struct ir_bb *bb, struct ir_inst *inst)
{
    assert(inst->bb == bb);
    assert(inst->users_count == 0);
    branch_unaccount(inst);
    uses_unaccount(inst);
    inst_list_unlink(inst);
}

void bb_kill_inst(struct ir_bb *bb, struct ir_inst *inst)
{
    bb_remove_inst(bb, inst);
    // Must not be used by anything.
    assert(inst->users_count == 0);
    talloc_free(inst);
}

// Move inst to bb/after (see bb_add_inst_after()). The instruction must have
// already been added to a BB in the same function. (The point of this function
// is to make block splitting/merging more efficient.)
void inst_move_to(struct ir_inst *inst, struct ir_bb *bb,
                  struct ir_inst *after)
{
    assert(inst->bb->fn == bb->fn);
    branch_unaccount(inst);
    inst_list_unlink(inst);
    inst_list_add(bb, after, inst);
    branch_account(inst);
}

void bb_add_inst(struct ir_bb *bb, struct ir_inst *inst)
{
    bb_add_inst_after(bb, bb->last, inst);
}

struct ir_inst *bb_add_inst_dup(struct ir_bb *bb, struct ir_inst *orig)
{
    struct ir_inst *inst = inst_dup(orig);
    bb_add_inst(bb, inst);
    return inst;
}

// Replace all uses of "old" with "new". If new is not added, add it in the
// same position as "old", otherwise don't touch its position.
// The old instruction is free'd.
struct ir_inst *bb_replace_inst(struct ir_inst *old, struct ir_inst *new)
{
    // Clean this up before adding "new", because:
    // - you can't have more than one branch instruction per BB
    // - if old and new have similar reads, that would resize the users arrays
    //   of the source instructions unnecessarily
    branch_unaccount(old);
    uses_unaccount(old);

    if (new->bb) {
        assert(new->bb->fn == old->bb->fn);
    } else {
        bb_add_inst_after(old->bb, old, new);
    }

    inst_replace_all_uses(old, new);

    inst_list_unlink(old);
    talloc_free(old);

    return new;
}

// Replace all uses of "old" with a copy of "orig".
// The copy will be inserted at the same position as "old".
// The old instruction is free'd.
struct ir_inst *bb_replace_inst_dup(struct ir_inst *old,
                                    const struct ir_inst *orig)
{
    return bb_replace_inst(old, inst_dup(orig));
}

struct ir_inst *bb_substitute(struct ir_inst *old, struct ir_inst *new)
{
    return bb_replace_inst_dup(old,
                INST(old->loc, IR_OP_COPY, new->result_type, INST_R1(new)));
}

struct ir_inst *bb_add_binop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                             struct ir_type result_type,
                             struct ir_inst *in1, struct ir_inst *in2)
{
    return BB_ADD_INST(bb, loc, op, result_type, INST_R2(in1, in2));
}

struct ir_inst *bb_add_unop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                            struct ir_type result_type, struct ir_inst *in)
{
    return BB_ADD_INST(bb, loc, op, result_type, INST_R1(in));
}

struct ir_inst *bb_add_nt_binop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                                struct ir_inst *in1, struct ir_inst *in2)
{
    return BB_ADD_INST(bb, loc, op, IR_INST_NO_TYPE, INST_R2(in1, in2));
}

struct ir_inst *bb_add_nt_inst(struct ir_bb *bb, LOC loc, enum ir_opcode op)
{
    return BB_ADD_INST(bb, loc, op, IR_INST_NO_TYPE);
}

struct ir_inst *bb_add_nt_unop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                               struct ir_inst *in)
{
    return BB_ADD_INST(bb, loc, op, IR_INST_NO_TYPE, INST_R1(in));
}

struct ir_inst *bb_add_jump(struct ir_bb *bb, LOC loc, struct ir_bb *target)
{
    return BB_ADD_INST(bb, loc, IR_OP_GOTO, IR_INST_NO_TYPE,
                       .branch = {target});
}

struct ir_inst *bb_add_branch(struct ir_bb *bb, LOC loc, struct ir_inst *cond,
                              struct ir_bb *t1, struct ir_bb *t2)
{
    return BB_ADD_INST(bb, loc, IR_OP_BRANCH, IR_INST_NO_TYPE, INST_R1(cond),
                       .branch = {t1, t2});
}

static struct ir_inst *add_before(struct ir_inst *rel, const struct ir_inst *n)
{
    struct ir_inst *new = inst_dup(n);
    bb_add_inst_before(rel->bb, rel, new);
    return new;
}

static struct ir_inst *add_after(struct ir_inst *rel, const struct ir_inst *n)
{
    struct ir_inst *new = inst_dup(n);
    bb_add_inst_after(rel->bb, rel, new);
    return new;
}

#define ADD_BEFORE(in, ...) \
    add_before((in), &(struct ir_inst) { __VA_ARGS__ })

#define ADD_AFTER(in, ...) \
    add_after((in), &(struct ir_inst) { __VA_ARGS__ })

// Add instructions to copy the value "in" into a new variable.
// The instructions are appended right after "in".
struct ir_inst *inst_spill_to_temp(struct ir_inst *in)
{
    struct ir_var *v = fn_add_var(in->bb->fn, in->loc, in->result_type);
    struct ir_inst *p = ADD_AFTER(in, in->loc, IR_OP_VAR_PTR, v->ptr_type,
                                  .var = v);
    struct ir_inst *r = ADD_AFTER(p, in->loc, IR_OP_WRITE_PTR, IR_INST_NO_TYPE,
                                  INST_R2(p, in));
    // So that users can add instructions after the returned instruction.
    return ADD_AFTER(r, in->loc, IR_OP_COPY, p->result_type, INST_R1(p));
}

static int upval_depth(struct ir_function *fn, struct ir_var *v)
{
    if (!v->fn || v->fn == fn)
        return -1;
    // Reading v from fn implies v->fn must be a parent of fn;
    int d = 0;
    while (fn) {
        if (fn->parent == v->fn)
            return d;
        fn = fn->parent;
        d++;
    }
    return -1;
}

bool fn_can_access_upval(struct ir_function *fn, struct ir_var *v)
{
    return upval_depth(fn, v) >= 0;
}

static int nested_depth(struct ir_function *caller, struct ir_function *callee)
{
    // Generally, a function can call its direct parent, and any nested function
    // can call the function its parent can call.
    // On any level, the caller must be a sibling or a direct parent.
    int d = 0;
    while (caller) {
        if (caller == callee->parent)
            return d;
        caller = caller->parent;
        d++;
    }
    return -1;
}

bool fn_can_call_nested(struct ir_function *caller, struct ir_function *callee)
{
    return nested_depth(caller, callee) >= 0;
}

static struct ir_inst *getarg0(struct ir_function *fn, struct ir_type cast_to)
{
    assert(fn->type->args->members_count > 0);
    struct ir_struct_member *m = fn->type->args->members[0];
    struct ir_inst *v = ADD_BEFORE(fn->entry->first, fn->loc, IR_OP_GETARG,
                                   m->type, .struct_member = m);
    return ADD_AFTER(v, fn->loc, IR_OP_CONV_FROM_G_PTR, cast_to, INST_R1(v));
}

static struct ir_inst *read_struct(struct ir_inst *val, int index)
{
    struct ir_type t = type_unptr(val->result_type);
    assert(type_is_structlike(t));
    struct ir_struct_type *st = type_get_structlike(t);
    assert(index < st->members_count);
    struct ir_struct_member *m = st->members[index];
    val = ADD_AFTER(val, val->loc, IR_OP_GET_STRUCT_MEMBER_PTR,
                    type_ptr_to(val->bb->fn->unit->global_types, m->type),
                    INST_R1(val), .struct_member = m);
    val = ADD_AFTER(val, val->loc, IR_OP_READ_PTR, m->type, INST_R1(val));
    return val;
}

struct fn_info {
    struct fn_info *parent;
    struct ir_function *fn;
    struct ir_type st_type, st_ptr_type;
    struct ir_struct_type *st;
    struct ir_struct_member **map_var;
};

static void collect_upvalues(struct fn_info *info, struct ir_function *cur)
{
    for (int b = 0; b < cur->blocks_count; b++) {
        struct ir_bb *bb = cur->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            if (in->op == IR_OP_UPVAL_PTR) {
                struct ir_var *v = in->var;
                if (v->fn == info->fn && !info->map_var[v->index]) {
                    info->map_var[v->index] =
                        struct_add(info->st, v->loc, bstr0(""), v->ptr_type,
                                   NULL);
                }
            }
        }
    }
    for (int n = 0; n < cur->nested_functions_count; n++)
        collect_upvalues(info, cur->nested_functions[n]);
}

static void handle_nested_fn(struct ir_function *fn, struct fn_info *prev_info);

static void handle_nested_calls(struct ir_function *fn,
                                struct fn_info *prev_info)
{
    struct fn_info info = {prev_info, fn};
    info.st = struct_start(fn->unit->global_types, fn->loc);
    info.st_type = MAKE_IR_TYPE(ttuple, info.st);
    info.map_var = talloc_zero_array(NULL, struct ir_struct_member*,
                                     fn->vars_count);
    if (prev_info) {
        // Possibly not needed, but it's simpler to always set this.
        struct_add(info.st, fn->loc, bstr0(""), prev_info->st_ptr_type, NULL);
    }
    // collect upvalues from direct children
    collect_upvalues(&info, fn);
    struct_end(info.st, true);
    // Create the frame struct on the stack, initialize it with pointers to
    // all vars referenced as upvalues, and get a pointer to the frame struct.
    info.st_type = MAKE_IR_TYPE(ttuple, info.st);
    info.st_ptr_type = type_ptr_to(fn->unit->global_types, info.st_type);
    struct ir_inst *ref = fn->entry->first;
    struct ir_inst *s = INST_NEW(fn->loc, IR_OP_CONSTRUCT_STRUCT, info.st_type,
                                 .read_count = info.st->members_count);
    if (prev_info)
        s->read[0].def = getarg0(fn, prev_info->st_ptr_type);
    for (int n = 0; n < fn->vars_count; n++) {
        struct ir_var *v = fn->vars[n];
        if (info.map_var[n]) {
            int idx = info.map_var[n]->index;
            assert(!s->read[idx].def);
            s->read[idx].def = ADD_BEFORE(ref, fn->loc, IR_OP_VAR_PTR,
                                          v->ptr_type, .var = v);
        }
    }
    bb_add_inst_before(fn->entry, ref, s);
    struct ir_inst *frame = inst_spill_to_temp(s);
    frame = ADD_AFTER(frame, frame->loc, IR_OP_CONV_TO_G_PTR, TYPE_G_PTR,
                      INST_R1(frame));
    // Handle directly nested calls.
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            if (in->op == IR_OP_UPVAL_CONTEXT) {
                struct ir_function *callee = in->fn->body;
                if (callee->parent == fn) {
                    in = bb_replace_inst_dup(in,
                        INST(in->loc, IR_OP_COPY, TYPE_G_PTR, INST_R1(frame)));
                }
            }
        }
    }
    for (int n = 0; n < fn->nested_functions_count; n++)
        handle_nested_fn(fn->nested_functions[n], &info);
    talloc_free(info.map_var);
}

// Pointer to the frame struct, depth frames below.
static struct ir_inst *ctx_for_frame(struct ir_inst *at,
                                     struct fn_info **info, int depth)
{
    assert(depth >= 0);
    struct ir_inst *t = getarg0(at->bb->fn, (*info)->st_ptr_type);
    while (depth > 0) {
        // member 0 is always the uplink (if one exists)
        t = read_struct(t, 0);
        *info = (*info)->parent;
        depth--;
    }
    return t;
}

static void replace_upvalues(struct ir_function *fn, struct fn_info *prev_info)
{
    if (!fn->parent)
        return;
    assert(fn->parent == prev_info->fn);
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        for (struct ir_inst *inst = bb->first; inst; inst = inst->next) {
            if (inst->op == IR_OP_UPVAL_PTR) {
                // If the upvalue is multiple parents downwards, we must follow
                // the chain of uplinks in the context structs of each frame.
                int d = upval_depth(fn, inst->var);
                struct fn_info *info = prev_info;
                struct ir_inst *t = ctx_for_frame(inst, &info, d);
                assert(info->fn == inst->var->fn);
                // Actually read the pointer to the variable.
                struct ir_struct_member *m = info->map_var[inst->var->index];
                t = read_struct(t, m->index);
                assert(type_equals(t->result_type, inst->result_type));
                inst = bb_substitute(inst, t);
            } else if (inst->op == IR_OP_UPVAL_CONTEXT) {
                struct ir_function *callee = inst->fn->body;
                // This handles sibling calls (direct calls are done elsewhere).
                if (callee->parent != fn) {
                    int d = nested_depth(fn, callee);
                    assert(d > 0);
                    struct fn_info *info = prev_info;
                    struct ir_inst *t = ctx_for_frame(inst, &info, d - 1);
                    inst = bb_replace_inst_dup(inst,
                        INST(inst->loc, IR_OP_CONV_TO_G_PTR, TYPE_G_PTR,
                             INST_R1(t)));
                }
            }
        }
    }
}

static void handle_nested_fn(struct ir_function *fn, struct fn_info *prev_info)
{
    replace_upvalues(fn, prev_info);
    if (fn->nested_functions_count > 0)
        handle_nested_calls(fn, prev_info);
}

void fn_complete_nested_calls(struct ir_function *fn)
{
    handle_nested_fn(fn, NULL);
}

struct ir_unit *unit_new(void)
{
    struct ir_unit *unit = talloc_zero(NULL, struct ir_unit);
    unit->global_types = talloc_steal(unit, types_new());
    unit->predef = talloc_zero(unit, struct ir_scope);
    add_predefined_types(unit->predef, unit->global_types);
    unit->symbols = talloc_struct(unit, struct ir_scope,
                                  { .next = unit->predef });
    return unit;
}

// "Raw" inlining; if no additional work is done, this will result in
// invalid IR.
// Duplicate the contents of orig and append them to fn.
// Returns the copied entry block of orig.
struct ir_bb *fn_inline_code(struct ir_function *fn, struct ir_function *orig)
{
    assert(orig->nested_functions_count == 0); // bad idea
    struct hashtable *old_to_new = ht_create(NULL, HT_DATA_dptr, HT_DATA_dptr);
    int bb_0 = fn->blocks_count;
    for (int b = 0; b < orig->blocks_count; b++)
        fn_add_bb(fn);
    int var_0 = fn->vars_count;
    for (int n = 0; n < orig->vars_count; n++) {
        struct ir_var *old_var = orig->vars[n];
        struct ir_var *new_var = fn_add_var(fn, old_var->loc, old_var->type);
        new_var->name = old_var->name;
    }
    // copy actual code
    for (int b = 0; b < orig->blocks_count; b++) {
        struct ir_bb *old = orig->blocks[b];
        struct ir_bb *new = fn->blocks[bb_0 + b];
        for (struct ir_inst *in = old->first; in; in = in->next) {
            struct ir_inst tmp = *in;
            tmp.next = tmp.prev = NULL;
            tmp.bb = NULL;
            tmp.users_count = 0;
            tmp.users = NULL;
            // prevent bb_add_inst() from setting up users-info
            tmp.read = NULL;
            // switch references to function-specific stuff
            for (int n = 0; n < 2; n++) {
                if (tmp.branch[n])
                    tmp.branch[n] = fn->blocks[bb_0 + tmp.branch[n]->index];
            }
            if (tmp.var && tmp.var->fn == orig)
                tmp.var = fn->vars[var_0 + tmp.var->index];
            struct ir_inst *new_in = bb_add_inst_dup(new, &tmp);
            HT_INSERT(dptr, dptr, old_to_new, in, new_in);
        }
    }
    // fix up the reads and update users-info
    for (int b = 0; b < orig->blocks_count; b++) {
        struct ir_bb *old = orig->blocks[b];
        struct ir_bb *new = fn->blocks[bb_0 + b];
        struct ir_inst *new_in = new->first;
        struct ir_inst *in = old->first;
        for (; in; in = in->next, new_in = new_in->next) {
            for (int n = 0; n < in->read_count; n++) {
                struct ir_inst *r = inst_getuse(in, n);
                inst_use(new_in, n, *HT_GET(dptr, dptr, old_to_new, r));
            }
        }
    }
    talloc_free(old_to_new);
    return fn->blocks[bb_0 + orig->entry->index];
}
