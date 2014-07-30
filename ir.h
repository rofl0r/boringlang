#ifndef BL_TREE_H
#define BL_TREE_H

#include <stdbool.h>
#include <stdint.h>
#include "lex.h"
#include "bstr.h"
#include "types.h"
#include "value.h"

// Representation of an imported or exported symbol on the link level.
struct ir_link_name {
    bstr name;
    bool visible;
    bool is_c;          // mangle name?
};

struct ir_bb {
    int index;
    struct ir_function *fn;
    struct ir_inst *first, *last;
    // List of jump target blocks (corresponds to the jump instruction in this
    // block).
    int jump_to_count;
    struct ir_bb **jump_to;
    // List of blocks that have this block as target.
    int jump_from_count;
    struct ir_bb **jump_from;
};

// @ALL ir_opcode
enum ir_opcode {
    IR_OP_ERROR,

    IR_OP_NOP,
    IR_OP_COPY,                 // return the input value (practically a NOP)

    // PHI nodes must be at the start of blocks.
    IR_OP_PHI,

    // Branch operations must be at the end of blocks.
    // There must be exactly 1 branch instruction in a block.
    IR_OP_GOTO,
    IR_OP_BRANCH,
    IR_OP_RET,
    IR_OP_ABORT,

    IR_OP_GETARG,
    IR_OP_READ_VAR,
    IR_OP_WRITE_VAR,
    IR_OP_VAR_PTR,              // take pointer of local variable
    IR_OP_UPVAL_PTR,            // take pointer of variable from parent

    IR_OP_UPVAL_CONTEXT,        // dummy; will be replaced with further code

    IR_OP_MAKE_CLOSURE,         // closure value out of fn-ptr & context
    IR_OP_GET_CLOSURE_FN,
    IR_OP_GET_CLOSURE_CTX,

    // xxx rename CONSTRUCT to MAKE
    IR_OP_CONSTRUCT_STRUCT,     // one input value for each struct member
    IR_OP_GET_STRUCT_MEMBER_PTR, // input is a pointer to a struct (not a value)
    IR_OP_GET_STRUCT_MEMBER,
    IR_OP_SET_STRUCT_MEMBER,    // keep in mind that the input struct is not
                                // changed, but a modified result is returned

    // Note that slices are bounded pointer types.
    // xxx rename CONSTRUCT to MAKE
    IR_OP_CONSTRUCT_SLICE,      // pointer + length => slice
    IR_OP_SLICE,                // i1[i2..i3]
    IR_OP_SLICE_COPY,           // copy contents to other slice (dest src)
    IR_OP_SLICE_SET,            // i1[] = i2
    IR_OP_GET_SLICE_LENGTH,
    IR_OP_GET_SLICE_PTR,        // ptr to the first item, no bounds check
    IR_OP_GET_SLICE_ITEM_PTR,
    //IR_OP_GET_SLICE_ITEM,
    //IR_OP_SET_SLICE_ITEM,

    IR_OP_CONSTRUCT_ARRAY,      // one input for each array item
    IR_OP_ARRAY_TO_SLICE,       // input value is a pointer to an array
    //IR_OP_GET_ARRAY_ITEM_PTR,

    IR_OP_READ_PTR,
    IR_OP_WRITE_PTR,

    IR_OP_LOAD_CONST,
    IR_OP_FN_PTR,

    IR_OP_CALL,
    IR_OP_CALL_PTR,

    // simple arithmetic operations

    // Make type smaller (same signedness) - might be very lossy.
    IR_OP_CONV_INT_TRUNC,
    // Change signedness (same size). Defined to follow 2's complement on
    // overflow cases.
    IR_OP_CONV_INT_SIGN,
    // Make type bigger (same signedness). Always lossless.
    IR_OP_CONV_INT_EXT,

    IR_OP_CONV_TO_G_PTR,
    IR_OP_CONV_FROM_G_PTR,

    // unary arithmetic

    IR_OP_NEG,
    IR_OP_NOT,

    // binary arithmetic

    IR_OP_ADD,
    IR_OP_SUB,
    IR_OP_MUL,
    IR_OP_DIV,
    IR_OP_MOD,

    IR_OP_AND,
    IR_OP_OR,
    IR_OP_XOR,

    IR_OP_SHIFT_R,
    IR_OP_SHIFT_L,

    // @COMPARABLE
    IR_OP_EQ,
    IR_OP_NOT_EQ,

    IR_OP_CMP_LT,
    IR_OP_CMP_GT,
    IR_OP_CMP_LT_EQ,
    IR_OP_CMP_GT_EQ,

    IR_OP_END,
};

#define IR_OP_ARITH_START IR_OP_CONV_INT_TRUNC
#define IR_OP_ARITH_END IR_OP_END

#define IR_INST_NO_TYPE MAKE_IR_TYPE0(any)

struct ir_use {
    struct ir_inst *def;
};

// sufficient until we need to support jump tables in the IR
#define BRANCH_MAX 2

struct ir_inst {
    source_pos loc;
    enum ir_opcode op;
    // If the node has no type, it should be IR_INST_NO_TYPE (== IR_TYPE_any).
    struct ir_type result_type;

    struct ir_bb *bb;
    struct ir_inst *prev, *next;

    // array of inputs virtual registers
    int read_count;
    struct ir_use *read;

    // keep track of users - this is a multiset (one element can appear more
    // than once, order doesn't matter)
    int users_count;
    struct ir_inst **users;

    // for debugging
    const char *comment;

    // IR_OP_VAR_PTR, IR_OP_READ_VAR, IR_OP_WRITE_VAR, IR_OP_UPVAL_PTR
    struct ir_var *var;

    // IR_OP_LOAD_CONST
    // NOTE: memory is always owned by ir_inst
    struct ir_const_val *const_value;

    // IR_OP_GOTO (branch[0] is target), IR_OP_BRANCH (false => 0, true => 1)
    // redundant with jump_to array in struct ir_bb
    struct ir_bb *branch[BRANCH_MAX];

    // IR_OP_GET_STRUCT_MEMBER_PTR, IR_OP_GETARG
    struct ir_struct_member *struct_member;

    // IR_OP_FN_PTR, IR_OP_CALL, IR_OP_UPVAL_CONTEXT
    struct ir_fn_decl *fn;

    // for free use by algorithms, strictly temporary and uninitialized
    int32_t scratch1_i;
    void *scratch1_p;
};

// @ALL ast_sym_type
enum ast_sym_type {
    AST_SYM_error,
    AST_SYM_var,
    AST_SYM_const_,
    AST_SYM_type,
    AST_SYM_label,
    AST_SYM_struct_member,
    AST_SYM_fn_decl,
    AST_SYM_var_decl,
};

struct ast_sym {
    enum ast_sym_type type;
    union {
        struct ir_var *var;
        struct ir_const_val *const_;
        struct ir_type type;
        struct ir_label *label;
        struct ir_struct_member *struct_member;
        struct ir_fn_decl *fn_decl;
        struct ir_var_decl *var_decl;
    } u;
};

struct scope_entry {
    bstr name;
    struct ast_sym sym;
};

struct ir_scope {
    int entries_count;
    struct scope_entry *entries;
    // TODO: add optional hashtable (if entries count gets large)
    struct ir_scope *next;
};

struct ast_sym *scope_lookup(struct ir_scope *scope, bstr name);
void scope_add(struct ir_scope *scope, bstr name, struct ast_sym entry);

struct ir_var {
    int index;
    bstr name;                  // optional, not unique
    source_pos loc;             // closest loc possible (might be not exact)
    struct ir_function *fn;
    struct ir_type type;
    struct ir_type ptr_type;    // redundant, but here because it's needed often
};

struct ir_function {
    source_pos loc;
    struct ir_fn_type *type;
    struct ir_unit *unit;
    struct ir_function *parent; // non-NULL if this is a nested function

    // Directly nested functions (with this function as parent).
    int nested_functions_count;
    struct ir_function **nested_functions;

    int register_count;         // implies maximum virtual register used

    int blocks_count;
    struct ir_bb **blocks;

    struct ir_bb *entry;

    int vars_count;
    struct ir_var **vars;
};

// The difference to ir_function is that the function body is not necessarily
// available (e.g. you can reference external functions).
struct ir_fn_decl {
    source_pos loc;
    struct ir_link_name name;
    bool nested;
    struct ir_fn_type *type;
    struct ir_function *body;   // body->type/name must be same as type/name
};

struct ir_var_decl {
    source_pos loc;
    struct ir_link_name name;
    struct ir_type type;
    struct ir_const_val *definition;
};

struct ir_unit {
    source_pos loc;
    //bstr name;

    struct ir_types *global_types;

    // This includes top-level functions only. Each function can still contain
    // further nested functions.
    int fn_decls_count;
    struct ir_fn_decl **fn_decls;

    int var_decls_count;
    struct ir_var_decl **var_decls;

    // Includes actually named symbols only.
    struct ir_scope *symbols;
    struct ir_scope *predef;
};

struct optimize_settings {
    bool opt_inline;
};
#define OPTIMIZE_DEFAULT {0}

struct ast_node;
struct ir_unit *bl_cg_expr(struct ast_node *ast);
struct ir_unit *bl_cg(struct ast_node *ast);

struct ir_unit *unit_new(void);

struct ir_bb *fn_inline_code(struct ir_function *fn, struct ir_function *orig);
struct ir_var *fn_add_var(struct ir_function *fn, LOC loc, struct ir_type t);
void fn_remove_var(struct ir_function *fn, struct ir_var *var);
bool fn_can_access_upval(struct ir_function *fn, struct ir_var *v);
bool fn_can_call_nested(struct ir_function *caller, struct ir_function *callee);

#define INST_R1(a) .read=(struct ir_use[]){{a}}, .read_count=1
#define INST_R2(a, b) .read=(struct ir_use[]){{a},{b}}, .read_count=2
#define INST_R3(a, b, c) .read=(struct ir_use[]){{a},{b},{c}}, .read_count=3
struct ir_inst *inst_dup(const struct ir_inst *orig);

void inst_use(struct ir_inst *in, int read_n, struct ir_inst *use);
struct ir_inst *inst_getuse(struct ir_inst *in, int read_n);
bool inst_has_users(struct ir_inst *in);
void inst_rewire_uses(struct ir_inst *in, struct ir_inst *use,
                      struct ir_inst *new_use);
void inst_replace_all_uses(struct ir_inst *old, struct ir_inst *new);
struct ir_inst *inst_spill_to_temp(struct ir_inst *in);

struct ir_bb *fn_add_bb(struct ir_function *fn);
void fn_remove_bb(struct ir_function *fn, struct ir_bb *bb);
void bb_rewire_jump(struct ir_bb *bb, struct ir_bb *from, struct ir_bb *to);

void bb_add_inst_after(struct ir_bb *bb, struct ir_inst *after,
                       struct ir_inst *add);
void bb_add_inst_before(struct ir_bb *bb, struct ir_inst *before,
                        struct ir_inst *add);
void bb_remove_inst(struct ir_bb *bb, struct ir_inst *inst);
void bb_kill_inst(struct ir_bb *bb, struct ir_inst *inst);
void bb_add_inst(struct ir_bb *bb, struct ir_inst *inst);
struct ir_inst *bb_add_inst_dup(struct ir_bb *bb, struct ir_inst *orig);
struct ir_inst *bb_replace_inst_dup(struct ir_inst *old,
                                    const struct ir_inst *orig);
struct ir_inst *bb_replace_inst(struct ir_inst *old, struct ir_inst *new);
struct ir_inst *bb_substitute(struct ir_inst *old, struct ir_inst *new);
void inst_move_to(struct ir_inst *inst, struct ir_bb *bb,
                  struct ir_inst *after);

#define INST_NEW(...) inst_dup(&(struct ir_inst) { __VA_ARGS__ })

#define INST(...) \
    &(struct ir_inst) { __VA_ARGS__ }

#define BB_ADD_INST(bb, ...) \
    bb_add_inst_dup(bb, &(struct ir_inst) { __VA_ARGS__ })

struct ir_inst *bb_add_binop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                             struct ir_type result_type,
                             struct ir_inst *in1, struct ir_inst *in2);
struct ir_inst *bb_add_unop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                            struct ir_type result_type, struct ir_inst *in);
struct ir_inst *bb_add_nt_binop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                                struct ir_inst *in1, struct ir_inst *in2);
struct ir_inst *bb_add_nt_inst(struct ir_bb *bb, LOC loc, enum ir_opcode op);
struct ir_inst *bb_add_nt_unop(struct ir_bb *bb, LOC loc, enum ir_opcode op,
                               struct ir_inst *in);
struct ir_inst *bb_add_jump(struct ir_bb *bb, LOC loc, struct ir_bb *target);
struct ir_inst *bb_add_branch(struct ir_bb *bb, LOC loc, struct ir_inst *cond,
                              struct ir_bb *t1, struct ir_bb *t2);

bool ir_op_is_branch(enum ir_opcode op);
bool ir_op_reads_side_effects(enum ir_opcode op);
bool ir_op_writes_side_effects(enum ir_opcode op);
bool ir_op_has_side_effects(enum ir_opcode op);
const char *ir_op_name(enum ir_opcode op);

void fn_complete_nested_calls(struct ir_function *fn);

// backend_c.c
void generate_c(FILE *f, struct ir_unit *unit);

// ir_opt.c
void fn_remove_global_ssa(struct ir_function *fn);
bool fn_simplify(struct ir_function *fn);
bool fn_simplify_harder(struct ir_function *fn);
bool fn_inline_all(struct ir_function *fn);
void unit_optimize(struct ir_unit *unit, struct optimize_settings *opt);

// ir_verify.c
void fn_verify(struct ir_function *fn);
void unit_verify(struct ir_unit *unit);


// ir_print.c
void dump_unit(FILE *f, struct ir_unit *unit);
void dump_fn(FILE *f, struct ir_function *fn);
void dump_cfg(FILE *f, struct ir_function *fn);
char *type_str(void *ctx, struct ir_type t);

#endif
