#ifndef BL_AST_H
#define BL_AST_H

#include "lex.h"
#include "bstr.h"

struct ast_id {
    source_pos loc;
    bstr id;
};

struct ast_lit {
    source_pos loc;
    struct lex_const lit;
};

struct ast_def_macro {
    source_pos loc;
    bstr name;
    int params_count;
    bstr *params;
    bool no_params;
    bool is_vararg;
    struct ast_node *contents;
};

struct ast_compound_lit {
    source_pos loc;
    int exprs_count;
    struct ast_node **exprs;
};

struct ast_struct_lit {
    source_pos loc;
    struct ast_node *type;
    int exprs_count;
    struct ast_node **exprs;
};

struct ast_tuple {
    source_pos loc;
    int exprs_count;
    struct ast_node **exprs;
};

struct ast_var {
    source_pos loc;
    bstr name;
    struct ast_node *type;      // can be NULL
    struct ast_node *init;      // can be NULL
};

enum null_op {
    NULL_OP_ERROR,

    NULL_OP_ARRAY_LENGTH,       // #
    NULL_OP_ANY,                // _
};

struct ast_null_op {
    source_pos loc;
    enum null_op op;
};

enum un_op {
    UN_OP_ERROR,

    UN_OP_MACRO_UNQUOTE,// %%e
    UN_OP_ADDR,         // &e
    UN_OP_PTR,          // e* type constructor or deref
    UN_OP_ARRAY,        // e[] (slice type constructor or empty slice op.)
    UN_OP_INIT,         // .= e (struct expansion)
    UN_OP_VARARG,       // ...e (vararg expansion)
    UN_OP_ARRAY_LENGTH, // #e
    UN_OP_NOT,
    UN_OP_BIN_NOT,
    UN_OP_NEG,

    UN_OP_END,
};

struct ast_un_op {
    source_pos loc;
    enum un_op op;
    struct ast_node *expr;
};

enum bin_op {
    BIN_OP_ERROR,

    BIN_OP_ARRAY,       // l[r] (static array type constructor or index op.)
    BIN_OP_DOT,
    BIN_OP_ASSIGN,
    BIN_OP_INIT,        // . e1 = e2
    BIN_OP_INIT_ARRAY,  // [e1] = e2
    BIN_OP_AND,
    BIN_OP_OR,
    BIN_OP_BIT_AND,
    BIN_OP_BIT_OR,
    BIN_OP_BIT_XOR,
    BIN_OP_SHIFT_R,
    BIN_OP_SHIFT_L,
    BIN_OP_ADD,
    BIN_OP_SUB,
    BIN_OP_MUL,
    BIN_OP_DIV,
    BIN_OP_MOD,
    BIN_OP_EQUAL,
    BIN_OP_UNEQUAL,
    BIN_OP_LT,
    BIN_OP_GT,
    BIN_OP_LT_EQ,
    BIN_OP_GT_EQ,

    BIN_OP_END
};

struct ast_bin_op {
    source_pos loc;
    enum bin_op op;
    struct ast_node *expr1, *expr2;
};

enum tern_op {
    TERN_OP_ERROR,

    TERN_OP_COND,       // e1 ? e2 : e3
    TERN_OP_SLICE,      // e1[e2 .. e3]
};

struct ast_tern_op {
    source_pos loc;
    enum tern_op op;
    struct ast_node *expr1, *expr2, *expr3;
};

struct ast_call {
    source_pos loc;
    struct ast_node *expr;
    int args_count;
    struct ast_node **args;
};

struct ast_struct_member {
    source_pos loc;
    bstr name;                  // can be empty for function params
    struct ast_node *type;
    struct ast_node *init;      // can be NULL
};

struct ast_struct_body {
    source_pos loc;
    int members_count;
    struct ast_struct_member *members;
};

struct ast_fn_signature {
    source_pos loc;
    bool is_vararg;
    bool is_c;
    struct ast_struct_body params;
    struct ast_node *ret_type;
};

struct ast_fn_type {
    struct ast_fn_signature sig;
};

struct ast_stackclosure_type {
    struct ast_fn_signature sig;
};

struct ast_fn {
    source_pos loc;
    bstr name;
    struct ast_fn_signature sig;
    struct ast_node *body;              // can be NULL
};

struct ast_struct_ {
    source_pos loc;
    bstr name;
    struct ast_struct_body *body;       // can be NULL
};

struct ast_ret {
    source_pos loc;
    struct ast_node *expr;      // can be NULL
};

struct ast_if_ {
    source_pos loc;
    struct ast_node *cond;
    struct ast_node *yes;
    struct ast_node *no;        // can be NULL
};

struct ast_while_ {
    source_pos loc;
    struct ast_node *cond;
    struct ast_node *body;
};

struct ast_block {
    source_pos loc;
    int stmts_count;
    struct ast_node **stmts;
};

struct ast_label {
    source_pos loc;
    bstr name;
};

struct ast_goto_ {
    source_pos loc;
    bstr label;
};

enum ast_node_type {
    AST_error,
    AST_id,
    AST_lit,
    AST_def_macro,
    AST_compound_lit,
    AST_struct_lit,
    AST_tuple,
    AST_var,
    AST_null_op,
    AST_un_op,
    AST_bin_op,
    AST_tern_op,
    AST_call,
    AST_fn_type,
    AST_stackclosure_type,
    AST_fn,
    AST_struct_,
    AST_ret,
    AST_if_,
    AST_while_,
    AST_block,
    AST_label,
    AST_goto_,
};

struct ast_node {
    enum ast_node_type type;
    union {
        struct ast_id id;
        struct ast_var var;
        struct ast_lit lit;
        struct ast_def_macro def_macro;
        struct ast_compound_lit compound_lit;
        struct ast_struct_lit struct_lit;
        struct ast_tuple tuple;
        struct ast_null_op null_op;
        struct ast_un_op un_op;
        struct ast_bin_op bin_op;
        struct ast_tern_op tern_op;
        struct ast_call call;
        struct ast_fn_type fn_type;
        struct ast_stackclosure_type stackclosure_type;
        struct ast_fn fn;
        struct ast_struct_ struct_;
        struct ast_ret ret;
        struct ast_if_ if_;
        struct ast_while_ while_;
        struct ast_block block;
        struct ast_label label;
        struct ast_goto_ goto_;
    } u;
};

source_pos ast_get_loc(struct ast_node *node);
struct ast_node *bl_parse(struct lexer *lex);
void dump_ast(FILE *dest, struct ast_node *ast, int flags);

enum {
    DUMP_AST_NOLOC = 1,
};

#endif
