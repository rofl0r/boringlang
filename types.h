#ifndef BL_TYPES_H
#define BL_TYPES_H

#include "union.h"
#include "lex.h"

// @ALL ir_type_type
enum ir_type_type {
    IR_TYPE_error,
    IR_TYPE_any,        // placeholder type
    IR_TYPE_tuntyped,   // like void in C void pointers
    IR_TYPE_tbool,
    IR_TYPE_tint,
    IR_TYPE_tdouble,
    IR_TYPE_tptr,
    IR_TYPE_tstruct,
    IR_TYPE_ttuple,
    IR_TYPE_tcompound,
    IR_TYPE_tfn,        // this is already a pointer, in some ways
    IR_TYPE_tstackclosure, // typically a struct with context + function ptr
    IR_TYPE_tarray,
    IR_TYPE_tslice,
};

#define MAKE_IR_TYPE(name, ...) \
    (struct ir_type) MAKE_UNION(IR_TYPE, name, __VA_ARGS__)

#define MAKE_IR_TYPE0(name) \
    (struct ir_type) MAKE_UNION0(IR_TYPE, name)

#define TYPE_ERROR MAKE_IR_TYPE0(error)
#define TYPE_BOOL MAKE_IR_TYPE0(tbool)
#define TYPE_ANY MAKE_IR_TYPE0(any)

enum ir_intt {
    // must match with assumptions INTT_* macros make
    IR_INTT_8 = 0,
    IR_INTT_16 = 1,
    IR_INTT_32 = 2,
    IR_INTT_64 = 3,
    IR_INTT_SIGNED = (1 << 2),
};

// The rank of an integer type is (log2(bits) - 3), i.e. you get the number of
// bits a type uses with (1 << (rank + 3)).
#define INTT_RANK(c) ((c) & 3)
#define INTT_BITS(c) (1 << (INTT_RANK(c) + 3))
#define INTT_SIGN(c) (!!((c) & IR_INTT_SIGNED))
#define INTT_MAKE(rank, sign) ((rank) | ((sign) ? IR_INTT_SIGNED : 0))

struct ir_type {
    enum ir_type_type type;
    union {
        int tint;       // see INTT_*
        struct ir_type *tptr;
        struct ir_struct_type *tstruct;
        struct ir_struct_type *ttuple;
        struct ir_struct_type *tcompound;
        struct ir_fn_type *tfn;
        struct ir_fn_type *tstackclosure;
        struct ir_array_type *tarray;
        struct ir_type *tslice;
    } u;
};

extern const struct ir_type TYPE_G_PTR;
extern const struct ir_type TYPE_CHAR;
extern const struct ir_type TYPE_STRING;

struct ir_struct_member {
    source_pos loc;
    char *name;                  // empty name = anonymous member
    int index;
    struct ir_type type;
    // For actual structs, init is always set.
    // For function parameters, init is only set if a default value is present.
    struct ir_const_val *init;
    //int offset;
};

struct ir_struct_type {
    source_pos loc;
    char *name;
    bool defined;                       // false if forward-declared
    int members_count;
    struct ir_struct_member **members;
    // For convenience. Must exactly equal ir_struct_member->init for each
    // member. This field can be NULL for types that are not really structs.
    struct ir_struct_const *init;
    // only to speed up name lookup
    struct ir_scope *scope;
};

enum ir_vararg {
    IR_VARARG_NONE,
    IR_VARARG_NATIVE,
    IR_VARARG_C,
};

struct ir_fn_type {
    source_pos loc;
    struct ir_struct_type *args;
    struct ir_type ret_type;
    enum ir_vararg vararg;
    // will need calling convention too
    // and perhaps linkage
};

struct ir_array_type {
    struct ir_type item_type;
    int dimension;
    struct ir_array_const *init;
};

// Contains predefined types. Also can serve as talloc context for various
// types needed by the tree.
struct ir_types {
    struct ir_type tvoid;       // (), empty tuple
    struct ir_type index;       // type for array indices and lengths
    struct ir_type varargs;     // vararg[]
    struct ir_type vararg;      // struct vararg
    struct ir_fn_type *c_main;
    int word_size;              // 32 or 64
};

struct ir_types *types_new(void);
void add_predefined_types(struct ir_scope *scope, struct ir_types *t);

bool type_equals(struct ir_type t1, struct ir_type t2);
bool type_is_complete(struct ir_type t);
bool type_is_integer(struct ir_type t);
bool type_is_fp(struct ir_type t);
bool type_is_ptr(struct ir_type t);
bool type_is_bool(struct ir_type t);
bool type_is_void(struct ir_type t);
bool type_is_untyped(struct ir_type t);
bool type_is_untyped_ptr(struct ir_type t);
bool type_is_typed_ptr(struct ir_type t);
bool type_is_structlike(struct ir_type t);
struct ir_struct_type *type_get_structlike(struct ir_type t);
bool type_get_sign(struct ir_type t);
int type_get_bits(struct ir_type t);
int type_int_order(struct ir_type t);
struct ir_type type_item_type(struct ir_type t);
int type_array_get_dimension(struct ir_type t);
bool fn_type_equals(struct ir_fn_type *fn1, struct ir_fn_type *fn2);
struct ir_type type_integer(bool sign, int bits);
struct ir_type type_integer_min(bool sign, int bits);
struct ir_type type_unptr(struct ir_type t);
struct ir_type type_ptr_to(struct ir_types *ctx, struct ir_type t);
struct ir_type type_array(struct ir_types *ctx, struct ir_type t, int dim);
struct ir_type type_slice_to(struct ir_types *ctx, struct ir_type t);
char *type_vararg_mangle(struct ir_types *ctx, struct ir_type t);
bool type_implicitly_convertible(struct ir_type from, struct ir_type to);
struct ir_type type_common(struct ir_type t1, struct ir_type t2);

struct ir_struct_type *struct_start(struct ir_types *ctx, LOC loc);
struct ir_struct_member *struct_add(struct ir_struct_type *st, LOC m_loc,
                                    char *m_name, struct ir_type m_type,
                                    struct ir_const_val *m_init);
void struct_end(struct ir_struct_type *st, bool add_init);
struct ir_struct_member *struct_find_member(struct ir_struct_type *t,
                                            char *name);

#endif
