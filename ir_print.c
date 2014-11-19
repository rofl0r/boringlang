#include "talloc.h"
#include "ir.h"
#include "value.h"

static int dump_varid(struct ir_function *fn, struct ir_var *var)
{
    for (int n = 0; n < fn->vars_count; n++)
        if (fn->vars[n] == var)
            return n;
    return -1;
}

static char *loc_str(void *ctx, LOC p)
{
    return talloc_steal(ctx, source_pos_string(p));
}

static char *fn_type_str(void *ctx, struct ir_fn_type *fn, int skip_args)
{
    char *res = talloc_strdup(ctx, "(");
    for (int n = skip_args; n < fn->args->members_count; n++) {
        struct ir_struct_member *m = fn->args->members[n];
        res = talloc_asprintf_append(res, "%s%s", (n > skip_args) ? "," : "",
                                        type_str(ctx, m->type));
    }
    res = talloc_asprintf_append(res, ")->%s", type_str(ctx, fn->ret_type));
    return res;
}

char *type_str(void *ctx, struct ir_type t)
{
    // @ALL ir_type_type
    switch (t.type) {
        case IR_TYPE_error: return "error";
        case IR_TYPE_any: return "?";
        case IR_TYPE_tuntyped: return "untyped";
        case IR_TYPE_tbool: return "bool";
        case IR_TYPE_tint: {
            int ti = *GET_UNION(IR_TYPE, tint, &t);
            return talloc_asprintf(ctx, "%s%d", INTT_SIGN(ti) ? "i": "u",
                                   INTT_BITS(ti));
        }
        case IR_TYPE_tdouble: return "double";
        case IR_TYPE_tptr: {
            struct ir_type pt = **GET_UNION(IR_TYPE, tptr, &t);
            return talloc_asprintf(ctx, "*%s", type_str(ctx, pt));
        }
        case IR_TYPE_tstruct: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tstruct, &t);
            return talloc_asprintf(ctx, "struct %s", st->name);
        }
        case IR_TYPE_ttuple: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, ttuple, &t);
            if (!st->members_count)
                return "void";
            char *res = talloc_strdup(ctx, "(");
            for (int n = 0; n < st->members_count; n++) {
                struct ir_struct_member *m = st->members[n];
                res = talloc_asprintf_append(res, "%s%s", n ? "," : "",
                                             type_str(ctx, m->type));
            }
            return talloc_asprintf_append(res, ")");
        }
        case IR_TYPE_tcompound: {
            struct ir_struct_type *st = *GET_UNION(IR_TYPE, tcompound, &t);
            char *res = talloc_strdup(ctx, "{");
            for (int n = 0; n < st->members_count; n++) {
                struct ir_struct_member *m = st->members[n];
                res = talloc_asprintf_append(res, "%s%s", n ? "," : "",
                                             type_str(ctx, m->type));
            }
            return talloc_asprintf_append(res, "}");
        }
        case IR_TYPE_tfn: {
            struct ir_fn_type *fn = *GET_UNION(IR_TYPE, tfn, &t);
            return talloc_asprintf(ctx, "fn%s", fn_type_str(ctx, fn, 0));
        }
        case IR_TYPE_tstackclosure: {
            struct ir_fn_type *sc = *GET_UNION(IR_TYPE, tstackclosure, &t);
            return talloc_asprintf(ctx, "^%s", fn_type_str(ctx, sc, 1));
        }
        case IR_TYPE_tarray: {
            struct ir_array_type *tarr = *GET_UNION(IR_TYPE, tarray, &t);
            return talloc_asprintf(ctx, "%s[%d]",
                            type_str(ctx, tarr->item_type), tarr->dimension);
        }
        case IR_TYPE_tslice: {
            struct ir_type et = **GET_UNION(IR_TYPE, tslice, &t);
            return talloc_asprintf(ctx, "%s[]", type_str(ctx, et));
        }
        default: assert(false);
    }
}

static char *link_str(void *ctx, struct ir_link_name name)
{
    return talloc_asprintf(ctx, "%s", name.name);
}

static char *inst_str(void *ctx, struct ir_function *fn, struct ir_inst *in)
{
    const char *ins = ir_op_name(in->op);
    // @ALL ir_opcode
    switch (in->op) {
        case IR_OP_GETARG: {
            struct ir_struct_member *m = in->struct_member;
            return talloc_asprintf(ctx, "%s %d '%s'", ins, m->index, m->name);
        }
        case IR_OP_VAR_PTR:
        case IR_OP_UPVAL_PTR:
        case IR_OP_READ_VAR:
        case IR_OP_WRITE_VAR:
        {
            struct ir_var *v = in->var;
            return talloc_asprintf(ctx, "%s %d%s '%s'", ins, v->index,
                                   v->fn == fn ? "" : " [non-local]", v->name);
        }
        case IR_OP_GET_STRUCT_MEMBER_PTR:
        case IR_OP_GET_STRUCT_MEMBER:
        case IR_OP_SET_STRUCT_MEMBER:
        {
            struct ir_struct_member *m = in->struct_member;
            if (m->name) {
                return talloc_asprintf(ctx, "%s '%s'", ins, m->name);
            } else {
                return talloc_asprintf(ctx, "%s &%d", ins, m->index);
            }
        }
        case IR_OP_LOAD_CONST: {
            struct ir_const_val *cval = in->const_value;
            return talloc_asprintf(ctx, "%s %s[%s]", ins,
                                   const_unparse(ctx, *cval),
                                   type_str(ctx, cval->type));
        }
        case IR_OP_UPVAL_CONTEXT:
        case IR_OP_FN_PTR:
        case IR_OP_CALL:
        {
            struct ir_fn_decl *fnref = in->fn;
            bool local = fnref->body && fnref->body->parent;
            return talloc_asprintf(ctx, "%s '%s'%s", ins,
                                   link_str(ctx, fnref->name),
                                   local ? " [non-global]" : "");
        }
        default:
            return (char*)ins;
    }
}

void dump_unit(FILE *f, struct ir_unit *unit)
{
    void *t = talloc_new(NULL);
    for (int n = 0; n < unit->fn_decls_count; n++) {
        struct ir_fn_decl *fnd = unit->fn_decls[n];
        fprintf(f, "fn %s%s:\n", link_str(t, fnd->name),
                fn_type_str(t, fnd->type, 0));
        if (!fnd->body) {
            fprintf(f, "(undef)\n");
        } else {
            struct ir_function *fn = fnd->body;
            dump_fn(f, fn);
            for (int i = 0; i < fn->nested_functions_count; i++) {
                dump_fn(f, fn->nested_functions[i]);
            }
        }
    }
    talloc_free(t);
}

void dump_fn(FILE *f, struct ir_function *fn)
{
    int print_use_info = 1;
    if (!fn) {
        fprintf(f, "function is NULL!\n");
        return;
    }
    void *t = talloc_new(NULL);
    fprintf(f, "Type: %s\n", fn_type_str(t, fn->type, 0));
    fprintf(f, "Parent chain:");
    struct ir_function *cur_p = fn;
    while (cur_p) {
        fprintf(f, " %p", cur_p);
        cur_p = cur_p->parent;
    }
    fprintf(f, "\n");
    fprintf(f, "Vars:\n");
    for (int n = 0; n < fn->vars_count; n++) {
        struct ir_var *var = fn->vars[n];
        fprintf(f, "   %d: %s '%s' %s\n", dump_varid(fn, var),
                type_str(t, var->type), var->name,
                loc_str(t, var->loc));
    }
    int in_nr = 0;
    for (int b = 0; b < fn->blocks_count; b++) {
        for (struct ir_inst *in = fn->blocks[b]->first; in; in = in->next)
            in->scratch1_i = in_nr++;
    }
    fprintf(f, "Entry block: %d\n", fn->entry->index);
    for (int b = 0; b < fn->blocks_count; b++) {
        struct ir_bb *bb = fn->blocks[b];
        fprintf(f, "%d (%p):", bb->index, bb);
        if (print_use_info && (bb->jump_from_count || fn->entry == bb)) {
            fprintf(f, "   {");
            for (int i = 0; i < bb->jump_from_count; i++)
                fprintf(f, "%d ", bb->jump_from[i]->index);
            if (fn->entry == bb)
                fprintf(f, "[entry]");
            fprintf(f, "}");
        }
        fprintf(f, "\n");
        for (struct ir_inst *in = bb->first; in; in = in->next) {
            fprintf(f, "  ");
            if (in->result_type.type != IR_TYPE_any || print_use_info)
                fprintf(f, "$%d[%s] = ", in->scratch1_i,
                        type_str(t, in->result_type));
            fprintf(f, "%s", inst_str(t, fn, in));
            for (int x = 0; x < in->read_count; x++) {
                struct ir_inst *r = in->read[x].def;
                fprintf(f, " $%d[%s]", r->scratch1_i,
                        type_str(t, r->result_type));
                if (bb != r->bb)
                    fprintf(f, "@%d", r->bb->index);
                if (x + 1 < in->read_count)
                    fprintf(f, ",");
            }
            if (in->branch[0]) {
                fprintf(f, " -> ");
                fprintf(f, "%d", in->branch[0]->index);
                if (in->branch[1])
                    fprintf(f, " %d", in->branch[1]->index);
            }
            if (in->comment)
                fprintf(f, " '%s'", in->comment);
            fprintf(f, "  {%s}", loc_str(t, in->loc));
            fprintf(f, "\n");
            if (print_use_info && in->users_count) {
                fprintf(f, "       used by: {");
                for (int n = 0; n < in->users_count; n++)
                    fprintf(f, "%d ", in->users[n]->scratch1_i);
                fprintf(f, "}\n");
            }
        }
    }
    talloc_free(t);
    /*
    for (int n = 0; n < fn->nested_functions_count; n++) {
        dump_fn(f, fn->nested_functions[n]);
    }
    */
}

void dump_cfg(FILE *f, struct ir_function *fn)
{
    fprintf(f, "digraph name {\n");
    fprintf(f, "  ne [label=\"entry\"];\n");
    fprintf(f, "  ne -> n%d;\n", fn->entry->index);
    for (int n = 0; n < fn->blocks_count; n++) {
        struct ir_bb *bb = fn->blocks[n];
        //fprintf(f, "  n%d [label=\"%p\"];\n", bb->index, bb);
        for (int i = 0; i < bb->jump_to_count; i++) {
            fprintf(f, "  n%d -> n%d;\n", bb->index, bb->jump_to[i]->index);
        }
    }
    fprintf(f, "}\n");
}
