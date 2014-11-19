#include "ast.h"
#include "union.h"

#define NEW_NODE(ctx, name, ...) \
    NEW_UNION(ctx, struct ast_node, AST, name, __VA_ARGS__)

struct op_map {
    int prec;
    const char *tok;
    int op;
    bool right_assoc;
};

#define PREC_MIN 0
#define PREC_MAX 16

#define PREC_STATEMENT 16
#define PREC_ASSIGN 15
#define PREC_TERMINAL 13        // "trailing" expressions
#define PREC_COMMA 14
#define PREC_COND 13
#define PREC_ARRAY 2
#define PREC_CALL 2

#define PREC_UNOP 2
static struct op_map un_ops[] = {
    {2,  "&",  UN_OP_ADDR},
    {2,  "*",  UN_OP_PTR},
    {2,  "...",UN_OP_VARARG},
    {2,  "#",  UN_OP_ARRAY_LENGTH},
    {2,  "!",  UN_OP_NOT},
    {2,  "~",  UN_OP_BIN_NOT},
    {2,  "-",  UN_OP_NEG},
    {2,  "%%", UN_OP_MACRO_UNQUOTE},
    {0}
};

static struct op_map un_post_ops[] = {
    {0},
};

static struct op_map bin_ops[] = {
    {1,  ".",  BIN_OP_DOT},
    {PREC_ASSIGN, "=", BIN_OP_ASSIGN, .right_assoc = true},
    {8,  "&&", BIN_OP_AND},
    {9,  "||", BIN_OP_OR},
    {10, "&",  BIN_OP_BIT_AND},
    {12, "|",  BIN_OP_BIT_OR},
    {11, "^",  BIN_OP_BIT_XOR},
    {5,  ">>", BIN_OP_SHIFT_R},
    {5,  "<<", BIN_OP_SHIFT_L},
    {4,  "+",  BIN_OP_ADD},
    {4,  "-",  BIN_OP_SUB},
    {3,  "*",  BIN_OP_MUL},
    {3,  "/",  BIN_OP_DIV},
    {3,  "%",  BIN_OP_MOD},
    {7,  "==", BIN_OP_EQUAL},
    {7,  "!=", BIN_OP_UNEQUAL},
    {6,  "<",  BIN_OP_LT},
    {6,  ">",  BIN_OP_GT},
    {6,  "<=", BIN_OP_LT_EQ},
    {6,  ">=", BIN_OP_GT_EQ},
    {0}
};

static struct op_map *find_op_str(const struct op_map map[], char *op)
{
    for (const struct op_map *m = map; m->tok; m++) {
        if (strcmp(op, m->tok) == 0)
            return (struct op_map *)m;
    }
    return NULL;
}

static struct op_map *find_op_id(const struct op_map map[], int op)
{
    for (const struct op_map *m = map; m->tok; m++) {
        if (op == m->op)
            return (struct op_map *)m;
    }
    return NULL;
}

static struct ast_node *parse_expr_opt(struct lexer *lex, int prec);
static struct ast_node *parse_expr(struct lexer *lex, int prec);

// not really a terminal (only as far as expression parsing is concerned)
static struct ast_node *parse_terminal(struct lexer *lex)
{
    source_pos start = lex->token.pos;
    if (lexer_peek(lex, TOKEN_ID)) {
        char *name = lexer_eat_id(lex);
        return NEW_NODE(lex, id, {start, name});
    } else if (lexer_peek(lex, TOKEN_LIT)) {
        struct lex_const value = lexer_eat_lit(lex);
        return NEW_NODE(lex, lit, {start, value});
    }
    return NULL;
}

static struct ast_node *fix_empty_node(struct lexer *lex, struct ast_node *node)
{
    if (node)
        return node;
    return NEW_NODE(lex, block, {lex->token.pos, 0, NULL});
}

// parse single statement, optionally braced by { }
// since '{' is not allowed as start of an expression, this function must
// be called as further non-terminal rule in a statement
static struct ast_node *parse_block(struct lexer *lex)
{
    if (lexer_try_eat_tok(lex, "{")) {
        struct ast_node *node
            = fix_empty_node(lex, parse_expr_opt(lex, PREC_MAX));
        lexer_eat_tok(lex, "}");
        return node;
    }
    return parse_expr(lex, PREC_TERMINAL);
}

static struct ast_node *parse_block_opt(struct lexer *lex)
{
    if (lexer_peek_tok(lex, "{"))
        return parse_block(lex);
    return parse_expr_opt(lex, PREC_TERMINAL);
}

static bool may_be_decl(struct lexer *lex)
{
    return lexer_peek(lex, TOKEN_ID);
}

// uses ast_struct_member, because that happens to cover var decls. as well
static struct ast_struct_member parse_decl(struct lexer *lex, bool fn_sig)
{
    source_pos loc = lex->token.pos;
    struct lexer_state_backup prev_state;
    lexer_state_backup(lex, &prev_state);
    char *name = lexer_eat_id(lex);
    struct ast_node *type = NULL;
    struct ast_node *init = NULL;
    if (lexer_try_eat_tok(lex, ":")) {
        type = parse_expr(lex, PREC_TERMINAL);
    } else if (fn_sig) {
        // Support parameters without parameter names.
        // (Basically a manual special-cased one-token lookahead.)
        // xxx this is ugly (change grammar or parsing mechanism)
        lexer_state_restore(lex, &prev_state);
        name = "";
        type = parse_expr(lex, PREC_TERMINAL);
    }
    if (lexer_try_eat_tok(lex, "="))
        init = parse_expr(lex, PREC_TERMINAL);
    return (struct ast_struct_member) {loc, name, type, init};
}

static struct ast_fn_signature parse_fn_signature(struct lexer *lex)
{
    struct ast_fn_signature sig = { .loc = lex->token.pos };
    if (lexer_try_eat_tok(lex, "{")) {
        if (lexer_peek(lex, TOKEN_ID)) {
            if (strcmp(lex->token.value, "C") != 0)
                lexer_error_at(lex, lex->token.pos,
                            "'C' or '}' expected");
            sig.is_c = true;
            lexer_next(lex);
        }
        lexer_eat_tok(lex, "}");
    }
    lexer_eat_tok(lex, "(");
    sig.params.loc = lex->token.pos;
    if (!lexer_peek_tok(lex, ")")) {
        do {
            if (lexer_try_eat_tok(lex, "...")) {
                sig.is_vararg = true;
                break;
            }
            struct ast_struct_member m = parse_decl(lex, true);
            BL_TARRAY_APPEND(lex, sig.params.members, sig.params.members_count,
                             m);
        } while (lexer_try_eat_tok(lex, ","));
    }
    lexer_eat_tok(lex, ")");
    lexer_eat_tok(lex, ":");
    // xxx fix precedence, shitty hack to get "var x:<fn_type>=y" working
    sig.ret_type = parse_expr(lex, PREC_ASSIGN - 1);
    return sig;
}

struct tuple {
    source_pos loc;
    int exp_count;
    struct ast_node **exp;
};

// Concatenate all expressions separated by "," into a tuple.
// If first is NULL, the first element is parsed by this function.
static struct tuple parse_tuple(struct lexer *lex, struct ast_node *first)
{
    if (!first) {
        // Important: only accept empty tuples if first!=NULL
        first = parse_expr_opt(lex, PREC_COMMA - 1);
    }
    struct tuple t = {first ? ast_get_loc(first) : lex->token.pos, 0, NULL};
    struct ast_node *item = first;
    while (item) {
        BL_TARRAY_APPEND(lex, t.exp, t.exp_count, item);
        if (!lexer_try_eat_tok(lex, ","))
            break;
        // Accept trailing "," (call the _opt version), wanted for struct
        // literals (accept trailing "," even in C) and needed for 1-element
        // tuples "(e,)". Note that Python accepts trailing "," in tuples as
        // well, even if they have more than one element.
        item = parse_expr_opt(lex, PREC_COMMA - 1);
    }
    return t;
}

static struct ast_node *parse_expr_opt(struct lexer *lex, int prec)
{
    source_pos start = lex->token.pos;

    if (prec < PREC_MIN) {
        if (lexer_try_eat_tok(lex, "(")) {
            // Special case for empty tuples "()"
            if (lexer_try_eat_tok(lex, ")"))
                return NEW_NODE(lex, tuple, {start, 0, NULL});
            // Could be an expression or a struct literal.
            struct ast_node *node = parse_expr(lex, PREC_MAX);
            lexer_eat_tok(lex, ")");
            if (lexer_try_eat_tok(lex, "{")) {
                // It's a struct literal.
                struct tuple t = parse_tuple(lex, NULL);
                lexer_eat_tok(lex, "}");
                return NEW_NODE(lex, struct_lit,
                                            {start, node, t.exp_count, t.exp});
            }
            return node;
        }
        if (lexer_try_eat_tok(lex, "{")) {
            struct tuple t = parse_tuple(lex, NULL);
            lexer_eat_tok(lex, "}");
            return NEW_NODE(lex, compound_lit, {start, t.exp_count, t.exp});
        }
        if (lexer_try_eat_tok(lex, ".")) {
            struct ast_node *node1 = parse_expr_opt(lex, PREC_ASSIGN - 1);
            lexer_eat_tok(lex, "=");
            struct ast_node *node2 = parse_expr(lex, PREC_TERMINAL);
            if (node1) {
                return NEW_NODE(lex, bin_op, {start, BIN_OP_INIT, node1,
                                              node2});
            } else {
                return NEW_NODE(lex, un_op, {start, UN_OP_INIT, node2});
            }
        }
        if (lexer_try_eat_tok(lex, "var")) {
            struct ast_struct_member d = parse_decl(lex, false);
            return NEW_NODE(lex, var, {start, d.name, d.type, d.init});
        }
        if (lexer_try_eat_tok(lex, "block")) {
            return parse_block(lex);
        }
        if (lexer_try_eat_tok(lex, "if")) {
            lexer_eat_tok(lex, "(");
            struct ast_node *cond = parse_expr(lex, PREC_MAX);
            lexer_eat_tok(lex, ")");
            struct ast_node *yes = parse_block(lex);
            struct ast_node *no = NULL;
            if (lexer_try_eat_tok(lex, "else"))
                no = parse_block(lex);
            return NEW_NODE(lex, if_, {start, cond, yes, no});
        }
        if (lexer_try_eat_tok(lex, "while")) {
            lexer_eat_tok(lex, "(");
            struct ast_node *cond = parse_expr(lex, PREC_MAX);
            lexer_eat_tok(lex, ")");
            struct ast_node *body = parse_block(lex);
            return NEW_NODE(lex, while_, {start, cond, body});
        }
        if (lexer_try_eat_tok(lex, "return")) {
            struct ast_node *res = parse_expr_opt(lex, PREC_TERMINAL);
            return NEW_NODE(lex, ret, {start, res});
        }
        if (lexer_try_eat_tok(lex, "goto")) {
            char *name = lexer_eat_id(lex);
            return NEW_NODE(lex, goto_, {start, name});
        }
        if (lexer_try_eat_tok(lex, "@")) {
            // xxx this sucks; label should always be able to start a new
            //     expression (currently requires adding ";")
            char *name = lexer_eat_id(lex);
            lexer_eat_tok(lex, ":");
            return NEW_NODE(lex, label, {start, name});
        }
        if (lexer_try_eat_tok(lex, "struct")) {
            char *name = lexer_eat_id(lex);
            struct ast_struct_body *body = NULL;
            if (lexer_try_eat_tok(lex, "{")) {
                body = talloc_struct(lex, struct ast_struct_body,
                                     { .loc = lex->token.pos });
                while (may_be_decl(lex)) {
                    struct ast_struct_member m = parse_decl(lex, false);
                    BL_TARRAY_APPEND(lex, body->members, body->members_count,
                                     m);
                    lexer_eat_tok(lex, ";");
                }
                lexer_eat_tok(lex, "}");
            }
            return NEW_NODE(lex, struct_, {start, name, body});
        }
        if (lexer_try_eat_tok(lex, "^")) {
            struct ast_fn_signature sig = parse_fn_signature(lex);
            return NEW_NODE(lex, stackclosure_type, {sig});
        }
        if (lexer_try_eat_tok(lex, "fn")) {
            if (lexer_peek(lex, TOKEN_ID)) {
                // Function declaration.
                char *name = lexer_eat_id(lex);
                struct ast_fn_signature sig = parse_fn_signature(lex);
                struct ast_node *body = parse_block_opt(lex);
                return NEW_NODE(lex, fn, {start, name, sig, body});
            } else {
                // Function pointer.
                struct ast_fn_signature sig = parse_fn_signature(lex);
                return NEW_NODE(lex, fn_type, {sig});
            }
        }
        // xxx make this "#"
        if (lexer_try_eat_tok(lex, "##")) {
            return NEW_NODE(lex, null_op, {start, NULL_OP_ARRAY_LENGTH});
        }
        if (lexer_try_eat_tok(lex, "_")) {
            return NEW_NODE(lex, null_op, {start, NULL_OP_ANY});
        }
        if (lexer_try_eat_tok(lex, "[")) {
            struct ast_node *e1 = parse_expr(lex, PREC_MAX);
            lexer_eat_tok(lex, "]");
            lexer_eat_tok(lex, "=");
            struct ast_node *e2 = parse_expr(lex, PREC_TERMINAL);
            return NEW_NODE(lex, bin_op, {start, BIN_OP_INIT_ARRAY, e1, e2});
        }
        if (lexer_try_eat_tok(lex, "macro")) {
            struct ast_def_macro macro = {start};
            macro.name = lexer_eat_id(lex);
            if (lexer_try_eat_tok(lex, "(")) {
                do {
                    if (lexer_try_eat_tok(lex, "...")) {
                        macro.is_vararg = true;
                        break;
                    }
                    char *p = lexer_eat_id(lex);
                    BL_TARRAY_APPEND(lex, macro.params, macro.params_count, p);
                } while (lexer_try_eat_tok(lex, ","));
                lexer_eat_tok(lex, ")");
            } else {
                macro.no_params = true;
            }
            lexer_eat_tok(lex, "{");
            macro.contents = parse_expr(lex, PREC_TERMINAL);
            lexer_eat_tok(lex, "}");
            return NEW_NODE(lex, def_macro, macro);
        }
        return parse_terminal(lex);
    }

    if (lexer_peek(lex, TOKEN_TOK)) {
        struct op_map *un = find_op_str(un_ops, lex->token.value);
        if (un && un->prec == prec) {
            lexer_next(lex);
            struct ast_node *node = parse_expr(lex, prec);
            return NEW_NODE(lex, un_op, {start, un->op, node});
        }
    }

    struct ast_node *node = parse_expr_opt(lex, prec - 1);

    if (!node)
        return NULL;

    start = lex->token.pos;

    if (prec == PREC_CALL && lexer_try_eat_tok(lex, "(")) {
        // function call
        struct tuple t = parse_tuple(lex, NULL);
        lexer_eat_tok(lex, ")");
        return NEW_NODE(lex, call, {start, node, t.exp_count, t.exp});
    }

    if (prec == PREC_ARRAY && lexer_try_eat_tok(lex, "[")) {
        // indexing/type construction, or slice operation
        if (lexer_try_eat_tok(lex, "]"))
            return NEW_NODE(lex, un_op, {start, UN_OP_ARRAY, node});
        struct ast_node *e2 = parse_expr(lex, PREC_MAX);
        if (lexer_try_eat_tok(lex, "..")) {
            struct ast_node *e3 = parse_expr(lex, PREC_MAX);
            lexer_eat_tok(lex, "]");
            return NEW_NODE(lex, tern_op, {start, TERN_OP_SLICE, node, e2, e3});
        } else {
            lexer_eat_tok(lex, "]");
            return NEW_NODE(lex, bin_op, {start, BIN_OP_ARRAY, node, e2});
        }
    }

    if (prec == PREC_COND && lexer_try_eat_tok(lex, "?")) {
        struct ast_node *e2 = parse_expr(lex, PREC_COND);
        lexer_eat_tok(lex, ":");
        struct ast_node *e3 = parse_expr(lex, PREC_COND);
        return NEW_NODE(lex, tern_op, {start, TERN_OP_COND, node, e2, e3});
    }

    if (lexer_peek(lex, TOKEN_TOK)) {
        struct op_map *bin = find_op_str(bin_ops, lex->token.value);
        struct op_map *un = find_op_str(un_post_ops, lex->token.value);
        assert(!(bin && un));
        if (bin && bin->prec != prec) bin = NULL;
        if (un && un->prec != prec) un = NULL;
        if (bin || un) {
            lexer_next(lex);
            if (bin) {
                struct ast_node *node2 = parse_expr(lex, prec);
                return NEW_NODE(lex, bin_op, {start, bin->op, node, node2});
            } else {
                return NEW_NODE(lex, un_op, {start, un->op, node});
            }
            assert(false);
        }
    }

    if (prec == PREC_COMMA && lexer_peek_tok(lex, ",")) {
        struct tuple t = parse_tuple(lex, node);
        return NEW_NODE(lex, tuple, {t.loc, t.exp_count, t.exp});
    }

    if (prec == PREC_STATEMENT && lexer_peek_tok(lex, ";")) {
        // ';' concatenates all expressions on the same level into a block
        struct ast_block block = {ast_get_loc(node), 0, NULL};
        struct ast_node *item = node;
        while (item) {
            BL_TARRAY_APPEND(lex, block.stmts, block.stmts_count, item);
            if (!lexer_try_eat_tok(lex, ";"))
                break;
            item = parse_expr_opt(lex, PREC_STATEMENT - 1);
        }
        return NEW_NODE(lex, block, block);
    }

    return node;
}

static struct ast_node *parse_expr(struct lexer *lex, int prec)
{
    struct ast_node *ret = parse_expr_opt(lex, prec);
    if (!ret)
        lexer_error_at(lex, lex->token.pos, "expression expected");
    return ret;
}

struct ast_node *bl_parse(struct lexer *lex)
{
    struct ast_node *node = fix_empty_node(lex, parse_expr_opt(lex, PREC_MAX));
    if (lex->token.type != TOKEN_ERROR && lex->token.type != TOKEN_EOF)
        lexer_expected_token(lex, TOKEN_EOF, NULL);
    if (!lex->errors)
        return node;
    return NULL;
}

static const char *ternop_to_str(int op)
{
    switch (op) {
        case TERN_OP_COND: return "?:";
        case TERN_OP_SLICE: return "..";
        default: assert(false);
    }
}

static const char *binop_to_str(int op)
{
    switch (op) {
        case BIN_OP_INIT: return ".=";
        case BIN_OP_ARRAY: return "[]";
        case BIN_OP_INIT_ARRAY: return "[]=";
    }
    struct op_map *m = find_op_id(bin_ops, op);
    assert(m);
    return m->tok;
}

static const char *unop_to_str(int op)
{
    switch (op) {
        case UN_OP_ARRAY: return "[]";
        case UN_OP_INIT: return ".=";
    }
    struct op_map *m = find_op_id(un_ops, op);
    if (!m)
        m = find_op_id(un_post_ops, op);
    assert(m);
    return m->tok;
}

static const char *nullop_to_str(int op)
{
    switch (op) {
        case NULL_OP_ARRAY_LENGTH: return "#";
        case NULL_OP_ANY: return "_";
        default: assert(false);
    }
}

struct dump_ctx {
    FILE *out;
    int level;
    int flags;
};

static void pre(struct dump_ctx *ctx)
{
    fprintf(ctx->out, "%*s", ctx->level * 4, "");
}

static void fin(struct dump_ctx *ctx, source_pos loc)
{
    if (ctx->flags & DUMP_AST_NOLOC) {
        fprintf(ctx->out, "\n");
    } else {
        char *p = source_pos_string(loc);
        fprintf(ctx->out, " (%s)\n", p);
        talloc_free(p);
    }
}

static void dump_node(struct dump_ctx *ctx, const char *role,
                      struct ast_node *node);

static void dump_expr_list(struct dump_ctx *ctx, const char *role,
                           struct ast_node **exprs, int exprs_count)
{
    ctx->level++;
    pre(ctx);
    fprintf(ctx->out, "{%s}\n", role);
    for (int n = 0; n < exprs_count; n++) {
        dump_node(ctx, NULL, exprs[n]);
    }
    ctx->level--;
}

static void dump_struct_body(struct dump_ctx *ctx, const char *role,
                             struct ast_struct_body *body)
{
    ctx->level++;
    pre(ctx);
    fprintf(ctx->out, "{%s}", role);
    fin(ctx, body->loc);
    for (int n = 0; n < body->members_count; n++) {
        struct ast_struct_member member = body->members[n];
        ctx->level++;
        pre(ctx);
        fprintf(ctx->out, "[member] '%s'", member.name);
        fin(ctx, member.loc);
        dump_node(ctx, "type", member.type);
        dump_node(ctx, "init", member.init);
        ctx->level--;
    }
    ctx->level--;
}

static void dump_fn_sig(struct dump_ctx *ctx, struct ast_fn_signature sig)
{
    ctx->level++;
    pre(ctx);
    fprintf(ctx->out, "{signature} is_vararg=%d is_c=%d", sig.is_vararg,
            sig.is_c);
    fin(ctx, sig.loc);
    dump_struct_body(ctx, "params", &sig.params);
    dump_node(ctx, "ret_type", sig.ret_type);
    ctx->level--;
}

static void dump_node(struct dump_ctx *ctx, const char *role,
                      struct ast_node *node)
{
    ctx->level++;
    pre(ctx);
    if (role)
        fprintf(ctx->out, "{%s} ", role);
    if (!node) {
        fprintf(ctx->out, "[null]\n");
        goto out;
    }
    switch (node->type) {
        case AST_id: {
            struct ast_id *id = GET_UNION(AST, id, node);
            fprintf(ctx->out, "[id] %s", id->id);
            fin(ctx, id->loc);
            break;
        }
        case AST_lit: {
            struct ast_lit *lit = GET_UNION(AST, lit, node);
            char *s = lexer_const_string(NULL, lit->lit);
            fprintf(ctx->out, "[lit] %s", s);
            talloc_free(s);
            fin(ctx, lit->loc);
            break;
        }
        case AST_def_macro: {
            struct ast_def_macro *macro = GET_UNION(AST, def_macro, node);
            fprintf(ctx->out, "[macro] %s no_params=%d is_vararg=%d",
                    macro->name, macro->no_params, macro->is_vararg);
            fin(ctx, macro->loc);
            if (!macro->no_params) {
                ctx->level++;
                pre(ctx);
                fprintf(ctx->out, "{params} ");
                for (int n = 0; n < macro->params_count; n++) {
                    char *p = macro->params[n];
                    if (n > 0)
                        fprintf(ctx->out, ", ");
                    fprintf(ctx->out, "%s", p);
                }
                fprintf(ctx->out, "\n");
                ctx->level--;
            }
            dump_node(ctx, "contents", macro->contents);
            break;
        }
        case AST_compound_lit: {
            struct ast_compound_lit *lit = GET_UNION(AST, compound_lit, node);
            fprintf(ctx->out, "[compound_lit]");
            fin(ctx, lit->loc);
            dump_expr_list(ctx, "lit", lit->exprs, lit->exprs_count);
            break;
        }
        case AST_struct_lit: {
            struct ast_struct_lit *lit = GET_UNION(AST, struct_lit, node);
            fprintf(ctx->out, "[struct_lit]");
            fin(ctx, lit->loc);
            dump_node(ctx, "type", lit->type);
            dump_expr_list(ctx, "init", lit->exprs, lit->exprs_count);
            break;
        }
        case AST_tuple: {
            struct ast_tuple *tp = GET_UNION(AST, tuple, node);
            fprintf(ctx->out, "[tuple]");
            fin(ctx, tp->loc);
            dump_expr_list(ctx, "tuple", tp->exprs, tp->exprs_count);
            break;
        }
        case AST_var: {
            struct ast_var *var = GET_UNION(AST, var, node);
            fprintf(ctx->out, "[var] %s", var->name);
            fin(ctx, var->loc);
            dump_node(ctx, "type", var->type);
            dump_node(ctx, "init", var->init);
            break;
        }
        case AST_null_op: {
            struct ast_null_op *op = GET_UNION(AST, null_op, node);
            fprintf(ctx->out, "[nullop] %s", nullop_to_str(op->op));
            fin(ctx, op->loc);
            break;
        }
        case AST_un_op: {
            struct ast_un_op *op = GET_UNION(AST, un_op, node);
            fprintf(ctx->out, "[unop] %s", unop_to_str(op->op));
            fin(ctx, op->loc);
            dump_node(ctx, NULL, op->expr);
            break;
        }
        case AST_bin_op: {
            struct ast_bin_op *op = GET_UNION(AST, bin_op, node);
            fprintf(ctx->out, "[binop] %s", binop_to_str(op->op));
            fin(ctx, op->loc);
            dump_node(ctx, "l", op->expr1);
            dump_node(ctx, "r", op->expr2);
            break;
        }
        case AST_tern_op: {
            struct ast_tern_op *op = GET_UNION(AST, tern_op, node);
            fprintf(ctx->out, "[ternop] %s", ternop_to_str(op->op));
            fin(ctx, op->loc);
            dump_node(ctx, "l", op->expr1);
            dump_node(ctx, "m", op->expr2);
            dump_node(ctx, "r", op->expr3);
            break;
        }
        case AST_call: {
            struct ast_call *call = GET_UNION(AST, call, node);
            fprintf(ctx->out, "[call]");
            fin(ctx, call->loc);
            dump_node(ctx, "fn", call->expr);
            dump_expr_list(ctx, "args", call->args, call->args_count);
            break;
        }
        case AST_fn_type: {
            struct ast_fn_type *fn_type = GET_UNION(AST, fn_type, node);
            fprintf(ctx->out, "[fn_type]");
            fin(ctx, fn_type->sig.loc);
            dump_fn_sig(ctx, fn_type->sig);
            break;
        }
        case AST_stackclosure_type: {
            struct ast_stackclosure_type *sc_type
                = GET_UNION(AST, stackclosure_type, node);
            fprintf(ctx->out, "[stackclosure_type]");
            fin(ctx, sc_type->sig.loc);
            dump_fn_sig(ctx, sc_type->sig);
            break;
        }
        case AST_fn: {
            struct ast_fn *fn = GET_UNION(AST, fn, node);
            fprintf(ctx->out, "[fn] '%s'", fn->name);
            fin(ctx, fn->loc);
            dump_fn_sig(ctx, fn->sig);
            dump_node(ctx, "body", fn->body);
            break;
        }
        case AST_struct_: {
            struct ast_struct_ *struct_ = GET_UNION(AST, struct_, node);
            fprintf(ctx->out, "[struct] '%s'", struct_->name);
            fin(ctx, struct_->loc);
            if (struct_->body)
                dump_struct_body(ctx, "body", struct_->body);
            break;
        }
        case AST_ret: {
            struct ast_ret *ret = GET_UNION(AST, ret, node);
            fprintf(ctx->out, "[return]");
            fin(ctx, ret->loc);
            dump_node(ctx, NULL, ret->expr);
            break;
        }
        case AST_if_: {
            struct ast_if_ *if_ = GET_UNION(AST, if_, node);
            fprintf(ctx->out, "[if]");
            fin(ctx, if_->loc);
            dump_node(ctx, "cond", if_->cond);
            dump_node(ctx, "yes", if_->yes);
            dump_node(ctx, "no", if_->no);
            break;
        }
        case AST_while_: {
            struct ast_while_ *while_ = GET_UNION(AST, while_, node);
            fprintf(ctx->out, "[while]");
            fin(ctx, while_->loc);
            dump_node(ctx, "cond", while_->cond);
            dump_node(ctx, "body", while_->body);
            break;
        }
        case AST_block: {
            struct ast_block *block = GET_UNION(AST, block, node);
            fprintf(ctx->out, "[block]");
            fin(ctx, block->loc);
            for (int n = 0; n < block->stmts_count; n++) {
                dump_node(ctx, NULL, block->stmts[n]);
            }
            break;
        }
        case AST_label: {
            struct ast_label *label = GET_UNION(AST, label, node);
            fprintf(ctx->out, "[label] '%s'", label->name);
            fin(ctx, label->loc);
            break;
        }
        case AST_goto_: {
            struct ast_goto_ *goto_ = GET_UNION(AST, goto_, node);
            fprintf(ctx->out, "[goto] '%s'", goto_->label);
            fin(ctx, goto_->loc);
            break;
        }
        default:
            fprintf(ctx->out, "[unknown %d]\n", node->type);
            abort();
    }
out:
    ctx->level--;
}

void dump_ast(FILE *f, struct ast_node *ast, int flags)
{
    dump_node(&(struct dump_ctx) {f, -1, flags}, NULL, ast);
}

source_pos ast_get_loc(struct ast_node *node)
{
    switch (node->type) {
        case AST_id: return GET_UNION(AST, id, node)->loc;
        case AST_lit: return GET_UNION(AST, lit, node)->loc;
        case AST_def_macro: return GET_UNION(AST, def_macro, node)->loc;
        case AST_compound_lit: return GET_UNION(AST, compound_lit, node)->loc;
        case AST_struct_lit: return GET_UNION(AST, struct_lit, node)->loc;
        case AST_tuple: return GET_UNION(AST, tuple, node)->loc;
        case AST_var: return GET_UNION(AST, var, node)->loc;
        case AST_null_op: return GET_UNION(AST, null_op, node)->loc;
        case AST_un_op: return GET_UNION(AST, un_op, node)->loc;
        case AST_bin_op: return GET_UNION(AST, bin_op, node)->loc;
        case AST_tern_op: return GET_UNION(AST, tern_op, node)->loc;
        case AST_call: return GET_UNION(AST, call, node)->loc;
        case AST_fn_type: return GET_UNION(AST, fn_type, node)->sig.loc;
        case AST_stackclosure_type:
            return GET_UNION(AST, stackclosure_type, node)->sig.loc;
        case AST_fn: return GET_UNION(AST, fn, node)->loc;
        case AST_struct_: return GET_UNION(AST, struct_, node)->loc;
        case AST_ret: return GET_UNION(AST, ret, node)->loc;
        case AST_if_: return GET_UNION(AST, if_, node)->loc;
        case AST_while_: return GET_UNION(AST, while_, node)->loc;
        case AST_block: return GET_UNION(AST, block, node)->loc;
        case AST_label: return GET_UNION(AST, label, node)->loc;
        case AST_goto_: return GET_UNION(AST, goto_, node)->loc;
        default: assert(false);
    }
}
