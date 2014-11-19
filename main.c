#include <stdio.h>
#include <assert.h>
#include "lex.h"
#include "ast.h"
#include "ir.h"
#include "bstr.h"
#include "utils.h"

static int gres = 0;

static bstr read_file(void *talloc_ctx, const char *filename)
{
    bstr res = {0};
    FILE *f = fopen(filename, "r");
    if (!f)
        goto error_exit;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    res = (bstr) {talloc_size(talloc_ctx, size), size};
    fread(res.start, res.len, 1, f);
    if (fclose(f) != 0)
        goto error_exit;
    return res;

error_exit:
    fprintf(stderr, "couldn't read file '%s'!\n", filename);
    talloc_free(res.start);
    return (bstr) {0};
}

static void dump_tokens(bstr src, const char *file)
{
    struct lexer *lex = lexer_new(src, bstr0(file));
    do {
        lexer_next(lex);
        char *s = full_token_string(lex->token);
        printf("%s\n", s);
        talloc_free(s);
    } while (!lexer_finished(lex));
    talloc_free(lex);
}

static struct ast_node *parse_ast(bstr data, bstr name)
{
    struct lexer *lex = lexer_new(data, name);
    lexer_next(lex);
    struct ast_node *ast = bl_parse(lex);
    if (ast) {
        // make the top node own all memory
        talloc_steal(NULL, ast);
        talloc_steal(ast, lex);
    } else {
        talloc_free(lex);
    }
    return ast;
}

static char *ast_to_string(struct ast_node *node, int flags)
{
    size_t sz = 0;
    char *data = NULL;
    FILE *f = open_memstream(&data, &sz);
    if (!f)
        abort();
    dump_ast(f, node, flags);
    fclose(f);
    if (!data)
        abort();
    char *res = talloc_strdup(NULL, data);
    free(data);
    return res;
}

static void test_syntax_ast(bstr a, bstr b, bool expect_equal)
{
    struct ast_node *at = parse_ast(a, bstr0("a"));
    struct ast_node *bt = parse_ast(b, bstr0("b"));
    if (!at || !bt) {
        fprintf(stderr, "one could not be parsed!\n");
        fprintf(stderr, "a: %.*s\n", BSTR_P(a));
        fprintf(stderr, "b: %.*s\n", BSTR_P(b));
        exit(1);
    } else {
        char *sa = ast_to_string(at, DUMP_AST_NOLOC);
        char *sb = ast_to_string(bt, DUMP_AST_NOLOC);
        if ((expect_equal && strcmp(sa, sb) != 0)
         || (!expect_equal && strcmp(sa, sb) == 0))
        {
            if (expect_equal)
                fprintf(stderr, "trees not equal:\n");
            else
                fprintf(stderr, "trees equal:\n");
            fprintf(stderr, "a:\n%s", sa);
            fprintf(stderr, "b:\n%s", sb);
            exit(1);
        }
        talloc_free(sa);
        talloc_free(sb);
    }
    talloc_free(at);
    talloc_free(bt);
}

static void parse_prec_test(bstr data)
{
    void *tmp = talloc_new(NULL);
    int state = 0;
    char *strings[3] = {0};
    while (data.len) {
        bstr line = bstr_getline(data, &data);
        if (bstrcmp0(line, "#syntax-a:") == 0) {
            state = 1;
        } else if (bstrcmp0(line, "#syntax-b:") == 0) {
            state = 2;
        } else if (bstrcmp0(line, "#test-eq") == 0) {
            test_syntax_ast(bstr0(strings[1]), bstr0(strings[2]), true);
            talloc_free(strings[1]);
            talloc_free(strings[2]);
            strings[1] = strings[2] = NULL;
            state = 0;
        } else if (bstrcmp0(line, "#test-neq") == 0) {
            test_syntax_ast(bstr0(strings[1]), bstr0(strings[2]), false);
            talloc_free(strings[1]);
            talloc_free(strings[2]);
            strings[1] = strings[2] = NULL;
            state = 0;
        } else if (bstr_startswith0(line, "#")) {
            fprintf(stderr, "not understood: '%.*s'\n", BSTR_P(line));
            exit(1);
            state = 0;
        } else {
            strings[state] = talloc_strndup_append_buffer(strings[state],
                                                          line.start, line.len);
            talloc_steal(tmp, strings[state]);
        }
    }
    talloc_free(tmp);
}

static void dump_cg(bstr src, const char *file)
{
    struct ast_node *ast = parse_ast(src, bstr0(file));
    gres = 1;
    if (ast) {
        dump_ast(stdout, ast, 0);
        struct ir_unit *un = bl_cg_expr(ast);
        if (un) {
            dump_unit(stdout, un);
            gres = 0;
        }
        talloc_free(un);
        talloc_free(ast);
    }
}

static void dump_cg_o(bstr src, const char *file)
{
    struct ast_node *ast = parse_ast(src, bstr0(file));
    gres = 1;
    if (ast) {
        dump_ast(stdout, ast, 0);
        struct ir_unit *un = bl_cg_expr(ast);
        if (un) {
            dump_unit(stdout, un);
            struct optimize_settings opt = OPTIMIZE_DEFAULT;
            unit_optimize(un, &opt);
            printf("------------------- after op: -------------------\n");
            dump_unit(stdout, un);
            gres = 0;
        }
        talloc_free(un);
        talloc_free(ast);
    }
}

static int dump_cg_c(bstr src, const char *file)
{
    struct ast_node *ast = parse_ast(src, bstr0(file));
    if (!ast)
        return 1;
    struct ir_unit *un = bl_cg_expr(ast);
    if (!un) {
        talloc_free(ast);
        return 2;
    }
    generate_c(stdout, un);
    talloc_free(un);
    talloc_free(ast);
    return 0;
}

static void random_tests(void)
{
    uint64_t v = 1;
    for (int i = 1; i < 64; i++) {
        assert(log2_up_u64(v) == i - 1);
        v = v << 1;
    }
    assert(log2_up_u64(0) == 0);
}

int main(int argc, char **argv)
{
    ta_enable_leak_report();

    void *ctx = talloc_new(NULL);

    random_tests();

    argc--; argv++;
    if (argc < 1) {
        fprintf(stderr, "No.\n");
        goto error_exit;
    }

    char *cmd = argv[0];
    argc--; argv++;

    char *nextarg = NULL;
    if (argc > 0) {
        nextarg = argv[0];
        argc--; argv++;
    }

    if (!nextarg) {
        fprintf(stderr, "Needs argument.\n");
        goto error_exit;
    }

    if (strcmp(cmd, "parse_arg") == 0) {
        struct ast_node *ast = parse_ast(bstr0(nextarg), bstr0(cmd));
        dump_ast(stdout, ast, 0);
        talloc_free(ast);
        goto done;
    } else if (strcmp(cmd, "tokens_arg") == 0) {
        dump_tokens(bstr0(nextarg), cmd);
        goto done;
    } else if (strcmp(cmd, "cg_arg") == 0) {
        dump_cg(bstr0(nextarg), cmd);
        goto done;
    } else if (strcmp(cmd, "cg_arg_o") == 0) {
        dump_cg_o(bstr0(nextarg), cmd);
        goto done;
    } else if (strcmp(cmd, "cg_arg_c") == 0) {
        gres = dump_cg_c(bstr0(nextarg), cmd);
        goto done;
    }

    bstr file_data = read_file(ctx, nextarg);

    if (strcmp(cmd, "tokens") == 0) {
        dump_tokens(file_data, nextarg);
    } else if (strcmp(cmd, "parse") == 0) {
        struct ast_node *ast = parse_ast(file_data, bstr0(nextarg));
        dump_ast(stdout, ast, 0);
        talloc_free(ast);
    } else if (strcmp(cmd, "cg") == 0) {
        dump_cg(file_data, nextarg);
        goto done;
    } else if (strcmp(cmd, "cg_o") == 0) {
        dump_cg_o(file_data, nextarg);
        goto done;
    } else if (strcmp(cmd, "cg_c") == 0) {
        gres = dump_cg_c(file_data, nextarg);
        goto done;
    } else if (strcmp(cmd, "parse_prec_test") == 0) {
        parse_prec_test(file_data);
    } else {
        fprintf(stderr, "Unknown command!\n");
        goto error_exit;
    }

    goto done;

error_exit:
    gres = 10;
done:
    talloc_free(ctx);
    return gres;
}
