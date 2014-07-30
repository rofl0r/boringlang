#include <stdlib.h>
#include <stdio.h>

#include "union.h"

struct ast_var {
    int stuff;
    char *var_name;
};

struct ast_fn {
    char *function_name;
};

enum ast_node_type {
    AST_error,
    AST_var,
    AST_fn,
};

struct ast_node {
    enum ast_node_type type;
    union {
        struct ast_var var;
        struct ast_fn fn;
    } u;
};

static char *visit(struct ast_node *node)
{
    switch (node->type) {
        case AST_var: ;
            struct ast_var *var = GET_UNION(AST, var, node);
            return var->var_name;
        case AST_fn: ;
            struct ast_fn *fn = GET_UNION(AST, fn, node);
            return fn->function_name;
        default:
            abort();
    }
}

int main(int argc, char **argv) {
    struct ast_node node1 = MAKE_UNION(AST, var, {.var_name = "hi"});
    printf("should read 'hi': '%s'\n", visit(&node1));

    struct ast_node node2 = MAKE_UNION(AST, fn, {.function_name = "bla"});
    printf("should read 'bla': '%s'\n", visit(&node2));
    printf("should return 1: %d\n", !!TEST_UNION(AST, fn, &node2));

    printf("should return 0: %d\n", !!TEST_UNION(AST, var, &node2));
    printf("and now we crash:\n");
    struct ast_var *bogus = GET_UNION(AST, var, &node2);
    printf("never printed: %s.\n", bogus->var_name);

    return 0;
}
