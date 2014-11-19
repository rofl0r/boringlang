#ifndef BL_LEX_H
#define BL_LEX_H

#include <stdbool.h>
#include "union.h"

struct source_pos {
    int line, column;
    int byte;
    char *filename;
};

typedef struct source_pos source_pos;
typedef struct source_pos LOC;

struct lex_int {
    uint64_t val;   // always a positive integer (even if sign==-1)
    int type;       // 0: unspecified, 0<n: i<n>, 0>n: u<n> (e.g. -32=="i32")
};

enum lex_const_type {
    LEX_CONST_cempty,
    LEX_CONST_cint,
    LEX_CONST_cdouble,
    LEX_CONST_cchar,
    LEX_CONST_cstring,
};

struct lex_const {
    enum lex_const_type type;
    union {
        struct lex_int cint;
        double cdouble;
        int cchar;
        char *cstring;
    } u;
};

#define MAKE_LEX_CONST(type, ...) \
    (struct lex_const) MAKE_UNION(LEX_CONST, type, __VA_ARGS__)

enum token_type {
    TOKEN_ERROR,
    TOKEN_EOF,
    TOKEN_TOK,
    TOKEN_ID,
    TOKEN_LIT,
};

struct token {
    enum token_type type;
    struct source_pos pos;
    char *value;
    struct lex_const lit_value;
};

struct lexer {
    char *source;
    int source_len;
    struct source_pos pos;
    struct token token;

    int errors;
};

struct lexer_state_backup {
    struct source_pos pos;
    struct token token;
    int errors;
};

char *source_pos_string(struct source_pos pos);
char *token_string(enum token_type type, char *value);
char *full_token_string(struct token token);

void merge_loc(struct source_pos *pos, struct source_pos npos);

struct lexer *lexer_new(char *source, char *filename);
void lexer_error_at(struct lexer *lex, struct source_pos pos,
                    const char *msg, ...);
bool lexer_eof(struct lexer *lex);
bool lexer_finished(struct lexer *lex);
void lexer_skip_ws(struct lexer *lex);
bool lexer_next(struct lexer *lex);

void lexer_state_backup(struct lexer *lex, struct lexer_state_backup *state);
bool lexer_state_restore(struct lexer *lex, struct lexer_state_backup *state);

void lexer_expected_token(struct lexer *lex, enum token_type type,
                          const char *value);

bool lexer_peek(struct lexer *lex, enum token_type type);
bool lexer_peek_tok(struct lexer *lex, const char *tok);
bool lexer_try_eat_tok(struct lexer *lex, const char *tok);
void lexer_eat_tok(struct lexer *lex, const char *tok);
char *lexer_eat_id(struct lexer *lex);
struct lex_const lexer_eat_lit(struct lexer *lex);

char *lexer_const_string(void *tctx, struct lex_const lc);

#endif
