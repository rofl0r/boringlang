#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>

#include "talloc.h"
#include "lex.h"
#include "union.h"
#include "value.h"

// hurr
#define lexer_fatal abort

static const char* operators[] = {
    // warning: longest matching prefixes must be first
    "...",
    "&&", "||", ">=", "<=", "<<", ">>", "==", "!=", "->", "..", "##", "%%",
    "+", "-", "*", "/", "=", ">", "<", "&", "*", "~", "!", ".", "=", "|", "^",
    "[", "]", "(", ")", "{", "}", "%", ":", ";", ",", "@", "?", "#",
    NULL,
    // not added: $§°'´`
};

static const char* keywords[] = {
    "_",
    "var", "fn", "if", "block", "else", "return", "goto", "while", "struct",
    "macro",
    NULL,
};

char *source_pos_string(struct source_pos pos)
{
    return talloc_asprintf(NULL, "%s:%d:%d", pos.filename ? pos.filename : "-",
                           pos.line, pos.column);
}

struct lexer *lexer_new(char *source, char *filename)
{
    struct lexer *lex = talloc_zero(NULL, struct lexer);
    lex->source = talloc_strdup(lex, source);
    lex->source_len = strlen(lex->source);
    lex->pos = (struct source_pos) {1, 1, 0, talloc_strdup(lex, filename)};
    return lex;
}

void lexer_error_at(struct lexer *lex, struct source_pos pos,
                    const char *msg, ...)
{
    va_list va;
    va_start(va, msg);

    char *spos = source_pos_string(pos);
    fprintf(stderr, "Error at %s: ", spos);
    talloc_free(spos);
    vfprintf(stderr, msg, va);
    fprintf(stderr, "\n");

    va_end(va);

    lex->errors++;
}

void lexer_state_backup(struct lexer *lex, struct lexer_state_backup *state)
{
    state->pos = lex->pos;
    state->token = lex->token;
    state->errors = lex->errors;
}

bool lexer_state_restore(struct lexer *lex, struct lexer_state_backup *state)
{
    // we can't roll back errors, because they are user visible
    if (lex->errors != state->errors)
        return false;
    lex->pos = state->pos;
    lex->token = state->token;
    return true;
}

bool lexer_eof(struct lexer *lex)
{
    return lex->pos.byte >= lex->source_len;
}

bool lexer_finished(struct lexer *lex)
{
    return lex->token.type == TOKEN_EOF || lex->token.type == TOKEN_ERROR;
}

// Read character and return its unicode codepoint, or -1 on EOF.
static int read_char(struct lexer *lex)
{
    if (lexer_eof(lex))
        return -1;
    // "should" do UTF-8 parsing here
    unsigned char c = lex->source[lex->pos.byte];
    lex->pos.byte++;
    lex->pos.column++;
    if (c == '\n') {
        lex->pos.line++;
        lex->pos.column = 1;
    }
    return c;
}

static bool skip_str(struct lexer *lex, const char *str)
{
    int len = strlen(str);
    if (lex->pos.byte + len > lex->source_len)
        return false;
    if (memcmp(lex->source + lex->pos.byte, str, len) != 0)
        return false;
    for (int n = 0; n < len; n++)
        read_char(lex);
    return true;
}

static int read_any(struct lexer *lex, const char *set)
{
    if (lexer_eof(lex))
        return 0;
    char c = lex->source[lex->pos.byte];
    if (!c || !strchr(set, c))
        return 0;
    return read_char(lex);
}

static bool skip_ws_only(struct lexer *lex)
{
    return read_any(lex, " \t\n\r");
}

static bool skip_nest_comment(struct lexer *lex)
{
    if (!skip_str(lex, "/*"))
        return false;
    struct source_pos start = lex->pos;
    while (!skip_str(lex, "*/")) {
        read_char(lex);
        if (lexer_eof(lex)) {
            lexer_error_at(lex, start, "unclosed comment");
            break;
        }
    }
    return true;
}

static bool skip_comment(struct lexer *lex)
{
    if (!skip_str(lex, "//"))
        return false;
    int line = lex->pos.line;
    while (lex->pos.line == line) {
        if (read_char(lex) < 0)
            break;
    }
    return true;
}

void lexer_skip_ws(struct lexer *lex)
{
    while (skip_ws_only(lex) || skip_nest_comment(lex) || skip_comment(lex)) {}
}

// partial (simplistic) number parsing only
static bool lex_number(struct lexer *lex)
{
    struct source_pos start = lex->pos;
    int num_start = lex->pos.byte;
    int radix = 0;
    const char *numset = "0123456789";
    if (skip_str(lex, "0x")) {
        radix = 16;
        numset = "0123456789abcdefABCDEF";
    } else if (skip_str(lex, "0b")) {
        radix = 2;
        numset = "01";
    }
    while (read_any(lex, numset)) {}
    if (lex->pos.byte == num_start) {
        lex->pos = start;
        return false;
    }
    int num_end = lex->pos.byte;
    if (skip_str(lex, ".")) {
        if (radix)
            goto err;
        int subnum_start = lex->pos.byte;
        while (read_any(lex, numset)) {}
        if (lex->pos.byte == subnum_start)
            goto err;
        num_end = lex->pos.byte;

        char *s = talloc_strndup(lex, lex->source + num_start, num_end - num_start);
        char *rest = NULL;
        double num = strtod(s, &rest);
        if (rest && rest[0])
            goto err;
        lex->token.type = TOKEN_LIT;
        lex->token.value = s;
        lex->token.lit_value = MAKE_LEX_CONST(cdouble, num);
    } else {
        char *s = talloc_strndup(lex, lex->source + num_start, num_end - num_start);
        char *rest = NULL;
        uint64_t val = strtoull(s, &rest, radix);
        if (rest && rest[0])
            goto err;
        int sign = 0, bits = 0;
        int tok = read_any(lex, "ui");
        if (tok) {
            sign = tok == 'u' ? 1 : -1;
            if (skip_str(lex, "8"))
                bits = 8;
            else if (skip_str(lex, "16"))
                bits = 16;
            else if (skip_str(lex, "32"))
                bits = 32;
            else if (skip_str(lex, "64"))
                bits = 64;
            else
                goto err;
            // NOTE: the semantics pass has to take care of overflow.
            //       Main reason: we want to allow things like -128i8.
        }
        lex->token.type = TOKEN_LIT;
        lex->token.value = s;
        lex->token.lit_value = MAKE_LEX_CONST(cint, {val, bits * sign});
    }
    return true;

err:
    lex->pos = start;
    return false;
}

static bool lex_id(struct lexer *lex)
{
    int start = lex->pos.byte;
    while (!lexer_eof(lex)) {
        unsigned char c = lex->source[lex->pos.byte];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '_')
        {
            read_char(lex);
        } else {
            break;
        }
    }
    if (start == lex->pos.byte)
        return false;
    lex->token.type = TOKEN_ID;
    lex->token.value = talloc_strndup(lex, lex->source + start,
                                      lex->pos.byte - start);
    for (const char **keyword = keywords; *keyword; keyword++) {
        if (strcmp(lex->token.value, *keyword) == 0) {
            lex->token.type = TOKEN_TOK;
            break;
        }
    }
    return true;
}

static int read_hex_digit(struct lexer *lex)
{
    unsigned char c = lex->source[lex->pos.byte];
    if (c >= '0' && c <= '9') {
        read_char(lex);
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        read_char(lex);
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        read_char(lex);
        return c - 'a' + 10;
    }
    return -1;
}

// Read the string escape. Assumes the '\' has already been read.
static char read_escape(struct lexer *lex)
{
    struct source_pos start = lex->pos;
    int c = read_char(lex);
    if (c < 0)
        goto error_exit;
    switch (c) {
        case '\\': return '\\';
        case '\'': return '\'';
        case '"': return '"';
        case 'n': return '\n';
        case 'r': return '\r';
        case 't': return '\t';
        case '0': return '\0';
        case 'x': {
            int hi = read_hex_digit(lex);
            if (hi < 0)
                goto error_exit;
            int lo = read_hex_digit(lex);
            if (lo < 0)
                goto error_exit;
            return lo | (hi << 4);
        }
        default:
            goto error_exit;
    }

error_exit:
    lexer_error_at(lex, start, "unknown string escape or EOF");
    return '?';
}

static bool lex_char(struct lexer *lex)
{
    if (!skip_str(lex, "'"))
        return false;
    int c = read_char(lex);
    if (c < 0) {
        lexer_error_at(lex, lex->pos, "character literal not finished");
        return false;
    }
    if (c == '\\')
        c = read_escape(lex);
    if (c < 0)
        return false;
    if (!skip_str(lex, "'"))
        lexer_error_at(lex, lex->pos, "character literal not closed");
    lex->token.type = TOKEN_LIT;
    lex->token.lit_value = MAKE_LEX_CONST(cchar, c);
    return true;
}

static bool lex_string(struct lexer *lex)
{
    if (!skip_str(lex, "\""))
        return false;
    struct source_pos start = lex->pos;
    struct source_pos last = start;
    char *vstr = talloc_strdup(lex, "");
    for (;;) {
        int c = read_char(lex);
        if (c < 0) {
            lexer_error_at(lex, start, "string literal not closed");
            return false;
        }
        if (c == '\\') {
            vstr = talloc_strndup_append(vstr, lex->source + last.byte,
                                         lex->pos.byte - 1 - last.byte);
            c = read_escape(lex);
            // Assume characters are always byte-range for now
            // (needs utf-8 encoder for full unicode)
            vstr = talloc_strndup_append(vstr, &(char) {c}, 1);
            last = lex->pos;
        }
        if (c == '"')
            break;
    }
    lex->token.type = TOKEN_LIT;
    vstr = talloc_strndup_append(vstr, lex->source + last.byte,
                                 lex->pos.byte - 1 - last.byte);
    lex->token.lit_value = MAKE_LEX_CONST(cstring, vstr);
    return true;
}

static bool lex_tok(struct lexer *lex)
{
    char *src = lex->source + lex->pos.byte;
    for (const char **op = operators; *op; op++) {
        char *tok = (char *)*op;
        int tok_len = strlen(tok);
        if (strncmp(src, tok, tok_len) == 0) {
            lex->token.type = TOKEN_TOK;
            lex->token.value = tok;
            // this is retarded (account for column pos)
            for (int n = 0; n < tok_len; n++)
                read_char(lex);
            return true;
        }
    }
    return false;
}

// Move to next token.
// Return false if the token is eof or error, return true otherwise.
bool lexer_next(struct lexer *lex)
{
    lex->token.type = TOKEN_ERROR;

    lexer_skip_ws(lex);

    lex->token = (struct token) {.pos = lex->pos};

    if (lexer_eof(lex)) {
        lex->token.type = TOKEN_EOF;
        return false;
    }

    // The order of these calls matters.
    if (lex_number(lex) || lex_tok(lex) || lex_id(lex) || lex_char(lex)
        || lex_string(lex))
        return true;

    if (lex->errors)
        return false;

    if (lex->source[lex->pos.byte] == '\0')
        lexer_error_at(lex, lex->pos, "embedded \\0!");
    else
        lexer_error_at(lex, lex->pos, "unlexable.");
    return false;
}

//-- Lexer helpers for parsers.

static const char *token_str[] = {
    [TOKEN_ERROR] = "error",
    [TOKEN_EOF] = "eof",
    [TOKEN_ID] = "id",
    [TOKEN_TOK] = "token",
    [TOKEN_LIT] = "literal",
};

char *token_string(enum token_type type, char *value)
{
    void *ctx = talloc_new(NULL);
    char *valuestr = NULL;
    if (value && value[0]) {
        valuestr = talloc_asprintf(ctx, "%s", value);
        if (type != TOKEN_TOK)
            valuestr = talloc_asprintf(ctx, "'%s'", valuestr);
    }
    char *res = (char *)token_str[type];
    if (valuestr)
        res = talloc_asprintf(ctx, "%s %s", res, valuestr);
    res = talloc_strdup(NULL, res);
    talloc_free(ctx);
    return res;
}

static char *int_tag(int tag)
{
    switch (tag) {
        case 0: return "";
        case 8: return "u8";
        case -8: return "i8";
        case 16: return "u16";
        case -16: return "i16";
        case 32: return "u32";
        case -32: return "i32";
        case 64: return "u64";
        case -64: return "i64";
        default: assert(false);
    }
}

static char *const_str(void *tctx, const char *desc, char *s)
{
    char *t = string_unparse(NULL, s);
    char *res = talloc_asprintf(tctx, "%s (%s)", t, desc);
    talloc_free(t);
    return res;
}

char *lexer_const_string(void *tctx, struct lex_const lc)
{
    //@ALL lexer_const_type
    switch (lc.type) {
        case LEX_CONST_cempty: return talloc_strdup(NULL, "()");
        case LEX_CONST_cint: {
            struct lex_int i = *GET_UNION(LEX_CONST, cint, &lc);
            return talloc_asprintf(tctx, "%"PRIu64"%s", i.val, int_tag(i.type));
        }
        case LEX_CONST_cdouble:
            return talloc_asprintf(tctx, "%f (double)",
                                    *GET_UNION(LEX_CONST, cdouble, &lc));
        case LEX_CONST_cchar: {
            char s[2] = { *GET_UNION(LEX_CONST, cchar, &lc), '\0' };
            return const_str(tctx, "char", s);
        }
        case LEX_CONST_cstring:
            return const_str(tctx, "string",
                             *GET_UNION(LEX_CONST, cstring, &lc));
        default: assert(false);
    }
}

char *full_token_string(struct token token)
{
    char *res = talloc_strdup(NULL, "");
    res = talloc_asprintf_append(res, "%s: %s",
                        talloc_steal(res, source_pos_string(token.pos)),
                        token_str[token.type]);
    if (token.type == TOKEN_LIT) {
        res = talloc_asprintf_append(res, " [%s]",
                        lexer_const_string(res, token.lit_value));
    } else if (token.value && token.value[0]) {
        res = talloc_asprintf_append(res, " [%s]", token.value);
    }
    talloc_free_children(res);
    return res;
}

void merge_loc(struct source_pos *pos, struct source_pos npos)
{
    if (npos.line)
        *pos = npos;
}

// Raise an error that the current token was expected to be a token of type
// type, and if value != NULL, with the given value.
void lexer_expected_token(struct lexer *lex, enum token_type type,
                          const char *value)
{
    void *ctx = talloc_new(NULL);
    lexer_error_at(lex, lex->pos, "expected token %s, but got %s",
                   talloc_steal(ctx, token_string(type, (char *)value)),
                   talloc_steal(ctx, token_string(lex->token.type,
                                                  lex->token.value)));
    talloc_free(ctx);
}

bool lexer_peek(struct lexer *lex, enum token_type type)
{
    return lex->token.type == type;
}

bool lexer_peek_tok(struct lexer *lex, const char *tok)
{
    return lexer_peek(lex, TOKEN_TOK) && strcmp(lex->token.value, tok) == 0;
}

bool lexer_try_eat_tok(struct lexer *lex, const char *tok)
{
    if (lexer_peek_tok(lex, tok)) {
        lexer_next(lex);
        return true;
    }
    return false;
}

void lexer_eat_tok(struct lexer *lex, const char *tok)
{
    if (!lexer_try_eat_tok(lex, tok))
        lexer_expected_token(lex, TOKEN_TOK, tok);
}

char *lexer_eat_id(struct lexer *lex)
{
    if (lexer_peek(lex, TOKEN_ID)) {
        char *id = lex->token.value;
        lexer_next(lex);
        return id;
    }
    lexer_expected_token(lex, TOKEN_ID, NULL);
    return "<error>";
}

struct lex_const lexer_eat_lit(struct lexer *lex)
{
    if (lexer_peek(lex, TOKEN_LIT)) {
        struct lex_const value = lex->token.lit_value;
        lexer_next(lex);
        return value;
    }
    lexer_expected_token(lex, TOKEN_LIT, NULL);
    return (struct lex_const) {0};
}
