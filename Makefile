# Makefile stolen from mplayer2

main:

OPT = -O0 -g -Werror=return-type
#OPT = -O3 -DNDEBUG

CFLAGS = -fwrapv -fmax-errors=4 -std=c99 -pipe -D_POSIX_C_SOURCE=200809L -Wundef -Wall -Wno-switch -Wno-parentheses -Wpointer-arith -Wredundant-decls -Werror=implicit-function-declaration -Wstrict-prototypes -Wmissing-prototypes -Wdisabled-optimization -Wno-pointer-sign -Wshadow $(OPT)

DEPFLAGS = -MD -MP

SOURCES = main.c \
          lex.c \
          value.c \
          parse.c \
          types.c \
          ir.c \
          ir_opt.c \
          ir_print.c \
          ir_verify.c \
          tycg.c \
          backend_c.c \
          utils.c \
          hashtable.c \
          ta/ta.c \
          ta/ta_talloc.c \
          ta/ta_utils.c

OBJECTS = $(SOURCES:.c=.o)
DEP_FILES = $(OBJECTS:.o=.d)
CLEAN_FILES = $(OBJECTS) $(DEP_FILES)

# Be less noisy, can be disabled with: V=1 make
ifndef V
$(eval override CC = @printf "CC\t$$@\n"; $(CC))
$(eval override RM = @$(RM))
endif

%.o: %.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) -f -- $(CLEAN_FILES)

main: $(OBJECTS)
CLEAN_FILES += main

# Potentially important tests.
prec_test: main
	./main parse_prec_test prectest.txt
run_tests: main
	./run_tests.py tests/tests.lst
tests: prec_test run_tests

# Worthless tests.

union_test.o: union_test.c
union_test: union_test.o
CLEAN_FILES += union_test.o union_test.d union_test

ht_test.o: ht_test.c
ht_test: ht_test.o talloc.o hashtable.o utils.o bstr.o
CLEAN_FILES += ht_test.o ht_test.d ht_test

-include $(DEP_FILES)
