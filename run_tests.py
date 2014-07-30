#!/usr/bin/env python

import os
import re
import subprocess
import sys
import tempfile

CC = "gcc"
CFLAGS = "-fmax-errors=4 -std=c99 -pipe -D_POSIX_C_SOURCE=200809L -W -Wall -Wno-unused-variable -Wno-unused-parameter -Wno-unused-label -Wno-unused-value -Wno-unused-but-set-variable -Wno-unused-function -Wno-main".split(" ")

class Table():
    pass

class TestMode():
    pass_ = 0
    fail_compile_parse = 1
    fail_compile_sem = 2
    fail_compile_ice = 3
    fail_c = 4
    fail_run = 5
    fail_output = 6
    fail_other = 7
    disable = 8

test_modes = [TestMode.pass_, TestMode.fail_compile_parse,
              TestMode.fail_compile_sem, TestMode.fail_compile_ice,
              TestMode.fail_c, TestMode.fail_run, TestMode.fail_output,
              TestMode.fail_other, TestMode.disable]

test_mode_names = {
    TestMode.pass_: ("pass", "Passed"),
    TestMode.fail_compile_parse: ("fail_compile_parse", "Compilation failed (parsing)"),
    TestMode.fail_compile_sem: ("fail_compile_sem", "Compilation failed (semantics)"),
    TestMode.fail_compile_ice: ("fail_compile_ice", "Compilation failed (ICE)"),
    TestMode.fail_c: ("fail_c", "C compilation/linking failed"),
    TestMode.fail_run: ("fail_run", "Run failed"),
    TestMode.fail_output: ("fail_output", "Output mismatched"),
    TestMode.fail_other: ("fail_other", "Expected failure didn't happen"),
    TestMode.disable: ("disable", "Disabled"),
}

test_stats = dict([(m, 0) for m in test_modes])

test_mode_values = {}
for m, (s, _) in test_mode_names.iteritems():
    test_mode_values[s] = m

def pick(v, m):
    if v not in m:
        raise Exception("Unknown value '%s'" % v)
    return m[v]

def run_test(filename):
    testname = os.path.basename(filename)
    print("Test '%s'..." % testname)
    workdir = tempfile.mkdtemp(prefix="boringtest")
    tempfiles = []
    src = open(filename)
    headers = Table()
    headers.mode = TestMode.pass_
    headers.is_expr = False
    headers.stdout = None
    while True:
        hline = src.readline()
        if not hline:
            break
        m = re.match("(?://|/\*) ([A-Z]+):(.*)", hline)
        if not m:
            break
        name, value = m.group(1), m.group(2)
        value = value.strip()
        if name == "TEST":
            headers.mode = pick(value, test_mode_values)
        elif name == "TYPE":
            headers.is_expr = pick(value, {"normal": False, "expr": True})
        elif name == "STDOUT":
            term = value + "*/"
            stdout = ""
            while True:
                line = src.readline()
                if not line:
                    raise Exception("unterminated STDOUT header")
                if line.strip() == term:
                    break
                stdout += line
            headers.stdout = stdout
        else:
            raise Exception("Unknown header '%s'" % name)
    src.close()
    def do_run():
        if headers.mode == TestMode.disable:
            return TestMode.disable
        # make is for fags
        tc = os.path.join(workdir, "t.c")
        tcf = open(tc, "w")
        tempfiles.append(tc)
        res = subprocess.call(["./main", "cg_c", filename], stdout=tcf)
        tcf.close()
        if res != 0:
            if res == 1:
                return TestMode.fail_compile_parse
            if res == 2:
                return TestMode.fail_compile_sem
            return TestMode.fail_compile_ice
        t = os.path.join(workdir, "t")
        tempfiles.append(t)
        res = subprocess.call([CC] + CFLAGS + [tc, "-o", t])
        if res != 0:
            return TestMode.fail_c
        p = subprocess.Popen([t], stdout=subprocess.PIPE)
        output, _ = p.communicate()
        res = p.wait()
        if res != 0:
            return TestMode.fail_run
        if headers.stdout is not None and headers.stdout != output:
            print("Program output: >\n%s<\nExpected: >\n%s<" % (output,
                  headers.stdout))
            return TestMode.fail_output
        return TestMode.pass_
    actual_res = do_run()
    for f in tempfiles:
        try:
            os.unlink(f)
        except OSError:
            pass
    os.rmdir(workdir)
    res = actual_res
    if res == TestMode.disable:
        pass
    elif res == headers.mode:
        res = TestMode.pass_
    else:
        if headers.mode != TestMode.pass_:
            res = TestMode.fail_other
    test_stats[res] += 1
    print("Test '%s': %s (expected %s, got %s)" % (testname,
        test_mode_names[res][0], test_mode_names[headers.mode][0],
        test_mode_names[actual_res][0]))

def run_tests(list_file_name):
    base = os.path.dirname(list_file_name)
    for f in [x.strip() for x in open(argv[1])]:
        run_test(os.path.join(base, f))
    print("SUMMARY:")
    test_sum = 0
    for m in test_modes:
        print("    %s: %d" % (test_mode_names[m][1], test_stats[m]))
        test_sum += test_stats[m]
    passed_tests = test_stats[TestMode.pass_]
    failed_tests = test_sum - passed_tests - test_stats[TestMode.disable]
    print("Passed/failed: %s/%d" % (passed_tests, failed_tests))
    if failed_tests:
        print("OMG OMG OMG ------- Some tests have failed ------- OMG OMG OMG")
        sys.exit(1)

if __name__ == "__main__":
    argv = sys.argv
    if len(argv) != 2:
        print("Usage: %s tests.lst" % argv[0])
        sys.exit(1)
    #subprocess.check_call(["make", "main"])
    run_tests(argv[1])
