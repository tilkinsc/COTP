project_ext =


# Compiler
debug = # -g

c_compiler := gcc
c_std := -std=c11
c_opt := -O2
c_warn := -Wall
c_shared := -shared
c_flags := $(c_std) $(c_opt) $(c_warn) $(debug)
c_ldflags := $(c_std) $(c_opt) $(c_warn) $(c_shared) $(debug)
c_testflags := $(c_std) $(c_opt) $(c_warn) $(debug)
c_libs := -lcrypto

cpp_compiler := g++
cpp_std := -std=c++11
cpp_opt := -O2
cpp_warn := -Wall
cpp_shared := -shared
cpp_flags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(debug)
cpp_ldflags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(cpp_shared) $(debug)
cpp_testflags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(debug)
cpp_libs := -lcrypto

# C Files
c_headers := $(wildcard *.h)
c_sources := $(wildcard *.c)
c_objects := $(patsubst %.c, %.o, $(c_sources))
c_test_sources := $(wildcard test/*.c)
cpp_test_sources := $(wildcard test/*.cpp)
c_test_objects := $(pathsubst test/%.c, %.o, $(c_test_sources))

# Libraries
lib_name := libcotp
lib_ext =

# Command Maps
cmd_rm =
cmd_ar = ar
cmd_mkdir = mkdir

# Platform Specific
ifeq ($(OS), Windows_NT)
	project_ext = .exe
	lib_ext = .dll
	cmd_rm = del
	cmd_mkdir +=
else
	lib_ext = .so
	cmd_rm = rm -f
	c_flags += -fPIC
	cpp_flags += -fPIC
	c_libs += -lm
endif # Linux

sta_lib := $(lib_name).a
dyn_lib := $(lib_name)$(lib_ext)

test_c = test_c$(project_ext)
test_cpp = test_cpp$(project_ext)

###############################################################################

.PHONY: all clean libs tests static dynamic test_c test_cpp

all: libs tests

clean:
	$(cmd_rm) $(c_objects) $(c_test_objects) $(sta_lib) $(dyn_lib) $(test_c) $(test_cpp)

libs: static dynamic

tests: prog_test_c prog_test_cpp

static: $(sta_lib)

dynamic: $(dyn_lib)

prog_test_c: libs $(test_c)

prog_test_cpp: libs $(test_cpp)

###############################################################################

%.o: %.c $(c_headers)
	$(c_compiler) $(c_flags) -o $@ -c $<

$(sta_lib): $(c_objects)
	$(cmd_ar) rcs -o $@ $^

$(dyn_lib): $(c_objects)
	$(c_compiler) $(c_ldflags) -o $@ $^ $(c_libs)

$(test_c): $(c_test_sources) $(sta_lib)
	$(c_compiler) $(c_testflags) -o $@ $< $(sta_lib) $(c_libs)

$(test_cpp): $(cpp_test_sources) $(sta_lib)
	$(cpp_compiler) $(cpp_testflags) -o $@ $< $(sta_lib) $(cpp_libs)
