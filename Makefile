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
c_libs := -lcrypto -lgdi32

cpp_compiler := g++
cpp_std := -std=c++11
cpp_opt := -O2
cpp_warn := -Wall
cpp_shared := -shared
cpp_flags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(debug)
cpp_ldflags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(cpp_shared) $(debug)
cpp_testflags := $(cpp_std) $(cpp_opt) $(cpp_warn) $(debug)
cpp_libs := -lcrypto -lgdi32

# Directories
tst_dir := test
bin_dir := bin
dyn_dir := dynamic
sta_dir := static
bin_dirs := $(bin_dir)\$(sta_dir) $(bin_dir)\$(dyn_dir) $(bin_dir)\$(tst_dir)

# C Files
c_headers := $(wildcard *.h)
c_sources := $(wildcard *.c)
c_dyn_objects := $(patsubst %.c, $(bin_dir)\$(dyn_dir)\\%.o, $(c_sources))
c_sta_objects := $(patsubst %.c, $(bin_dir)\$(sta_dir)\\%.o, $(c_sources))

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
	lib_ext = dll
	cmd_rm = del
	cmd_mkdir +=
endif # Windows_NT
ifeq ($(OS), Linux)
	lib_ext = so
	cmd_rm = rm
	c_flags += -fPIC
	cpp_flags += -fPIC
endif # Linux

sta_lib := $(bin_dir)\$(lib_name).a
dyn_lib := $(bin_dir)\$(lib_name).$(lib_ext)

test_c = $(bin_dir)\test_c$(project_ext)
test_cpp = $(bin_dir)\test_c++$(project_ext)

###############################################################################

.PHONY: all clean libs tests static dynamic test_c test_cpp

all: libs tests

clean:
	$(cmd_rm) $(c_sta_objects) $(c_dyn_objects)

libs: static dynamic

tests: test_c test_cpp

static: $(bin_dir)\$(sta_dir) $(sta_lib)

dynamic: $(bin_dir)\$(dyn_dir) $(dyn_lib)

test_c: $(test_c)

test_cpp: $(test_cpp)

###############################################################################

$(bin_dir)\$(sta_dir)\\%.o: %.c $(c_headers) $(bin_dir)\$(sta_dir)
	$(c_compiler) $(c_flags) -o $@ -c $<

$(sta_lib): $(c_sta_objects)
	$(cmd_ar) rcs -o $@ $^

$(bin_dir)\$(dyn_dir)\\%.o: %.c $(c_headers) $(bin_dir)\$(dyn_dir)
	$(c_compiler) $(c_flags) -o $@ -c $<

$(dyn_lib): $(c_dyn_objects)
	$(c_compiler) $(c_ldflags) -o $@ $^ $(c_libs)

$(test_c): $(tst_dir)\main.c $(sta_lib)
	$(c_compiler) $(c_testflags) -L$(bin_dir) -o $@ $< $(c_libs) $(sta_lib)

$(test_cpp): $(tst_dir)\main.cpp $(sta_lib)
	$(cpp_compiler) $(cpp_testflags) -L$(bin_dir) -o $@ $< $(cpp_libs) $(sta_lib)

$(bin_dir)\$(sta_dir) $(bin_dir)\$(dyn_dir):
	-@mkdir $@
