project_ext =


tst_dir := test
bin_dir := bin
dyn_dir := dynamic
sta_dir := static
bin_dirs := $(bin_dir)/$(sta_dir) $(bin_dir)/$(dyn_dir) $(bin_dir)/$(tst_dir)

# Compiler
c_compiler := gcc
c_std := -std=c11
c_opt := -O2
c_warn := -Wall
c_ldflags := -lcrypto -lgdi32
c_flags := $(c_std) $(c_opt) $(c_warn)

cpp_compiler := g++
cpp_std := -std=c++11
cpp_opt := -O2
cpp_warn := -Wall
cpp_ldflags := -lcrypto -lgdi32
cpp_flags := $(cpp_std) $(cpp_opt) $(cpp_warn)

# C files
c_headers := $(wildcard *.h)
c_sources := $(wildcard *.c)
c_dyn_objects := $(patsubst %.c, $(bin_dir)/$(dyn_dir)/%.o, $(c_sources))
c_sta_objects := $(patsubst %.c, $(bin_dir)/$(sta_dir)/%.o, $(c_sources))

# Libraries
lib_name := cotp
lib_ext =

# Platform defines
os := $(shell uname -s)
ifeq ($(os), Windows_NT) 
	project_ext = .exe
	lib_ext = dll
endif # Windows_NT
ifeq ($(os), Linux)
	lib_ext = so
endif # Linux

sta_lib := $(bin_dir)/$(lib_name).a
dyn_lib := $(bin_dir)/$(lib_name).$(lib_ext)

test_c = $(bin_dir)/test_c$(project_ext)
test_cpp = $(bin_dir)/test_c++$(project_ext)


.PHONY: all clean libs tests static dynamic test_c test_cpp
all:
	@$(MAKE) libs
	@$(MAKE) tests
clean:
	rm -rf $(wildcard $(bin_dir) *.$(project_ext) *.o *.a *.$(lib_ext))
libs:
	@$(MAKE) static
	@$(MAKE) dynamic
tests:
	@$(MAKE) test_c
	@$(MAKE) test_cpp
static:
	@echo "Building static library"
	@$(MAKE) $(sta_lib)
dynamic:
	@echo "Building dynamic library"
	@$(MAKE) $(dyn_lib)
test_c:
	@echo "Building test C application"
	@$(MAKE) $(test_c)
test_cpp:
	@echo "Building test C++ application"
	@$(MAKE) $(test_cpp)

$(bin_dir)/$(sta_dir)/%.o: %.c $(c_headers) $(bin_dir)/$(sta_dir)
	$(c_compiler) $(c_flags) -c $< -o $@

$(sta_lib): $(c_sta_objects)
	ar rcs $@ $^

$(bin_dir)/$(dyn_dir)/%.o: %.c $(c_headers) $(bin_dir)/$(dyn_dir)
	$(c_compiler) $(c_flags) -fPIC -c $< -o $@

$(dyn_lib): $(c_dyn_objects)
	$(c_compiler) $(c_flags) -shared $^ -o $@ $(c_ldflags)

$(test_c): $(tst_dir)/main.c $(sta_lib)
	$(c_compiler) $(c_flags) -c $< -o $@ -L$(bin_dir) $(c_ldflags)

$(test_cpp): $(tst_dir)/main.cpp $(sta_lib)
	$(cpp_compiler) $(cpp_flags) -c $< -o $@ -L$(bin_dir) $(c_ldflags)

$(bin_dir):
	-mkdir $@

$(bin_dirs): $(bin_dir)
	-mkdir $@
