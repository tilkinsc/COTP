include vendor/mk_simple/mk_simple.mk


# Project naming
project_name := cotp
project_ext := .exe
c_test = $(bin_dir)/test_c$(project_ext)
cpp_test = $(bin_dir)/test_cpp$(project_ext)

# Paths
tst_dir := test
bin_dir := bin
stc_dir := static
dyn_dir := dynamic
bin_dirs := $(bin_dir) $(bin_dir)/$(stc_dir) $(bin_dir)/$(dyn_dir)

# Files & extensions
c_header_ext := h
c_source_ext := c
cpp_header_ext := hpp
cpp_source_ext := cpp
lib_name := $(project_name)
lib_ext = dll

static_lib := $(bin_dir)/$(lib_name).a
dynamic_lib := $(bin_dir)/$(lib_name).$(lib_ext)
c_main := $(tst_dir)/main.$(c_source_ext)
cpp_main := $(tst_dir)/main.$(cpp_source_ext)

c_headers := $(wildcard *.$(c_header_ext))
c_sources := $(wildcard *.$(c_source_ext))
cpp_headers := $(wildcard *.$(cpp_header_ext))
cpp_sources := $(wildcard *.$(cpp_source_ext))
static_objects := $(patsubst %.$(c_source_ext),	\
	$(bin_dir)/$(stc_dir)/%.o,					\
	$(filter-out $(main), $(c_sources)))
dynamic_objects := $(patsubst %.$(c_source_ext),	\
	$(bin_dir)/$(dyn_dir)/%.o,						\
	$(filter-out $(main), $(c_sources)))

# Compiler stuff
c_compiler := gcc
c_std = -std=c11
c_warn := -Wall
c_opt := -O2
# c_defs :=
# c_includes :=
c_flags := $(c_std) $(c_opt) $(c_warn)
c_ldflags := -L$(bin_dir) -lcrypto -lgdi32

cpp_compiler = g++
cpp_std = -std=c++11
cpp_warn = -Wall
cpp_opt = -O2
# cpp_defs =
# cpp_includes :=
cpp_flags := $(cpp_std) $(cpp_opt) $(cpp_warn)
cpp_ldflags := -lcrypto -lgdi32


.PHONY: all clean libs test
all:
	@$(MAKE) libs
	@$(MAKE) test
clean:
	rm -rf $(wildcard $(c_test) $(bin_dir) *.o *.$(lib_ext))
libs:
	@$(MAKE) $(dynamic_lib)
	@$(MAKE) $(static_lib)
test:
	@$(MAKE) $(c_test)
	@$(MAKE) $(cpp_test)

$(c_test): $(c_main) $(static_lib)
	$(c_compiler) $(c_flags) $(c_main) -o $@ $(c_ldflags) -lcotp

$(cpp_test): $(cpp_main) $(static_lib)
	$(cpp_compiler) $(cpp_flags) $(cpp_main) -o $@ $(cpp_ldflags) -lcotp


# Static objects & libraries
$(eval $(call mk_static_objs,				\
	$(static_objects),						\
	$(c_compiler),							\
	$(bin_dir)/$(stc_dir)/%.o,				\
	%.$(c_source_ext),						\
	$(c_flags) $(c_includes),				\
	$(bin_dirs) $(c_headers) $(c_sources)))

$(eval $(call mk_static_lib,				\
	$(static_lib),							\
	ar,										\
	rcs,									\
	$(static_objects),))

# Dynamic objects & libraries
$(eval $(call mk_dynamic_objs,				\
	$(dynamic_objects),						\
	$(c_compiler),							\
	$(bin_dir)/$(dyn_dir)/%.o,				\
	%.$(c_source_ext),						\
	$(c_flags),								\
	$(bin_dirs) $(c_headers) $(c_sources)))

$(eval $(call mk_dynamic_lib,	\
	$(dynamic_lib),				\
	$(c_compiler),				\
	$(c_flags),					\
	$(c_ldflags),				\
	$(dynamic_objects),))

$(bin_dirs):
	-mkdir $@
