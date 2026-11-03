BEFORE_VARS := $(.VARIABLES)

TARGET=RepShell

CPUS ?= $(shell nproc || echo 1)
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(CPUS)
MAKEFLAGS += --no-print-directory

# Remove built in rules
MAKEFLAGS += --no-builtin-rules

# Use -Wno-attributes due to an antlr bug https://github.com/antlr/antlr4/issues/3217
CFLAGS_ANTLR = -std=c++11 -Wno-attributes
CFLAGS_CPP = -Wall -Werror -Wextra -std=c++11 -Wno-unused-parameter -Wno-unused-variable -Wno-attributes -Wno-unused-function -Wno-overloaded-virtual

CFLAGS_ANTLR += -O3
# CFLAGS_CPP += -O3
# CFLAGS_ANTLR += -g
CFLAGS_CPP += -g
# 

COMMON_OBJECTS = out/utils.o out/tracer.o
ANTLR_OBJECTS = $(patsubst out/antlr_src/%.cpp,out/antlr_out/%.o, $(wildcard out/antlr_src/*.cpp))

OBJECTS_REPSHELL = out/RepShell.o $(COMMON_OBJECTS) $(ANTLR_OBJECTS) out/antlr_runtime/runtime/libantlr4_cpp_runtime.a
OBJECTS_REPDRY = out/RepDry.o $(COMMON_OBJECTS)

OBJECTS = \
	$(patsubst src/cpp/%.cpp,out/%.o, $(wildcard src/cpp/*.cpp)) \
	$(ANTLR_OBJECTS) \
	out/antlr_runtime/runtime/libantlr4_cpp_runtime.a

INCLUDES_ANTLR = -isystem libs/antlr4-cpp-runtime/runtime/src/
INCLUDES_CPP = $(INCLUDES_ANTLR) -I include/  -isystem out/antlr_src

DEPS = \
	$(patsubst src/cpp/%.cpp,out/%.d, $(wildcard src/cpp/*.cpp)) \
	$(patsubst out/antlr_src/%.cpp,out/antlr_out/%.d, $(wildcard out/antlr_src/*.cpp))

all: out/$(TARGET) out/RepDry

dev: out/$(TARGET)
	@cd example && make
	
install:
	sudo apt-get install antlr4 cmake

valgrind: out/$(TARGET)
	@cd example && valgrind --leak-check=full -s ../$<

out:
	mkdir -p $@
	
clean:
	rm -rf out

.PHONY: all dev clean valgrind

out/%.o: src/cpp/%.cpp out/antlr_src Makefile | out
	@#Use g++ to build o file and a dependecy tree .d file for every cpp file
	ccache g++ $(INCLUDES_CPP) $(CFLAGS_CPP) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

out/antlr_src/%.cpp: src/antlr/$(TARGET).g4 out/antlr_src Makefile
	touch $@

out/antlr_out:
	mkdir -p $@

out/antlr_out/%.o: out/antlr_src/%.cpp src/antlr/$(TARGET).g4 Makefile | out/antlr_out
	ccache g++ $(INCLUDES_ANTLR) $(CFLAGS_ANTLR) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

out/antlr_src: src/antlr/$(TARGET).g4
	rm -rf $@
	antlr4 -no-listener -message-format gnu -Xexact-output-dir -Dlanguage=Cpp $< -o $@

out/antlr_runtime/Makefile:
	mkdir -p out/antlr_runtime
	cd out/antlr_runtime && cmake ../../libs/antlr4-cpp-runtime/
	
out/antlr_runtime/runtime/libantlr4_cpp_runtime.a: out/antlr_runtime/Makefile
	$(MAKE) -C out/antlr_runtime

-include $(DEPS)

out/$(TARGET): $(OBJECTS_REPSHELL)
	g++ -flto $(CFLAGS_CPP) $(OBJECTS_REPSHELL) -o $@

out/RepDry: $(OBJECTS_REPDRY)
	g++ -flto $(CFLAGS_CPP) $(OBJECTS_REPDRY) -o $@


.PRECIOUS: out/$(TARGET) $(OBJECTS)

clean-example:
	@cd example && make clean
	rm example/RepDep.d

vars:
	@echo "$(BEFORE_VARS) $(AFTER_VARS)" | xargs -n1 | sort | uniq -u

AFTER_VARS := $(.VARIABLES)

nothing:

# $(info Val: [$(DEPS)])

#strace -ff gcc -c lib.c -o lib.o -I inc1 -I inc2 2>&1 | grep -A 5 -E "example.o|header1|header2|lib.o"
#strace -ff gcc example.o lib.o -o example 2>&1 | grep -E "lib.o|example.o"
