CPUS ?= $(shell nproc || echo 1)
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(CPUS)
MAKEFLAGS += --no-print-directory

# Remove built in rules
MAKEFLAGS += --no-builtin-rules

CFLAGS_CPP = -Wall -Werror -Wextra -std=c++11 -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-overloaded-virtual -g

OBJECTS = $(patsubst src/cpp/%.cpp,out/%.o, $(wildcard src/cpp/*.cpp))
DEPS = $(patsubst %.o,%.d, $(OBJECTS))

all: out/RepDry

out:
	mkdir -p $@

clean:
	rm -rf out

test: out/RepDry
	test/run_tests.sh

.PHONY: all clean test

out/%.o: src/cpp/%.cpp Makefile | out
	@#Use g++ to build o file and a dependecy tree .d file for every cpp file
	ccache g++ -I include/ $(CFLAGS_CPP) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $(patsubst %.d,%.o,$@) -c $< -o $@

-include $(DEPS)

out/RepDry: $(OBJECTS)
	g++ -flto $(CFLAGS_CPP) $(OBJECTS) -o $@

.PRECIOUS: out/RepDry $(OBJECTS)
