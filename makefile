

CXX_FLAGS = -Wall -Wextra -O2 -fpic -I./include --std=c++11

VPATH=src:benchmarks:test

OBJS=aes.o
LIB_TARGET=libbcrypto.a


all: $(LIB_TARGET)


run_all_tests: test benchmark
	./aesavs
	./benchmark


clean:
	rm -rf *.o aesavs benchmark $(LIB_TARGET)


test: $(LIB_TARGET) aesavs.o
	$(CXX) $(CXX_FLAGS) -L. -o aesavs aesavs.o -lbcrypto -lgtest -lgtest_main -pthread


benchmark: $(LIB_TARGET) bench.o
	$(CXX) $(CXX_FLAGS) -L. -o benchmark bench.o -lbcrypto -lbenchmark -lbenchmark_main -pthread


$(LIB_TARGET): $(OBJS)
	ar rs $(LIB_TARGET) $(OBJS)


## Generic compilation rule
%.o : %.cpp
	$(CXX) $(CXX_FLAGS) -c $< -o $@
