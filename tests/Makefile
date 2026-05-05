CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wno-return-type

SRC_BIN  := test_generator.cpp
SRC_TRIE := test_trie_generator.cpp

all: test_pointer test_vector test_radix test_patricia

test_pointer: $(SRC_BIN)
	$(CXX) $(CXXFLAGS) -DUSE_POINTER_IMPL  -o $@ $<

test_vector: $(SRC_BIN)
	$(CXX) $(CXXFLAGS) -DUSE_VECTOR_IMPL   -o $@ $<

test_radix: $(SRC_TRIE)
	$(CXX) $(CXXFLAGS) -DUSE_RADIX_IMPL    -o $@ $<

test_patricia: $(SRC_TRIE)
	$(CXX) $(CXXFLAGS) -DUSE_PATRICIA_IMPL -o $@ $<

run: all
	@echo "=== Pointer ===";    ./test_pointer
	@echo
	@echo "=== Vector ===";     ./test_vector
	@echo
	@echo "=== Radix ===";      ./test_radix
	@echo
	@echo "=== Patricia ===";   ./test_patricia

run-bin: test_pointer test_vector
	@echo "=== Pointer ===";  ./test_pointer
	@echo
	@echo "=== Vector ===";   ./test_vector

run-trie: test_radix test_patricia
	@echo "=== Radix ===";    ./test_radix
	@echo
	@echo "=== Patricia ==="; ./test_patricia

clean:
	rm -f test_pointer test_vector test_radix test_patricia

.PHONY: all run run-bin run-trie clean
