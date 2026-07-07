CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall

all: fast_stats

fast_stats: fast_stats.cpp
	$(CXX) $(CXXFLAGS) -o fast_stats fast_stats.cpp

clean:
	rm -f fast_stats

.PHONY: all clean
