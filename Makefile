CXX = g++
CXXFLAGS = -std=c++20 -Wall
LDFLAGS = -lpcap -lncurses

TARGET = isa-top
SRCS = isa-top.cpp display_speeds.cpp read_packets.cpp 
HEADERS = display_speeds.hpp connections.hpp read_packets.hpp 
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

pack:
	tar -cf xkrejz07.tar $(SRCS) $(HEADERS) Makefile README.md

.PHONY: all clean run