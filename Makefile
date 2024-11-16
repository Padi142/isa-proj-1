CXX = g++
CXXFLAGS = -std=c++20 -Wall
LDFLAGS = -lpcap -lncurses

TARGET = isa-top
SRCS = isa-top.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean run