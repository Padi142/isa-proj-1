cmake_minimum_required(VERSION 3.29)
project(isa)

set(CMAKE_CXX_STANDARD 20)

add_executable(isa main.cpp)

target_link_libraries(isa pcap ncurses)