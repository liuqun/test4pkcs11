# (Please set your editor with UTF-8 encoding if The Chinese characters are unreadable)

# Top Level Project Definitions
cmake_minimum_required(VERSION 3.0)

project(MyTestProject C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS False)

add_executable(helloworld helloworld.c)
