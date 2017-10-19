# (Please set your editor with UTF-8 encoding if The Chinese characters are unreadable)

# Top Level Project Definitions
cmake_minimum_required(VERSION 3.0)

project(MyTestProject C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS False)

aux_source_directory(./src SRC_LIST)
add_executable(helloworld ${SRC_LIST})

include(CheckIncludeFile)
check_include_file(dlfcn.h HAVE_DLFCN_H)
if(NOT HAVE_DLFCN_H)
	message(FATAL_ERROR "The C/C++ toolchain does not have <dlfcn.h>")
endif(NOT HAVE_DLFCN_H)

find_library(LIBDL dl)
if(NOT LIBDL)
	message(FATAL_ERROR "The C/C++ toolchain does not have libdl.so or libdl.a")
endif(NOT LIBDL)

find_package(PkgConfig REQUIRED)
pkg_check_modules(P11_KIT REQUIRED p11-kit-1)
if(NOT P11_KIT_FOUND)
	message(FATAL_ERROR "Can not find p11-kit/pkcs11.h to build our program. opencryptoki.h is going to be supported later.")
endif()
target_include_directories(helloworld PRIVATE ${P11_KIT_INCLUDE_DIRS})
target_link_libraries(helloworld dl)
