cmake_minimum_required(VERSION 3.0.0)

project(meminject)

add_executable(hello helloworld.cc)
add_library(lib SHARED dll.cxx dll.h)
add_executable(injecter injecter.cc injecter.h)

# add_executable()