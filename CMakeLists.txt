cmake_minimum_required(VERSION 3.20)

project(netwatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(netwatch
    src/main.cpp
)