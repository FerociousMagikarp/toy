cmake_minimum_required(VERSION 3.14)

project(toy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20) 
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(TOY_BUILD_TEST "Build test." OFF)

file(GLOB TOY_INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/hash
)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(
    ${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${TOY_INCLUDE_DIR}>
)

target_compile_options(
    ${PROJECT_NAME} INTERFACE
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

if (TOY_BUILD_TEST)
    add_subdirectory(test)
endif()
