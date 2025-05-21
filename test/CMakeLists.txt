cmake_minimum_required(VERSION 3.14)

set(TEST_NAME toy_test)

include(FetchContent)

FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG master
    GIT_SHALLOW true
)

FetchContent_MakeAvailable(doctest)

file(GLOB TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_executable(${TEST_NAME} ${TEST_SOURCE})

target_link_libraries(${TEST_NAME} PUBLIC doctest::doctest)

target_include_directories(
    ${TEST_NAME} PUBLIC
    $<BUILD_INTERFACE:${TOY_INCLUDE_DIR}>
)

target_compile_options(
    ${TEST_NAME} PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)
