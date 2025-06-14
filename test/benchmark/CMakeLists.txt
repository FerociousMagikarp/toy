cmake_minimum_required(VERSION 3.14)

include(FetchContent)

set(BENCH_NAME toy_bench)

FetchContent_Declare(
    nanobench
    GIT_REPOSITORY https://github.com/martinus/nanobench.git
    GIT_TAG master
    GIT_SHALLOW true
)

FetchContent_MakeAvailable(nanobench)

file(GLOB BENCH_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_executable(${BENCH_NAME} ${BENCH_SOURCE})

target_link_libraries(${BENCH_NAME} PUBLIC nanobench::nanobench doctest::doctest)

target_include_directories(
    ${BENCH_NAME} PUBLIC
    $<BUILD_INTERFACE:${TOY_INCLUDE_DIR}>
)

target_compile_options(
    ${BENCH_NAME} PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)
