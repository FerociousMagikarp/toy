#include "doctest/doctest.h"
#include "nanobench.h"

#include <random>
#include <array>
#include <set>
#include "container/avl_set.hpp"

using namespace toy;

TEST_CASE("avl_set")
{
    std::mt19937 rand;
    rand.seed(42);
    std::uniform_int_distribution<int> distrib(0, 100000);
    std::array<int, 50000> data;
    for (auto& d : data)
        d = distrib(rand);
    std::array<int, 50000> find_data;
    for (auto& d : find_data)
        d = distrib(rand);

    avl_set<int> toy_set;
    std::set<int> std_set;

    auto bench = ankerl::nanobench::Bench();
    bench.minEpochIterations(20)
         .title("set 50000 data");
    bench.run("toy::avl_set -- insert", [&data, &toy_set]() -> void
    {
        for (int d : data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.insert(d));
    });

    bench.run("std::set -- insert", [&data, &std_set]() -> void
    {
        for (int d : data)
            ankerl::nanobench::doNotOptimizeAway(std_set.insert(d));
    });

    bench.run("toy::avl_set -- find", [&find_data, &toy_set]() -> void
    {
        for (int d : find_data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.find(d));
    });

    bench.run("std::set -- find", [&find_data, &std_set]() -> void
    {
        for (int d : find_data)
            ankerl::nanobench::doNotOptimizeAway(std_set.find(d));
    });

    bench.run("toy::avl_set -- erase", [&data, &toy_set]() -> void
    {
        for (int d : data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.erase(d));
    });

    bench.run("std::set -- erase", [&data, &std_set]() -> void
    {
        for (int d : data)
            ankerl::nanobench::doNotOptimizeAway(std_set.erase(d));
    });

    std::array<int, 100> short_data;
    for (auto& d : short_data)
        d = distrib(rand);
    std::array<int, 100> short_find_data;
    for (auto& d : short_find_data)
        d = distrib(rand);

    bench.title("set 100 data");
    bench.run("toy::avl_set -- insert", [&short_data, &toy_set]() -> void
    {
        for (int d : short_data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.insert(d));
    });

    bench.run("std::set -- insert", [&short_data, &std_set]() -> void
    {
        for (int d : short_data)
            ankerl::nanobench::doNotOptimizeAway(std_set.insert(d));
    });

    bench.run("toy::avl_set -- find", [&short_find_data, &toy_set]() -> void
    {
        for (int d : short_find_data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.find(d));
    });

    bench.run("std::set -- find", [&short_find_data, &std_set]() -> void
    {
        for (int d : short_find_data)
            ankerl::nanobench::doNotOptimizeAway(std_set.find(d));
    });

    bench.run("toy::avl_set -- erase", [&short_data, &toy_set]() -> void
    {
        for (int d : short_data)
            ankerl::nanobench::doNotOptimizeAway(toy_set.erase(d));
    });

    bench.run("std::set -- erase", [&short_data, &std_set]() -> void
    {
        for (int d : short_data)
            ankerl::nanobench::doNotOptimizeAway(std_set.erase(d));
    });
}
