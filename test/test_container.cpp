#include "doctest/doctest.h"
#include "container/avl_set.hpp"

using namespace toy;

TEST_CASE("avl_set")
{
    avl_set<int> test_set;

    CHECK(test_set.empty());
    for (int i = 0; i < 10; i++)
    {
        auto [pos, success] = test_set.insert(i);
        CHECK(*pos == i);
        CHECK(success == true);
    }
    for (int i = 0; i < 10; i++)
    {
        auto [pos, success] = test_set.insert(i);
        CHECK(*pos == i);
        CHECK(success == false);
    }
    auto find_iter1 = test_set.find(5);
    CHECK(*find_iter1 == 5);
    auto find_iter2 = test_set.find(100);
    CHECK(find_iter2 == test_set.end());
    auto find_iter3 = [](const avl_set<int>& s, int val) -> avl_set<int>::const_iterator
    {
        return s.find(val);
    } (test_set, -100);
    CHECK(find_iter3 == test_set.end());
    CHECK(*test_set.begin() == 0);
    CHECK(!test_set.empty());
    CHECK(test_set.size() == 10);
    int value = 0;
    for (auto iter = test_set.cbegin(); iter != test_set.cend(); ++iter)
    {
        CHECK(*iter == value++);
    }
    for (auto iter = test_set.crbegin(); iter != test_set.crend(); ++iter)
    {
        CHECK(*iter == --value);
    }
    auto find_iter4 = test_set.find(0);
    auto erase_iter = test_set.erase(find_iter4);
    CHECK(*erase_iter == 1);
    value = 9;
    for (auto iter = test_set.rbegin(); iter != test_set.rend(); ++iter)
    {
        CHECK(*iter == value--);
    }
    CHECK(test_set.size() == 9);
    auto find_iter5 = test_set.find(0);
    CHECK(find_iter5 == test_set.end());
    CHECK(test_set.erase(-10) == 0);
    CHECK(test_set.erase(3) == 1);
    CHECK(test_set.size() == 8);
    CHECK(test_set.erase(7) == 1);
    CHECK(test_set.size() == 7);
    constexpr std::array<int, 7> remain_value = { 1, 2, 4, 5, 6, 8, 9 };
    for (auto iter = test_set.cbegin(); iter != test_set.cend(); ++iter)
    {
        CHECK(*iter == remain_value[std::distance(test_set.cbegin(), iter)]);
    }
    CHECK(test_set.contains(6));
    CHECK(!test_set.contains(3));
    CHECK(*test_set.lower_bound(7) == 8);
    CHECK(*test_set.upper_bound(7) == 8);
    CHECK(test_set.count(6) == 1);
    CHECK(test_set.count(7) == 0);
    [](const avl_set<int>& s) -> void
    {
        CHECK(*s.lower_bound(5) == 5);
        CHECK(*s.upper_bound(5) == 6);
        CHECK(*s.lower_bound(9) == 9);
        CHECK(s.upper_bound(9) == s.cend());
    }(test_set);
}
