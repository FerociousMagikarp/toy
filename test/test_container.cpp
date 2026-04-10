#include "doctest/doctest.h"
#include "container/avl_set.hpp"
#include <set>

using namespace toy;

template <typename T>
class TestAllocator
{
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    constexpr TestAllocator() = default;
    constexpr ~TestAllocator() = default;
    template< class U >
    constexpr TestAllocator(const TestAllocator<U>& other) noexcept
        : all_alloc_record(other.all_alloc_record),
          m_allocator(other.m_allocator)
    { }

    constexpr T* allocate(std::size_t n)
    {
        auto res = m_allocator.allocate(n);
        all_alloc_record.insert(res);
        return res;
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        all_alloc_record.erase(p);
        m_allocator.deallocate(p, n);
    }

    // 实际使用的时候不能这么用
    std::set<void*> all_alloc_record;
    [[no_unique_address]] std::allocator<T> m_allocator;
};

TEST_CASE("avl_set")
{
    using set_t = avl_set<int, std::less<int>{}, TestAllocator<int>>;
    set_t test_set;

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
    {
        auto _test_alloc = test_set.get_allocator();
        CHECK(_test_alloc.all_alloc_record.size() == 10);
    }
    auto find_iter1 = test_set.find(5);
    CHECK(*find_iter1 == 5);
    auto find_iter2 = test_set.find(100);
    CHECK(find_iter2 == test_set.end());
    auto find_iter3 = [](const set_t& s, int val) -> set_t::const_iterator
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
    [](const set_t& s) -> void
    {
        CHECK(*s.lower_bound(5) == 5);
        CHECK(*s.upper_bound(5) == 6);
        CHECK(*s.lower_bound(9) == 9);
        CHECK(s.upper_bound(9) == s.cend());
    }(test_set);

    {
        auto _test_alloc = test_set.get_allocator();
        CHECK(_test_alloc.all_alloc_record.size() == 7);
    }

    test_set.clear();
    {
        auto _test_alloc = test_set.get_allocator();
        CHECK(_test_alloc.all_alloc_record.size() == 0);
    }
}
