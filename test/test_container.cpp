#include "doctest/doctest.h"
#include "container/detail/avl.hpp"
#include <iostream>

using namespace toy;

using _test_avl_tree_t = detail::avl_tree<int, int, std::identity, std::less<int>, std::allocator<int>>;

[[maybe_unused]] static void show_avl_tree(const _test_avl_tree_t& tree)
{
    std::cout << "size : " << tree.size() << "\n\n";
    if (tree.empty())
    {
        std::cout << "tree empty!\n";
        return;
    }

    // generate by deepseek
    auto print_tree = [&](std::string prefix, const _test_avl_tree_t::_base_ptr_type node, bool is_left, auto&& print_tree) -> void
    {
        if (node == nullptr)
            return;
        std::cout << prefix << (is_left ? "├──" : "└──");
        std::cout << *static_cast<_test_avl_tree_t::_node_ptr_type>(node)->value_ptr() << "  (h: " << node->height << ")\n";

        print_tree(prefix + (is_left ? "|  " : "   "), node->left, true, print_tree);
        print_tree(prefix + (is_left ? "|  " : "   "), node->right, false, print_tree);
    };

    print_tree("", tree.m_header.parent, false, print_tree);

    std::cout << std::endl;
}

TEST_CASE("avl_tree")
{
    const auto const_tree = _test_avl_tree_t{};
    CHECK(const_tree.empty() == true);
    CHECK(const_tree.begin() == const_tree.end());
    CHECK(const_tree.rbegin() == const_tree.rend());
    CHECK(const_tree.max_size() > 0);

	auto tree = _test_avl_tree_t{};
	auto [first_iter, first_insert_res] = tree.insert_unique(7);
    CHECK(first_insert_res == true);
    CHECK(*first_iter == 7);
    first_iter++;
    CHECK(first_iter == tree.cend());
    first_iter--;
    CHECK(*first_iter == 7);
    CHECK(first_iter == tree.cbegin());

    tree.insert_unique(5);
    tree.insert_unique(2);
    tree.insert_unique(8);
    tree.insert_unique(9);
    tree.insert_unique(6);
    tree.insert_unique(1);
    tree.insert_unique(4);
    tree.insert_unique(3);

    auto [repeat_iter, repeat_insert_res] = tree.insert_unique(2);
    CHECK(repeat_iter == tree.cend());
    CHECK(repeat_insert_res == false);

    tree.insert_unique(8);
    // show_avl_tree(tree);

    CHECK(tree.size() == 9);

    int value = 1;
    for (auto iter = tree.begin(); iter != tree.end(); ++iter)
    {
        CHECK(*iter == value++);
    }

    CHECK(tree.crbegin() == tree.rbegin());
    CHECK(tree.crend() == tree.rend());
    for (auto iter = tree.rbegin(); iter != tree.rend(); ++iter)
    {
        CHECK(*iter == --value);
        if (value < 0)
            break;
    }
}
