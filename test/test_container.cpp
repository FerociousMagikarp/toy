#include "doctest/doctest.h"
#include "container/detail/avl.hpp"
#include "container/detail/node.hpp"
#include "container/detail/node_traits.hpp"
#include "container/detail/node_allocator.hpp"
#include <iostream>

using namespace toy;

using _test_node = detail::container_node<int, detail::avl_node_base>;
using _test_avl_node_traits = detail::node_traits<_test_node, std::identity, 0>;
using _test_avl_tree_t = detail::avl_tree<int, int, _test_avl_node_traits, std::less<int>>;
using _test_node_alloc = detail::node_allocator<int, _test_node>;
using _test_avl_iterator = detail::avl_tree_iterator<_test_avl_node_traits>;

[[maybe_unused]] static void show_avl_tree(const _test_avl_tree_t& tree)
{
    std::cout << "size : " << tree.size() << "\n\n";
    if (tree.empty())
    {
        std::cout << "tree empty!\n";
        return;
    }

    // generate by deepseek
    auto print_tree = [&](std::string prefix, const _test_avl_tree_t::_base_ptr node, bool is_left, auto&& print_tree) -> void
    {
        if (node == nullptr)
            return;
        std::cout << prefix << (is_left ? "|----" : "*----");
        std::cout << "{" << *static_cast<_test_node*>(node)->value_ptr() << "}  (h: " << node->height << ")\n";

        print_tree(prefix + (is_left ? "|  " : "   "), node->left, true, print_tree);
        print_tree(prefix + (is_left ? "|  " : "   "), node->right, false, print_tree);
    };

    print_tree("", tree.m_header.parent, false, print_tree);

    std::cout << std::endl;
}

static bool check_avl_tree_balance(const _test_avl_tree_t& tree)
{
    using signed_size = std::make_signed_t<std::size_t>;

    auto check_tree = [&](const _test_avl_tree_t::_base_ptr node, auto&& check_tree) -> bool
    {
        if (node == nullptr)
            return true;
        if (!check_tree(node->left, check_tree))
            return false;
        if (!check_tree(node->right, check_tree))
            return false;
        auto [left_height, right_height] = detail::_get_child_node_height(node);
        if (node->height != std::max(left_height, right_height) + 1)
            return false;
        if (std::abs(static_cast<signed_size>(left_height) - static_cast<signed_size>(right_height)) > 1)
            return false;
        return true;
    };

    return check_tree(tree.m_header.parent, check_tree);
}

template <typename Arg>
std::pair<_test_avl_iterator, bool> insert_avl_node(_test_avl_tree_t& tree, Arg&& val)
{
    // only test
    auto node_alloc = _test_node_alloc();

    auto [parent_pos, insert_left] = tree.get_insert_unique_pos(_test_avl_node_traits::get_key(val));
    if (parent_pos == nullptr)
        return std::make_pair(_test_avl_iterator{tree.end()}, false);
    auto res = tree.insert_node(parent_pos, insert_left, node_alloc.create_node(std::forward<Arg>(val)));
    return std::make_pair(_test_avl_iterator{res}, true);
}

TEST_CASE("avl_tree")
{
    const auto const_tree = _test_avl_tree_t{};
    CHECK(const_tree.empty() == true);
    CHECK(const_tree.begin() == const_tree.end());

	auto tree = _test_avl_tree_t{};
	auto [first_iter, first_insert_res] = insert_avl_node(tree, 7);
    CHECK(check_avl_tree_balance(tree));
    CHECK(first_insert_res == true);
    CHECK(*first_iter == 7);
    first_iter++;
    CHECK(first_iter == _test_avl_iterator(tree.end()));
    first_iter--;
    CHECK(*first_iter == 7);
    CHECK(first_iter == _test_avl_iterator(tree.begin()));

    insert_avl_node(tree, 5);
    CHECK(check_avl_tree_balance(tree));
    first_iter--;
    CHECK(*first_iter == 5);
    insert_avl_node(tree, 2);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 8);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 9);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 6);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 1);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 4);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 3);
    CHECK(check_avl_tree_balance(tree));

    auto [repeat_iter, repeat_insert_res] = insert_avl_node(tree, 2);
    CHECK(repeat_insert_res == false);

    insert_avl_node(tree, 8);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 10);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 11);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 12);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 0);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, -1);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, -2);
    CHECK(check_avl_tree_balance(tree));
    insert_avl_node(tree, 12);
    CHECK(check_avl_tree_balance(tree));
    // show_avl_tree(tree);

    CHECK(tree.size() == 15);

    int value = -2;
    for (auto iter = _test_avl_iterator(tree.begin()); iter != _test_avl_iterator(tree.end()); ++iter)
    {
        CHECK(*iter == value++);
    }
}