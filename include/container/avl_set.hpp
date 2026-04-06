#pragma once

#include <memory>
#include <functional>
#include "container/detail/avl.hpp"
#include "container/detail/node.hpp"
#include "container/detail/node_traits.hpp"
#include "container/detail/node_allocator.hpp"

namespace toy
{

template <typename Compare, typename Key, typename K>
concept comparable_param = detail::_comparable_param<Compare, Key, K>;

template <typename Key, typename Compare = std::less<Key>, typename Allocator = std::allocator<Key>>
class avl_set
{
public:
    using key_type        = Key;
    using value_type      = Key;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using key_compare     = Compare;
    using value_compare   = Compare;
    using allocator_type  = Allocator;
    using reference       = value_type&;
    using const_reference = const value_type&;
    using pointer         = typename std::allocator_traits<Allocator>::pointer;
    using const_pointer   = typename std::allocator_traits<Allocator>::const_pointer;

private:
    using _avl_node_type   = detail::container_node<Key, detail::avl_node_base>;
    using _avl_node_traits = detail::node_traits<_avl_node_type, std::identity{}, 0>;

    detail::avl_tree<key_type, key_type, _avl_node_traits, key_compare> m_avl_tree;
    [[no_unique_address]] detail::node_allocator<value_type, _avl_node_type, allocator_type> m_node_alloc;

public:
    using iterator               = detail::avl_tree_iterator<_avl_node_traits>;
    using const_iterator         = detail::avl_tree_const_iterator<_avl_node_traits>;
    using reverse_iterator       = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    constexpr avl_set() = default;
    constexpr ~avl_set() { clear(); }

    constexpr allocator_type get_allocator() const noexcept { return allocator_type(m_node_alloc.get_node_alloc()); }

    constexpr iterator               begin()   noexcept       { return iterator(m_avl_tree.begin()); }
    constexpr const_iterator         begin()   const noexcept { return const_iterator(m_avl_tree.begin()); }
    constexpr const_iterator         cbegin()  const noexcept { return const_iterator(m_avl_tree.begin()); }
    constexpr iterator               end()     noexcept       { return iterator(m_avl_tree.end()); }
    constexpr const_iterator         end()     const noexcept { return const_iterator(m_avl_tree.end()); }
    constexpr const_iterator         cend()    const noexcept { return const_iterator(m_avl_tree.end()); }
    constexpr reverse_iterator       rbegin()  noexcept       { return reverse_iterator(end()); }
    constexpr const_reverse_iterator rbegin()  const noexcept { return const_reverse_iterator(end()); }
    constexpr const_reverse_iterator crbegin() const noexcept { return const_reverse_iterator(end()); }
    constexpr reverse_iterator       rend()    noexcept       { return reverse_iterator(begin()); }
    constexpr const_reverse_iterator rend()    const noexcept { return const_reverse_iterator(begin()); }
    constexpr const_reverse_iterator crend()   const noexcept { return const_reverse_iterator(begin()); }

    constexpr bool      empty()    const noexcept { return m_avl_tree.empty(); }
    constexpr size_type size()     const noexcept { return m_avl_tree.size(); }
    constexpr size_type max_size() const noexcept { return std::allocator_traits<allocator_type>::max_size(); }

    constexpr void clear() noexcept
    {
        for (auto pos = cbegin(); pos != cend();)
        {
            pos = erase(pos);
        }
    }

    constexpr std::pair<iterator, bool> insert(const value_type& value)
    {
        auto [parent_pos, insert_res] = m_avl_tree.get_insert_unique_pos(_avl_node_traits::get_key(value));
        if (insert_res == detail::_insert_unique_pos_res_second::none)
            return std::make_pair(iterator(parent_pos), false);
        auto res = m_avl_tree.insert_node(parent_pos, insert_res == detail::_insert_unique_pos_res_second::left, m_node_alloc.create_node(value));
        return std::make_pair(iterator{res}, true);
    }

    constexpr iterator erase(const_iterator pos) noexcept
    {
        auto ptr = detail::_get_avl_iterator_ptr<_avl_node_traits>(pos);
        auto res = m_avl_tree.erase_node(ptr);
        m_node_alloc.drop_node(_avl_node_traits::cast_to_node(const_cast<typename _avl_node_traits::base_ptr>(ptr)));
        return iterator(res);
    }

    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr size_type erase(K&& x) noexcept(noexcept(m_avl_tree.find(x)))
    {
        auto pos = m_avl_tree.find(x);
        if (pos == m_avl_tree.end())
            return 0;
        erase(const_iterator(pos));
        return 1;
    }

    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr bool count(const K& x) const noexcept(noexcept(m_avl_tree.contains(x))) { return m_avl_tree.contains(x) ? 1 : 0; }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr iterator find(const K& x) noexcept(noexcept(m_avl_tree.find(x))) { return iterator(m_avl_tree.find(x)); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr const_iterator find(const K& x) const noexcept(noexcept(m_avl_tree.find(x))) { return const_iterator(m_avl_tree.find(x)); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr bool contains(const K& x) const noexcept(noexcept(m_avl_tree.contains(x))) { return m_avl_tree.contains(x); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr iterator lower_bound(const K& x) noexcept(noexcept(m_avl_tree.lower_bound(x))) { return iterator(m_avl_tree.lower_bound(x)); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr const_iterator lower_bound(const K& x) const noexcept(noexcept(m_avl_tree.lower_bound(x))) { return const_iterator(m_avl_tree.lower_bound(x)); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr iterator upper_bound(const K& x) noexcept(noexcept(m_avl_tree.upper_bound(x))) { return iterator(m_avl_tree.upper_bound(x)); }
    template <typename K> requires comparable_param<key_compare, key_type, K>
    constexpr const_iterator upper_bound(const K& x) const noexcept(noexcept(m_avl_tree.upper_bound(x))) { return const_iterator(m_avl_tree.upper_bound(x)); }
};

} // namespace toy
