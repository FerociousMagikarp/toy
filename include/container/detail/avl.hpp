#pragma once

#include <memory>
#include <cstddef>
#include <type_traits>
#include <iterator>
#include <utility>
#include <concepts>

namespace toy::detail
{
struct avl_node_base
{
    using base_node_ptr = avl_node_base*;

    base_node_ptr left;
    base_node_ptr right;
    base_node_ptr parent;
    std::size_t   height;
};

struct avl_header_node final : public avl_node_base
{
    // left   : min node
    // right  : max node
    // parent : root node
    // height : size

    constexpr avl_header_node() noexcept { reset(); }
    constexpr avl_header_node(avl_header_node&& x) noexcept
    {
        if (x.parent != nullptr)
            move_data(x);
        else
            reset();
    }
    constexpr ~avl_header_node() = default;

    constexpr void move_data(avl_header_node& other) noexcept
    {
        parent = other.parent;
        left   = other.left;
        right  = other.right;
        height = other.height;

        other.reset();
    }

    constexpr void reset() noexcept
    {
        parent = nullptr;
        left   = this;
        right  = this;
        height = 0;
    }
};

constexpr std::size_t _get_node_height(const avl_node_base* node) noexcept
{
    std::size_t left_height = node->left == nullptr ? 0 : node->left->height;
    std::size_t right_height = node->right == nullptr ? 0 : node->right->height;
    return std::max(left_height, right_height) + 1;
}

constexpr std::pair<std::size_t, std::size_t> _get_child_node_height(const avl_node_base* node) noexcept
{
    std::size_t left_height = node->left == nullptr ? 0 : node->left->height;
    std::size_t right_height = node->right == nullptr ? 0 : node->right->height;
    return std::pair(left_height, right_height);
}

template <typename T>
concept avl_node_base_pointer = std::is_pointer_v<T> 
    && std::is_same_v<std::remove_const_t<std::remove_pointer_t<T>>, avl_node_base>;

template <avl_node_base_pointer NodePtr>
constexpr NodePtr _find_avl_minimum(NodePtr x) noexcept
{
    while (x->left != nullptr)
        x = x->left;
    return x;
}

template <avl_node_base_pointer NodePtr>
constexpr NodePtr _find_avl_maximum(NodePtr x) noexcept
{
    while (x->right != nullptr)
        x = x->right;
    return x;
}

template <avl_node_base_pointer NodePtr>
constexpr NodePtr _avl_node_increment(NodePtr x) noexcept
{
    if (x->right != nullptr)
    {
        return _find_avl_minimum(x->right);
    }
    else
    {
        NodePtr y = x->parent;
        while (x == y->right)
        {
            x = y;
            y = x->parent;
        }
        if (x->right != y)
            return y;
        else
            return x;
    }
}

template <avl_node_base_pointer NodePtr>
constexpr NodePtr _avl_node_decrement(NodePtr x) noexcept
{
    if (x->parent->parent == x && x->right != nullptr && x->height > x->parent->height)
    {
        return x->right;
    }
    
    if (x->left != nullptr)
    {
        return _find_avl_maximum(x->left);
    }
    else
    {
        NodePtr y = x->parent;
        while (x == y->left)
        {
            x = y;
            y = x->parent;
        }
        return y;
    }
}

constexpr void _avl_tree_rotate_left(avl_node_base* x, avl_node_base*& root) noexcept
{
    auto y = x->right;

    y->parent = x->parent;
    if (x == root)
        root = y;
    else if (x->parent->left == x)
        x->parent->left = y;
    else // if (x->parent->right == x)
        x->parent->right = y;

    x->right = y->left;
    if (y->left != nullptr)
        y->left->parent = x;
    y->left = x;
    x->parent = y;
}

constexpr void _avl_tree_rotate_right(avl_node_base* x, avl_node_base*& root) noexcept
{
    auto y = x->left;

    y->parent = x->parent;
    if (x == root)
        root = y;
    else if (x->parent->left == x)
        x->parent->left = y;
    else // if (x->parent->right == x)
        x->parent->right = y;

    x->left = y->right;
    if (y->right != nullptr)
        y->right->parent = x;
    y->right = x;
    x->parent = y;
}

template <typename NodeTraits>
class avl_tree_iterator;

template <typename NodeTraits>
class avl_tree_const_iterator;

template <typename Iter>
struct _avl_tree_iterator_member_types;

template <typename NodeTraits>
struct _avl_tree_iterator_member_types<avl_tree_iterator<NodeTraits>>
{
    using difference_type   = std::ptrdiff_t;
    using value_type        = typename NodeTraits::value_type;
    using pointer           = value_type*;
    using reference         = value_type&;
    using iterator_category = std::bidirectional_iterator_tag;

    using _base_ptr = avl_node_base*;
    using _node_ptr = typename NodeTraits::node_ptr;
};

template <typename NodeTraits>
struct _avl_tree_iterator_member_types<avl_tree_const_iterator<NodeTraits>>
{
    using difference_type   = std::ptrdiff_t;
    using value_type        = typename NodeTraits::value_type;
    using pointer           = const value_type*;
    using reference         = const value_type&;
    using iterator_category = std::bidirectional_iterator_tag;

    using _base_ptr = const avl_node_base*;
    using _node_ptr = const typename NodeTraits::node_ptr;
};

template <typename NodeTraits, typename Derived>
class avl_tree_iterator_base
{
protected:
    using _self = Derived;
    using _type_traits = _avl_tree_iterator_member_types<Derived>;
    using _base_ptr = typename _type_traits::_base_ptr;
    using _node_ptr = typename _type_traits::_node_ptr;

    _base_ptr m_node;

    using _difference_type   = typename _type_traits::difference_type;
    using _value_type        = typename _type_traits::value_type;
    using _pointer           = typename _type_traits::pointer;
    using _reference         = typename _type_traits::reference;
    using _iterator_category = typename _type_traits::iterator_category;

public:
    constexpr avl_tree_iterator_base() noexcept : m_node{} {}
    explicit constexpr avl_tree_iterator_base(_base_ptr node) : m_node(node) {}

    constexpr _reference operator*() const noexcept { return *NodeTraits::value_ptr(m_node); }
    constexpr _pointer operator->() const noexcept { return NodeTraits::value_ptr(m_node); }
    constexpr _self& operator++() noexcept
    {
        m_node = _avl_node_increment(m_node);
        return *static_cast<_self*>(this);
    }
    constexpr _self operator++(int) noexcept
    {
        _self tmp = *static_cast<_self*>(this);
        m_node = _avl_node_increment(m_node);
        return tmp;
    }
    constexpr _self& operator--() noexcept
    {
        m_node = _avl_node_decrement(m_node);
        return *static_cast<_self*>(this);
    }
    constexpr _self operator--(int) noexcept
    {
        _self tmp = *static_cast<_self*>(this);
        m_node = _avl_node_decrement(m_node);
        return tmp;
    }
    friend constexpr bool operator==(const _self& x, const _self& y) noexcept { return x.m_node == y.m_node; }
};

template <typename NodeTraits>
class avl_tree_iterator final : public avl_tree_iterator_base<NodeTraits, avl_tree_iterator<NodeTraits>>
{
private:
    friend class avl_tree_const_iterator<NodeTraits>;

    using _self     = avl_tree_iterator<NodeTraits>;
    using _base     = avl_tree_iterator_base<NodeTraits, _self>;

    using _type_traits = _avl_tree_iterator_member_types<_self>;
    using _base_ptr    = typename _type_traits::_base_ptr;
    using _node_ptr    = typename _type_traits::_node_ptr;

public:
    using difference_type   = typename _type_traits::difference_type;
    using value_type        = typename _type_traits::value_type;
    using pointer           = typename _type_traits::pointer;
    using reference         = typename _type_traits::reference;
    using iterator_category = typename _type_traits::iterator_category;

    constexpr avl_tree_iterator() noexcept : _base() {}
    explicit constexpr avl_tree_iterator(_base_ptr node) : _base(node) {}
    constexpr avl_tree_iterator(const avl_tree_iterator&) = default;
    constexpr avl_tree_iterator(avl_tree_iterator&&) = default;
    constexpr avl_tree_iterator& operator=(const avl_tree_iterator&) = default;
    constexpr avl_tree_iterator& operator=(avl_tree_iterator&&) = default;
};

template <typename NodeTraits>
class avl_tree_const_iterator final : public avl_tree_iterator_base<NodeTraits, avl_tree_const_iterator<NodeTraits>>
{
private:
    template <typename _Traits>
    friend constexpr typename _Traits::const_base_ptr _get_avl_iterator_ptr(const avl_tree_const_iterator<_Traits>&) noexcept;

    using _self     = avl_tree_const_iterator<NodeTraits>;
    using _base     = avl_tree_iterator_base<NodeTraits, _self>;

    using _type_traits = _avl_tree_iterator_member_types<_self>;
    using _base_ptr    = typename _type_traits::_base_ptr;
    using _node_ptr    = typename _type_traits::_node_ptr;

public:
    using difference_type   = typename _type_traits::difference_type;
    using value_type        = typename _type_traits::value_type;
    using pointer           = typename _type_traits::pointer;
    using reference         = typename _type_traits::reference;
    using iterator_category = typename _type_traits::iterator_category;

    constexpr avl_tree_const_iterator() noexcept : _base() {}
    explicit constexpr avl_tree_const_iterator(_base_ptr node) noexcept : _base(node) {}
    constexpr avl_tree_const_iterator(const avl_tree_iterator<NodeTraits>& it) noexcept : _base(it.m_node) {}
    constexpr avl_tree_const_iterator(const avl_tree_const_iterator&) = default;
    constexpr avl_tree_const_iterator(avl_tree_const_iterator&&) = default;
    constexpr avl_tree_const_iterator& operator=(const avl_tree_const_iterator&) = default;
    constexpr avl_tree_const_iterator& operator=(avl_tree_const_iterator&&) = default;
};

template <typename _Traits>
constexpr typename _Traits::const_base_ptr _get_avl_iterator_ptr(const avl_tree_const_iterator<_Traits>& iter) noexcept
{
    return iter.m_node;
}

enum class _insert_unique_pos_res_second
{
    none, left, right,
};

template <typename Key, typename Val, typename NodeTraits, auto Compare>
    requires std::strict_weak_order<decltype(Compare), Key, Key>
class avl_tree
{
public:
    using key_type    = Key;
    using value_type  = Val;
    using size_type   = std::size_t;
    using key_compare = decltype(Compare);

    using _node_traits    = NodeTraits;
    using _base_ptr       = avl_node_base*;
    using _const_base_ptr = const avl_node_base*;

    template <typename K>
    constexpr static bool is_bound_noexcept_v = noexcept(_node_traits::get_key(std::declval<_base_ptr>())) &&
                                                noexcept(Compare(std::declval<key_type>(), std::declval<K>())) &&
                                                noexcept(Compare(std::declval<K>(), std::declval<key_type>()));

    avl_header_node m_header;

    constexpr avl_tree() = default;
    constexpr ~avl_tree() = default;
    avl_tree(const avl_tree&) = delete;
    avl_tree& operator=(const avl_tree&) = delete;
    constexpr avl_tree(avl_tree&&) = default;
    constexpr avl_tree& operator=(avl_tree&&) = default;

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr std::pair<_base_ptr, _insert_unique_pos_res_second> get_insert_unique_pos(const K& key) noexcept(is_bound_noexcept_v<K>)
    {
        using enum _insert_unique_pos_res_second;

        _base_ptr pos = m_header.parent;
        _base_ptr parent = std::addressof(m_header);
        _insert_unique_pos_res_second insert_res = left;

        while (pos != nullptr)
        {
            parent = pos;
            insert_res = Compare(key, _node_traits::get_key(pos)) ? left : right;
            pos = insert_res == left ? pos->left : pos->right;
        }

        if (insert_res == left)
        {
            if (parent != m_header.left)
            {
                auto dec_node = _avl_node_decrement(parent);
                if (!Compare(_node_traits::get_key(dec_node), key))
                    return std::make_pair(dec_node, none);
            }
        }
        else if (!Compare(_node_traits::get_key(parent), key))
        {
            return std::make_pair(parent, none);
        }

        return std::make_pair(parent, insert_res);
    }

    constexpr _base_ptr insert_node(_base_ptr parent, bool insert_left, _base_ptr node) noexcept
    {
        m_header.height++;
        node->parent = parent;
        node->left = node->right = nullptr;
        node->height = 1;

        if (insert_left)
        {
            parent->left = node;
            if (parent == std::addressof(m_header))
            {
                parent->parent = node;
                parent->right = node;
            }
            else if (parent == m_header.left)
            {
                m_header.left = node;
            }
        }
        else
        {
            parent->right = node;
            if (parent == m_header.right)
                m_header.right = node;
        }

        rebalence(parent);

        return node;
    }

    constexpr _base_ptr erase_node(_const_base_ptr _node) noexcept
    {
        _base_ptr node = const_cast<_base_ptr>(_node);
        _base_ptr rebalance_node;
        _base_ptr replace_node = nullptr;
        auto inc_node = _avl_node_increment(node);
        if (node->left == nullptr && node->right == nullptr)
        {
            if (node->parent == std::addressof(m_header))
            {
                m_header.parent = nullptr;
                m_header.left = m_header.right = std::addressof(m_header);
            }
            else
            {
                if (node == m_header.left)
                    m_header.left = inc_node;
                else if (node == m_header.right)
                    m_header.right = _avl_node_decrement(node);
                if (node == node->parent->left)
                    node->parent->left = nullptr;
                else // if (node == node->parent->right)
                    node->parent->right = nullptr;
            }
            rebalance_node = node->parent;
        }
        else
        {
            auto [left_height, right_height] = _get_child_node_height(node);
            if (left_height >= right_height)
            {
                auto dec_node = _avl_node_decrement(node);
                if (dec_node->parent != node)
                {
                    dec_node->parent->right = dec_node->left;
                    if (dec_node->left)
                        dec_node->left->parent = dec_node->parent;
                    dec_node->left = node->left;
                    node->left->parent = dec_node;
                    rebalance_node = dec_node->parent;
                }
                else
                {
                    rebalance_node = node->parent;
                }

                if (node->parent == std::addressof(m_header))
                {
                    node->parent->parent = dec_node;
                }
                else if (node == node->parent->left)
                {
                    node->parent->left = dec_node;
                }
                else // if (node == node->parent->right)
                {
                    node->parent->right = dec_node;
                    if (node == m_header.right)
                        m_header.right = dec_node;
                }
                dec_node->right = node->right;
                if (node->right)
                    node->right->parent = dec_node;
                dec_node->parent = node->parent;
                replace_node = dec_node;
            }
            else // if (left_height < right_height)
            {
                if (inc_node->parent != node)
                {
                    inc_node->parent->left = inc_node->right;
                    if (inc_node->right)
                        inc_node->right->parent = inc_node->parent;
                    inc_node->right = node->right;
                    node->right->parent = inc_node;
                    rebalance_node = inc_node->parent;
                }
                else
                {
                    rebalance_node = node->parent;
                }

                if (node->parent == std::addressof(m_header))
                {
                    node->parent->parent = inc_node;
                }
                else if (node == node->parent->right)
                {
                    node->parent->right = inc_node;
                }
                else // if (node == node->parent->left)
                {
                    node->parent->left = inc_node;
                    if (node == m_header.left)
                        m_header.left = inc_node;
                }
                inc_node->left = node->left;
                if (node->left)
                    node->left->parent = inc_node;
                inc_node->parent = node->parent;
                replace_node = inc_node;
            }
            node->left = node->right = nullptr;
        }
        node->parent = nullptr;
        node->height = 0;

        m_header.height--;
        if (replace_node)
            replace_node->height = _get_node_height(replace_node);
        rebalence(rebalance_node);

        return inc_node;
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _const_base_ptr lower_bound(const K& key) const noexcept(is_bound_noexcept_v<K>)
    {
        _const_base_ptr x = m_header.parent;
        _const_base_ptr y = end();
        while (x != nullptr)
        {
            bool go_left = !Compare(_node_traits::get_key(x), key);
            y = go_left ? x : y;
            _const_base_ptr x_children[2] = {x->right, x->left};
            x = x_children[go_left];
        }
        return y;
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _base_ptr lower_bound(const K& key) noexcept(is_bound_noexcept_v<K>)
    {
        return const_cast<_base_ptr>(std::as_const(*this).lower_bound(key));
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _const_base_ptr upper_bound(const K& key) const noexcept(is_bound_noexcept_v<K>)
    {
        _const_base_ptr x = m_header.parent;
        _const_base_ptr y = end();
        while (x != nullptr)
        {
            bool go_left = Compare(key, _node_traits::get_key(x));
            y = go_left ? x : y;
            _const_base_ptr x_children[2] = {x->right, x->left};
            x = x_children[go_left];
        }
        return y;
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _base_ptr upper_bound(const K& key) noexcept(is_bound_noexcept_v<K>)
    {
        return const_cast<_base_ptr>(std::as_const(*this).upper_bound(key));
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _const_base_ptr find(const K& key) const noexcept(is_bound_noexcept_v<K>)
    {
        _const_base_ptr x = m_header.parent;
        while (x != nullptr) {
            bool go_left = Compare(key, _node_traits::get_key(x));
            if (!go_left && !Compare(_node_traits::get_key(x), key))
                return x;
            _const_base_ptr children[2] = {x->right, x->left};
            x = children[go_left];
        }
        return end();
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr _base_ptr find(const K& key) noexcept(is_bound_noexcept_v<K>)
    {
        return const_cast<_base_ptr>(std::as_const(*this).find(key));
    }

    template <typename K>
        requires std::strict_weak_order<key_compare, key_type, K>
    constexpr bool contains(const K& key) const noexcept(is_bound_noexcept_v<K>)
    {
        _const_base_ptr x = m_header.parent;
        while (x != nullptr) {
            bool go_left = Compare(key, _node_traits::get_key(x));
            if (!go_left && !Compare(_node_traits::get_key(x), key))
                return true;
            _const_base_ptr children[2] = {x->right, x->left};
            x = children[go_left];
        }
        return false;
    }

    constexpr _base_ptr       begin() noexcept       { return m_header.left; }
    constexpr _const_base_ptr begin() const noexcept { return m_header.left; }
    constexpr _base_ptr       end()   noexcept       { return std::addressof(m_header); }
    constexpr _const_base_ptr end()   const noexcept { return std::addressof(m_header); }

    constexpr bool empty() const noexcept { return m_header.height == 0; }
    constexpr size_type size() const noexcept { return m_header.height; }

private:
    constexpr void rebalence(_base_ptr node) noexcept
    {
        using signed_size = std::make_signed_t<std::size_t>;

        while (node != std::addressof(m_header))
        {
            auto [left_height, right_height] = _get_child_node_height(node);
            if (std::abs(static_cast<signed_size>(left_height) - static_cast<signed_size>(right_height)) > 1)
            {
                if (left_height < right_height)
                {
                    auto [child_left_height, child_right_height] = _get_child_node_height(node->right);
                    if (child_left_height > child_right_height)
                    {
                        auto child_node = node->right;
                        _avl_tree_rotate_right(child_node, m_header.parent);
                        child_node->height = _get_node_height(child_node);
                    }
                    _avl_tree_rotate_left(node, m_header.parent);
                }
                else
                {
                    auto [child_left_height, child_right_height] = _get_child_node_height(node->left);
                    if (child_left_height < child_right_height)
                    {
                        auto child_node = node->left;
                        _avl_tree_rotate_left(child_node, m_header.parent);
                        child_node->height = _get_node_height(child_node);
                    }
                    _avl_tree_rotate_right(node, m_header.parent);
                }
            }
            auto height = _get_node_height(node);
            node->height = height;
            node = node->parent;
        }
    }

};

} // namespace toy::detail
