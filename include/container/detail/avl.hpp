#pragma once

#include <array>
#include <memory>
#include <cstddef>
#include <type_traits>
#include <iterator>

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

    avl_header_node() noexcept { reset(); }
    avl_header_node(avl_header_node&& x) noexcept
    {
        if (x.parent != nullptr)
            move_data(x);
        else
            reset();
    }

    void move_data(avl_header_node& other) noexcept
    {
        parent = other.parent;
        left   = other.left;
        right  = other.right;
        height = other.height;

        other.reset();
    }

    void reset() noexcept
    {
        parent = nullptr;
        left   = this;
        right  = this;
        height = 0;
    }
};

inline std::size_t _get_node_height(const avl_node_base* node) noexcept
{
    std::size_t left_height = node->left == nullptr ? 0 : node->left->height;
    std::size_t right_height = node->right == nullptr ? 0 : node->right->height;
    return std::max(left_height, right_height) + 1;
}

inline std::pair<std::size_t, std::size_t> _get_child_node_height(const avl_node_base* node) noexcept
{
    std::size_t left_height = node->left == nullptr ? 0 : node->left->height;
    std::size_t right_height = node->right == nullptr ? 0 : node->right->height;
    return std::pair(left_height, right_height);
}

template <typename T>
concept avl_node_base_pointer = std::is_pointer_v<T> 
    && std::is_same_v<std::remove_const_t<std::remove_pointer_t<T>>, avl_node_base>;

template <avl_node_base_pointer NodePtr>
NodePtr _find_avl_minimum(NodePtr x) noexcept
{
    while (x->left != nullptr)
        x = x->left;
    return x;
}

template <avl_node_base_pointer NodePtr>
NodePtr _find_avl_maximum(NodePtr x) noexcept
{
    while (x->right != nullptr)
        x = x->right;
    return x;
}

template <avl_node_base_pointer NodePtr>
NodePtr _avl_node_increment(NodePtr x) noexcept
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
NodePtr _avl_node_decrement(NodePtr x) noexcept
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

inline void _avl_tree_rotate_left(avl_node_base* x, avl_node_base*& root) noexcept
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

inline void _avl_tree_rotate_right(avl_node_base* x, avl_node_base*& root) noexcept
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

template <typename T>
struct avl_node final : public avl_node_base
{
    alignas(T) std::array<std::byte, sizeof(T)> value;

    void* value_addr() noexcept { return static_cast<void*>(value.data()); }
    const void* value_addr() const noexcept { return static_cast<const void*>(value.data()); }
    T* value_ptr() noexcept { return static_cast<T*>(value_addr()); }
    const T* value_ptr() const noexcept { return static_cast<const T*>(value_addr()); }
};

template <typename T>
class avl_tree_iterator;

template <typename T>
class avl_tree_const_iterator;

template <typename Iter>
struct _avl_tree_iterator_member_types;

template <typename T>
struct _avl_tree_iterator_member_types<avl_tree_iterator<T>>
{
    using difference_type   = std::ptrdiff_t;
    using value_type        = T;
    using pointer           = T*;
    using reference         = T&;
    using iterator_category = std::bidirectional_iterator_tag;

    using _base_ptr = avl_node_base*;
    using _node_ptr = avl_node<T>*;
};

template <typename T>
struct _avl_tree_iterator_member_types<avl_tree_const_iterator<T>>
{
    using difference_type   = std::ptrdiff_t;
    using value_type        = T;
    using pointer           = const T*;
    using reference         = const T&;
    using iterator_category = std::bidirectional_iterator_tag;

    using _base_ptr = const avl_node_base*;
    using _node_ptr = const avl_node<T>*;
};

template <typename T, typename Derived>
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
    avl_tree_iterator_base() noexcept : m_node{} {}
    explicit avl_tree_iterator_base(_base_ptr node) : m_node(node) {}

    _reference operator*() const noexcept { return *static_cast<_node_ptr>(m_node)->value_ptr(); }
    _pointer operator->() const noexcept { return static_cast<_node_ptr>(m_node)->value_ptr(); }
    _self& operator++() noexcept
    {
        m_node = _avl_node_increment(m_node);
        return *static_cast<_self*>(this);
    }
    _self operator++(int) noexcept
    {
        _self tmp = *static_cast<_self*>(this);
        m_node = _avl_node_increment(m_node);
        return tmp;
    }
    _self& operator--() noexcept
    {
        m_node = _avl_node_decrement(m_node);
        return *static_cast<_self*>(this);
    }
    _self operator--(int) noexcept
    {
        _self tmp = *static_cast<_self*>(this);
        m_node = _avl_node_decrement(m_node);
        return tmp;
    }
    friend bool operator==(const _self& x, const _self& y) noexcept { return x.m_node == y.m_node; }
};

template <typename T>
class avl_tree_iterator final : public avl_tree_iterator_base<T, avl_tree_iterator<T>>
{
private:
    friend class avl_tree_const_iterator<T>;

    using _self     = avl_tree_iterator<T>;
    using _base     = avl_tree_iterator_base<T, _self>;

    using _type_traits = _avl_tree_iterator_member_types<_self>;
    using _base_ptr = typename _type_traits::_base_ptr;
    using _node_ptr = typename _type_traits::_node_ptr;

public:
    using difference_type   = typename _type_traits::difference_type;
    using value_type        = typename _type_traits::value_type;
    using pointer           = typename _type_traits::pointer;
    using reference         = typename _type_traits::reference;
    using iterator_category = typename _type_traits::iterator_category;

    avl_tree_iterator() noexcept : _base() {}
    explicit avl_tree_iterator(_base_ptr node) : _base(node) {}
};

template <typename T>
class avl_tree_const_iterator final : public avl_tree_iterator_base<T, avl_tree_const_iterator<T>>
{
private:
    using _self     = avl_tree_const_iterator<T>;
    using _base     = avl_tree_iterator_base<T, _self>;

    using _type_traits = _avl_tree_iterator_member_types<_self>;
    using _base_ptr = typename _type_traits::_base_ptr;
    using _node_ptr = typename _type_traits::_node_ptr;

public:
    using difference_type   = typename _type_traits::difference_type;
    using value_type        = typename _type_traits::value_type;
    using pointer           = typename _type_traits::pointer;
    using reference         = typename _type_traits::reference;
    using iterator_category = typename _type_traits::iterator_category;

    avl_tree_const_iterator() noexcept : _base() {}
    explicit avl_tree_const_iterator(_base_ptr node) noexcept : _base(node) {}
    avl_tree_const_iterator(const avl_tree_iterator<T>& it) noexcept : _base(it.m_node) {}
};

template <typename Key, typename Val, typename KeyOfValue, typename Compare, typename Alloc>
class avl_tree
{
public:
    static_assert(std::is_invocable_v<const Compare&, const Key&, const Key&>, "comparison object must be invocable as const");

    using key_type        = Key;
    using value_type      = Val;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using key_compare     = Compare;
    using allocator_type  = Alloc;
    using reference       = value_type&;
    using const_reference = const value_type&;
    using pointer         = typename std::allocator_traits<allocator_type>::pointer;
    using const_pointer   = typename std::allocator_traits<allocator_type>::const_pointer;

    using iterator               = avl_tree_iterator<value_type>;
    using const_iterator         = avl_tree_const_iterator<value_type>;
    using reverse_iterator       = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    using _node_type         = avl_node<value_type>;
    using _node_ptr_type     = _node_type*;
    using _base_ptr_type     = avl_node_base*;
    using _alloc_traits      = std::allocator_traits<allocator_type>;
    using _node_allocator    = typename _alloc_traits::template rebind_alloc<_node_type>;
    using _node_alloc_traits = std::allocator_traits<_node_allocator>;

    avl_header_node m_header;
    [[no_unique_address]] _node_allocator m_node_alloc;
    [[no_unique_address]] Compare m_compare;

    const key_type& _get_key(_base_ptr_type node_ptr) const noexcept
    {
        return KeyOfValue{}(*static_cast<_node_ptr_type>(node_ptr)->value_ptr());
    }

    _node_ptr_type _get_left(_base_ptr_type node_ptr) const noexcept
    {
        return static_cast<_node_ptr_type>(node_ptr->left);
    }

    _node_ptr_type _get_right(_base_ptr_type node_ptr) const noexcept
    {
        return static_cast<_node_ptr_type>(node_ptr->right);
    }

    _node_ptr_type _get_root() const noexcept { return static_cast<_node_ptr_type>(m_header.parent); }

    template <typename Arg>
    _node_ptr_type _construct_node(Arg&& arg)
    {
        auto node = m_node_alloc.allocate(1);
        try
        {
            _node_alloc_traits::construct(m_node_alloc, node->value_ptr(), std::forward<Arg>(arg));
        }
        catch (const std::exception& e)
        {
            m_node_alloc.deallocate(node, 1);
            throw e;
        }
        return node;
    }

    void _insert_rebalence(_base_ptr_type node) noexcept
    {
        using signed_size = std::make_signed_t<std::size_t>;

        while (node != &m_header)
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
                
                do
                {
                    auto height = _get_node_height(node);
                    if (node->height == height)
                        break;
                    node->height = height;
                    node = node->parent;
                } while (node != &m_header);
                break;
            }
            auto height = std::max(left_height, right_height) + 1;
            if (node->height == height)
                break;
            node->height = height;
            node = node->parent;
        }
    }

    template <typename Arg>
    std::pair<iterator, bool> insert_unique(Arg&& arg)
    {
        const key_type& k = KeyOfValue{}(arg);
        _node_ptr_type x = _get_root();
        _base_ptr_type y = &m_header;
        bool comp = true;

        while (x != nullptr)
        {
            y = x;
            comp = m_compare(k, _get_key(x));
            x = comp ? _get_left(x) : _get_right(x);
        }

        if (comp)
        {
            if (y != m_header.left)
            {
                if (!m_compare(_get_key(_avl_node_decrement(y)), k))
                    return std::make_pair(end(), false);
            }
        }
        else if (!m_compare(_get_key(y), k))
        {
            return std::make_pair(end(), false);
        }

        m_header.height++;
        auto node = _construct_node(std::forward<Arg>(arg));

        node->parent = y;
        node->left = node->right = nullptr;
        node->height = 1;

        if (comp)
        {
            y->left = node;
            if (y == &m_header)
            {
                y->parent = node;
                y->right = node;
            }
            else if (y == m_header.left)
            {
                m_header.left = node;
            }
        }
        else
        {
            y->right = node;
            if (y == m_header.right)
            {
                m_header.right = node;
            }
        }

        _insert_rebalence(node->parent);

        return std::make_pair(iterator(node), true);
    }

    constexpr allocator_type get_allocator() noexcept { return allocator_type(m_node_alloc); }

    iterator               begin()   noexcept       { return iterator(m_header.left); }
    const_iterator         begin()   const noexcept { return const_iterator(m_header.left); }
    const_iterator         cbegin()  const noexcept { return const_iterator(m_header.left); }
    iterator               end()     noexcept       { return iterator(&m_header); }
    const_iterator         end()     const noexcept { return const_iterator(&m_header); }
    const_iterator         cend()    const noexcept { return const_iterator(&m_header); }
    reverse_iterator       rbegin()  noexcept       { return reverse_iterator(end()); }
    const_reverse_iterator rbegin()  const noexcept { return const_reverse_iterator(end()); }
    const_reverse_iterator crbegin() const noexcept { return const_reverse_iterator(end()); }
    reverse_iterator       rend()    noexcept       { return reverse_iterator(begin()); }
    const_reverse_iterator rend()    const noexcept { return const_reverse_iterator(begin()); }
    const_reverse_iterator crend()   const noexcept { return const_reverse_iterator(begin()); }

    bool empty() const noexcept { return m_header.height == 0; }
    size_type size() const noexcept { return m_header.height; }
    size_type max_size() const noexcept { return _alloc_traits::max_size(m_node_alloc); }
};

} // namespace toy::detail
