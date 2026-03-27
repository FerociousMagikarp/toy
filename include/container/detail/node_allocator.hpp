#pragma once

#include <memory>

namespace toy::detail
{

template <typename Val, typename Node, typename Alloc = std::allocator<Val>,
    typename NodeAlloc = typename std::allocator_traits<Alloc>::template rebind_alloc<Node>>
struct node_allocator : public NodeAlloc
{
    using value_type      = Val;
    using size_type       = std::size_t;
    using allocator_type  = Alloc;
    using reference       = value_type&;
    using const_reference = const value_type&;
    using pointer         = typename std::allocator_traits<allocator_type>::pointer;
    using const_pointer   = typename std::allocator_traits<allocator_type>::const_pointer;

    using node_type         = Node;
    using node_ptr          = node_type*;
    using alloc_traits      = std::allocator_traits<allocator_type>;
    using node_alloc        = NodeAlloc;
    using node_alloc_traits = std::allocator_traits<node_alloc>;

    constexpr node_allocator() noexcept {}
    constexpr ~node_allocator() noexcept {}

    constexpr node_alloc&       get_node_alloc() noexcept { return *this; }
    constexpr const node_alloc& get_node_alloc() const noexcept { return *this; }

    constexpr node_ptr get_node() { return node_alloc_traits::allocate(get_node_alloc(), 1); }
    constexpr void     put_node(node_ptr node) noexcept { node_alloc_traits::deallocate(get_node_alloc(), node, 1); }

    template <typename... Args>
    constexpr void construct_node(node_ptr node, Args&&... args)
    {
        try
        {
            std::construct_at(node);
            node_alloc_traits::construct(get_node_alloc(), node->value_ptr(), std::forward<Args>(args)...);
        }
        catch (...)
        {
            std::destroy_at(node);
            put_node(node);
            throw;
        }
    }

    constexpr void destroy_node(node_ptr node) noexcept
    {
        node_alloc_traits::destroy(get_node_alloc(), node->value_ptr());
        std::destroy_at(node);
    }

    template <typename... Args>
    constexpr node_ptr create_node(Args&&... args)
    {
        auto node = get_node();
        construct_node(node, std::forward<Args>(args)...);
        return node;
    }

    constexpr void drop_node(node_ptr node) noexcept
    {
        destroy_node(node);
        put_node(node);
    }
};

} // namespace toy::detail
