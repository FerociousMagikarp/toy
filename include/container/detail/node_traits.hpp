#pragma once

#include "node.hpp"

namespace toy::detail
{

template <typename Node, auto KeyOfVal, std::size_t N>
struct node_traits {};

template <typename Val, typename... Base, auto KeyOfVal, std::size_t N>
    requires (N < sizeof...(Base))
struct node_traits<container_node<Val, Base...>, KeyOfVal, N>
{
    using value_type = Val;
    using base_type = _get_type_at_t<N, Base...>;
    using node_type = container_node<Val, Base...>;
    using base_ptr = base_type*;
    using node_ptr = node_type*;
    using const_base_ptr = const base_type*;
    using const_node_ptr = const node_type*;

    static base_ptr cast_to_base(node_ptr node) noexcept
    {
        using index_ptr = _node_base_index<N, base_type>*;
        auto mid = static_cast<index_ptr>(node);
        return static_cast<base_ptr>(mid);
    }

    static const_base_ptr cast_to_base(const_node_ptr node) noexcept
    {
        using const_index_ptr = const _node_base_index<N, base_type>*;
        auto mid = static_cast<const_index_ptr>(node);
        return static_cast<const_base_ptr>(mid);
    }

    static node_ptr cast_to_node(base_ptr base) noexcept
    {
        using index_ptr = _node_base_index<N, base_type>*;
        auto mid = static_cast<index_ptr>(base);
        return static_cast<node_ptr>(mid);
    }

    static const_node_ptr cast_to_node(const_base_ptr base) noexcept
    {
        using const_index_ptr = const _node_base_index<N, base_type>*;
        auto mid = static_cast<const_index_ptr>(base);
        return static_cast<const_node_ptr>(mid);
    }

    static void* value_addr(base_ptr base) noexcept { return cast_to_node(base)->value_addr(); }
    static const void* value_addr(const_base_ptr base) noexcept { return cast_to_node(base)->value_addr(); }
    static Val* value_ptr(base_ptr base) noexcept { return cast_to_node(base)->value_ptr(); }
    static const Val* value_ptr(const_base_ptr base) noexcept { return cast_to_node(base)->value_ptr(); }

    static const auto& get_key(const_base_ptr base)
        noexcept(noexcept(KeyOfVal(std::declval<value_type>())))
    { return KeyOfVal(*value_ptr(base)); }
    static const auto& get_key(value_type&& val)
        noexcept(noexcept(KeyOfVal(std::declval<value_type>())))
    { return KeyOfVal(std::forward<value_type>(val)); }
    static const auto& get_key(const value_type& val)
        noexcept(noexcept(KeyOfVal(std::declval<value_type>())))
    { return KeyOfVal(val); }
};

} // namespace toy::detail
