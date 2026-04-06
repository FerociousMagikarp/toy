#pragma once

#include <array>

namespace toy::detail
{
template <std::size_t N, typename NodeBase>
struct _node_base_index : public NodeBase {};

template <std::size_t N, typename... NodeBase>
struct _node_helper {};

template <std::size_t N, typename NodeBase, typename... Other>
struct _node_helper<N, NodeBase, Other...> : public _node_base_index<N, NodeBase>,
    public _node_helper<N + 1, Other...> {
};

template <std::size_t N, typename T, typename... Other>
struct _get_type_at
{
    using type = _get_type_at<N - 1, Other...>;
};

template <typename T, typename... Other>
struct _get_type_at<0, T, Other...>
{
    using type = T;
};

template <std::size_t N, typename... Ts>
    requires (N < sizeof...(Ts))
using _get_type_at_t = typename _get_type_at<N, Ts...>::type;

template <typename Val, typename... NodeBase>
struct container_node : public _node_helper<0, NodeBase...>
{
    alignas(Val) std::array<std::byte, sizeof(Val)> value;

    constexpr void* value_addr() noexcept { return static_cast<void*>(value.data()); }
    constexpr const void* value_addr() const noexcept { return static_cast<const void*>(value.data()); }
    constexpr Val* value_ptr() noexcept { return static_cast<Val*>(value_addr()); }
    constexpr const Val* value_ptr() const noexcept { return static_cast<const Val*>(value_addr()); }
};

} // namespace toy::detail
