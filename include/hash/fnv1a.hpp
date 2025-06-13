#pragma once

#include "hash.hpp"

namespace toy
{

namespace detail
{
template <int N>
    requires (N == 32 || N == 64)
class fnv1a
{
private:
    using value_type = std::conditional_t<N == 32, std::uint32_t, std::uint64_t>;
    constexpr static value_type OFFSET = std::conditional_t<
        N == 32,
        std::integral_constant<std::uint32_t, 2166136261U>,
        std::integral_constant<std::uint64_t, 14695981039346656037ULL>
    >::value;
    constexpr static value_type PRIME = std::conditional_t<
        N == 32,
        std::integral_constant<std::uint32_t, 16777619U>,
        std::integral_constant<std::uint64_t, 1099511628211ULL>
    >::value;

    value_type m_val;

    template <byte_char_cpt B>
    constexpr void sppend_bytes(std::span<const B> input) noexcept
    {
        for (const B c : input)
        {
            m_val ^= static_cast<value_type>(c);
            m_val *= PRIME;
        }
    }

public:
    constexpr fnv1a() noexcept : m_val(OFFSET) {}
    constexpr ~fnv1a() noexcept {}

    template <byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        sppend_bytes(input);
    }

    constexpr hash_result_value<N> result() const noexcept
    {
        hash_result_value<N> res;
        res.value = m_val;
        return res;
    }
};
} // namespace detail

using fnv1a_32 = detail::fnv1a<32>;
using fnv1a_64 = detail::fnv1a<64>;

template <>
struct hash_result<fnv1a_32>
{
    using type = hash_result_value<32>;
};

template <>
struct hash_result<fnv1a_64>
{
    using type = hash_result_value<64>;
};

} // namespace toy
