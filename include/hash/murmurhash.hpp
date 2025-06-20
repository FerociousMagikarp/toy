#pragma once

#include "hash.hpp"

namespace toy
{

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp
class murmurhash1
{
private:
    constexpr static std::uint32_t M = 0xc6a4a793u;
    std::uint32_t m_seed = 0;
    std::uint32_t m_hash = 0;

public:
    constexpr explicit murmurhash1(std::uint32_t seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash1() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        m_hash = m_seed ^ (static_cast<std::uint32_t>(input.size()) * M);
        for  (std::size_t i = 0; i + 4 <= input.size(); i += 4)
        {
            auto k = detail::cast_from_bytes_at_unsafe<std::uint32_t>(input, i);
            m_hash += k;
            m_hash *= M;
            m_hash ^= m_hash >> 16;
        }
        input = input.subspan(input.size() - input.size() % 4);

        switch (input.size())
        {
        case 3:
            m_hash += static_cast<std::uint32_t>(input[2]) << 16;
            [[fallthrough]];
        case 2:
            m_hash += static_cast<std::uint32_t>(input[1]) << 8;
            [[fallthrough]];
        case 1:
            m_hash += static_cast<std::uint32_t>(input[0]);
            m_hash *= M;
            m_hash ^= m_hash >> 16;
            break;
        default:
            break;
        };
        m_hash *= M;
        m_hash ^= m_hash >> 10;
        m_hash *= M;
        m_hash ^= m_hash >> 17;
    }

    constexpr hash_result_value<32> result() const noexcept
    {
        hash_result_value<32> res;
        res.value = m_hash;
        return res;
    }
};


template <>
struct hash_result<murmurhash1>
{
    using type = hash_result_value<32>;
};

} // namespace toy
