#pragma once

#include "hash.hpp"

namespace toy
{

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp
class murmurhash1
{
private:
    using value_type = std::uint32_t;

    constexpr static value_type M = 0xc6a4a793u;
    value_type m_seed = 0;
    value_type m_hash = 0;

public:
    constexpr explicit murmurhash1(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash1() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        m_hash = m_seed ^ (static_cast<value_type>(input.size()) * M);

        for  (std::size_t i = 0; i + sizeof(value_type) <= input.size(); i += sizeof(value_type))
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type>(input, i);
            m_hash += k;
            m_hash *= M;
            m_hash ^= m_hash >> 16;
        }
        input = input.subspan(input.size() - input.size() % 4);

        switch (input.size())
        {
        case 3:
            m_hash += static_cast<value_type>(input[2]) << 16;
            [[fallthrough]];
        case 2:
            m_hash += static_cast<value_type>(input[1]) << 8;
            [[fallthrough]];
        case 1:
            m_hash += static_cast<value_type>(input[0]);
            m_hash *= M;
            m_hash ^= m_hash >> 16;
            break;
        default:
            break;
        };
        
    }

    constexpr hash_result_value<32> result() const noexcept
    {
        hash_result_value<32> res;

        value_type hash = m_hash;
        hash *= M;
        hash ^= hash >> 10;
        hash *= M;
        hash ^= hash >> 17;
        res.value = hash;
        return res;
    }
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint32_t MurmurHash2 ( const void * key, int len, uint32_t seed )
class murmurhash2
{
private:
    using value_type = std::uint32_t;

    constexpr static value_type M = 0x5bd1e995u;
    value_type m_seed = 0;
    value_type m_hash = 0;

public:
    constexpr explicit murmurhash2(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash2() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        m_hash = m_seed ^ static_cast<value_type>(input.size());

        for  (std::size_t i = 0; i + sizeof(value_type) <= input.size(); i += sizeof(value_type))
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type>(input, i);
            k *= M;
            k ^= k >> 24;
            k *= M;

            m_hash *= M;
            m_hash ^= k;
        }
        input = input.subspan(input.size() - input.size() % 4);

        switch (input.size())
        {
        case 3:
            m_hash ^= static_cast<value_type>(input[2]) << 16;
            [[fallthrough]];
        case 2:
            m_hash ^= static_cast<value_type>(input[1]) << 8;
            [[fallthrough]];
        case 1:
            m_hash ^= static_cast<value_type>(input[0]);
            m_hash *= M;
            break;
        default:
            break;
        };

    }

    constexpr hash_result_value<32> result() const noexcept
    {
        hash_result_value<32> res;
        
        value_type hash = m_hash;
        hash ^= hash >> 13;
        hash *= M;
        hash ^= hash >> 15;

        res.value = hash;

        return res;
    }
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed )
// 64-bit hash for 64-bit platforms
class murmurhash2_64a
{
private:
    using value_type = std::uint64_t;

    constexpr static value_type M = 0xc6a4a7935bd1e995ull;
    value_type m_seed = 0;
    value_type m_hash = 0;

public:
    constexpr explicit murmurhash2_64a(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash2_64a() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        m_hash = m_seed ^ (static_cast<value_type>(input.size()) * M);

        for  (std::size_t i = 0; i + sizeof(value_type) <= input.size(); i += sizeof(value_type))
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type>(input, i);
            k *= M;
            k ^= k >> 47;
            k *= M;

            m_hash ^= k;
            m_hash *= M;
        }
        input = input.subspan(input.size() - input.size() % 8);

        switch (input.size())
        {
        case 7:
            m_hash ^= static_cast<value_type>(input[6]) << 48;
            [[fallthrough]];
        case 6:
            m_hash ^= static_cast<value_type>(input[5]) << 40;
            [[fallthrough]];
        case 5:
            m_hash ^= static_cast<value_type>(input[4]) << 32;
            [[fallthrough]];
        case 4:
            m_hash ^= static_cast<value_type>(input[3]) << 24;
            [[fallthrough]];
        case 3:
            m_hash ^= static_cast<value_type>(input[2]) << 16;
            [[fallthrough]];
        case 2:
            m_hash ^= static_cast<value_type>(input[1]) << 8;
        case 1:
            m_hash ^= static_cast<value_type>(input[0]);
            m_hash *= M;
            break;
        default:
            break;
        };

    }

    constexpr hash_result_value<64> result() const noexcept
    {
        hash_result_value<64> res;
        
        value_type hash = m_hash;
        hash ^= hash >> 47;
        hash *= M;
        hash ^= hash >> 47;

        res.value = hash;

        return res;
    }
};

template <>
struct hash_result<murmurhash1>
{
    using type = hash_result_value<32>;
};

template <>
struct hash_result<murmurhash2>
{
    using type = hash_result_value<32>;
};

template <>
struct hash_result<murmurhash2_64a>
{
    using type = hash_result_value<64>;
};


} // namespace toy
