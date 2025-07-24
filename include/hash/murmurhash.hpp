#pragma once

#include "hash.hpp"

namespace toy
{

namespace detail
{

template <typename Derived, std::unsigned_integral HashType>
class murmurhash_base
{
public:
    template <byte_char_cpt B>
    constexpr auto operator()(std::span<const B> input) const noexcept
    {
        auto hash = static_cast<const Derived*>(this)->init_hash(input.size());

        for (std::size_t i = 0; i + sizeof(HashType) <= input.size(); i += sizeof(HashType))
        {
            auto k = cast_from_bytes_at_unsafe<HashType>(input, i);
            hash = static_cast<const Derived*>(this)->mix(k, hash);
        }
        input = input.subspan(input.size() - input.size() % sizeof(HashType));

        if (!input.empty())
        {
            std::array<std::uint8_t, sizeof(HashType)> final_mix_val{};
            std::copy(input.begin(), input.end(), final_mix_val.begin());
            auto k = cast_from_bytes<HashType>(std::span<const std::uint8_t, sizeof(HashType)>{final_mix_val});

            hash = static_cast<const Derived*>(this)->final_mix(k, hash);
        }

        hash_result_value<sizeof(HashType) * 8> res;
        res.value = static_cast<const Derived*>(this)->final_hash(hash);;
        return res;
    }
};

} // namespace detail

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp
class murmurhash1 : public detail::murmurhash_base<murmurhash1, std::uint32_t>
{
private:
    friend class detail::murmurhash_base<murmurhash1, std::uint32_t>;

    using value_type = std::uint32_t;

    constexpr static value_type M = 0xc6a4a793u;
    value_type m_seed = 0;

    constexpr value_type init_hash(std::size_t size) const noexcept
    {
        return m_seed ^ (static_cast<value_type>(size) * M);
    }

    constexpr value_type mix(value_type k, value_type hash) const noexcept
    {
        hash += k;
        hash *= M;
        hash ^= hash >> 16;
        return hash;
    }

    constexpr value_type final_mix(value_type k, value_type hash) const noexcept
    {
        return mix(k, hash);
    }

    constexpr value_type final_hash(value_type hash) const noexcept
    {
        hash *= M;
        hash ^= hash >> 10;
        hash *= M;
        hash ^= hash >> 17;
        return hash;
    }

public:
    constexpr explicit murmurhash1(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash1() noexcept {}
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint32_t MurmurHash2 ( const void * key, int len, uint32_t seed )
class murmurhash2 : public detail::murmurhash_base<murmurhash2, std::uint32_t>
{
private:
    friend class detail::murmurhash_base<murmurhash2, std::uint32_t>;

    using value_type = std::uint32_t;

    constexpr static value_type M = 0x5bd1e995u;
    value_type m_seed = 0;

    constexpr value_type init_hash(std::size_t size) const noexcept
    {
        return m_seed ^ static_cast<value_type>(size);
    }

    constexpr value_type mix(value_type k, value_type hash) const noexcept
    {
        k *= M;
        k ^= k >> 24;
        k *= M;

        hash *= M;
        hash ^= k;

        return hash;
    }

    constexpr value_type final_mix(value_type k, value_type hash) const noexcept
    {
        hash ^= k;
        hash *= M;
        return hash;
    }

    constexpr value_type final_hash(value_type hash) const noexcept
    {
        hash ^= hash >> 13;
        hash *= M;
        hash ^= hash >> 15;
        return hash;
    }

public:
    constexpr explicit murmurhash2(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash2() noexcept {}
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed )
// 64-bit hash for 64-bit platforms
class murmurhash2_64a : public detail::murmurhash_base<murmurhash2_64a, std::uint64_t>
{
private:
    friend class detail::murmurhash_base<murmurhash2_64a, std::uint64_t>;

    using value_type = std::uint64_t;

    constexpr static value_type M = 0xc6a4a7935bd1e995ull;
    value_type m_seed = 0;

    constexpr value_type init_hash(std::size_t size) const noexcept
    {
        return m_seed ^ (static_cast<value_type>(size) * M);
    }

    constexpr value_type mix(value_type k, value_type hash) const noexcept
    {
        k *= M;
        k ^= k >> 47;
        k *= M;

        hash ^= k;
        hash *= M;

        return hash;
    }

    constexpr value_type final_mix(value_type k, value_type hash) const noexcept
    {
        hash ^= k;
        hash *= M;
        return hash;
    }

    constexpr value_type final_hash(value_type hash) const noexcept
    {
        hash ^= hash >> 47;
        hash *= M;
        hash ^= hash >> 47;
        return hash;
    }

public:
    constexpr explicit murmurhash2_64a(value_type seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash2_64a() noexcept {}
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint64_t MurmurHash64B ( const void * key, int len, uint64_t seed )
// 64-bit hash for 32-bit platforms
class murmurhash2_64b
{
private:
    constexpr static std::uint32_t M = 0x5bd1e995u;
    std::uint64_t m_seed = 0;

public:
    constexpr explicit murmurhash2_64b(std::uint64_t seed = 0) noexcept : m_seed(seed) {}
    constexpr ~murmurhash2_64b() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr hash_result_value<64> operator()(std::span<const B> input) const noexcept
    {
        auto hash1 = static_cast<std::uint32_t>(m_seed) ^ static_cast<std::uint32_t>(input.size());
        auto hash2 = static_cast<std::uint32_t>(m_seed >> 32);

        for (std::size_t i = 0; i + sizeof(std::uint64_t) <= input.size(); i += sizeof(std::uint64_t))
        {
            auto k1 = detail::cast_from_bytes_at_unsafe<std::uint32_t>(input, i);
            k1 *= M;
            k1 ^= k1 >> 24;
            k1 *= M;
            hash1 *= M;
            hash1 ^= k1;

            auto k2 = detail::cast_from_bytes_at_unsafe<std::uint32_t>(input, i + sizeof(std::uint32_t));
            k2 *= M;
            k2 ^= k2 >> 24;
            k2 *= M;
            hash2 *= M;
            hash2 ^= k2;
        }
        input = input.subspan(input.size() - input.size() % sizeof(std::uint64_t));

        if (input.size() >= sizeof(std::uint32_t))
        {
            auto k1 = detail::cast_from_bytes<std::uint32_t>(input.template first<sizeof(std::uint32_t)>());
            k1 *= M;
            k1 ^= k1 >> 24;
            k1 *= M;
            hash1 *= M;
            hash1 ^= k1;

            input = input.subspan(sizeof(std::uint32_t));
        }

        if (!input.empty())
        {
            std::array<std::uint8_t, sizeof(std::uint32_t)> final_mix_val{};
            std::copy(input.begin(), input.end(), final_mix_val.begin());
            auto k = detail::cast_from_bytes<std::uint32_t>(std::span<const std::uint8_t, sizeof(std::uint32_t)>{final_mix_val});

            hash2 ^= k;
            hash2 *= M;
        }

        hash1 ^= (hash2 >> 18);
        hash1 *= M;
        hash2 ^= (hash1 >> 22);
        hash2 *= M;
        hash1 ^= hash2 >> 17;
        hash1 *= M;
        hash2 ^= hash1 >> 19;
        hash2 *= M;

        hash_result_value<64> res;
        res.value = (static_cast<std::uint64_t>(hash1) << 32) | static_cast<std::uint64_t>(hash2);
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

template <>
struct hash_result<murmurhash2_64b>
{
    using type = hash_result_value<64>;
};

template <>
struct is_stream_hash<murmurhash1> : public std::false_type {};

template <>
struct is_stream_hash<murmurhash2> : public std::false_type {};

template <>
struct is_stream_hash<murmurhash2_64a> : public std::false_type {};

template <>
struct is_stream_hash<murmurhash2_64b> : public std::false_type {};

} // namespace toy
