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

constexpr std::uint32_t murmurhash3_fmix32(std::uint32_t h) noexcept
{
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;

    return h;
}

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


// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// uint32_t MurmurHash2A ( const void * key, int len, uint32_t seed )
class murmurhash2a : public detail::_hash_stream_save_to_buffer_base<murmurhash2a, 4>
{
private:
    friend class detail::_hash_stream_save_to_buffer_base<murmurhash2a, 4>;

    using value_type = std::uint32_t;

    constexpr static value_type M = 0x5bd1e995u;
    constexpr static std::size_t MAX_BUFFER_SIZE = 4;

    value_type m_seed = 0;
    value_type m_hash = 0;

    constexpr std::uint32_t mix(std::uint32_t h, std::uint32_t k) const noexcept
    {
        k *= M;
        k ^= k >> 24;
        k *= M;
        h *= M;
        h ^= k;

        return h;
    }

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + MAX_BUFFER_SIZE <= input.size(); i += MAX_BUFFER_SIZE)
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type>(input, i);
            m_hash = mix(m_hash, k);
        }

        return input.subspan(input.size() - input.size() % MAX_BUFFER_SIZE);
    }

public:
    constexpr explicit murmurhash2a(value_type seed = 0) noexcept : m_seed(seed), m_hash(seed) {}
    constexpr ~murmurhash2a() noexcept {}

    constexpr hash_result_value<32> result() const noexcept
    {
        hash_result_value<32> res;
        std::uint32_t t = 0;
        if (this->m_buffer_size > 0)
        {
            std::array<std::uint8_t, MAX_BUFFER_SIZE> buffer{};
            std::copy_n(this->m_buffer.begin(), this->m_buffer_size, buffer.begin());
            t = detail::cast_from_bytes<std::uint32_t>(std::span<const std::uint8_t, MAX_BUFFER_SIZE>{buffer});
        }
        auto hash = mix(m_hash, t);
        hash = mix(hash, static_cast<std::uint32_t>(this->m_total_len));

        hash ^= hash >> 13;
        hash *= M;
        hash ^= hash >> 15;
        res.value = hash;

        return res;
    }
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
// void MurmurHash3_x86_32 ( const void * key, int len, uint32_t seed, void * out )
class murmurhash3_x86_32 : public detail::_hash_stream_save_to_buffer_base<murmurhash3_x86_32, 4>
{
private:
    friend class detail::_hash_stream_save_to_buffer_base<murmurhash3_x86_32, 4>;

    using value_type = std::uint32_t;

    constexpr static value_type C1 = 0xcc9e2d51u;
    constexpr static value_type C2 = 0x1b873593u;
    constexpr static value_type BIAS = 0xe6546b64u;
    constexpr static std::size_t MAX_BUFFER_SIZE = 4;

    value_type m_seed = 0;
    value_type m_hash = 0;

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + MAX_BUFFER_SIZE <= input.size(); i += MAX_BUFFER_SIZE)
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type>(input, i);
            k *= C1;
            k = std::rotl(k, 15);
            k *= C2;

            m_hash ^= k;
            m_hash = std::rotl(m_hash, 13);
            m_hash = m_hash * 5 + BIAS;
        }

        return input.subspan(input.size() - input.size() % MAX_BUFFER_SIZE);
    }

public:
    constexpr explicit murmurhash3_x86_32(value_type seed = 0) noexcept : m_seed(seed), m_hash(seed) {}
    constexpr ~murmurhash3_x86_32() noexcept {}

    constexpr hash_result_value<32> result() const noexcept
    {
        hash_result_value<32> res;

        auto hash = m_hash;
        if (this->m_buffer_size > 0)
        {
            std::array<std::uint8_t, MAX_BUFFER_SIZE> buffer{};
            std::copy_n(this->m_buffer.begin(), this->m_buffer_size, buffer.begin());
            auto k = detail::cast_from_bytes<std::uint32_t>(std::span<const std::uint8_t, MAX_BUFFER_SIZE>{buffer});

            k *= C1;
            k = std::rotl(k, 15);
            k *= C2;
            hash ^= k;
        }

        hash ^= static_cast<value_type>(this->m_total_len);
        res.value = detail::murmurhash3_fmix32(hash);

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
struct hash_result<murmurhash2a>
{
    using type = hash_result_value<32>;
};

template <>
struct hash_result<murmurhash3_x86_32>
{
    using type = hash_result_value<32>;
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
