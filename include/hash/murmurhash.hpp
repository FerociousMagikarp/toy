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

constexpr std::uint64_t murmurhash3_fmix64(std::uint64_t h) noexcept
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33;

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

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
// void MurmurHash3_x86_32 ( const void * key, int len, uint32_t seed, void * out )
class murmurhash3_x86_128 : public detail::_hash_stream_save_to_buffer_base<murmurhash3_x86_128, 16>
{
private:
    friend class detail::_hash_stream_save_to_buffer_base<murmurhash3_x86_128, 16>;

    using value_type = std::uint32_t;

    constexpr static std::array<value_type, 4> C =
    {
        0x239b961bu,
        0xab0e9789u,
        0x38b34ae5u,
        0xa1e38b93u
    };
    constexpr static std::array<value_type, 4> BIAS = 
    {
        0x561ccd1bu,
        0x0bcaa747u,
        0x96cd1c35u,
        0x32ac3b17u
    };
    constexpr static std::size_t MAX_BUFFER_SIZE = 16;

    value_type m_seed = 0;
    std::array<value_type, 4> m_hash{};

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + MAX_BUFFER_SIZE <= input.size(); i += MAX_BUFFER_SIZE)
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type, 4>(input, i);
            
            k[0] *= C[0];
            k[0] = std::rotl(k[0], 15);
            k[0] *= C[1];
            m_hash[0] ^= k[0];
            m_hash[0] = std::rotl(m_hash[0], 19);
            m_hash[0] += m_hash[1];
            m_hash[0] = m_hash[0] * 5 + BIAS[0];

            k[1] *= C[1];
            k[1] = std::rotl(k[1], 16);
            k[1] *= C[2];
            m_hash[1] ^= k[1];
            m_hash[1] = std::rotl(m_hash[1], 17);
            m_hash[1] += m_hash[2];
            m_hash[1] = m_hash[1] * 5 + BIAS[1];

            k[2] *= C[2];
            k[2] = std::rotl(k[2], 17);
            k[2] *= C[3];
            m_hash[2] ^= k[2];
            m_hash[2] = std::rotl(m_hash[2], 15);
            m_hash[2] += m_hash[3];
            m_hash[2] = m_hash[2] * 5 + BIAS[2];

            k[3] *= C[3];
            k[3] = std::rotl(k[3], 18);
            k[3] *= C[0];
            m_hash[3] ^= k[3];
            m_hash[3] = std::rotl(m_hash[3], 13);
            m_hash[3] += m_hash[0];
            m_hash[3] = m_hash[3] * 5 + BIAS[3];
        }

        return input.subspan(input.size() - input.size() % MAX_BUFFER_SIZE);
    }

public:
    constexpr explicit murmurhash3_x86_128(value_type seed = 0) noexcept : m_seed(seed)
    {
        m_hash.fill(seed);
    }
    constexpr ~murmurhash3_x86_128() noexcept {}

    constexpr hash_result_value<128> result() const noexcept
    {
        hash_result_value<128> res;

        auto hash = m_hash;
        if (this->m_buffer_size > 0)
        {
            std::array<std::uint8_t, MAX_BUFFER_SIZE> buffer{};
            std::copy_n(this->m_buffer.begin(), this->m_buffer_size, buffer.begin());
            auto k = detail::cast_from_bytes<value_type, 4>(std::span<const std::uint8_t, MAX_BUFFER_SIZE>{buffer});

            switch (((this->m_buffer_size - 1) >> 2) & 0x03)
            {
            case 3:
                k[3] *= C[3];
                k[3] = std::rotl(k[3], 18);
                k[3] *= C[0];
                hash[3] ^= k[3];
                [[fallthrough]];
            case 2:
                k[2] *= C[2];
                k[2] = std::rotl(k[2], 17);
                k[2] *= C[3];
                hash[2] ^= k[2];
                [[fallthrough]];
            case 1:
                k[1] *= C[1];
                k[1] = std::rotl(k[1], 16);
                k[1] *= C[2];
                hash[1] ^= k[1];
                [[fallthrough]];
            case 0:
                k[0] *= C[0];
                k[0] = std::rotl(k[0], 15);
                k[0] *= C[1];
                hash[0] ^= k[0];
                break;
            default:
                break;
            }
        }
        hash[0] ^= static_cast<value_type>(this->m_total_len);
        hash[1] ^= static_cast<value_type>(this->m_total_len);
        hash[2] ^= static_cast<value_type>(this->m_total_len);
        hash[3] ^= static_cast<value_type>(this->m_total_len);

        hash[0] += hash[1]; hash[0] += hash[2]; hash[0] += hash[3];
        hash[1] += hash[0]; hash[2] += hash[0]; hash[3] += hash[0];

        hash[0] = detail::murmurhash3_fmix32(hash[0]);
        hash[1] = detail::murmurhash3_fmix32(hash[1]);
        hash[2] = detail::murmurhash3_fmix32(hash[2]);
        hash[3] = detail::murmurhash3_fmix32(hash[3]);

        hash[0] += hash[1]; hash[0] += hash[2]; hash[0] += hash[3];
        hash[1] += hash[0]; hash[2] += hash[0]; hash[3] += hash[0];

        res.value[0] = (static_cast<std::uint64_t>(hash[1]) << 32) | static_cast<std::uint64_t>(hash[0]);
        res.value[1] = (static_cast<std::uint64_t>(hash[3]) << 32) | static_cast<std::uint64_t>(hash[2]);

        return res;
    }
};

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
// void MurmurHash3_x64_128 ( const void * key, int len, uint32_t seed, void * out )
class murmurhash3_x64_128 : public detail::_hash_stream_save_to_buffer_base<murmurhash3_x64_128, 16>
{
private:
    friend class detail::_hash_stream_save_to_buffer_base<murmurhash3_x64_128, 16>;

    using value_type = std::uint64_t;

    constexpr static std::array<value_type, 2> C =
    {
        0x87c37b91114253d5ull,
        0x4cf5ad432745937full
    };
    constexpr static std::array<value_type, 2> BIAS = 
    {
        0x52dce729ull,
        0x38495ab5ull
    };
    constexpr static std::size_t MAX_BUFFER_SIZE = 16;

    value_type m_seed = 0;
    std::array<value_type, 2> m_hash{};

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + MAX_BUFFER_SIZE <= input.size(); i += MAX_BUFFER_SIZE)
        {
            auto k = detail::cast_from_bytes_at_unsafe<value_type, 2>(input, i);
            
            k[0] *= C[0];
            k[0] = std::rotl(k[0], 31);
            k[0] *= C[1];
            m_hash[0] ^= k[0];
            m_hash[0] = std::rotl(m_hash[0], 27);
            m_hash[0] += m_hash[1];
            m_hash[0] = m_hash[0] * 5 + BIAS[0];

            k[1] *= C[1];
            k[1] = std::rotl(k[1], 33);
            k[1] *= C[0];
            m_hash[1] ^= k[1];
            m_hash[1] = std::rotl(m_hash[1], 31);
            m_hash[1] += m_hash[0];
            m_hash[1] = m_hash[1] * 5 + BIAS[1];
        }

        return input.subspan(input.size() - input.size() % MAX_BUFFER_SIZE);
    }

public:
    constexpr explicit murmurhash3_x64_128(value_type seed = 0) noexcept : m_seed(seed)
    {
        m_hash.fill(seed);
    }
    constexpr ~murmurhash3_x64_128() noexcept {}

    constexpr hash_result_value<128> result() const noexcept
    {
        hash_result_value<128> res;

        res.value = m_hash;
        if (this->m_buffer_size > 0)
        {
            std::array<std::uint8_t, MAX_BUFFER_SIZE> buffer{};
            std::copy_n(this->m_buffer.begin(), this->m_buffer_size, buffer.begin());
            auto k = detail::cast_from_bytes<value_type, 2>(std::span<const std::uint8_t, MAX_BUFFER_SIZE>{buffer});

            if (this->m_buffer_size > 8)
            {
                k[1] *= C[1];
                k[1] = std::rotl(k[1], 33);
                k[1] *= C[0];
                res.value[1] ^= k[1];
            }
            k[0] *= C[0];
            k[0] = std::rotl(k[0], 31);
            k[0] *= C[1];
            res.value[0] ^= k[0];
        }
        res.value[0] ^= static_cast<value_type>(this->m_total_len);
        res.value[1] ^= static_cast<value_type>(this->m_total_len);

        res.value[0] += res.value[1];
        res.value[1] += res.value[0];

        res.value[0] = detail::murmurhash3_fmix64(res.value[0]);
        res.value[1] = detail::murmurhash3_fmix64(res.value[1]);

        res.value[0] += res.value[1];
        res.value[1] += res.value[0];

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
struct hash_result<murmurhash3_x86_128>
{
    using type = hash_result_value<128>;
};

template <>
struct hash_result<murmurhash3_x64_128>
{
    using type = hash_result_value<128>;
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
