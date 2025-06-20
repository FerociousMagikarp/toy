#pragma once

#include <array>
#include "hash.hpp"

namespace toy
{

// from https://github.com/Cyan4973/xxHash

namespace detail
{

struct xxhash32_data
{
    using value_type = std::uint32_t;

    constexpr static std::array<value_type, 5> PRIMES =
    {
        0x9E3779B1U,
        0x85EBCA77U,
        0xC2B2AE3DU,
        0x27D4EB2FU,
        0x165667B1U,
    };
    constexpr static std::size_t MAX_BUFFER_SIZE = 16;
    constexpr static int ROUND_ROT = 13;
    constexpr static std::array<int, 3> AVALANCHE_SHIFT = { 15, 13, 16 };
    constexpr static std::array<int, 4> MERGE_ACC_ROT = { 1, 7, 12, 18 };
};

struct xxhash64_data
{
    using value_type = std::uint64_t;

    constexpr static std::array<value_type, 5> PRIMES =
    {
        0x9E3779B185EBCA87ULL,
        0xC2B2AE3D27D4EB4FULL,
        0x165667B19E3779F9ULL,
        0x85EBCA77C2B2AE63ULL,
        0x27D4EB2F165667C5ULL,
    };
    constexpr static std::size_t MAX_BUFFER_SIZE = 32;
    constexpr static int ROUND_ROT = 31;
    constexpr static std::array<int, 3> AVALANCHE_SHIFT = { 33, 29, 32 };
    constexpr static std::array<int, 4> MERGE_ACC_ROT = { 1, 7, 12, 18 };
};

} // namespace detail

template <int N>
    requires (N == 32 || N == 64)
class xxhash
{
private:
    using data_type = std::conditional_t<N == 32, detail::xxhash32_data, detail::xxhash64_data>;

public:
    using value_type = typename data_type::value_type;

private:
    constexpr static std::array<value_type, 5> PRIMES = data_type::PRIMES;
    constexpr static std::size_t MAX_BUFFER_SIZE = data_type::MAX_BUFFER_SIZE;
    constexpr static int ROUND_ROT = data_type::ROUND_ROT;
    constexpr static std::array<int, 3> AVALANCHE_SHIFT = data_type::AVALANCHE_SHIFT;
    constexpr static std::array<int, 4> MERGE_ACC_ROT = data_type::MERGE_ACC_ROT;

    std::array<value_type, 4> m_accs{};
    std::array<std::uint8_t, MAX_BUFFER_SIZE> m_buffer{};
    std::size_t m_buffer_size = 0;
    std::size_t m_total_len = 0;

    constexpr void init_accs(value_type seed) noexcept
    {
        m_accs[0] = seed + PRIMES[0] + PRIMES[1];
        m_accs[1] = seed + PRIMES[1];
        m_accs[2] = seed + 0;
        m_accs[3] = seed - PRIMES[0];
    }

    constexpr value_type round(value_type acc, value_type input) const noexcept
    {
        acc += input * PRIMES[1];
        acc = std::rotl(acc, ROUND_ROT);
        acc *= PRIMES[0];
        return acc;
    }

    constexpr value_type merge_round(value_type acc, value_type val) const noexcept
    {
        val = round(0, val);
        acc ^= val;
        acc = acc * PRIMES[0] + PRIMES[3];
        return acc;
    }

    constexpr value_type merge_accs() const noexcept
    {
        value_type h = std::rotl(m_accs[0], MERGE_ACC_ROT[0]) + std::rotl(m_accs[1], MERGE_ACC_ROT[1])
            + std::rotl(m_accs[2], MERGE_ACC_ROT[2]) + std::rotl(m_accs[3], MERGE_ACC_ROT[3]);
        if constexpr (N == 64)
        {
            h = merge_round(h, m_accs[0]);
            h = merge_round(h, m_accs[1]);
            h = merge_round(h, m_accs[2]);
            h = merge_round(h, m_accs[3]);
        }
        return h;
    }

    constexpr value_type avalanche(value_type hash) const noexcept
    {
        hash ^= hash >> AVALANCHE_SHIFT[0];
        hash *= PRIMES[1];
        hash ^= hash >> AVALANCHE_SHIFT[1];
        hash *= PRIMES[2];
        hash ^= hash >> AVALANCHE_SHIFT[2];
        return hash;
    }

    constexpr value_type finalize(value_type hash, std::span<const std::uint8_t> input) const noexcept
    {
        constexpr std::size_t UINT32_SIZE = sizeof(std::uint32_t);
        constexpr std::size_t UINT64_SIZE = sizeof(std::uint64_t);
        if constexpr (N == 32)
        {
            for (std::size_t i = 0; i + UINT32_SIZE <= input.size(); i += UINT32_SIZE)
            {
                hash += detail::cast_from_bytes_at_unsafe<std::uint32_t>(input, i) * PRIMES[2];
                hash = std::rotl(hash, 17) * PRIMES[3];
            }

            for (std::size_t i = input.size() - input.size() % UINT32_SIZE; i < input.size(); i++)
            {
                hash += static_cast<value_type>(input[i]) * PRIMES[4];
                hash = std::rotl(hash, 11) * PRIMES[0];
            }
        }
        else if constexpr (N == 64)
        {
            for (std::size_t i = 0; i + UINT64_SIZE <= input.size(); i += UINT64_SIZE)
            {
                const auto k1 = round(0, detail::cast_from_bytes_at_unsafe<std::uint64_t>(input, i));
                hash ^= k1;
                hash = std::rotl(hash, 27) * PRIMES[0] + PRIMES[3];
            }

            if (input.size() % UINT64_SIZE >= UINT32_SIZE)
            {
                std::size_t index = input.size() - input.size() % UINT64_SIZE;
                hash ^= static_cast<value_type>(detail::cast_from_bytes_at_unsafe<std::uint32_t>(input, index)) * PRIMES[0];
                hash = std::rotl(hash, 23) * PRIMES[1] + PRIMES[2];
            }

            for (std::size_t i = input.size() - input.size() % UINT32_SIZE; i < input.size(); i++)
            {
                hash ^= static_cast<value_type>(input[i]) * PRIMES[4];
                hash = std::rotl(hash, 11) * PRIMES[0];
            }
        }
        else
        {
            static_assert(detail::always_false<decltype(N)>);
        }
        return avalanche(hash);
    }

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + MAX_BUFFER_SIZE <= input.size(); i += MAX_BUFFER_SIZE)
        {
            constexpr std::size_t val_size = sizeof(value_type);
            m_accs[0] = round(m_accs[0], detail::cast_from_bytes_at_unsafe<value_type>(input, i));
            m_accs[1] = round(m_accs[1], detail::cast_from_bytes_at_unsafe<value_type>(input, i + val_size));
            m_accs[2] = round(m_accs[2], detail::cast_from_bytes_at_unsafe<value_type>(input, i + val_size * 2));
            m_accs[3] = round(m_accs[3], detail::cast_from_bytes_at_unsafe<value_type>(input, i + val_size * 3));
        }

        return input.subspan(input.size() - input.size() % MAX_BUFFER_SIZE);
    }

    constexpr value_type digest(std::span<const std::uint8_t> buffer) const noexcept
    {
        value_type h = 0;
        if (m_total_len >= MAX_BUFFER_SIZE)
            h = merge_accs();
        else
            h = m_accs[2] + PRIMES[4];
        h += static_cast<value_type>(m_total_len);

        return finalize(h, buffer);
    }

public:
    constexpr explicit xxhash(value_type seed = 0) noexcept
    {
        init_accs(seed);
    }
    constexpr ~xxhash() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        m_total_len += input.size();
        detail::update_buffer(input, m_buffer, m_buffer_size, [this]<detail::byte_char_cpt T>(std::span<const T> val) -> std::span<const T>
        {
            return this->consume_long(val);
        });
    }

    constexpr hash_result_value<N> result() const noexcept
    {
        hash_result_value<N> res;
        value_type val = digest(std::span<const std::uint8_t>(m_buffer.begin(), m_buffer.begin() + m_buffer_size));
        res.value = val;
        return res;
    }
};

template <int N>
struct hash_result<xxhash<N>>
{
    using type = hash_result_value<N>;
};

using xxhash32 = xxhash<32>;
using xxhash64 = xxhash<64>;

} // namespace toy