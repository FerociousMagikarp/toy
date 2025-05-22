#pragma once

#include "hash.hpp"

namespace toy
{

// from https://www.ietf.org/rfc/rfc1321.txt
class md5
{
private:
    constexpr static std::array<std::uint32_t, 64> TABLE_T =
    {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    constexpr static std::array<int, 16> TABLE_S =
    {
        7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21,
    };
    constexpr static std::size_t BLOCK_SIZE = 512 / 8;

    std::array<std::uint32_t, 4> m_state =
    {
        std::bit_cast<std::uint32_t>(std::array<std::uint8_t, 4>{0x01, 0x23, 0x45, 0x67}),
        std::bit_cast<std::uint32_t>(std::array<std::uint8_t, 4>{0x89, 0xab, 0xcd, 0xef}),
        std::bit_cast<std::uint32_t>(std::array<std::uint8_t, 4>{0xfe, 0xdc, 0xba, 0x98}),
        std::bit_cast<std::uint32_t>(std::array<std::uint8_t, 4>{0x76, 0x54, 0x32, 0x10}),
    };

    std::array<std::uint8_t, BLOCK_SIZE> m_buffer{};
    std::size_t m_buffer_size = 0;
    std::size_t m_total_len = 0;

    constexpr std::uint32_t func_f(std::uint32_t x, std::uint32_t y, std::uint32_t z) const noexcept
    {
        return (x & y) | (~x & z);
    }

    constexpr std::uint32_t func_g(std::uint32_t x, std::uint32_t y, std::uint32_t z) const noexcept
    {
        return (x & z) | (y & ~z);
    }

    constexpr std::uint32_t func_h(std::uint32_t x, std::uint32_t y, std::uint32_t z) const noexcept
    {
        return x ^ y ^ z;
    }

    constexpr std::uint32_t func_i(std::uint32_t x, std::uint32_t y, std::uint32_t z) const noexcept
    {
        return y ^ (x | ~z);
    }

    constexpr void func_ff(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) const noexcept
    {
        a += func_f(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr void func_gg(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) const noexcept
    {
        a += func_g(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr void func_hh(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) const noexcept
    {
        a += func_h(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr void func_ii(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) const noexcept
    {
        a += func_i(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr void transform(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> state) const noexcept
    {
        std::array<std::uint32_t, 4> st = { state[0], state[1], state[2], state[3] };

        // round 1
        for (std::size_t i = 0; i < 16; i++)
        {
            func_ff(st[(16 - i) & 0x03], st[(17 - i) & 0x03], st[(18 - i) & 0x03], st[(19 - i) & 0x03],
                x[i], TABLE_S[i & 0x03], TABLE_T[i]);
        }

        // round 2
        for (std::size_t i = 0; i < 16; i++)
        {
            func_gg(st[(16 - i) & 0x03], st[(17 - i) & 0x03], st[(18 - i) & 0x03], st[(19 - i) & 0x03],
                x[(i * 5 + 1) & 0x0f], TABLE_S[(i & 0x03) + 4], TABLE_T[i + 16]);
        }

        // round 3
        for (std::size_t i = 0; i < 16; i++)
        {
            func_hh(st[(16 - i) & 0x03], st[(17 - i) & 0x03], st[(18 - i) & 0x03], st[(19 - i) & 0x03],
                x[(i * 3 + 5) & 0x0f], TABLE_S[(i & 0x03) + 8], TABLE_T[i + 32]);
        }

        // round 4
        for (std::size_t i = 0; i < 16; i++)
        {
            func_ii(st[(16 - i) & 0x03], st[(17 - i) & 0x03], st[(18 - i) & 0x03], st[(19 - i) & 0x03],
                x[(i * 7) & 0x0f], TABLE_S[(i & 0x03) + 12], TABLE_T[i + 48]);
        }

        state[0] += st[0];
        state[1] += st[1];
        state[2] += st[2];
        state[3] += st[3];
    }

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input, std::span<std::uint32_t, 4> state) const noexcept
    {
        std::array<std::uint32_t, BLOCK_SIZE / 4> x{};
        while (input.size() >= BLOCK_SIZE)
        {
            for (auto& x_val : x)
            {
                x_val = detail::read_integral<std::uint32_t>(input);
            }

            transform(x, state);
        }
        return input;
    }

public:
    constexpr md5([[maybe_unused]]std::uint64_t seed) noexcept {}
    constexpr ~md5() noexcept {}

    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        if (input.empty())
            return;

        m_total_len += input.size();

        if (m_buffer_size + input.size() < BLOCK_SIZE)
        {
            std::copy(input.begin(), input.end(), m_buffer.begin() + m_buffer_size);
            m_buffer_size += input.size();
            return;
        }

        if (m_buffer_size > 0)
        {
            std::size_t copy_count = BLOCK_SIZE - m_buffer_size;
            std::copy(input.begin(), input.begin() + copy_count, m_buffer.begin() + m_buffer_size);
            input = input.subspan(copy_count);
            consume_long(std::span<const std::uint8_t>(m_buffer), m_state);
            m_buffer_size = 0;
        }

        if (input.size() >= BLOCK_SIZE)
        {
            input = consume_long(input, m_state);
        }

        if (!input.empty())
        {
            std::copy(input.begin(), input.end(), m_buffer.begin());
            m_buffer_size = input.size();
        }
    }

    constexpr hash_result_value<128> result() const noexcept
    {
        hash_result_value<128> res{};

        constexpr std::size_t X_SIZE = BLOCK_SIZE / 4;
        std::array<std::uint32_t, X_SIZE> x{};
        std::array<std::uint8_t, 4> remain{};
        std::span<const std::uint8_t> buffer = m_buffer;
        std::size_t x_front_size = m_buffer_size / 4; // m_buffer_size < BLOCK_SIZE
        for (std::size_t i = 0; i < x.size(); i++)
        {
            if (i >= x_front_size)
                break;
            x[i] = detail::read_integral<std::uint32_t>(buffer);
        }
        std::size_t x_remain = m_buffer_size % 4;
        for (std::size_t i = 0; i < x_remain; i++)
        {
            remain[i] = m_buffer[m_buffer_size - x_remain + i];
        }
        remain[x_remain] = 0x80;
        std::array<std::uint32_t, 4> state = m_state;
        x[x_front_size] = detail::cast_from_bytes<std::uint32_t>(std::span<const std::uint8_t, 4>(remain));

        if (m_buffer_size >= BLOCK_SIZE - 8)
        {
            transform(x, state);
            x.fill(0);
        }

        // use bit count
        x[X_SIZE - 2] = static_cast<std::uint32_t>(static_cast<std::uint64_t>(m_total_len) << 3);
        x[X_SIZE - 1] = static_cast<std::uint32_t>(static_cast<std::uint64_t>(m_total_len) >> 29);

        transform(x, state);

        auto temp_state = std::bit_cast<std::array<std::uint8_t, 16>>(state);
        std::reverse(temp_state.begin(), temp_state.end());

        res.value = std::bit_cast<std::array<std::uint64_t, 2>>(temp_state);

        return res;
    }

};

template <>
struct hash_result<md5>
{
    using type = hash_result_value<128>;
};

} // namespace toy
