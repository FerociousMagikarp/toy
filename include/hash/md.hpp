#pragma once

#include "hash.hpp"

namespace toy
{
namespace detail
{
template <typename Derived>
class md_base
{
protected:
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

    template <byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept;

public:
    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept;

    constexpr hash_result_value<128> result() const noexcept;
};

} // namespace detail

// from https://www.ietf.org/rfc/rfc1319.txt
class md2
{
private:
    constexpr static std::array<std::uint8_t, 256> PI_SUBST =
    {
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
        19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
        76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
        138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
        245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
        148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
        39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
        181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
        150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
        112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
        96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
        85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
        234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
        129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
        8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
        203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
        166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
        31, 26, 219, 153, 141, 51, 159, 17, 131, 20
    };

    constexpr static std::size_t BLOCK_SIZE = 16;
    constexpr static std::size_t X_SIZE = 48;

    std::array<std::uint8_t, BLOCK_SIZE> m_buffer{};
    std::size_t m_buffer_size = 0;
    std::array<std::uint8_t, X_SIZE> m_x{};
    std::array<std::uint8_t, BLOCK_SIZE> m_checksum{};

    constexpr static void transform_x(std::uint8_t& t, std::uint8_t i, std::span<std::uint8_t, X_SIZE> x) noexcept
    {
        for (std::uint8_t& x_val : x)
        {
            x_val = x_val ^ PI_SUBST[t];
            t = x_val;
        }
        t += i;
    }

    template <detail::byte_char_cpt B>
    constexpr void transform(std::span<const B, BLOCK_SIZE> input, std::span<std::uint8_t, X_SIZE> x) const noexcept
    {
        for (std::size_t i = 0; i < BLOCK_SIZE; i++)
        {
            x[16 + i] = static_cast<std::uint8_t>(input[i]);
            x[32 + i] = x[16 + i] ^ x[i];
        }

        constexpr std::uint8_t ROUND_COUNT = 18;
        [x] <std::size_t... Index>(std::index_sequence<Index...>) -> void
        {
            std::uint8_t t = 0;
            (transform_x(t, static_cast<std::uint8_t>(Index), x), ...);
        }(std::make_index_sequence<ROUND_COUNT>{});
    }

    template <detail::byte_char_cpt B>
    constexpr void make_checksum(std::span<const B, BLOCK_SIZE> input, std::span<std::uint8_t, BLOCK_SIZE> checksum) const noexcept
    {
        std::uint8_t l = checksum.back();

        for (std::size_t i = 0; i < BLOCK_SIZE; i++)
        {
            auto c = static_cast<std::uint8_t>(input[i]);
            checksum[i] ^= PI_SUBST[c ^ l];
            l = checksum[i];
        }
    }

    template <detail::byte_char_cpt B>
    constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
    {
        for (std::size_t i = 0; i + BLOCK_SIZE <= input.size(); i += BLOCK_SIZE)
        {
            auto block = std::span<const B, BLOCK_SIZE>(input.data() + i, BLOCK_SIZE);

            make_checksum(block, m_checksum);
            transform(block, m_x);
        }

        return input.subspan(input.size() - input.size() % BLOCK_SIZE);
    }

public:
    template <detail::byte_char_cpt B>
    constexpr void update(std::span<const B> input) noexcept
    {
        detail::update_buffer(input, m_buffer, m_buffer_size, [this]<detail::byte_char_cpt T>(std::span<const T> val) -> std::span<const T>
        {
            return this->consume_long(val);
        });
    }

    constexpr hash_result_value<128> result() const noexcept
    {
        hash_result_value<128> res{};

        std::array<std::uint8_t, X_SIZE> x_copy = m_x;
        std::array<std::uint8_t, BLOCK_SIZE * 2> data{};
        std::copy(m_buffer.begin(), m_buffer.begin() + m_buffer_size, data.begin());
        std::fill(data.begin() + m_buffer_size, data.begin() + BLOCK_SIZE, static_cast<std::uint8_t>(BLOCK_SIZE - m_buffer_size));
        std::copy(m_checksum.begin(), m_checksum.end(), data.begin() + BLOCK_SIZE);

        make_checksum(std::span<const std::uint8_t, BLOCK_SIZE>(data.cbegin(), data.cbegin() + BLOCK_SIZE),
            std::span<std::uint8_t, BLOCK_SIZE>(data.begin() + BLOCK_SIZE, data.end()));
        transform(std::span<const std::uint8_t, BLOCK_SIZE>(data.cbegin(), data.cbegin() + BLOCK_SIZE), x_copy);
        transform(std::span<const std::uint8_t, BLOCK_SIZE>(data.cbegin() + BLOCK_SIZE, data.cend()), x_copy);

        std::array<std::uint8_t, 16> res_val{};
        std::copy(x_copy.begin(), x_copy.begin() + 16, res_val.begin());
        std::reverse(res_val.begin(), res_val.end());
        res.value = std::bit_cast<std::array<std::uint64_t, 2>>(res_val);

        return res;
    }
};

// from https://www.ietf.org/rfc/rfc1320.txt
class md4 : public detail::md_base<md4>
{
    friend class detail::md_base<md4>;
private:
    constexpr static std::array<int, 12> TABLE_S =
    {
        3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15,
    };

    constexpr static std::uint32_t func_f(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & y) | (~x & z);
    }

    constexpr static std::uint32_t func_g(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & y) | (x & z) | (y & z);
    }

    constexpr static std::uint32_t func_h(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return x ^ y ^ z;
    }

    constexpr static void func_ff(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s) noexcept
    {
        a += func_f(b, c, d) + x;
        a = std::rotl(a, s);
    }

    constexpr static void func_gg(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s) noexcept
    {
        a += func_g(b, c, d) + x + 0x5a827999u;
        a = std::rotl(a, s);
    }

    constexpr static void func_hh(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s) noexcept
    {
        a += func_h(b, c, d) + x + 0x6ed9eba1u;
        a = std::rotl(a, s);
    }

    template <std::uint8_t Index>
    constexpr void transform_round_2(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        func_gg(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
            x[(Index * 4) % 16 + Index / 4], TABLE_S[Index % 4 + 4]);
        if constexpr (Index < 15)
            transform_round_2<Index + 1>(x, st);
    }

    template <std::uint8_t Index>
    constexpr void transform_round_3(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        constexpr std::uint8_t X_INDEX_TEMP = ((Index >> 1) & 0x05) | ((Index & 0x05) << 1);
        constexpr std::uint8_t X_INDEX = ((X_INDEX_TEMP >> 2) & 0x03) | ((X_INDEX_TEMP & 0x03) << 2);
        func_hh(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
            x[X_INDEX], TABLE_S[Index % 4 + 8]);
        if constexpr (Index < 15)
            transform_round_3<Index + 1>(x, st);
    }

    constexpr void transform_round_1(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_ff(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[Index], TABLE_S[Index % 4]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform_round_2(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_gg(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[(Index * 4) % 16 + Index / 4], TABLE_S[Index % 4 + 4]), ...);
        }(std::make_index_sequence<16>{});
    }

    consteval static std::size_t get_transform_round_3_x_index(std::size_t index) noexcept
    {
        index = ((index >> 1) & 0x05) | ((index & 0x05) << 1);
        return ((index >> 2) & 0x03) | ((index & 0x03) << 2);
    }

    constexpr void transform_round_3(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_hh(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[get_transform_round_3_x_index(Index)], TABLE_S[Index % 4 + 8]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> state) const noexcept
    {
        std::array<std::uint32_t, 4> st = { state[0], state[1], state[2], state[3] };

        transform_round_1(x, st);
        transform_round_2(x, st);
        transform_round_3(x, st);

        state[0] += st[0];
        state[1] += st[1];
        state[2] += st[2];
        state[3] += st[3];
    }

public:
    constexpr md4() noexcept {}
    constexpr ~md4() noexcept {}
};

// from https://www.ietf.org/rfc/rfc1321.txt
class md5 : public detail::md_base<md5>
{
    friend class detail::md_base<md5>;
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

    constexpr static std::uint32_t func_f(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & y) | (~x & z);
    }

    constexpr static std::uint32_t func_g(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & z) | (y & ~z);
    }

    constexpr static std::uint32_t func_h(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return x ^ y ^ z;
    }

    constexpr static std::uint32_t func_i(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return y ^ (x | ~z);
    }

    constexpr static void func_ff(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) noexcept
    {
        a += func_f(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr static void func_gg(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) noexcept
    {
        a += func_g(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr static void func_hh(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) noexcept
    {
        a += func_h(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr static void func_ii(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, int s, std::uint32_t ac) noexcept
    {
        a += func_i(b, c, d) + x + ac;
        a = std::rotl(a, s);
        a += b;
    }

    constexpr void transform_round_1(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_ff(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[Index], TABLE_S[Index % 4], TABLE_T[Index]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform_round_2(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_gg(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[(Index * 5 + 1) % 16], TABLE_S[Index % 4 + 4], TABLE_T[Index + 16]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform_round_3(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_hh(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[(Index * 3 + 5) % 16], TABLE_S[Index % 4 + 8], TABLE_T[Index + 32]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform_round_4(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> st) const noexcept
    {
        [x, st] <std::size_t... Index> (std::index_sequence<Index...>) -> void
        {
            (func_ii(st[(16 - Index) % 4], st[(17 - Index) % 4], st[(18 - Index) % 4], st[(19 - Index) % 4],
                x[(Index * 7) % 16], TABLE_S[Index % 4 + 12], TABLE_T[Index + 48]), ...);
        }(std::make_index_sequence<16>{});
    }

    constexpr void transform(std::span<const std::uint32_t, 16> x, std::span<std::uint32_t, 4> state) const noexcept
    {
        std::array<std::uint32_t, 4> st = { state[0], state[1], state[2], state[3] };

        transform_round_1(x, st);
        transform_round_2(x, st);
        transform_round_3(x, st);
        transform_round_4(x, st);

        state[0] += st[0];
        state[1] += st[1];
        state[2] += st[2];
        state[3] += st[3];
    }

public:
    constexpr md5() noexcept {}
    constexpr ~md5() noexcept {}
};

namespace detail
{
template <typename Derived>
template <byte_char_cpt B>
constexpr std::span<const B> md_base<Derived>::consume_long(std::span<const B> input) noexcept
{
    for (std::size_t i = 0; i + BLOCK_SIZE <= input.size(); i += BLOCK_SIZE)
    {
        auto x = detail::cast_from_bytes_at_unsafe<std::uint32_t, BLOCK_SIZE / 4>(input, i);
        static_cast<const Derived*>(this)->transform(x, m_state);
    }
    return input.subspan(input.size() - input.size() % BLOCK_SIZE);
}

template <typename Derived>
template <detail::byte_char_cpt B>
constexpr void md_base<Derived>::update(std::span<const B> input) noexcept
{
    m_total_len += input.size();
    detail::update_buffer(input, m_buffer, m_buffer_size, [this]<detail::byte_char_cpt T>(std::span<const T> val) ->std::span<const T>
    {
        return this->consume_long(val);
    });
}

template <typename Derived>
constexpr hash_result_value<128> md_base<Derived>::result() const noexcept
{
    hash_result_value<128> res{};

    constexpr std::size_t X_SIZE = BLOCK_SIZE / 4;
    std::array<std::uint8_t, 4> remain{};
    std::size_t x_front_size = m_buffer_size / 4; // m_buffer_size < BLOCK_SIZE
    std::array<std::uint32_t, X_SIZE> x = cast_from_bytes<std::uint32_t, X_SIZE>(std::span<const std::uint8_t, BLOCK_SIZE>(m_buffer));
    std::fill(x.begin() + x_front_size, x.end(), 0);

    std::size_t x_remain = m_buffer_size % 4;
    for (std::size_t i = 0; i < x_remain; i++)
    {
        remain[i] = m_buffer[m_buffer_size - x_remain + i];
    }
    remain[x_remain] = 0x80;
    std::array<std::uint32_t, 4> state = m_state;
    x[x_front_size] = cast_from_bytes<std::uint32_t>(std::span<const std::uint8_t, 4>(remain));

    if (m_buffer_size >= BLOCK_SIZE - 8)
    {
        static_cast<const Derived*>(this)->transform(x, state);
        x.fill(0);
    }

    // use bit count
    x[X_SIZE - 2] = static_cast<std::uint32_t>(static_cast<std::uint64_t>(m_total_len) << 3);
    x[X_SIZE - 1] = static_cast<std::uint32_t>(static_cast<std::uint64_t>(m_total_len) >> 29);

    static_cast<const Derived*>(this)->transform(x, state);

    auto temp_state = std::bit_cast<std::array<std::uint8_t, 16>>(state);
    std::reverse(temp_state.begin(), temp_state.end());

    res.value = std::bit_cast<std::array<std::uint64_t, 2>>(temp_state);

    return res;
}

} // namespace detail

template <>
struct hash_result<md2>
{
    using type = hash_result_value<128>;
};

template <>
struct hash_result<md4>
{
    using type = hash_result_value<128>;
};

template <>
struct hash_result<md5>
{
    using type = hash_result_value<128>;
};

} // namespace toy
