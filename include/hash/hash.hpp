#pragma once

#include <concepts>
#include <span>
#include <string>
#include <string_view>
#include <charconv>
#include <algorithm>
#include <bit>

namespace toy
{

namespace detail
{
template <typename T, typename... Args>
concept one_of_cpt = (std::same_as<Args, T> || ...);

template <typename T>
concept byte_char_cpt = one_of_cpt<T, char, unsigned char, std::byte, std::int8_t, std::uint8_t, char8_t>;

template <class... T>
constexpr bool always_false = false;

template <std::unsigned_integral T, byte_char_cpt B>
constexpr T cast_from_bytes(std::span<const B, sizeof(T)> val) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
    {
        std::array<B, sizeof(T)> arr;
        std::copy(val.begin(), val.end(), arr.begin());
        return std::bit_cast<T>(arr);
    }
    else
    {
        return[val]<std::size_t... Idx>(std::index_sequence<Idx...>) -> T
        {
            return static_cast<T>(((static_cast<T>(val[Idx]) << ((sizeof(T) - 1 - Idx) * 8)) | ...));
        } (std::make_index_sequence<sizeof(T)>());
    }
}

template <std::unsigned_integral T, std::size_t N, byte_char_cpt B>
constexpr std::array<T, N> cast_from_bytes(std::span<const B, sizeof(T) * N> val) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
    {
        std::array<B, sizeof(T) * N> arr;
        std::copy(val.begin(), val.end(), arr.begin());
        return std::bit_cast<std::array<T, N>>(arr);
    }
    else
    {
        std::array<T, N> res{};
        std::span<const B> data = val;
        for (std::size_t i = 0; i < N; i++)
        {
            res[i] = cast_from_bytes<T>(data.template first<sizeof(T)>());
            data = data.subspan(sizeof(T));
        }
        return res;
    }
}

template <std::unsigned_integral T, byte_char_cpt B>
constexpr T cast_from_bytes_at_unsafe(std::span<const B> val, std::size_t index) noexcept
{
    return cast_from_bytes<T>(std::span<const B, sizeof(T)>(val.data() + index, sizeof(T)));
}

template <std::unsigned_integral T, std::size_t N, byte_char_cpt B>
constexpr std::array<T, N> cast_from_bytes_at_unsafe(std::span<const B> val, std::size_t index) noexcept
{
    return cast_from_bytes<T, N>(std::span<const B, sizeof(T) * N>(val.data() + index, sizeof(T) * N));
}

template <byte_char_cpt B, std::size_t MAX_BUFFER_SIZE, typename F>
constexpr void update_buffer(std::span<const B> input, std::array<std::uint8_t, MAX_BUFFER_SIZE>& buffer, std::size_t& buffer_size, F&& consume_func) noexcept
{
    if (input.empty())
        return;

    if (buffer_size + input.size() < MAX_BUFFER_SIZE)
    {
        std::copy(input.begin(), input.end(), buffer.begin() + buffer_size);
        buffer_size += input.size();
        return;
    }

    if (buffer_size > 0)
    {
        std::size_t copy_count = MAX_BUFFER_SIZE - buffer_size;
        std::copy(input.begin(), input.begin() + copy_count, buffer.begin() + buffer_size);
        input = input.subspan(copy_count);
        consume_func(std::span<const std::uint8_t>{buffer});
        buffer_size = 0;
    }

    if (input.size() >= MAX_BUFFER_SIZE)
    {
        input = consume_func(input);
    }

    if (!input.empty())
    {
        std::copy(input.begin(), input.end(), buffer.begin());
        buffer_size = input.size();
    }
}

template<std::size_t N> struct _hash_result_base;
template<> struct _hash_result_base<8>{ using type = std::uint8_t; };
template<> struct _hash_result_base<16>{ using type = std::uint16_t; };
template<> struct _hash_result_base<32>{ using type = std::uint32_t; };
template<> struct _hash_result_base<64>{ using type = std::uint64_t; };

consteval std::size_t _get_base_bit(std::size_t N)
{
    if (N % 64 == 0) return 64;
    else if (N % 32 == 0) return 32;
    else if (N % 16 == 0) return 16;
    else return 8;
}

} // namespace detail

template <std::size_t N>
    requires (N % 32 == 0 && N > 0)
struct hash_result_value
{
    constexpr static std::size_t base_bit = detail::_get_base_bit(N);
    constexpr static std::size_t count = N / base_bit;
    using base_type = typename detail::_hash_result_base<base_bit>::type;
    // std::bitset ???
    using value_type = std::conditional_t<count == 1, base_type, std::array<base_type, count>>;

    value_type value{};

    friend constexpr bool operator==(const hash_result_value& lhs, const hash_result_value& rhs)
    {
        return lhs.value == rhs.value;
    }

    std::string to_hexstring() const
    {
        std::string res(N / 4, '0');
        constexpr std::size_t base_char_count = base_bit / 4;
        using iter_t = typename std::string::iterator;
        std::string temp(base_char_count, '1');
        auto copy_to_res_func = [&temp, this](iter_t res_begin, base_type val) -> void
        {
            auto result = std::to_chars(temp.data(), temp.data() + temp.size(), val, 16);
            std::size_t size = result.ptr - temp.data();
            std::copy(temp.begin(), temp.begin() + size, res_begin + (temp.size() - size));
        };
        if constexpr (count == 1)
        {
            copy_to_res_func(res.begin(), value);
        }
        else
        {
            for (std::size_t i = 0; i < count; i++)
            {
                auto iter = res.begin() + (res.size() - (i + 1) * base_char_count);
                copy_to_res_func(iter, value[i]);
            }
        }
        return res;
    }
};


namespace detail
{
template <std::size_t N>
constexpr void _hash_result_value_append(hash_result_value<N>& res, typename hash_result_value<N>::base_type val)
{
    using type = hash_result_value<N>;

    if constexpr (type::count == 1)
    {
        res.value += val;
    }
    else
    {
        res.value[0] += val;
        if (res.value[0] < val)
        {
            for (std::size_t i = 1; i < type::count; i++)
            {
                res.value[i] += 1;
                if (res.value[i] != 0)
                    break;
            }
        }
    }
}

template <std::size_t N>
constexpr void _hash_result_value_shift_left(hash_result_value<N>& res, int val);

template <std::size_t N>
constexpr void _hash_result_value_shift_right(hash_result_value<N>& res, int val);

template <std::size_t N>
constexpr void _hash_result_value_shift_left(hash_result_value<N>& res, int val)
{
    if (val == 0)
        return;
    if (val < 0)
        _hash_result_value_shift_right(res, -val);

    using type = hash_result_value<N>;
    constexpr std::size_t base_bit = type::base_bit;

    if constexpr (type::count == 1)
    {
        res.value <<= val;
    }
    else
    {
        const auto quotient = static_cast<std::size_t>(val) / base_bit;
        const auto remainder = static_cast<std::size_t>(val) % base_bit;

        for (std::size_t i = type::count - 1; i > quotient; i--)
            res.value[i] = (res.value[i - quotient] << remainder) | (res.value[i - quotient - 1] >> (base_bit - remainder));
        res.value[quotient] = res.value[0] << remainder;
        for (std::size_t i = 0; i < quotient; i++)
            res.value[i] = 0;
    }
}

template <std::size_t N>
constexpr void _hash_result_value_shift_right(hash_result_value<N>& res, int val)
{
    if (val == 0)
        return;
    if (val < 0)
        _hash_result_value_shift_left(res, -val);

    using type = hash_result_value<N>;
    constexpr auto base_bit = type::base_bit;

    if constexpr (type::count == 1)
    {
        res.value >>= val;
    }
    else
    {
        const auto quotient = static_cast<std::size_t>(val) / base_bit;
        const auto remainder = static_cast<std::size_t>(val) % base_bit;

        for (std::size_t i = 0; i < type::count - quotient - 1; i++)
            res.value[i] = (res.value[i + quotient] >> remainder) | (res.value[i + quotient + 1] << (base_bit - remainder));
        res.value[type::count - quotient - 1] = res.value.back() >> remainder;
        for (std::size_t i = type::count - quotient; i < type::count; i++)
            res.value[i] = 0;
    }
}

template <std::size_t N>
consteval hash_result_value<N> _set_result_value_hex_val(std::string_view val)
{
    using base_type = typename hash_result_value<N>::base_type;
    hash_result_value<N> res;

    for (const char c : val)
    {
        _hash_result_value_shift_left(res, 4);
        if (c >= '0' && c <= '9')
            _hash_result_value_append(res, static_cast<base_type>(c - '0'));
        else if (c >= 'a' && c <= 'f')
            _hash_result_value_append(res, static_cast<base_type>(c - 'a' + 10));
        else if (c >= 'A' && c <= 'F')
            _hash_result_value_append(res, static_cast<base_type>(c - 'A' + 10));
        else
            throw "Unexpected character.";
    }

    return res;
}

} // namespace detail

inline namespace literals
{

inline namespace hash_literals
{

consteval hash_result_value<32> operator ""_hash_hex_32(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<32>(std::string_view{ str, len });
}

consteval hash_result_value<64> operator ""_hash_hex_64(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<64>(std::string_view{ str, len });
}

consteval hash_result_value<128> operator ""_hash_hex_128(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<128>(std::string_view{ str, len });
}

consteval hash_result_value<160> operator ""_hash_hex_160(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<160>(std::string_view{ str, len });
}

consteval hash_result_value<224> operator ""_hash_hex_224(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<224>(std::string_view{ str, len });
}

consteval hash_result_value<256> operator ""_hash_hex_256(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<256>(std::string_view{ str, len });
}

consteval hash_result_value<384> operator ""_hash_hex_384(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<384>(std::string_view{ str, len });
}

consteval hash_result_value<512> operator ""_hash_hex_512(const char* str, std::size_t len)
{
    return detail::_set_result_value_hex_val<512>(std::string_view{ str, len });
}


} // namespace hash_literals

} // namespace literals

template <typename T>
struct hash_result;

template <typename T>
using hash_result_t = typename hash_result<T>::type;

template <typename T>
class hash
{
public:
    template <typename... Args>
        requires std::is_constructible_v<T, Args...>
    constexpr explicit hash(Args&&... args) noexcept : m_val(std::forward<Args>(args)...) {}
    constexpr ~hash() noexcept {}

    constexpr hash& update(std::string_view s) noexcept
    {
        m_val.update(std::span<const char>(s.data(), s.size()));
        return *this;
    }

    constexpr hash& update(std::u8string_view s) noexcept
    {
        m_val.update(std::span<const char8_t>(s.data(), s.size()));
        return *this;
    }

    [[nodiscard]] constexpr hash_result_t<T> result() const noexcept
    {
        return m_val.result();
    }

private:
    T m_val;
};

} // namespace toy
