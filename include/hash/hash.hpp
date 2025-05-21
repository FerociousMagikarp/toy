#pragma once

#include <concepts>
#include <span>
#include <string_view>
#include <bit>

namespace toy
{

namespace detail
{
template <typename T, typename... Args>
concept one_of_cpt = (std::same_as<Args, T> || ...);

template <typename T>
concept byte_char_cpt = one_of_cpt<T, char, unsigned char, std::byte, std::int8_t, std::uint8_t, char8_t>;

template <std::unsigned_integral T, byte_char_cpt B>
constexpr T cast_from_bytes(std::span<const B, sizeof(T)> val) noexcept
{
    return[val]<std::size_t... Idx>(std::index_sequence<Idx...>) -> T
    {
        if constexpr (std::endian::native == std::endian::little)
            return static_cast<T>(((static_cast<T>(val[Idx]) << (Idx * 8)) | ...));
        else
            return static_cast<T>(((static_cast<T>(val[Idx]) << ((sizeof(T) - 1 - Idx) * 8)) | ...));
    } (std::make_index_sequence<sizeof(T)>());
}

template <std::unsigned_integral T, byte_char_cpt B>
constexpr T read_integral(std::span<const B>& val) noexcept
{
    constexpr auto SIZE_OF_T = sizeof(T);
    const auto res = cast_from_bytes<T>(val.template first<SIZE_OF_T>());
    val = val.subspan(SIZE_OF_T);
    return res;
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
    constexpr explicit hash(std::uint64_t seed = 0) noexcept : m_val(seed) {}
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
