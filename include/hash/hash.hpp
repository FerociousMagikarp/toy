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

} // namespace detail

template <typename T>
struct hash_result;

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

    [[nodiscard]] constexpr hash_result<T> result() const noexcept
    {
        return m_val.result();
    }

private:
    T m_val;
};

} // namespace toy
