#pragma once

#include <algorithm>
#include "hash.hpp"

namespace toy
{
class xxhash64;

namespace detail
{

template <typename T>
concept xxhash_cpt = one_of_cpt<T, xxhash64>;

} // namespace detail

template <detail::xxhash_cpt T>
struct hash_result<T>
{
	template <std::integral I>
	constexpr hash_result(I val) noexcept : m_val(static_cast<T::value_type>(val)) {}
	constexpr ~hash_result() noexcept {}

	friend constexpr bool operator==(const hash_result& left, const hash_result& right) noexcept
	{
		return left.m_val == right.m_val;
	}

	T::value_type m_val;
};

class xxhash64
{
public:
	using value_type = std::uint64_t;

private:
	constexpr static std::array<value_type, 5> PRIMES =
	{
		0x9E3779B185EBCA87ULL,
		0xC2B2AE3D27D4EB4FULL,
		0x165667B19E3779F9ULL,
		0x85EBCA77C2B2AE63ULL,
		0x27D4EB2F165667C5ULL,
	};
	constexpr static std::size_t MAX_BUFFER_SIZE = 32;

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
		acc = std::rotl(acc, 31);
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
		value_type h64 = std::rotl(m_accs[0], 1) + std::rotl(m_accs[1], 7) + std::rotl(m_accs[2], 12) + std::rotl(m_accs[3], 18);
		h64 = merge_round(h64, m_accs[0]);
		h64 = merge_round(h64, m_accs[1]);
		h64 = merge_round(h64, m_accs[2]);
		h64 = merge_round(h64, m_accs[3]);
		return h64;
	}

	constexpr value_type avalanche(value_type hash) const noexcept
	{
		hash ^= hash >> 33;
		hash *= PRIMES[1];
		hash ^= hash >> 29;
		hash *= PRIMES[2];
		hash ^= hash >> 32;
		return hash;
	}

	constexpr value_type finalize(value_type hash, std::span<const std::uint8_t> input) const noexcept
	{
		while (input.size() >= sizeof(std::uint64_t))
		{
			const auto k1 = round(0, detail::read_integral<std::uint64_t>(input));
			hash ^= k1;
			hash = std::rotl(hash, 27) * PRIMES[0] + PRIMES[3];
		}

		if (input.size() >= sizeof(std::uint32_t))
		{
			hash ^= static_cast<std::uint64_t>(detail::read_integral<std::uint32_t>(input)) * PRIMES[0];
			hash = std::rotl(hash, 23) * PRIMES[1] + PRIMES[2];
		}

		while (!input.empty())
		{
			hash ^= static_cast<std::uint64_t>(detail::read_integral<std::uint8_t>(input)) * PRIMES[4];
			hash = std::rotl(hash, 11) * PRIMES[0];
		}

		return avalanche(hash);
	}

	template <detail::byte_char_cpt B>
	constexpr std::span<const B> consume_long(std::span<const B> input) noexcept
	{
		do
		{
			m_accs[0] = round(m_accs[0], detail::read_integral<value_type>(input));
			m_accs[1] = round(m_accs[1], detail::read_integral<value_type>(input));
			m_accs[2] = round(m_accs[2], detail::read_integral<value_type>(input));
			m_accs[3] = round(m_accs[3], detail::read_integral<value_type>(input));
		} while (input.size() >= MAX_BUFFER_SIZE);

		return input;
	}

	constexpr value_type digest(std::span<const std::uint8_t> buffer) const noexcept
	{
		value_type h64 = 0;
		if (m_total_len >= MAX_BUFFER_SIZE)
			h64 = merge_accs();
		else
			h64 = m_accs[2] + PRIMES[4];
		h64 += static_cast<std::uint64_t>(m_total_len);

		return finalize(h64, buffer);
	}

public:
	constexpr explicit xxhash64(value_type seed = 0) noexcept
	{
		init_accs(seed);
	}
	constexpr ~xxhash64() noexcept {}

	template <detail::byte_char_cpt B>
	constexpr void update(std::span<const B> input) noexcept
	{
		if (input.empty())
			return;

		m_total_len += input.size();

		if (m_buffer_size + input.size() < MAX_BUFFER_SIZE)
		{
			std::copy(input.begin(), input.end(), m_buffer.begin() + m_buffer_size);
			m_buffer_size += input.size();
			return;
		}

		if (m_buffer_size > 0)
		{
			std::size_t copy_count = MAX_BUFFER_SIZE - m_buffer_size;
			std::copy(input.begin(), input.begin() + copy_count, m_buffer.begin() + m_buffer_size);
			input = input.subspan(copy_count);
			consume_long(std::span<const std::uint8_t>{m_buffer});
			m_buffer_size = 0;
		}

		if (input.size() >= MAX_BUFFER_SIZE)
		{
			input = consume_long(input);
		}

		if (!input.empty())
		{
			std::copy(input.begin(), input.end(), m_buffer.begin());
			m_buffer_size = input.size();
		}
	}

	constexpr hash_result<xxhash64> result() const noexcept
	{
		return digest(std::span<const std::uint8_t>(m_buffer.begin(), m_buffer.begin() + m_buffer_size));
	}
};

} // namespace toy