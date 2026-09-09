// Project-level Boost.UUID public-entry harness for RV64/RVV under QEMU.
#define BOOST_UUID_REPORT_IMPLEMENTATION

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>

using boost::uuids::from_chars;
using boost::uuids::from_chars_error;
using boost::uuids::from_chars_result;
using boost::uuids::uuid;

struct Observation {
    std::size_t offset;
    from_chars_error error;
    std::array<std::uint8_t, 16> bytes;
};

template<class Ch>
static Observation parse_public(Ch const* first, std::size_t size) noexcept {
    uuid value{};
    from_chars_result<Ch> result = from_chars(first, first + size, value);

    Observation observation{
        static_cast<std::size_t>(result.ptr - first),
        result.ec,
        {},
    };
    if (result.ec == from_chars_error::none) {
        std::size_t index = 0;
        for (auto byte : value) {
            observation.bytes[index++] = byte;
        }
    }
    return observation;
}

extern "C" __attribute__((noinline, used, flatten))
Observation rax_parse_char(char const* first, std::size_t size) noexcept {
    return parse_public(first, size);
}

extern "C" __attribute__((noinline, used, flatten))
Observation rax_parse_char16(char16_t const* first, std::size_t size) noexcept {
    return parse_public(first, size);
}

extern "C" __attribute__((noinline, used, flatten))
Observation rax_parse_char32(char32_t const* first, std::size_t size) noexcept {
    return parse_public(first, size);
}

struct Case {
    char const* id;
    char const* text;
    std::size_t expected_offset;
    from_chars_error expected_error;
    char const* expected_hex;
};

static constexpr Case CASES[] = {
    {
        "success-lower",
        "00010203-0405-0607-0809-0a0b0c0d0e0f",
        36,
        from_chars_error::none,
        "000102030405060708090a0b0c0d0e0f",
    },
    {
        "success-upper",
        "12345678-90AB-CDEF-1234-567890abcdef",
        36,
        from_chars_error::none,
        "1234567890abcdef1234567890abcdef",
    },
    {
        "success-prefix-extra",
        "00010203-0405-0607-0809-0a0b0c0d0e0f-extra",
        36,
        from_chars_error::none,
        "000102030405060708090a0b0c0d0e0f",
    },
    {
        "eoi-empty",
        "",
        0,
        from_chars_error::unexpected_end_of_input,
        "",
    },
    {
        "eoi-one",
        "0",
        1,
        from_chars_error::unexpected_end_of_input,
        "",
    },
    {
        "eoi-35",
        "01234567-89aB-cDeF-0123-456789AbCdE",
        35,
        from_chars_error::unexpected_end_of_input,
        "",
    },
    {
        "hex-at-zero",
        "G0000000-0000-0000-0000-000000000000",
        0,
        from_chars_error::hex_digit_expected,
        "",
    },
    {
        "hex-at-six",
        "abcdefGh-0000-0000-0000-000000000000",
        6,
        from_chars_error::hex_digit_expected,
        "",
    },
    {
        "hex-at-35",
        "01234567-89aB-cDeF-0123-456789AbCdEG",
        35,
        from_chars_error::hex_digit_expected,
        "",
    },
    {
        "dash-at-8",
        "0000000000000-0000-0000-000000000000",
        8,
        from_chars_error::dash_expected,
        "",
    },
    {
        "dash-at-13",
        "00000000-000000000-0000-000000000000",
        13,
        from_chars_error::dash_expected,
        "",
    },
    {
        "dash-at-18",
        "00000000-0000-000000000-000000000000",
        18,
        from_chars_error::dash_expected,
        "",
    },
    {
        "dash-at-23",
        "00000000-0000-0000-00000000000000000",
        23,
        from_chars_error::dash_expected,
        "",
    },
};

static char const* error_name(from_chars_error error) noexcept {
    switch (error) {
    case from_chars_error::none:
        return "none";
    case from_chars_error::unexpected_end_of_input:
        return "unexpected_end_of_input";
    case from_chars_error::hex_digit_expected:
        return "hex_digit_expected";
    case from_chars_error::dash_expected:
        return "dash_expected";
    case from_chars_error::closing_brace_expected:
        return "closing_brace_expected";
    case from_chars_error::unexpected_extra_input:
        return "unexpected_extra_input";
    }
    return "unknown";
}

static std::string hex_bytes(std::array<std::uint8_t, 16> const& bytes) {
    static constexpr char DIGITS[] = "0123456789abcdef";
    std::string result;
    result.reserve(32);
    for (std::uint8_t byte : bytes) {
        result.push_back(DIGITS[byte >> 4]);
        result.push_back(DIGITS[byte & 15]);
    }
    return result;
}

template<class Ch>
static std::basic_string<Ch> widen_ascii(std::string_view text) {
    std::basic_string<Ch> result;
    result.reserve(text.size());
    for (unsigned char byte : text) {
        result.push_back(static_cast<Ch>(byte));
    }
    return result;
}

static bool observation_matches(
    Case const& test_case,
    Observation const& observation
) {
    std::string actual_hex =
        observation.error == from_chars_error::none
            ? hex_bytes(observation.bytes)
            : std::string{};
    return observation.offset == test_case.expected_offset &&
           observation.error == test_case.expected_error &&
           actual_hex == test_case.expected_hex;
}

static bool report(
    Case const& test_case,
    char const* character_type,
    Observation const& observation
) {
    std::string actual_hex =
        observation.error == from_chars_error::none
            ? hex_bytes(observation.bytes)
            : std::string{};
    bool passed = observation_matches(test_case, observation);

    std::printf(
        "%s\t%s\t%s\t%zu\t%s\t%s\n",
        test_case.id,
        character_type,
        passed ? "pass" : "fail",
        observation.offset,
        error_name(observation.error),
        actual_hex.c_str()
    );
    if (!passed) {
        std::fprintf(
            stderr,
            "case %s/%s: expected offset=%zu error=%s hex=%s\n",
            test_case.id,
            character_type,
            test_case.expected_offset,
            error_name(test_case.expected_error),
            test_case.expected_hex
        );
    }
    return passed;
}

static bool run_case(Case const& test_case) {
    std::string_view text(test_case.text);
    bool passed = true;

    std::string value8(test_case.text);
    passed &= report(
        test_case,
        "char",
        rax_parse_char(value8.data(), value8.size())
    );

    std::u16string value16 = widen_ascii<char16_t>(text);
    passed &= report(
        test_case,
        "char16_t",
        rax_parse_char16(value16.data(), value16.size())
    );

    std::u32string value32 = widen_ascii<char32_t>(text);
    passed &= report(
        test_case,
        "char32_t",
        rax_parse_char32(value32.data(), value32.size())
    );

    return passed;
}

static Case const* find_case(char const* id) noexcept {
    for (Case const& test_case : CASES) {
        if (std::strcmp(test_case.id, id) == 0) {
            return &test_case;
        }
    }
    return nullptr;
}

static std::uint64_t consume(
    std::uint64_t state,
    Observation const& observation
) noexcept {
    state ^= static_cast<std::uint64_t>(observation.offset) +
             0x9e3779b97f4a7c15ULL;
    state = (state << 9) | (state >> (64 - 9));
    state ^= static_cast<std::uint64_t>(observation.error) *
             0xbf58476d1ce4e5b9ULL;
    for (std::uint8_t byte : observation.bytes) {
        state = state * 1099511628211ULL + byte;
    }
    return state;
}

static volatile std::uint64_t BENCHMARK_SINK = 0;

static bool benchmark_case(
    Case const& test_case,
    std::uint64_t iterations
) {
    if (iterations == 0) {
        return false;
    }
    std::string input(test_case.text);
    Observation first = rax_parse_char(input.data(), input.size());
    if (!observation_matches(test_case, first)) {
        return false;
    }

    std::uint64_t sink = consume(0, first);
    constexpr std::uint64_t WARMUP_ITERATIONS = 10000;
    for (std::uint64_t index = 0; index < WARMUP_ITERATIONS; ++index) {
        asm volatile("" : : "r"(input.data()) : "memory");
        sink = consume(
            sink,
            rax_parse_char(input.data(), input.size())
        );
    }

    auto begin = std::chrono::steady_clock::now();
    for (std::uint64_t index = 0; index < iterations; ++index) {
        asm volatile("" : : "r"(input.data()) : "memory");
        sink = consume(
            sink,
            rax_parse_char(input.data(), input.size())
        );
    }
    auto end = std::chrono::steady_clock::now();
    BENCHMARK_SINK = sink;
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end - begin
    ).count();
    if (elapsed <= 0) {
        return false;
    }

    std::printf(
        "BENCH\t%s\tchar\t%llu\t%lld\t%llu\n",
        test_case.id,
        static_cast<unsigned long long>(iterations),
        static_cast<long long>(elapsed),
        static_cast<unsigned long long>(sink)
    );
    return true;
}

static bool parse_iterations(char const* text, std::uint64_t& value) noexcept {
    if (text == nullptr || *text == '\0' || *text == '-') {
        return false;
    }
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(text, &end, 10);
    if (*end != '\0' || parsed == 0 ||
        parsed > std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--probe") == 0) {
        return run_case(CASES[0]) ? 0 : 1;
    }
    if (argc == 4 && std::strcmp(argv[1], "--benchmark") == 0) {
        Case const* test_case = find_case(argv[2]);
        std::uint64_t iterations = 0;
        if (test_case == nullptr || !parse_iterations(argv[3], iterations)) {
            std::fprintf(stderr, "invalid benchmark arguments\n");
            return 2;
        }
        return benchmark_case(*test_case, iterations) ? 0 : 1;
    }
    if (argc != 1) {
        std::fprintf(
            stderr,
            "usage: %s [--probe | --benchmark CASE ITERATIONS]\n",
            argv[0]
        );
        return 2;
    }

    bool passed = true;
    for (Case const& test_case : CASES) {
        passed &= run_case(test_case);
    }
    return passed ? 0 : 1;
}
