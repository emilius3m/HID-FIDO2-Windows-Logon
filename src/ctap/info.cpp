#include "hidfido/ctap_info.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace hidfido::ctap {
namespace {
constexpr std::size_t max_response_size = 8192;
constexpr std::uint64_t max_map_entries = 128;
constexpr std::uint64_t max_array_entries = 512;
constexpr unsigned max_depth = 8;

[[noreturn]] void invalid(const char* message) {
    throw std::runtime_error(std::string("CTAP GetInfo: ") + message);
}

void validate_utf8(std::span<const std::uint8_t> value) {
    std::size_t index{};
    while (index < value.size()) {
        const auto first = value[index++];
        if (first <= 0x7f) continue;
        unsigned trailing{};
        std::uint32_t scalar{};
        std::uint32_t minimum{};
        if (first >= 0xc2 && first <= 0xdf) {
            trailing = 1; scalar = first & 0x1fU; minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            trailing = 2; scalar = first & 0x0fU; minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            trailing = 3; scalar = first & 0x07U; minimum = 0x10000;
        } else {
            invalid("invalid UTF-8 text");
        }
        if (trailing > value.size() - index) invalid("truncated UTF-8 text");
        for (unsigned item = 0; item < trailing; ++item) {
            const auto next = value[index++];
            if ((next & 0xc0U) != 0x80U) invalid("invalid UTF-8 continuation");
            scalar = (scalar << 6) | (next & 0x3fU);
        }
        if (scalar < minimum || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff)) invalid("invalid UTF-8 scalar");
    }
}

struct Head {
    std::uint8_t major{};
    std::uint8_t additional{};
    std::uint64_t value{};
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> input) : input_(input) {}

    Head head() {
        if (++items_ > 4096) invalid("too many CBOR items");
        const auto initial = byte();
        Head result{static_cast<std::uint8_t>(initial >> 5),
                    static_cast<std::uint8_t>(initial & 31U), 0};
        if (result.additional < 24) {
            result.value = result.additional;
            return result;
        }
        if (result.additional > 27) invalid("indefinite or reserved CBOR length");
        const auto length = 1U << (result.additional - 24U);
        for (unsigned index = 0; index < length; ++index) {
            result.value = (result.value << 8) | byte();
        }
        if (result.major != 7) {
            if ((length == 1 && result.value < 24) ||
                (length == 2 && result.value <= 0xff) ||
                (length == 4 && result.value <= 0xffff) ||
                (length == 8 && result.value <= 0xffffffffULL)) {
                invalid("nonminimal CBOR integer or length");
            }
        } else if (result.additional == 24 && result.value < 32) {
            invalid("invalid CBOR simple value");
        }
        return result;
    }

    std::uint64_t container(std::uint8_t major, std::uint64_t limit) {
        const auto item = head();
        if (item.major != major) invalid("unexpected CBOR container type");
        if (item.value > limit) invalid("CBOR container exceeds limit");
        return item.value;
    }

    std::uint64_t uint_value() {
        const auto item = head();
        if (item.major != 0) invalid("expected unsigned integer");
        return item.value;
    }

    std::uint32_t uint32_value() {
        const auto value = uint_value();
        if (value > std::numeric_limits<std::uint32_t>::max()) {
            invalid("unsigned integer exceeds 32 bits");
        }
        return static_cast<std::uint32_t>(value);
    }

    std::string text(std::size_t limit = 256) {
        const auto item = head();
        if (item.major != 3) invalid("expected text string");
        if (item.value > limit) invalid("text string exceeds limit");
        const auto value = raw(item.value);
        validate_utf8(value);
        return {reinterpret_cast<const char*>(value.data()), value.size()};
    }

    std::span<const std::uint8_t> bytes() {
        const auto item = head();
        if (item.major != 2) invalid("expected byte string");
        return raw(item.value);
    }

    bool boolean() {
        const auto item = head();
        if (item.major != 7 || (item.additional != 20 && item.additional != 21)) {
            invalid("expected boolean");
        }
        return item.additional == 21;
    }

    void skip(unsigned depth = 1) {
        if (depth > max_depth) invalid("CBOR nesting exceeds limit");
        const auto item = head();
        switch (item.major) {
        case 0:
        case 1:
        case 7:
            return;
        case 2:
            static_cast<void>(raw(item.value));
            return;
        case 3:
            validate_utf8(raw(item.value));
            return;
        case 4:
            if (item.value > max_array_entries) invalid("CBOR array exceeds limit");
            for (std::uint64_t index = 0; index < item.value; ++index) skip(depth + 1);
            return;
        case 5: {
            if (item.value > max_map_entries) invalid("CBOR map exceeds limit");
            std::vector<std::span<const std::uint8_t>> keys;
            keys.reserve(static_cast<std::size_t>(item.value));
            for (std::uint64_t index = 0; index < item.value; ++index) {
                const auto start = position_;
                const auto major = peek() >> 5;
                if (major == 4 || major == 5 || major == 6) {
                    invalid("unsupported complex CBOR map key");
                }
                skip(depth + 1);
                const auto key = input_.subspan(start, position_ - start);
                for (const auto previous : keys) {
                    if (std::ranges::equal(previous, key)) invalid("duplicate CBOR map key");
                }
                keys.push_back(key);
                skip(depth + 1);
            }
            return;
        }
        default:
            invalid("CBOR tags are not permitted by CTAP");
        }
    }

    bool finished() const noexcept { return position_ == input_.size(); }

private:
    std::uint8_t peek() const {
        if (position_ == input_.size()) invalid("truncated CBOR");
        return input_[position_];
    }

    std::uint8_t byte() {
        const auto value = peek();
        ++position_;
        return value;
    }

    std::span<const std::uint8_t> raw(std::uint64_t length) {
        if (length > input_.size() - position_) invalid("truncated CBOR string");
        const auto count = static_cast<std::size_t>(length);
        const auto value = input_.subspan(position_, count);
        position_ += count;
        return value;
    }

    std::span<const std::uint8_t> input_;
    std::size_t position_{};
    std::size_t items_{};
};

std::vector<std::string> string_array(Reader& reader, bool allow_empty) {
    const auto count = reader.container(4, 64);
    if (!allow_empty && count == 0) invalid("required string list is empty");
    std::vector<std::string> values;
    values.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        auto value = reader.text();
        if (value.empty()) invalid("empty capability name");
        if (std::ranges::find(values, value) != values.end()) invalid("duplicate capability name");
        values.push_back(std::move(value));
    }
    return values;
}

void options(Reader& reader, AuthenticatorInfo& result) {
    const auto count = reader.container(5, max_map_entries);
    std::vector<std::string> names;
    names.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        auto name = reader.text();
        if (std::ranges::find(names, name) != names.end()) invalid("duplicate option name");
        const auto value = reader.boolean();
        if (name == "clientPin") result.client_pin = value;
        else if (name == "uv") result.uv = value;
        else if (name == "rk") result.rk = value;
        names.push_back(std::move(name));
    }
}
}

AuthenticatorInfo parse_get_info(std::span<const std::uint8_t> response) {
    if (response.empty()) invalid("missing status byte");
    if (response.size() > max_response_size) invalid("response exceeds 8192 bytes");
    if (response[0] != 0) invalid("authenticator returned nonzero CTAP status");
    Reader reader(response.subspan(1));
    const auto count = reader.container(5, max_map_entries);
    AuthenticatorInfo result;
    std::vector<std::uint64_t> seen;
    seen.reserve(static_cast<std::size_t>(count));
    bool has_aaguid{};
    for (std::uint64_t index = 0; index < count; ++index) {
        const auto key = reader.uint_value();
        if (std::ranges::find(seen, key) != seen.end()) invalid("duplicate GetInfo member");
        seen.push_back(key);
        switch (key) {
        case 1:
            result.versions = string_array(reader, false);
            break;
        case 2:
            result.extensions = string_array(reader, true);
            break;
        case 3: {
            const auto value = reader.bytes();
            if (value.size() != result.aaguid.size()) invalid("AAGUID must contain 16 bytes");
            std::ranges::copy(value, result.aaguid.begin());
            has_aaguid = true;
            break;
        }
        case 4:
            options(reader, result);
            break;
        case 5:
            result.max_msg_size = reader.uint32_value();
            if (*result.max_msg_size == 0) invalid("maxMsgSize must be positive");
            break;
        case 6: {
            const auto protocols = reader.container(4, 64);
            if (protocols == 0) invalid("PIN protocol list must not be empty");
            for (std::uint64_t protocol = 0; protocol < protocols; ++protocol) {
                const auto value = reader.uint32_value();
                if (std::ranges::find(result.pin_protocols, value) != result.pin_protocols.end()) {
                    invalid("duplicate PIN protocol");
                }
                result.pin_protocols.push_back(value);
            }
            break;
        }
        default:
            reader.skip(2);
            break;
        }
    }
    if (!reader.finished()) invalid("trailing bytes after GetInfo map");
    if (result.versions.empty()) invalid("missing required versions member");
    if (!has_aaguid) invalid("missing required AAGUID member");
    result.hmac_secret = std::ranges::find(result.extensions, "hmac-secret") != result.extensions.end();
    return result;
}

}
