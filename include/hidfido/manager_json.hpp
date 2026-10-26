#pragma once
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace hidfido::management {
struct Json {
    enum class Kind { null, boolean, number, string, array, object } kind{Kind::null};
    std::uint64_t number{};
    std::string string;
    std::vector<Json> array;
    std::map<std::string, Json, std::less<>> object;
    const Json& at(std::string_view key) const {
        if (kind != Kind::object) throw std::runtime_error("Expected JSON object");
        const auto found = object.find(key);
        if (found == object.end()) throw std::runtime_error("Missing JSON field");
        return found->second;
    }
    const Json* find(std::string_view key) const noexcept {
        const auto found = object.find(key); return found == object.end() ? nullptr : &found->second;
    }
    const std::string& text() const { if (kind != Kind::string) throw std::runtime_error("Expected JSON string"); return string; }
    std::uint64_t integer() const { if (kind != Kind::number) throw std::runtime_error("Expected JSON integer"); return number; }
    bool flag() const { if (kind != Kind::boolean) throw std::runtime_error("Expected JSON boolean"); return number != 0; }
};
class JsonReader {
public:
    explicit JsonReader(std::string_view data) : data_(data) {
        if (data.empty() || data.size() > 1024 * 1024) fail();
    }
    Json parse() { auto result = value(0); space(); if (at_ != data_.size()) fail(); return result; }
private:
    [[noreturn]] static void fail() { throw std::runtime_error("Invalid bounded JSON"); }
    char peek() const { if (at_ == data_.size()) fail(); return data_[at_]; }
    char take() { const auto result = peek(); ++at_; return result; }
    void expect(char c) { if (take() != c) fail(); }
    void space() { while (at_ < data_.size() && (data_[at_] == ' ' || data_[at_] == '\r' || data_[at_] == '\n' || data_[at_] == '\t')) ++at_; }
    void literal(std::string_view s) { for (auto c : s) expect(c); }
    unsigned hex4() {
        unsigned result{};
        for (unsigned i = 0; i < 4; ++i) { const auto c = take(); const unsigned n = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99; if (n > 15) fail(); result = result * 16 + n; }
        return result;
    }
    static void utf8(std::string& out, unsigned c) {
        if (!c || c > 0x10ffff) fail();
        if (c < 0x80) out.push_back(static_cast<char>(c));
        else if (c < 0x800) { out.push_back(static_cast<char>(0xc0 | (c >> 6))); out.push_back(static_cast<char>(0x80 | (c & 63))); }
        else if (c < 0x10000) { out.push_back(static_cast<char>(0xe0 | (c >> 12))); out.push_back(static_cast<char>(0x80 | ((c >> 6) & 63))); out.push_back(static_cast<char>(0x80 | (c & 63))); }
        else { out.push_back(static_cast<char>(0xf0 | (c >> 18))); out.push_back(static_cast<char>(0x80 | ((c >> 12) & 63))); out.push_back(static_cast<char>(0x80 | ((c >> 6) & 63))); out.push_back(static_cast<char>(0x80 | (c & 63))); }
    }
    std::string text() {
        expect('"'); std::string result;
        for (;;) {
            const auto c = static_cast<unsigned char>(take());
            if (c == '"') return result;
            if (c < 32 || result.size() >= 65536) fail();
            if (c != '\\') { result.push_back(static_cast<char>(c)); continue; }
            switch (take()) {
            case '"': result += '"'; break; case '\\': result += '\\'; break; case '/': result += '/'; break;
            case 'n': result += '\n'; break; case 'r': result += '\r'; break; case 't': result += '\t'; break;
            case 'b': result += '\b'; break; case 'f': result += '\f'; break;
            case 'u': { auto c1 = hex4(); if (c1 >= 0xd800 && c1 <= 0xdbff) { expect('\\'); expect('u'); const auto c2 = hex4(); if (c2 < 0xdc00 || c2 > 0xdfff) fail(); c1 = 0x10000 + ((c1 - 0xd800) << 10) + c2 - 0xdc00; } else if (c1 >= 0xdc00 && c1 <= 0xdfff) fail(); utf8(result, c1); break; }
            default: fail();
            }
        }
    }
    Json value(unsigned depth) {
        if (depth > 12 || ++items_ > 20000) fail(); space(); Json out; const auto c = peek();
        if (c == '"') { out.kind = Json::Kind::string; out.string = text(); }
        else if (c == '{') {
            out.kind = Json::Kind::object; ++at_; space(); if (peek() == '}') { ++at_; return out; }
            for (;;) { space(); auto key = text(); space(); expect(':'); if (!out.object.emplace(std::move(key), value(depth + 1)).second) fail(); space(); const auto end = take(); if (end == '}') break; if (end != ',') fail(); }
        } else if (c == '[') {
            out.kind = Json::Kind::array; ++at_; space(); if (peek() == ']') { ++at_; return out; }
            for (;;) { out.array.push_back(value(depth + 1)); space(); const auto end = take(); if (end == ']') break; if (end != ',') fail(); }
        } else if (c >= '0' && c <= '9') {
            out.kind = Json::Kind::number; const bool zero = c == '0';
            do { const auto n = static_cast<unsigned>(take() - '0'); if (out.number > (std::numeric_limits<std::uint64_t>::max() - n) / 10) fail(); out.number = out.number * 10 + n; if (zero) break; } while (at_ < data_.size() && data_[at_] >= '0' && data_[at_] <= '9');
        } else if (c == 'n') literal("null");
        else if (c == 't') { literal("true"); out.kind = Json::Kind::boolean; out.number = 1; }
        else if (c == 'f') { literal("false"); out.kind = Json::Kind::boolean; }
        else fail(); return out;
    }
    std::string_view data_; std::size_t at_{}, items_{};
};
inline Json parse_json(std::string_view data) { return JsonReader(data).parse(); }
inline std::string json_string(std::string_view value) {
    std::string out = "\""; constexpr char digits[] = "0123456789abcdef";
    for (unsigned char c : value) { if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); } else if (c < 32) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; } else out += static_cast<char>(c); }
    return out + '"';
}
}
