// POSIX pax/ustar archives for folder encryption. The writer emits only
// directories and regular files; the reader accepts exactly those (plus pax
// path/size records) and validates every path before touching the disk.
#include "hidfido/age.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>

namespace hidfido::age {
namespace {
namespace fs = std::filesystem;
constexpr std::size_t block = 512;
constexpr std::size_t record = 20 * block;
constexpr std::uint64_t max_octal_size = 077777777777ull;
constexpr std::size_t max_pax_bytes = 1 << 20;
constexpr std::size_t max_path_bytes = 4096;

using Block = std::array<std::uint8_t, block>;

void put_text(Block& header, std::size_t offset, std::size_t length, std::string_view value) {
    if (value.size() > length) throw std::logic_error("tar field overflow");
    std::copy(value.begin(), value.end(), header.begin() + static_cast<std::ptrdiff_t>(offset));
}

void put_octal(Block& header, std::size_t offset, std::size_t length, std::uint64_t value) {
    std::string digits(length - 1, '0');
    for (std::size_t i = digits.size(); i-- > 0 && value;) {
        digits[i] = static_cast<char>('0' + (value & 7));
        value >>= 3;
    }
    if (value) throw std::logic_error("tar numeric field overflow");
    put_text(header, offset, length, digits);  // Trailing NUL already present.
}

std::uint32_t checksum(const Block& header) noexcept {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < block; ++i) sum += (i >= 148 && i < 156) ? ' ' : header[i];
    return sum;
}

void seal_header(Block& header) {
    put_text(header, 257, 6, std::string_view("ustar\0", 6));
    put_text(header, 263, 2, "00");
    const auto sum = checksum(header);
    put_octal(header, 148, 7, sum);
    header[155] = ' ';
}

std::string pax_record(std::string_view key, std::string_view value) {
    // "<length> <key>=<value>\n" where length counts its own digits.
    const auto body = std::string(" ") + std::string(key) + "=" + std::string(value) + "\n";
    auto length = body.size() + 1;
    while (std::to_string(length).size() + body.size() != length) ++length;
    return std::to_string(length) + body;
}

bool plain_ascii(std::string_view text) noexcept {
    return std::ranges::all_of(text, [](char c) { return c >= 0x20 && c < 0x7f; });
}

class Writer {
public:
    explicit Writer(const Sink& sink) : sink_(sink) {}
    void entry(std::string_view path, bool directory, std::uint64_t size, std::uint64_t mtime) {
        std::string pax;
        if (path.size() > 100 || !plain_ascii(path)) pax += pax_record("path", path);
        if (size > max_octal_size) pax += pax_record("size", std::to_string(size));
        if (!pax.empty()) {
            Block extended{};
            put_text(extended, 0, 100, "PaxHeaders/entry");
            put_octal(extended, 100, 8, 0644);
            put_octal(extended, 108, 8, 0);
            put_octal(extended, 116, 8, 0);
            put_octal(extended, 124, 12, pax.size());
            put_octal(extended, 136, 12, mtime);
            extended[156] = 'x';
            seal_header(extended);
            emit(extended);
            emit_data(std::span(reinterpret_cast<const std::uint8_t*>(pax.data()), pax.size()));
            pad(pax.size());
        }
        Block header{};
        const auto fallback = path.size() > 100 || !plain_ascii(path)
            ? std::string(directory ? "long-name/" : "long-name") : std::string(path);
        put_text(header, 0, 100, fallback);
        put_octal(header, 100, 8, directory ? 0755 : 0644);
        put_octal(header, 108, 8, 0);
        put_octal(header, 116, 8, 0);
        put_octal(header, 124, 12, size > max_octal_size ? 0 : size);
        put_octal(header, 136, 12, mtime);
        header[156] = directory ? '5' : '0';
        seal_header(header);
        emit(header);
    }
    void emit_data(std::span<const std::uint8_t> data) {
        sink_(data);
        written_ += data.size();
    }
    void pad(std::uint64_t size) {
        static constexpr Block zeros{};
        const auto remainder = static_cast<std::size_t>(size % block);
        if (remainder) emit_data(std::span(zeros).first(block - remainder));
    }
    void close() {
        static constexpr Block zeros{};
        emit(zeros);
        emit(zeros);
        while (written_ % record) emit(zeros);
    }
private:
    void emit(const Block& data) { emit_data(data); }
    const Sink& sink_;
    std::uint64_t written_{};
};

std::uint64_t unix_time(const fs::file_time_type& time) noexcept {
    try {
        const auto system = std::chrono::clock_cast<std::chrono::system_clock>(time);
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(system.time_since_epoch()).count();
        return seconds > 0 ? static_cast<std::uint64_t>(seconds) : 0;
    } catch (...) {
        return 0;
    }
}

std::string utf8(const fs::path& path) {
    const auto text = path.generic_u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}

bool valid_utf8(std::string_view text) noexcept {
    for (std::size_t i = 0; i < text.size();) {
        const auto c = static_cast<unsigned char>(text[i]);
        std::size_t extra = 0;
        std::uint32_t point = 0;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xe0) == 0xc0) { extra = 1; point = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { extra = 2; point = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { extra = 3; point = c & 0x07; }
        else return false;
        if (i + extra >= text.size()) return false;
        for (std::size_t j = 1; j <= extra; ++j) {
            const auto next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xc0) != 0x80) return false;
            point = (point << 6) | (next & 0x3f);
        }
        if ((extra == 1 && point < 0x80) || (extra == 2 && point < 0x800) || (extra == 3 && point < 0x10000) ||
            point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return false;
        i += extra + 1;
    }
    return true;
}

bool reserved_name(std::string_view segment) noexcept {
    const auto stem = segment.substr(0, segment.find('.'));
    std::string upper;
    for (const char c : stem) upper += (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
    while (!upper.empty() && upper.back() == ' ') upper.pop_back();
    if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || upper == "CONIN$" || upper == "CONOUT$") return true;
    return upper.size() == 4 && (upper.starts_with("COM") || upper.starts_with("LPT")) && upper[3] >= '0' && upper[3] <= '9';
}

class Reader {
public:
    explicit Reader(const Source& source) : source_(source) {}
    bool read_exact(std::span<std::uint8_t> output) {
        std::size_t done = 0;
        while (done < output.size()) {
            const auto count = source_(output.subspan(done));
            if (!count) {
                if (done == 0) return false;
                throw FormatError("Truncated folder archive");
            }
            done += count;
        }
        return true;
    }
    void require(std::span<std::uint8_t> output) {
        if (!read_exact(output)) throw FormatError("Truncated folder archive");
    }
    void skip_padding(std::uint64_t size) {
        Block padding{};
        const auto remainder = static_cast<std::size_t>(size % block);
        if (remainder) require(std::span(padding).first(block - remainder));
    }
    void require_zero_tail() {
        Block data{};
        for (;;) {
            const auto count = source_(data);
            if (!count) return;
            if (!std::all_of(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(count), [](std::uint8_t b) { return b == 0; })) {
                throw FormatError("Unexpected data after the end of the folder archive");
            }
        }
    }
private:
    const Source& source_;
};

std::string field(const Block& header, std::size_t offset, std::size_t length) {
    const auto begin = header.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = std::find(begin, begin + static_cast<std::ptrdiff_t>(length), std::uint8_t{0});
    return {begin, end};
}

std::uint64_t octal(const Block& header, std::size_t offset, std::size_t length) {
    if (header[offset] & 0x80) throw FormatError("Unsupported binary number in folder archive");
    std::uint64_t value = 0;
    bool digits = false;
    for (std::size_t i = offset; i < offset + length; ++i) {
        const auto c = header[i];
        if (c == 0 || c == ' ') { if (digits) break; continue; }
        if (c < '0' || c > '7') throw FormatError("Invalid number in folder archive");
        if (value > (UINT64_MAX >> 3)) throw FormatError("Number too large in folder archive");
        value = (value << 3) | (c - '0');
        digits = true;
    }
    return value;
}

std::map<std::string, std::string> parse_pax(std::string_view data) {
    std::map<std::string, std::string> records;
    while (!data.empty()) {
        const auto space = data.find(' ');
        if (space == std::string_view::npos || space == 0 || space > 7) throw FormatError("Malformed pax record");
        std::size_t length = 0;
        for (const char c : data.substr(0, space)) {
            if (c < '0' || c > '9') throw FormatError("Malformed pax record length");
            length = length * 10 + static_cast<std::size_t>(c - '0');
        }
        if (length <= space + 1 || length > data.size() || data[length - 1] != '\n') throw FormatError("Malformed pax record");
        const auto entry = data.substr(space + 1, length - space - 2);
        const auto equals = entry.find('=');
        if (equals == std::string_view::npos || equals == 0) throw FormatError("Malformed pax record");
        records[std::string(entry.substr(0, equals))] = std::string(entry.substr(equals + 1));
        data.remove_prefix(length);
    }
    return records;
}

std::uint64_t parse_decimal(std::string_view text) {
    if (text.empty() || text.size() > 19) throw FormatError("Invalid pax size");
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') throw FormatError("Invalid pax size");
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return value;
}
}

std::vector<std::string> safe_archive_path(std::string_view path) {
    if (path.empty() || path.size() > max_path_bytes) throw FormatError("Invalid path length in folder archive");
    if (path.front() == '/') throw FormatError("Absolute path in folder archive");
    if (!valid_utf8(path)) throw FormatError("Path in folder archive is not valid UTF-8");
    std::vector<std::string> segments;
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto end = std::min(path.find('/', start), path.size());
        const auto segment = path.substr(start, end - start);
        start = end + 1;
        if (segment.empty() || segment == ".") continue;
        if (segment == "..") throw FormatError("Parent directory reference in folder archive");
        for (const char c : segment) {
            const auto u = static_cast<unsigned char>(c);
            if (u < 0x20 || c == '\\' || c == ':' || c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*') {
                throw FormatError("Path in folder archive is not valid on Windows");
            }
        }
        if (segment.back() == '.' || segment.back() == ' ' || reserved_name(segment)) {
            throw FormatError("Path in folder archive is not valid on Windows");
        }
        segments.emplace_back(segment);
        if (segments.size() > 256) throw FormatError("Path in folder archive is too deep");
    }
    if (segments.empty()) throw FormatError("Empty path in folder archive");
    return segments;
}

ArchiveStats write_tar(const fs::path& folder, const Sink& sink) {
    const auto status = fs::symlink_status(folder);
    if (!fs::is_directory(status) || fs::is_symlink(status)) throw std::invalid_argument("Not a folder");
    auto root = folder.filename();
    if (root.empty()) root = folder.parent_path().filename();
    if (root.empty()) throw std::invalid_argument("Cannot archive a drive root; choose a folder");
    std::vector<fs::path> entries;
    for (auto it = fs::recursive_directory_iterator(folder, fs::directory_options::none); it != fs::recursive_directory_iterator(); ++it) {
        const auto entry_status = it->symlink_status();
        if (fs::is_symlink(entry_status) || (!fs::is_directory(entry_status) && !fs::is_regular_file(entry_status))) {
            throw std::runtime_error("Folder contains a link or special file, which is not supported: " + utf8(it->path()));
        }
        entries.push_back(fs::relative(it->path(), folder));
    }
    std::ranges::sort(entries, [](const fs::path& a, const fs::path& b) { return a.generic_u8string() < b.generic_u8string(); });
    Writer writer(sink);
    ArchiveStats stats;
    const auto root_name = utf8(root);
    (void)safe_archive_path(root_name);
    writer.entry(root_name + "/", true, 0, unix_time(fs::last_write_time(folder)));
    ++stats.directories;
    std::vector<std::uint8_t> buffer(chunk_size);
    for (const auto& relative : entries) {
        const auto full = folder / relative;
        auto name = root_name + "/" + utf8(relative);
        (void)safe_archive_path(name);
        const auto mtime = unix_time(fs::last_write_time(full));
        if (fs::is_directory(fs::symlink_status(full))) {
            writer.entry(name + "/", true, 0, mtime);
            ++stats.directories;
            continue;
        }
        std::ifstream input(full, std::ios::binary);
        if (!input) throw std::runtime_error("Cannot open " + utf8(full));
        const auto size = fs::file_size(full);
        writer.entry(name, false, size, mtime);
        std::uint64_t remaining = size;
        while (remaining) {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(count));
            if (static_cast<std::size_t>(input.gcount()) != count) throw std::runtime_error("File changed while archiving: " + utf8(full));
            writer.emit_data(std::span(buffer).first(count));
            remaining -= count;
        }
        if (input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("File changed while archiving: " + utf8(full));
        writer.pad(size);
        ++stats.files;
        stats.bytes += size;
    }
    wipe(buffer);
    writer.close();
    return stats;
}

ArchiveStats extract_tar(const Source& source, const fs::path& destination) {
    if (!fs::is_directory(fs::symlink_status(destination)) || !fs::is_empty(destination)) {
        throw std::invalid_argument("Extraction folder must exist and be empty");
    }
    Reader reader(source);
    ArchiveStats stats;
    std::map<std::string, std::string> pax;
    std::vector<std::uint8_t> buffer(chunk_size);
    for (;;) {
        Block header{};
        if (!reader.read_exact(header)) throw FormatError("Folder archive has no end marker");
        if (std::all_of(header.begin(), header.end(), [](std::uint8_t b) { return b == 0; })) {
            if (!pax.empty()) throw FormatError("Dangling pax header in folder archive");
            reader.require_zero_tail();
            wipe(buffer);
            return stats;
        }
        const auto stored = octal(header, 148, 8);
        std::uint32_t signed_sum = 0;
        for (std::size_t i = 0; i < block; ++i) {
            signed_sum += (i >= 148 && i < 156) ? ' ' : static_cast<std::uint32_t>(static_cast<std::int8_t>(header[i]));
        }
        if (stored != checksum(header) && stored != signed_sum) throw FormatError("Corrupted folder archive header");
        const auto magic = field(header, 257, 6);
        if (magic != "ustar" && magic != "ustar ") throw FormatError("Unsupported folder archive format");
        const char type = static_cast<char>(header[156]);
        auto size = octal(header, 124, 12);
        if (type == 'x' || type == 'g') {
            if (size > max_pax_bytes) throw FormatError("Oversized pax header in folder archive");
            std::string data(static_cast<std::size_t>(size), '\0');
            reader.require(std::span(reinterpret_cast<std::uint8_t*>(data.data()), data.size()));
            reader.skip_padding(size);
            auto records = parse_pax(data);
            for (const auto& [key, value] : records) {
                if (key.starts_with("GNU.sparse")) throw FormatError("Sparse files are not supported");
            }
            if (type == 'x') pax = std::move(records);
            continue;
        }
        std::string path;
        if (const auto found = pax.find("path"); found != pax.end()) path = found->second;
        else {
            const auto prefix = field(header, 345, 155);
            path = prefix.empty() ? field(header, 0, 100) : prefix + "/" + field(header, 0, 100);
        }
        if (const auto found = pax.find("size"); found != pax.end()) size = parse_decimal(found->second);
        pax.clear();
        const bool directory = type == '5';
        if (!directory && type != '0' && type != '\0' && type != '7') {
            throw FormatError(std::string("Unsupported entry type in folder archive (links and devices are refused): ") + path);
        }
        const auto segments = safe_archive_path(path);
        auto target = destination;
        for (const auto& segment : segments) {
            target /= fs::path(std::u8string(reinterpret_cast<const char8_t*>(segment.data()), segment.size()));
        }
        if (directory) {
            if (size != 0) throw FormatError("Directory entry with data in folder archive");
            if (fs::exists(fs::symlink_status(target)) && !fs::is_directory(fs::symlink_status(target))) {
                throw FormatError("Conflicting entries in folder archive: " + path);
            }
            fs::create_directories(target);
            ++stats.directories;
            continue;
        }
        fs::create_directories(target.parent_path());
        if (fs::exists(fs::symlink_status(target))) throw FormatError("Duplicate entry in folder archive: " + path);
        std::ofstream output(target, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("Cannot create " + utf8(target));
        std::uint64_t remaining = size;
        while (remaining) {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
            reader.require(std::span(buffer).first(count));
            output.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(count));
            if (!output) throw std::runtime_error("Cannot write " + utf8(target));
            remaining -= count;
        }
        output.close();
        if (!output) throw std::runtime_error("Cannot write " + utf8(target));
        reader.skip_padding(size);
        ++stats.files;
        stats.bytes += size;
    }
}
}
