// Profiles, output naming and complete file/folder operations on top of the
// age core. Results are always written under a temporary name and moved into
// place only after the whole operation succeeded and was authenticated.
#include "hidfido/age_files.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace hidfido::age::files {
namespace {
std::string trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    return std::string(text.substr(begin, text.find_last_not_of(" \t\r\n") - begin + 1));
}

bool ends_with_ci(std::u8string_view text, std::u8string_view suffix) noexcept {
    if (text.size() < suffix.size()) return false;
    const auto tail = text.substr(text.size() - suffix.size());
    return std::equal(tail.begin(), tail.end(), suffix.begin(), [](char8_t a, char8_t b) {
        const auto lower = [](char8_t c) { return c >= u8'A' && c <= u8'Z' ? static_cast<char8_t>(c - u8'A' + u8'a') : c; };
        return lower(a) == lower(b);
    });
}

std::string random_suffix() {
    std::array<std::uint8_t, 6> random{};
    random_bytes(random);
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : random) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}

fs::path absolute_input(const fs::path& input) {
    auto path = fs::absolute(input).lexically_normal();
    if (path.filename().empty()) path = path.parent_path();
    return path;
}

bool taken(const fs::path& path) {
    std::error_code error;
    return fs::exists(fs::symlink_status(path, error));
}

fs::path claim(const fs::path& wanted, bool rename_if_exists) {
    if (!taken(wanted)) return wanted;
    if (!rename_if_exists) throw Error(Problem::output_exists, wanted);
    return available_name(wanted);
}

void check_continue(const Observer& observer) {
    if (observer.keep_going && !observer.keep_going()) throw Error(Problem::cancelled);
}

void report(const Observer& observer, std::uint64_t done, std::uint64_t total) {
    if (observer.progress) observer.progress(total ? (std::min)(done, total) : done, total);
}

// A file written under a temporary name; removed unless committed.
class PendingFile {
public:
    explicit PendingFile(fs::path target) : target_(std::move(target)) {
        temporary_ = target_;
        temporary_ += ".partial-" + random_suffix();
        stream_.open(temporary_, std::ios::binary | std::ios::trunc);
        if (!stream_) throw Error(Problem::write_failed, temporary_);
    }
    ~PendingFile() {
        if (committed_) return;
        stream_.close();
        std::error_code ignored;
        fs::remove(temporary_, ignored);
    }
    PendingFile(const PendingFile&) = delete;
    PendingFile& operator=(const PendingFile&) = delete;
    std::ofstream& stream() noexcept { return stream_; }
    void commit() {
        stream_.close();
        if (!stream_) throw Error(Problem::write_failed, temporary_);
        if (taken(target_)) throw Error(Problem::output_exists, target_);
        fs::rename(temporary_, target_);
        committed_ = true;
    }
private:
    fs::path target_, temporary_;
    std::ofstream stream_;
    bool committed_{};
};

// A private staging folder next to the destination; removed unless released.
class StagingFolder {
public:
    explicit StagingFolder(const fs::path& parent)
        : path_(parent / (".hid-fido2-age-" + random_suffix() + ".partial")) {
        if (!fs::create_directory(path_)) throw Error(Problem::write_failed, path_);
    }
    ~StagingFolder() {
        if (path_.empty()) return;
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }
    StagingFolder(const StagingFolder&) = delete;
    StagingFolder& operator=(const StagingFolder&) = delete;
    const fs::path& path() const noexcept { return path_; }
    void released() noexcept { path_.clear(); }
private:
    fs::path path_;
};

std::uint64_t folder_bytes(const fs::path& folder) {
    std::uint64_t total = 0;
    for (const auto& entry : fs::recursive_directory_iterator(folder)) {
        std::error_code ignored;
        if (entry.is_regular_file(ignored)) total += entry.file_size();
    }
    return total;
}
}

Error::Error(Problem problem, fs::path path, std::size_t line)
    : std::runtime_error("age file operation failed"), problem_(problem), path_(std::move(path)), line_(line) {}

// ---- Profiles ----
bool valid_label(std::string_view label) noexcept {
    if (label.empty() || label.size() > max_label_bytes || label.front() == ' ' || label.back() == ' ') return false;
    return std::ranges::none_of(label, [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; });
}

Profile parse_profile(std::string_view text) {
    if (text.starts_with("\xEF\xBB\xBF")) text.remove_prefix(3);
    Profile profile;
    std::string label;
    std::size_t number = 0;
    while (!text.empty()) {
        const auto end = text.find('\n');
        const auto raw = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        ++number;
        const auto line = trim(raw);
        if (line.empty()) continue;
        if (line.front() == '#') { label = trim(std::string_view(line).substr(1)); continue; }
        if (line.starts_with("AGE-SECRET-KEY-")) throw Error(Problem::profile_secret, {}, number);
        try {
            if (line.starts_with("AGE-PLUGIN-FIDO2PRF-1")) {
                profile.keys.push_back({label, Fido2PrfCredential::parse(line)});
            } else if (line.starts_with("age1")) {
                profile.recovery.push_back({label, X25519Recipient::parse(line)});
            } else {
                throw Error(Problem::profile_line, {}, number);
            }
        } catch (const FormatError&) {
            throw Error(Problem::profile_line, {}, number);
        }
        label.clear();
    }
    if (profile.empty()) throw Error(Problem::profile_empty);
    return profile;
}

Profile read_profile(const fs::path& path) {
    std::error_code error;
    const auto status = fs::status(path, error);
    if (!fs::exists(status)) throw Error(Problem::profile_missing, path);
    if (!fs::is_regular_file(status)) throw Error(Problem::profile_unreadable, path);
    const auto size = fs::file_size(path, error);
    if (error || size > max_profile_bytes) throw Error(Problem::profile_unreadable, path);
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Error(Problem::profile_unreadable, path);
    std::string text(static_cast<std::size_t>(size), '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (static_cast<std::size_t>(input.gcount()) != text.size()) throw Error(Problem::profile_unreadable, path);
    try {
        return parse_profile(text);
    } catch (const Error& failure) {
        throw Error(failure.problem(), path, failure.line());
    }
}

void append_profile(const fs::path& path, std::string_view label, std::string_view recipient_line, std::string_view date) {
    if (!valid_label(label)) throw Error(Problem::profile_label);
    (void)parse_profile(std::string(recipient_line));  // Only a public recipient may be written.
    bool needs_newline = false;
    if (taken(path)) {
        (void)read_profile(path);  // Never append to a file we would not accept.
        std::ifstream existing(path, std::ios::binary | std::ios::ate);
        if (existing && existing.tellg() > 0) {
            existing.seekg(-1, std::ios::end);
            needs_newline = existing.get() != '\n';
        }
    } else if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }
    std::ofstream output(path, std::ios::binary | std::ios::app);
    if (!output) throw Error(Problem::write_failed, path);
    if (needs_newline) output << "\n";
    output << "# hid-fido2-age " << date << "\n# " << label << "\n" << recipient_line << "\n";
    output.close();
    if (!output) throw Error(Problem::write_failed, path);
}

std::string strip_whitespace(std::string_view text) {
    std::string result;
    for (const char c : text) if (c != ' ' && c != '\t' && c != '\r' && c != '\n') result.push_back(c);
    return result;
}

std::string group_recovery_key(std::string_view secret) {
    constexpr std::string_view prefix = "AGE-SECRET-KEY-1";
    if (!secret.starts_with(prefix)) return std::string(secret);
    std::string grouped(prefix);
    for (std::size_t i = prefix.size(); i < secret.size(); i += 4) {
        grouped += ' ';
        grouped += secret.substr(i, 4);
    }
    return grouped;
}

// ---- Names ----
bool is_folder_archive(const fs::path& path) {
    const auto name = path.filename().u8string();
    return name.size() > 8 && ends_with_ci(name, u8".tar.age");
}

fs::path encrypted_name(const fs::path& input, bool folder) {
    auto path = absolute_input(input);
    path += folder ? ".tar.age" : ".age";
    return path;
}

fs::path decrypted_name(const fs::path& input) {
    const auto path = absolute_input(input);
    const auto name = path.filename().u8string();
    const std::size_t strip = is_folder_archive(path) ? 8 : ends_with_ci(name, u8".age") && name.size() > 4 ? 4 : 0;
    if (!strip) throw Error(Problem::not_age_name, path);
    return path.parent_path() / fs::path(name.substr(0, name.size() - strip));
}

fs::path available_name(const fs::path& wanted) {
    if (!taken(wanted)) return wanted;
    auto base = wanted.filename().u8string();
    std::u8string suffix;
    if (ends_with_ci(base, u8".age") && base.size() > 4) {
        suffix = base.substr(base.size() - 4);
        base.resize(base.size() - 4);
    }
    const auto dot = base.rfind(u8'.');
    if (dot != std::u8string::npos && dot > 0) {
        suffix = base.substr(dot) + suffix;
        base.resize(dot);
    }
    for (unsigned number = 2; number < 10000; ++number) {
        const auto text = std::to_string(number);
        const auto candidate = wanted.parent_path() /
            fs::path(base + u8" (" + std::u8string(text.begin(), text.end()) + u8")" + suffix);
        if (!taken(candidate)) return candidate;
    }
    throw Error(Problem::output_exists, wanted);
}

std::vector<Stanza> read_stanzas(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Error(Problem::input_missing, path);
    std::string mac_input;
    crypto::Hash mac{};
    return parse_header(input, mac_input, mac);
}

bool has_stanza(std::span<const Stanza> stanzas, std::string_view type) noexcept {
    return std::ranges::any_of(stanzas, [&](const Stanza& stanza) { return stanza.type == type; });
}

// ---- Operations ----
Result encrypt(const fs::path& input, std::span<Recipient* const> recipients,
               std::optional<fs::path> output, bool rename_if_exists, const Observer& observer) {
    std::error_code error;
    const auto status = fs::symlink_status(input, error);
    const bool folder = fs::is_directory(status);
    if (!folder && !fs::is_regular_file(status)) throw Error(Problem::input_missing, input);
    if (recipients.empty()) throw Error(Problem::no_recipients);
    const auto source = absolute_input(input);
    auto target = output ? fs::absolute(*output).lexically_normal() : encrypted_name(source, folder);
    if (folder) {
        // The archive must not contain its own partial output.
        const auto inside = fs::weakly_canonical(target).lexically_relative(fs::weakly_canonical(source));
        if (!inside.empty() && *inside.begin() != "..") throw Error(Problem::output_inside_input, target);
    }
    target = claim(target, rename_if_exists);
    const auto total = folder ? folder_bytes(source) : fs::file_size(source);
    PendingFile pending(target);
    Encryptor encryptor(pending.stream(), recipients);  // Asks each security key here.
    check_continue(observer);
    Result result{target, folder, {}};
    std::uint64_t done = 0;
    if (folder) {
        result.stats = write_tar(source, [&](std::span<const std::uint8_t> data) {
            check_continue(observer);
            encryptor.write(data);
            done += data.size();
            report(observer, done, total);
        });
    } else {
        std::ifstream stream(source, std::ios::binary);
        if (!stream) throw Error(Problem::read_failed, source);
        std::vector<std::uint8_t> buffer(chunk_size);
        for (;;) {
            check_continue(observer);
            stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto count = static_cast<std::size_t>(stream.gcount());
            if (stream.bad()) throw Error(Problem::read_failed, source);
            if (count) encryptor.write(std::span(buffer).first(count));
            done += count;
            report(observer, done, total);
            if (count < buffer.size()) break;
        }
        wipe(buffer);
        result.stats.files = 1;
        result.stats.bytes = done;
    }
    encryptor.finish();
    pending.commit();
    return result;
}

Result decrypt(const fs::path& input, std::span<Identity* const> identities,
               std::optional<fs::path> output, bool rename_if_exists, const Observer& observer) {
    std::error_code error;
    if (!fs::is_regular_file(fs::symlink_status(input, error))) throw Error(Problem::input_missing, input);
    const auto source = absolute_input(input);
    const bool folder = is_folder_archive(source);
    if (!folder && !output) (void)decrypted_name(source);  // Check the name before asking for a key.
    std::ifstream stream(source, std::ios::binary);
    if (!stream) throw Error(Problem::read_failed, source);
    const auto total = fs::file_size(source);
    Decryptor decryptor(stream, identities);  // Asks for a security key here.
    const auto pull = [&](std::span<std::uint8_t> data) {
        check_continue(observer);
        const auto count = decryptor.read(data);
        const auto position = stream.tellg();
        report(observer, position >= 0 ? static_cast<std::uint64_t>(position) : total, total);
        return count;
    };
    if (!folder) {
        const auto target = claim(output ? fs::absolute(*output).lexically_normal() : decrypted_name(source), rename_if_exists);
        PendingFile pending(target);
        std::vector<std::uint8_t> buffer(chunk_size);
        std::uint64_t written = 0;
        for (std::size_t count; (count = pull(buffer)) != 0;) {
            pending.stream().write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(count));
            if (!pending.stream()) throw Error(Problem::write_failed, target);
            written += count;
        }
        wipe(buffer);
        if (!decryptor.finished()) throw FormatError("Truncated age payload");
        pending.commit();
        return {target, false, {1, 0, written}};
    }
    if (output) {
        const auto target = claim(fs::absolute(*output).lexically_normal(), rename_if_exists);
        StagingFolder staging(target.parent_path());
        const auto stats = extract_tar(pull, staging.path());
        if (!decryptor.finished()) throw FormatError("Truncated age payload");
        fs::rename(staging.path(), target);
        staging.released();
        return {target, true, stats};
    }
    const auto parent = source.parent_path();
    StagingFolder staging(parent);
    const auto stats = extract_tar(pull, staging.path());
    if (!decryptor.finished()) throw FormatError("Truncated age payload");
    std::vector<std::pair<fs::path, fs::path>> moves;
    for (const auto& entry : fs::directory_iterator(staging.path())) {
        auto destination = parent / entry.path().filename();
        if (taken(destination)) {
            if (!rename_if_exists) throw Error(Problem::output_exists, destination);
            destination = available_name(destination);
        }
        for (const auto& [from, to] : moves) {
            if (to == destination) throw Error(Problem::output_exists, destination);
        }
        moves.emplace_back(entry.path(), destination);
    }
    for (const auto& [from, to] : moves) fs::rename(from, to);
    return {moves.size() == 1 ? moves.front().second : parent, true, stats};
}
}
