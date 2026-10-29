#pragma once

#include "hidfido/age.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// File-level operations shared by the command-line tool, the graphical helper
// and the manager: recipient profiles, output naming and complete encrypt /
// decrypt operations for files and folders. Portable: no device I/O, no UI and
// no localization. Problems are reported as codes for the caller to phrase.
namespace hidfido::age::files {
namespace fs = std::filesystem;

// Relative to the user's roaming application data folder.
inline constexpr std::string_view profile_relative_path = "HID-FIDO2-WinLogon/Files/destinatari.txt";
inline constexpr std::size_t max_profile_bytes = 1 << 20;
inline constexpr std::size_t max_label_bytes = 128;

enum class Problem {
    profile_missing, profile_unreadable, profile_line, profile_secret, profile_empty, profile_label,
    no_recipients, input_missing, output_exists, output_inside_input, not_age_name,
    read_failed, write_failed, cancelled,
};

class Error : public std::runtime_error {
public:
    Error(Problem problem, fs::path path = {}, std::size_t line = 0);
    Problem problem() const noexcept { return problem_; }
    const fs::path& path() const noexcept { return path_; }
    std::size_t line() const noexcept { return line_; }
private:
    Problem problem_;
    fs::path path_;
    std::size_t line_;
};

// ---- Profiles ----------------------------------------------------------------
// One public recipient per line; '#' lines are comments, and the comment right
// before a recipient is its label. Secret keys are refused.
struct KeyEntry {
    std::string label;  // UTF-8
    Fido2PrfCredential credential;
};
struct RecoveryEntry {
    std::string label;  // UTF-8
    X25519Recipient recipient;
};
struct Profile {
    std::vector<KeyEntry> keys;
    std::vector<RecoveryEntry> recovery;
    bool empty() const noexcept { return keys.empty() && recovery.empty(); }
};
Profile parse_profile(std::string_view text);
// A missing file is Problem::profile_missing; the file is bounded in size.
Profile read_profile(const fs::path& path);
// Validates the existing profile (if any), then appends a dated, labelled entry.
// Creates the parent folder. Labels must be non-empty single-line text.
void append_profile(const fs::path& path, std::string_view label, std::string_view recipient_line, std::string_view date);
bool valid_label(std::string_view label) noexcept;
// "AGE-SECRET-KEY-1 ABCD EFGH ..." for copying by hand; whitespace is ignored on input.
std::string group_recovery_key(std::string_view secret);
std::string strip_whitespace(std::string_view text);

// ---- Names ---------------------------------------------------------------------
bool is_folder_archive(const fs::path& path);
fs::path encrypted_name(const fs::path& input, bool folder);
// Strips ".age" (and ".tar.age" for folder archives); Problem::not_age_name otherwise.
fs::path decrypted_name(const fs::path& input);
// The path itself if free, otherwise "name (2).ext", "name (3).ext", ... keeping
// compound endings such as ".tar.age" and ".pdf.age" intact.
fs::path available_name(const fs::path& wanted);

// Reads only the header (public recipient stanzas) of an age file.
std::vector<Stanza> read_stanzas(const fs::path& path);
bool has_stanza(std::span<const Stanza> stanzas, std::string_view type) noexcept;

// ---- Operations ------------------------------------------------------------------
struct Observer {
    // Bytes processed and total (0 when unknown). Called from the working thread.
    std::function<void(std::uint64_t done, std::uint64_t total)> progress;
    // Returning false cancels between chunks (Problem::cancelled); no output is kept.
    std::function<bool()> keep_going;
};
struct Result {
    fs::path output;   // file, created folder, or the folder that received the entries
    bool folder{};
    ArchiveStats stats;
};
// Encrypts a file or a folder (as NAME.tar.age). The output is written under a
// temporary name and renamed only when complete. Without `output`, the result
// goes next to the input; an existing name is refused unless `rename_if_exists`.
Result encrypt(const fs::path& input, std::span<Recipient* const> recipients,
               std::optional<fs::path> output, bool rename_if_exists, const Observer& observer = {});
// Decrypts a file, or extracts a folder archive (".tar.age"). Folder archives
// are extracted into a private staging folder and moved into place only after
// the whole stream is authenticated: into `output` (a new folder) when given,
// otherwise next to the archive.
Result decrypt(const fs::path& input, std::span<Identity* const> identities,
               std::optional<fs::path> output, bool rename_if_exists, const Observer& observer = {});
}
