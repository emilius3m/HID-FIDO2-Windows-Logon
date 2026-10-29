#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hidfido::installer {
struct ManifestFile { std::string path; std::uint64_t length{}; std::string sha256; };
struct Manifest {
    std::string version;
    std::string release_id;
    std::vector<ManifestFile> files;
    bool native_management{};
};
// Pure, bounded manifest parsing and identity checks. No code is loaded.
// Accepts the current payload set and the 0.9.0 set (without the
// file-encryption helper), so installed releases can be updated or restored.
Manifest parse_manifest(std::span<const std::uint8_t> bytes);
// The payload set written by new packages.
std::span<const std::string_view> native_payload_paths() noexcept;
std::string sha256_hex(std::span<const std::uint8_t> bytes);
bool valid_signer_pin(std::string_view text) noexcept;
std::wstring quote_argument(std::wstring_view value);

// Pins the source directory chain and every payload against writes/renames
// until destruction, and validates hashes plus the selected trust profile.
// Signed releases require pinned Authenticode and a pinned detached CMS over
// release.json. A prototype accepts only unsigned files after caller consent.
class PinnedPackage {
public:
    PinnedPackage(const std::filesystem::path& directory, std::string_view signer_pin,
                  bool allow_unsigned_prototype);
    ~PinnedPackage();
    PinnedPackage(const PinnedPackage&) = delete;
    PinnedPackage& operator=(const PinnedPackage&) = delete;
    const Manifest& manifest() const noexcept;
private:
    struct State;
    std::unique_ptr<State> state_;
};
}
