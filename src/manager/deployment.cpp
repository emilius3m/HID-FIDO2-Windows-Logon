#include "platform.hpp"
#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <algorithm>
#include <array>
#include <map>

namespace hidfido::management {
namespace {
constexpr wchar_t cp_path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8B5D856B-C940-4AFB-A050-167F5D4F75E2}";
constexpr wchar_t com_path[] = L"SOFTWARE\\Classes\\CLSID\\{8B5D856B-C940-4AFB-A050-167F5D4F75E2}";
constexpr wchar_t password_path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}";
constexpr wchar_t provider_name[] = L"HID FIDO2 Windows Logon";
struct RegKey { HKEY h{}; ~RegKey() { if (h) RegCloseKey(h); } };
struct RegValue { DWORD type{}; std::vector<std::uint8_t> bytes; };
struct Entry { bool exists{}; std::map<std::wstring, RegValue> values; std::vector<std::wstring> children; };
struct Expected { std::wstring path; std::map<std::wstring, std::wstring> values; std::vector<std::wstring> children; };
std::wstring reg_text(const RegValue& value) {
    if (value.type != REG_SZ || value.bytes.size() < 2 || value.bytes.size() % 2) throw std::runtime_error("Unexpected registry value type");
    const auto* data = reinterpret_cast<const wchar_t*>(value.bytes.data()); const auto size = value.bytes.size() / 2;
    if (data[size - 1] || std::find(data, data + size - 1, L'\0') != data + size - 1) throw std::runtime_error("Invalid registry string"); return {data, size - 1};
}
Entry read_entry(const std::wstring& path, HKEY hive = HKEY_LOCAL_MACHINE) {
    RegKey key; const auto opened = RegOpenKeyExW(hive, path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key.h); Entry result;
    if (opened == ERROR_FILE_NOT_FOUND) return result; if (opened != ERROR_SUCCESS) throw std::runtime_error("Registry read denied"); result.exists = true;
    for (DWORD index = 0;; ++index) {
        if (index > 256) throw std::runtime_error("Registry entry exceeds bound"); std::array<wchar_t, 512> name{}; DWORD chars = static_cast<DWORD>(name.size()), bytes = 65536, type{}; std::vector<std::uint8_t> data(bytes);
        const auto status = RegEnumValueW(key.h, index, name.data(), &chars, nullptr, &type, data.data(), &bytes);
        if (status == ERROR_NO_MORE_ITEMS) break; if (status != ERROR_SUCCESS) throw std::runtime_error("Registry value exceeds bound"); data.resize(bytes); result.values.emplace(std::wstring(name.data(), chars), RegValue{type, std::move(data)});
    }
    for (DWORD index = 0;; ++index) { if (index > 128) throw std::runtime_error("Registry subkeys exceed bound"); std::array<wchar_t, 512> name{}; DWORD chars = static_cast<DWORD>(name.size()); const auto status = RegEnumKeyExW(key.h, index, name.data(), &chars, nullptr, nullptr, nullptr, nullptr); if (status == ERROR_NO_MORE_ITEMS) break; if (status != ERROR_SUCCESS) throw std::runtime_error("Registry subkey exceeds bound"); result.children.emplace_back(name.data(), chars); }
    std::sort(result.children.begin(), result.children.end()); return result;
}
std::array<Expected, 3> expected(const Deployment& d) {
    const std::map<std::wstring, std::wstring> shared{{L"", provider_name}, {L"HidFidoDeploymentId", widen(d.id)}, {L"HidFidoReleaseId", widen(d.release_id)}};
    return {Expected{cp_path, shared, {}}, Expected{com_path, shared, {L"InprocServer32"}}, Expected{std::wstring(com_path) + L"\\InprocServer32", {{L"", d.provider.wstring()}, {L"ThreadingModel", L"Apartment"}}, {}}};
}
void assert_entry(const Expected& e, bool partial, HKEY hive = HKEY_LOCAL_MACHINE) {
    const auto actual = read_entry(e.path, hive); if (!actual.exists) { if (partial) return; throw std::runtime_error("Required provider registration missing"); }
    for (const auto& [name, value] : actual.values) { const auto found = e.values.find(name); if (found == e.values.end() || reg_text(value) != found->second) throw std::runtime_error("Foreign or modified provider registration"); }
    for (const auto& child : actual.children) if (std::find(e.children.begin(), e.children.end(), child) == e.children.end()) throw std::runtime_error("Unexpected provider subkey");
    if (!partial && (actual.values.size() != e.values.size() || actual.children != e.children)) throw std::runtime_error("Incomplete provider registration");
}
void assert_registration(const Deployment& d, bool partial = false) { for (const auto& entry : expected(d)) assert_entry(entry, partial); }
void assert_absent() { if (read_entry(cp_path).exists || read_entry(com_path).exists) throw std::runtime_error("Provider already registered"); }
void delete_entry(const Expected& e, HKEY hive = HKEY_LOCAL_MACHINE) {
    assert_entry(e, true, hive); const auto at = e.path.rfind(L'\\'); const auto parent = e.path.substr(0, at), child = e.path.substr(at + 1); RegKey key;
    const auto opened = RegOpenKeyExW(hive, parent.c_str(), 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &key.h);
    if (opened == ERROR_FILE_NOT_FOUND) return; if (opened != ERROR_SUCCESS) throw std::runtime_error("Registry delete denied");
    const auto status = RegDeleteTreeW(key.h, child.c_str()); if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) throw std::runtime_error("Provider removal failed");
}
void remove_registration(const Deployment& d) { assert_registration(d, true); const auto entries = expected(d); delete_entry(entries[0]); assert_entry(entries[2], true); delete_entry(entries[1]); }
void create_entry(const Expected& e, HKEY hive = HKEY_LOCAL_MACHINE) {
    RegKey key; DWORD disposition{};
    if (RegCreateKeyExW(hive, e.path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_READ | KEY_WOW64_64KEY, nullptr, &key.h, &disposition) != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY) throw std::runtime_error("Exclusive provider registration failed");
    const auto write = [&](const std::wstring& name, const std::wstring& value) { if (RegSetValueExW(key.h, name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) throw std::runtime_error("Provider registration write failed"); };
    // Identity first; cleanup accepts only a subset of the expected values.
    for (const auto name : {L"HidFidoDeploymentId", L"HidFidoReleaseId"}) { const auto found = e.values.find(name); if (found != e.values.end()) write(found->first, found->second); }
    for (const auto& [name, value] : e.values) if (name != L"HidFidoDeploymentId" && name != L"HidFidoReleaseId") write(name, value);
}
void register_deployment(const Deployment& d) { assert_absent(); const auto entries = expected(d); create_entry(entries[1]); create_entry(entries[2]); create_entry(entries[0]); assert_registration(d); }
void fallback_available() {
    const auto password = read_entry(password_path); if (!password.exists) throw std::runtime_error("Windows password provider unavailable");
    if (const auto disabled = password.values.find(L"Disabled"); disabled != password.values.end()) {
        bool off{}; if (disabled->second.type == REG_DWORD && disabled->second.bytes.size() == 4) { DWORD n{}; memcpy(&n, disabled->second.bytes.data(), 4); off = n != 0; } else off = reg_text(disabled->second) != L"0";
        if (off) throw std::runtime_error("Windows password provider disabled");
    }
    for (const auto path : {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"SOFTWARE\\Policies\\Microsoft\\Windows\\System"}) {
        const auto policy = read_entry(path); if (const auto excluded = policy.values.find(L"ExcludedCredentialProviders"); excluded != policy.values.end()) {
            if (excluded->second.bytes.size() % 2) throw std::runtime_error("Unsupported credential policy");
            const auto* chars = reinterpret_cast<const wchar_t*>(excluded->second.bytes.data()); std::wstring value(chars, excluded->second.bytes.size() / 2);
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(towupper(c)); });
            if (value.find(L"{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}") != value.npos) throw std::runtime_error("Windows password provider excluded by policy");
        }
    }
}
bool same_path(const std::filesystem::path& a, const std::filesystem::path& b) { return _wcsicmp(a.lexically_normal().c_str(), b.lexically_normal().c_str()) == 0; }
installer::Manifest checked_release(const std::filesystem::path& directory, std::string_view expected_hash) {
    check_protected(directory, true); const auto bytes = read_bytes(directory / L"release.json", 1024 * 1024);
    if (installer::sha256_hex(bytes) != expected_hash) throw std::runtime_error("Protected release manifest changed"); return installer::parse_manifest(bytes);
}
Deployment read_deployment(std::string_view id) {
    if (!valid_id(id, 32)) throw std::runtime_error("Invalid deployment identity"); const auto root = install_root(); const auto states = root / L"deployments";
    check_protected(root, true); check_protected(states, true); const auto path = states / (widen(id) + L".json"); check_protected(path, false);
    const auto state = parse_json(read_text(path)); const auto schema = state.at("Schema").integer();
    if ((schema != 1 && schema != 2) || state.at("ProjectId").text() != "HID-FIDO2-WinLogon" || state.at("ProviderClsid").text() != narrow(provider_clsid) || state.at("DeploymentId").text() != id || state.at("Architecture").text() != "8664") throw std::runtime_error("Unsupported deployment state");
    Deployment d; d.id = std::string(id); d.release_id = state.at("ReleaseId").text(); d.manifest_hash = state.at("PackageManifestSha256").text();
    if (!valid_id(d.release_id, 64) || !valid_id(d.manifest_hash, 64)) throw std::runtime_error("Invalid release identity");
    d.directory = root / L"releases" / widen(d.release_id); d.provider = d.directory / L"bin" / L"HidFido2CredentialProvider.dll"; d.manifest = path;
    if (!same_path(d.directory, widen(state.at("ReleaseDirectory").text())) || !same_path(d.provider, widen(state.at("ProviderPath").text()))) throw std::runtime_error("Deployment outside protected namespace");
    const auto release = checked_release(d.directory, d.manifest_hash); if (release.release_id != d.release_id) throw std::runtime_error("Deployment release mismatch");
    d.version = release.version; d.prototype = state.at("AllowUnsignedPrototype").flag(); d.native = schema == 2;
    return d;
}
std::string deployment_text(const Deployment& d) {
    return "{\"Schema\":2,\"ProjectId\":\"HID-FIDO2-WinLogon\",\"ProviderClsid\":" + json_string(narrow(provider_clsid)) + ",\"DeploymentId\":" + json_string(d.id) + ",\"ReleaseId\":" + json_string(d.release_id) + ",\"Architecture\":\"8664\",\"ReleaseDirectory\":" + json_string(narrow(d.directory.wstring())) + ",\"ProviderPath\":" + json_string(narrow(d.provider.wstring())) + ",\"PackageManifestSha256\":" + json_string(d.manifest_hash) + ",\"AllowUnsignedPrototype\":" + (d.prototype ? "true" : "false") + "}";
}
class Mutex {
public:
    Mutex() : handle_(CreateMutexW(nullptr, FALSE, L"Global\\HidFido2CredentialProviderDeployment")) { if (!handle_.valid()) win_error("Deployment mutex"); const auto wait = WaitForSingleObject(handle_.get(), 0); if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) throw std::runtime_error("Another deployment is running"); }
    ~Mutex() { ReleaseMutex(handle_.get()); }
private: Handle handle_;
};
class WindowsTransaction final : public TransactionBackend {
public:
    WindowsTransaction(std::filesystem::path source, std::string pin, std::wstring sid, bool legacy)
        : source_(std::move(source)), pin_(std::move(pin)), sid_(std::move(sid)), legacy_(legacy) {}
    void preflight() override {
        if (!elevated() || current_sid() != sid_) throw std::runtime_error("Administrator identity mismatch");
        package_ = std::make_unique<installer::PinnedPackage>(source_, pin_, pin_.empty()); if (!package_->manifest().native_management) throw std::runtime_error("Native package required");
        fallback_available(); previous_ = active_deployment(); if (previous_) assert_registration(*previous_); else assert_absent();
        if (legacy_ && (!pin_.empty() || !previous_)) throw std::runtime_error("Legacy exception only for an existing local prototype");
        if (previous_ && previous_->release_id == package_->manifest().release_id) throw std::runtime_error("This release is already installed");
    }
    void prepare() override {
        directory_ = stage_package(source_, pin_); staged_pin_ = std::make_unique<installer::PinnedPackage>(directory_, pin_, pin_.empty());
        const auto status = parse_status(capture_status(directory_ / L"bin" / L"hid-fido2-vault.exe", sid_));
        const auto verified = std::count_if(status.keys.begin(), status.keys.end(), [](const auto& key) { return key.proof != "unknown"; });
        if (!status.enrolled || !status.active || status.keys.size() < 2 || (verified < 2 && !legacy_)) throw std::runtime_error("Two active keys and hardware protection proofs required");
        if (run_native(directory_ / L"bin" / L"provider-smoke.exe", {(directory_ / L"bin" / L"HidFido2CredentialProvider.dll").wstring()}) != 0) throw std::runtime_error("Native production COM test failed");
        next_.id = random_id(); next_.release_id = staged_pin_->manifest().release_id; next_.directory = directory_; next_.provider = directory_ / L"bin" / L"HidFido2CredentialProvider.dll";
        next_.manifest_hash = installer::sha256_hex(read_bytes(directory_ / L"release.json", 1024 * 1024)); next_.prototype = pin_.empty(); next_.native = true; next_.version = staged_pin_->manifest().version;
        const auto states = install_root() / L"deployments"; new_directory(states); next_.manifest = states / (widen(next_.id) + L".json");
        write_new_text(next_.manifest, deployment_text(next_));
        const auto recovery = std::wstring(L"Windows Registry Editor Version 5.00\r\n\r\n[-HKEY_LOCAL_MACHINE\\") + cp_path + L"]\r\n";
        std::vector<std::uint8_t> bytes{0xff, 0xfe}; const auto* raw = reinterpret_cast<const std::uint8_t*>(recovery.data()); bytes.insert(bytes.end(), raw, raw + recovery.size() * 2); write_new(states / (widen(next_.id) + L".disable-provider.reg"), bytes);
        write_new_text(states / (widen(next_.id) + L".prepared.json"), "{\"Operation\":\"NativeUpdatePrepared\",\"NewReleaseId\":" + json_string(next_.release_id) + ",\"PreviousDeploymentId\":" + json_string(previous_ ? previous_->id : "") + "}");
        // State and recovery exist before any change to authentication.
        if (previous_) assert_registration(*previous_); else assert_absent(); fallback_available();
    }
    void remove_previous() override { if (previous_) remove_registration(*previous_); }
    void activate_new() override { register_deployment(next_); }
    void verify_new() override { assert_registration(next_); fallback_available(); }
    void cleanup_new() override {
        const auto cp = read_entry(cp_path), com = read_entry(com_path);
        if (previous_) {
            const auto belongs_to_old = [&](const Entry& entry) { const auto id = entry.values.find(L"HidFidoDeploymentId"); return id != entry.values.end() && reg_text(id->second) == widen(previous_->id); };
            if (belongs_to_old(cp) || belongs_to_old(com)) { assert_registration(*previous_, true); return; }
        }
        remove_registration(next_);
    }
    void restore_previous() override {
        if (!previous_) return;
        // Restore only a validated previous registration. Current vault
        // authorities, counters and password generation are never rolled back.
        const auto status = parse_status(capture_status(directory_ / L"bin" / L"hid-fido2-vault.exe", sid_));
        unsigned major{}, minor{}; const auto version = widen(previous_->version); swscanf_s(version.c_str(), L"%u.%u", &major, &minor);
        if (status.schema > 1 && major == 0 && minor < 5) throw std::runtime_error("Old provider cannot read the current vault");
        const auto manifest = checked_release(previous_->directory, previous_->manifest_hash);
        for (const auto& file : manifest.files) { const auto path = previous_->directory / widen(file.path); check_protected(path, false); const auto bytes = read_bytes(path); if (bytes.size() != file.length || installer::sha256_hex(bytes) != file.sha256) throw std::runtime_error("Previous release changed"); }
        remove_registration(*previous_); register_deployment(*previous_);
    }
private:
    std::filesystem::path source_, directory_; std::string pin_; std::wstring sid_; bool legacy_{};
    std::unique_ptr<installer::PinnedPackage> package_, staged_pin_; std::optional<Deployment> previous_; Deployment next_;
};
}
std::optional<Deployment> active_deployment() {
    const auto cp = read_entry(cp_path), com = read_entry(com_path); if (!cp.exists && !com.exists) return {};
    const auto& identity = cp.exists ? cp : com;
    const auto id = identity.values.find(L"HidFidoDeploymentId"), release = identity.values.find(L"HidFidoReleaseId");
    if (id == identity.values.end() || release == identity.values.end()) throw std::runtime_error("Unowned project registration");
    auto deployment = read_deployment(narrow(reg_text(id->second)));
    if (reg_text(release->second) != widen(deployment.release_id)) throw std::runtime_error("Registered release mismatch");
    assert_registration(deployment, true); return deployment;
}
Status observe(const std::filesystem::path& package, std::wstring_view sid) {
    auto status = parse_status(capture_status(package / L"bin" / L"hid-fido2-vault.exe", sid));
    if (const auto active = active_deployment()) { status.has_deployment = true; status.registered = read_entry(cp_path).exists; status.provider_path = active->provider.wstring(); status.provider_version = file_version(active->provider); }
    return status;
}
std::string audit_current(std::wstring_view sid) {
    if (!elevated() || current_sid() != sid) throw std::runtime_error("Audit identity mismatch");
    fallback_available(); const auto deployment = active_deployment();
    if (!deployment) return "{\"Registered\":false,\"WritesToAuthentication\":false}";
    assert_registration(*deployment); const auto manifest = checked_release(deployment->directory, deployment->manifest_hash);
    for (const auto& file : manifest.files) { const auto path = deployment->directory / widen(file.path); check_protected(path, false); const auto bytes = read_bytes(path); if (bytes.size() != file.length || installer::sha256_hex(bytes) != file.sha256) throw std::runtime_error("Installed payload changed"); }
    const auto status = observe(deployment->directory, sid);
    return "{\"Registered\":true,\"ProviderVersion\":" + json_string(narrow(status.provider_version)) + ",\"ReleaseId\":" + json_string(deployment->release_id) + ",\"VaultSchema\":" + std::to_string(status.schema) + ",\"AccountActive\":" + (status.active ? "true" : "false") + ",\"KeyCount\":" + std::to_string(status.keys.size()) + ",\"BackupCount\":" + std::to_string(status.backups.size()) + ",\"PayloadsVerified\":" + std::to_string(manifest.files.size()) + ",\"PasswordProviderAvailable\":true,\"WritesToAuthentication\":false}";
}
std::filesystem::path stage_package(const std::filesystem::path& source, std::string_view pin) {
    if (!elevated()) throw std::runtime_error("Administrator required"); installer::PinnedPackage package(source, pin, pin.empty());
    if (!package.manifest().native_management) throw std::runtime_error("Native release required"); verify_install_ancestors(); const auto root = install_root(), releases = root / L"releases", destination = releases / widen(package.manifest().release_id);
    new_directory(root); new_directory(releases); auto pins = pin_directories(releases);
    if (std::filesystem::exists(destination)) {
        check_protected(destination, true); installer::PinnedPackage existing(destination, pin, pin.empty());
        if (existing.manifest().release_id != package.manifest().release_id || installer::sha256_hex(read_bytes(destination / L"release.json")) != installer::sha256_hex(read_bytes(source / L"release.json"))) throw std::runtime_error("Existing release differs");
    } else {
        new_directory(destination); new_directory(destination / L"bin");
        for (const auto& file : package.manifest().files) write_new(destination / widen(file.path), read_bytes(source / widen(file.path)));
        write_new(destination / L"release.json", read_bytes(source / L"release.json", 1024 * 1024));
        if (!pin.empty()) write_new(destination / L"release.p7s", read_bytes(source / L"release.p7s", 1024 * 1024));
    }
    installer::PinnedPackage verified(destination, pin, pin.empty()); for (const auto& file : verified.manifest().files) check_protected(destination / widen(file.path), false); check_protected(destination / L"bin", true); check_protected(destination / L"release.json", false); return destination;
}
TransactionResult install_or_update(const std::filesystem::path& source, std::string_view pin, std::wstring_view sid, bool legacy) {
    Mutex mutex; const auto previous = active_deployment(); WindowsTransaction backend(source, std::string(pin), std::wstring(sid), legacy); return transact(backend, previous.has_value());
}
void uninstall_provider() { if (!elevated()) throw std::runtime_error("Administrator required"); Mutex mutex; const auto active = active_deployment(); if (active) remove_registration(*active); }
void create_shortcuts(const std::filesystem::path& package) {
    const auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com) && com != RPC_E_CHANGED_MODE) throw std::runtime_error("Shortcut COM initialization failed");
    struct Co { bool initialized; ~Co() { if (initialized) CoUninitialize(); } } co{SUCCEEDED(com)};
    check_protected(package, true); const auto target = package / L"Gestione-HID-FIDO2.exe"; check_protected(target, false);
    for (const auto& folder_id : {FOLDERID_Programs, FOLDERID_Desktop}) {
        wchar_t* folder{}; if (FAILED(SHGetKnownFolderPath(folder_id, 0, nullptr, &folder))) throw std::runtime_error("Shortcut folder unavailable"); const std::filesystem::path directory(folder); CoTaskMemFree(folder);
        const auto path = directory / L"Gestione HID FIDO2.lnk"; IShellLinkW* link{}; if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)))) throw std::runtime_error("Shortcut creation failed");
        struct Release { IShellLinkW* value; ~Release() { value->Release(); } } release{link}; IPersistFile* persist{}; if (FAILED(link->QueryInterface(IID_PPV_ARGS(&persist)))) throw std::runtime_error("Shortcut persistence unavailable");
        struct ReleaseFile { IPersistFile* value; ~ReleaseFile() { value->Release(); } } file{persist};
        if (std::filesystem::exists(path)) {
            if (GetFileAttributesW(path.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("Reparse shortcut refused");
            if (FAILED(persist->Load(path.c_str(), STGM_READ))) throw std::runtime_error("Existing shortcut unreadable"); std::array<wchar_t, 32768> old{}; link->GetPath(old.data(), static_cast<int>(old.size()), nullptr, SLGP_RAWPATH);
            const auto prefix = install_root().wstring() + L"\\"; if (_wcsnicmp(old.data(), prefix.c_str(), prefix.size()) != 0) throw std::runtime_error("Shortcut belongs to another program");
        }
        if (FAILED(link->SetPath(target.c_str())) || FAILED(link->SetArguments(L"--manage")) || FAILED(link->SetWorkingDirectory(package.c_str())) || FAILED(link->SetIconLocation(target.c_str(), 0)) || FAILED(link->SetDescription(L"Gestione delle chiavi FIDO2 e dell'accesso a Windows"))) throw std::runtime_error("Shortcut configuration failed");
        IPropertyStore* properties{}; if (SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&properties)))) { PROPVARIANT id{}; InitPropVariantFromString(L"HIDFIDO.WindowsLogon.Manager", &id); properties->SetValue(PKEY_AppUserModel_ID, id); properties->Commit(); PropVariantClear(&id); properties->Release(); }
        if (FAILED(persist->Save(path.c_str(), TRUE))) throw std::runtime_error("Shortcut save failed"); SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, path.c_str(), nullptr);
    }
}
}
