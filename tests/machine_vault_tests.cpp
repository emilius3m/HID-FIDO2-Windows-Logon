#include "hidfido/machine_vault.hpp"
#include "hidfido/account.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using namespace hidfido;
using vault::SecureBytes;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action> void rejects(Action&& action, const char* message) {
    bool rejected{};
    try { action(); } catch (const std::exception&) { rejected = true; }
    require(rejected, message);
}

Hash random_hash() {
    Hash value{};
    require(BCryptGenRandom(nullptr, value.data(), static_cast<ULONG>(value.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "test RNG failed");
    return value;
}

std::span<const std::uint8_t> utf16(std::wstring_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size() * sizeof(wchar_t)};
}

bool same(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    return std::ranges::equal(a, b);
}

Credential credential(std::uint8_t tag) {
    Credential result;
    result.id = Bytes(48, tag);
    result.x = random_hash();
    result.y = random_hash();
    result.user_handle = random_hash();
    result.sign_count = tag;
    return result;
}

constexpr std::string_view sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
constexpr std::wstring_view first_password = L"Prima-Password!è";
constexpr std::wstring_view second_password = L"Seconda password con spazi";

struct Fixture {
    SecureBytes data_key = vault::new_data_key();
    Hash principale_secret = random_hash();
    Hash riserva_secret = random_hash();
    vault::AccountRecord record;
    Fixture() {
        record = vault::create_record(std::string(sid), "utente", utf16(first_password), data_key.bytes());
        vault::add_wrapper(record, L"Principale", credential(1), random_hash(), principale_secret, data_key.bytes());
        vault::add_wrapper(record, L"Riserva", credential(2), random_hash(), riserva_secret, data_key.bytes());
    }
};

void two_independent_keys() {
    Fixture f;
    auto from_principale = vault::unwrap_data_key(f.record, f.record.wrappers[0], f.principale_secret);
    auto from_riserva = vault::unwrap_data_key(f.record, f.record.wrappers[1], f.riserva_secret);
    require(same(from_principale.bytes(), f.data_key.bytes()), "Principale did not unwrap the DEK");
    require(same(from_riserva.bytes(), f.data_key.bytes()), "Riserva did not unwrap the DEK");
    rejects([&] { (void)vault::unwrap_data_key(f.record, f.record.wrappers[0], f.riserva_secret); },
            "A key opened another key's wrapper");
    rejects([&] { (void)vault::unwrap_data_key(f.record, f.record.wrappers[1], random_hash()); },
            "A random secret opened a wrapper");
    auto password = vault::open_password(f.record, from_riserva.bytes());
    require(same(password.bytes(), utf16(first_password)), "Password payload changed");
    rejects([&] { (void)vault::open_password(f.record, random_hash()); }, "Wrong DEK opened the password");
}

void password_change_keeps_wrappers() {
    Fixture f;
    vault::replace_password(f.record, f.data_key.bytes(), utf16(second_password));
    require(f.record.password_generation == 1 && !f.record.stale, "Generation or stale flag not updated");
    // Only one key was needed for the update; the other wrapper still works.
    auto from_riserva = vault::unwrap_data_key(f.record, f.record.wrappers[1], f.riserva_secret);
    auto password = vault::open_password(f.record, from_riserva.bytes());
    require(same(password.bytes(), utf16(second_password)), "Updated password not returned");

    f.record.stale = true;
    const auto before = vault::serialize(vault::Vault{{f.record}});
    rejects([&] { vault::replace_password(f.record, random_hash(), utf16(first_password)); },
            "Password replaced with a wrong DEK");
    require(vault::serialize(vault::Vault{{f.record}}) == before, "Failed update modified the record");
    rejects([&] { vault::replace_password(f.record, f.data_key.bytes(), {}); }, "Empty password accepted");
    const std::wstring with_nul(L"ab\0cd", 5);
    rejects([&] { vault::replace_password(f.record, f.data_key.bytes(), utf16(with_nul)); }, "NUL accepted");
    const std::wstring too_long(vault::max_password_units + 1, L'x');
    rejects([&] { vault::replace_password(f.record, f.data_key.bytes(), utf16(too_long)); }, "Long password accepted");
}

void wrapper_management() {
    Fixture f;
    rejects([&] { vault::add_wrapper(f.record, L"Terza", credential(3), random_hash(), random_hash(), random_hash()); },
            "Wrapper added with a wrong DEK");
    rejects([&] { vault::add_wrapper(f.record, L"Principale", credential(4), random_hash(), random_hash(), f.data_key.bytes()); },
            "Duplicate label accepted");
    rejects([&] { vault::add_wrapper(f.record, L"Altra", credential(1), random_hash(), random_hash(), f.data_key.bytes()); },
            "Duplicate credential accepted");
    rejects([&] { vault::add_wrapper(f.record, L"", credential(5), random_hash(), random_hash(), f.data_key.bytes()); },
            "Empty label accepted");
    vault::remove_wrapper(f.record, L"Riserva");
    require(f.record.wrappers.size() == 1, "Wrapper not removed");
    rejects([&] { vault::remove_wrapper(f.record, L"Principale"); }, "Last wrapper removed");
    rejects([&] { vault::remove_wrapper(f.record, L"Assente"); }, "Missing wrapper removed");
    rejects([] { (void)vault::create_record("not-a-sid", "utente", utf16(first_password), random_hash()); },
            "Invalid SID accepted");
}

void unlock_order() {
    Fixture f;
    unsigned calls{};
    auto unlocked = vault::unlock_data_key(f.record, [&](vault::KeyWrapper& wrapper) -> SecureBytes {
        ++calls;
        if (wrapper.label == L"Principale") throw vault::CredentialNotOnKey();
        wrapper.credential.sign_count = 77;
        SecureBytes secret(32);
        std::ranges::copy(f.riserva_secret, secret.bytes().begin());
        return secret;
    });
    require(calls == 2 && unlocked.wrapper_index == 1, "Riserva not selected after Principale was absent");
    require(same(unlocked.data_key.bytes(), f.data_key.bytes()), "Unlocked DEK differs");
    require(f.record.wrappers[1].credential.sign_count == 77, "Counter update lost");

    rejects([&] {
        (void)vault::unlock_data_key(f.record, [](vault::KeyWrapper&) -> SecureBytes { throw vault::CredentialNotOnKey(); });
    }, "Unlock succeeded with no enrolled key attached");
    calls = 0;
    rejects([&] {
        (void)vault::unlock_data_key(f.record, [&](vault::KeyWrapper&) -> SecureBytes {
            ++calls;
            throw std::runtime_error("PIN invalid");
        });
    }, "Authenticator error was swallowed");
    require(calls == 1, "Unlock continued after an authenticator error");
    rejects([&] {
        (void)vault::unlock_data_key(f.record, [](vault::KeyWrapper&) {
            SecureBytes secret(32);
            return secret;
        });
    }, "Wrong secret unlocked the vault");
}

void machine_security_policy() {
    vault::validate_machine_security_sddl(vault::machine_sddl);
    vault::validate_machine_security_sddl(L"O:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)");
    for (const auto sddl : {
        L"O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)", // inheritance not protected
        L"O:BAD:NO_ACCESS_CONTROL",         // null DACL
        L"O:BAD:P",                        // no required grants
        L"O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)", // untrusted owner
        L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
        L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)",
        L"O:BAD:P(A;OICI;FA;;;SY)(A;;FA;;;BA)",
        L"O:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)",
        L"O:BAD:P(A;;FA;;;SY)",
        L"O:BAD:P(D;;FW;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)"
    }) rejects([&] { vault::validate_machine_security_sddl(sddl); }, "Unsafe machine descriptor accepted");
}

template<class Action> void conflict(Action&& action, const char* message) {
    bool rejected{};
    try { action(); } catch (const vault::ConcurrencyConflict&) { rejected = true; }
    require(rejected, message);
}

void authority_cas() {
    Fixture f;
    const auto before = f.record;
    auto verified = before;
    verified.wrappers[0].credential.sign_count += 1;
    auto current = before;
    current.wrappers[1].credential.sign_count += 17; // unrelated use preserved
    vault::apply_verified_key_use(current, before, verified, 0);
    require(current.wrappers[0].credential.sign_count == 2 && current.wrappers[1].credential.sign_count == 19,
            "CAS did not preserve unrelated key counter");
    conflict([&] { vault::apply_verified_key_use(current, before, verified, 0); }, "A proof committed twice");
    conflict([&] { auto value = before; vault::apply_verified_key_use(value, before, before, 0); }, "Equal nonzero counter accepted");
    auto zero = before;
    zero.wrappers[0].credential.sign_count = 0;
    auto zero_current = zero;
    vault::apply_verified_key_use(zero_current, zero, zero, 0); // WebAuthn 0/0 supported

    const auto check = [&](auto mutate) {
        auto changed = before;
        mutate(changed);
        const auto unchanged = vault::serialize(vault::Vault{{changed}});
        conflict([&] { vault::apply_verified_key_use(changed, before, verified, 0); }, "Changed authority was accepted");
        require(vault::serialize(vault::Vault{{changed}}) == unchanged, "Failed CAS partially updated the record");
    };
    check([](auto& value) { value.record_id[0] ^= 1; });
    check([](auto& value) { value.sid.back() = '2'; });
    check([](auto& value) { value.account_name += "-renamed"; });
    check([](auto& value) { ++value.password_generation; });
    check([](auto& value) { value.password.ciphertext[0] ^= 1; });
    check([](auto& value) { value.password.tag[0] ^= 1; });
    check([](auto& value) { value.payload_salt[0] ^= 1; });
    check([](auto& value) { value.stale = true; });
    check([](auto& value) { vault::remove_wrapper(value, L"Principale"); });
    check([](auto& value) { value.wrappers[0].credential.x[0] ^= 1; });
    check([](auto& value) { value.wrappers[0].credential.y[0] ^= 1; });
    check([](auto& value) { value.wrappers[0].salt[0] ^= 1; });
    check([](auto& value) { value.wrappers[0].wrapped_key.tag[0] ^= 1; });
    check([](auto& value) { ++value.wrappers[0].credential.sign_count; });
    check([](auto& value) {
        value.wrappers[0].protection_state = vault::ProtectionState::verified_denied;
        value.wrappers[0].protection_checked_at_unix = 1;
        value.wrappers[0].protection_verification_version = vault::protection_verification_version;
    });
    auto forged = verified;
    forged.wrappers[0].wrapped_key.ciphertext[0] ^= 1;
    conflict([&] { auto value = before; vault::apply_verified_key_use(value, before, forged, 0); }, "Forged verified key accepted");
    conflict([&] { auto value = before; vault::apply_verified_key_use(value, before, verified, 8); }, "Invalid wrapper index accepted");
    // Recovery can authenticate a consistently stale record to replace its password.
    auto stale = before; stale.stale = true; auto stale_verified = stale;
    ++stale_verified.wrappers[0].credential.sign_count;
    auto stale_current = stale;
    vault::apply_verified_key_use(stale_current, stale, stale_verified, 0);
}

void rejected_password_generation() {
    Fixture f;
    const auto attempted = f.record;
    auto current = attempted;
    ++current.wrappers[1].credential.sign_count;
    require(vault::suspend_password_generation(current, attempted) && current.stale,
            "Rejected password generation was not suspended");
    require(vault::suspend_password_generation(current, attempted), "Suspension is not idempotent");
    const auto unchanged = [&](auto mutate) {
        auto changed = attempted;
        mutate(changed);
        const auto bytes = vault::serialize(vault::Vault{{changed}});
        require(!vault::suspend_password_generation(changed, attempted), "Older rejection suspended another generation");
        require(vault::serialize(vault::Vault{{changed}}) == bytes, "Unrelated generation changed on rejection");
    };
    unchanged([](auto& record) { ++record.password_generation; });
    unchanged([](auto& record) { record.record_id[0] ^= 1; });
    unchanged([](auto& record) { record.sid.back() = '2'; });
}

void schema_migration_and_provenance() {
    Fixture f;
    const auto legacy_bytes = vault::serialize(vault::Vault{{f.record}}, 1);
    const auto legacy = vault::parse(legacy_bytes);
    require(legacy.source_schema == 1, "Schema-1 source was not identified");
    for (const auto& key : legacy.accounts[0].wrappers) {
        require(key.protection_state == vault::ProtectionState::unknown &&
                !key.protection_checked_at_unix && !key.protection_verification_version,
                "Legacy key was falsely marked verified");
    }
    const auto migrated_bytes = vault::serialize(legacy);
    const auto migrated = vault::parse(migrated_bytes);
    require(migrated.source_schema == 2, "Normal serialization did not migrate to schema 2");
    require(migrated.accounts[0].password.ciphertext == f.record.password.ciphertext &&
            migrated.accounts[0].wrappers[0].wrapped_key.tag == f.record.wrappers[0].wrapped_key.tag,
            "Schema migration altered cryptographic payloads");
    auto opened = vault::open_password(migrated.accounts[0], f.data_key.bytes());
    require(same(opened.bytes(), utf16(first_password)), "Migrated password does not open");
    auto verified = f.record;
    verified.wrappers[0].protection_state = vault::ProtectionState::verified_distinct;
    verified.wrappers[0].protection_checked_at_unix = 1792886400;
    verified.wrappers[0].protection_verification_version = vault::protection_verification_version;
    const auto proof_bytes = vault::serialize(vault::Vault{{verified}});
    const auto proof = vault::parse(proof_bytes).accounts[0].wrappers[0];
    require(proof.protection_state == vault::ProtectionState::verified_distinct &&
            proof.protection_checked_at_unix == 1792886400 && proof.protection_verification_version == 1,
            "Protection provenance did not roundtrip");
    rejects([&] { (void)vault::serialize(vault::Vault{{verified}}, 1); }, "Verified metadata silently downgraded to schema 1");
    auto invalid = f.record;
    invalid.wrappers[0].protection_checked_at_unix = 1;
    rejects([&] { (void)vault::serialize(vault::Vault{{invalid}}); }, "Unknown state accepted proof metadata");
    invalid = verified; invalid.wrappers[0].protection_checked_at_unix = 0;
    rejects([&] { (void)vault::serialize(vault::Vault{{invalid}}); }, "Verified state accepted without time");
    invalid = verified; invalid.wrappers[0].protection_verification_version = 2;
    rejects([&] { (void)vault::serialize(vault::Vault{{invalid}}); }, "Unknown proof protocol version accepted");
    invalid = verified; invalid.wrappers[0].protection_state = static_cast<vault::ProtectionState>(9);
    rejects([&] { (void)vault::serialize(vault::Vault{{invalid}}); }, "Unknown protection enum accepted");
    require(!vault::provider_version_supports_schema2(0, 4) && vault::provider_version_supports_schema2(0, 5) &&
            vault::provider_version_supports_schema2(1, 0), "Provider compatibility guard policy differs");
}

void conservative_backup_restore() {
    Fixture f;
    const auto backup = f.record;
    auto current = backup;
    vault::remove_wrapper(current, L"Riserva");
    current.wrappers[0].credential.sign_count = 99;
    current.wrappers[0].protection_state = vault::ProtectionState::verified_denied;
    current.wrappers[0].protection_checked_at_unix = 1;
    current.wrappers[0].protection_verification_version = 1;
    vault::validate_backup_restore(current, backup);
    const auto authority = current.wrappers[0];
    // Actual restore re-seals only the independently verified password payload.
    auto password = vault::open_password(backup, f.data_key.bytes());
    current.password.tag[0] ^= 0x80; // damaged active payload, valid record framing
    vault::restore_password_payload(current, backup, f.data_key.bytes(), password.bytes());
    require(current.password_generation == backup.password_generation + 1 && current.wrappers.size() == 1 &&
            current.wrappers[0].credential.sign_count == authority.credential.sign_count &&
            current.wrappers[0].protection_state == authority.protection_state,
            "Restore revived a revoked key or reduced current authority");
    auto recovered = vault::open_password(current, f.data_key.bytes());
    require(same(recovered.bytes(), utf16(first_password)), "Restore did not repair the damaged password payload");
    auto unchanged = backup;
    const auto bytes = vault::serialize(vault::Vault{{unchanged}});
    rejects([&] { vault::restore_password_payload(unchanged, backup, f.data_key.bytes(), utf16(second_password)); },
            "Recovery accepted a different supposedly verified password");
    require(vault::serialize(vault::Vault{{unchanged}}) == bytes, "Failed recovery changed the record");
    rejects([&] { vault::validate_backup_restore(current, backup); }, "Older password generation accepted");
    auto foreign = backup; foreign.record_id[0] ^= 1;
    rejects([&] { vault::validate_backup_restore(backup, foreign); }, "Another record backup accepted");
    auto future_counter = backup; future_counter.wrappers[0].credential.sign_count += 1;
    rejects([&] { vault::validate_backup_restore(backup, future_counter); }, "Higher backup counter could roll back authority");
}

Bytes reseal(Bytes data) {
    data.resize(data.size() - 32);
    const auto checksum = sha256(data);
    data.insert(data.end(), checksum.begin(), checksum.end());
    return data;
}

std::size_t find(const Bytes& data, std::span<const std::uint8_t> needle) {
    const auto found = std::search(data.begin(), data.end(), needle.begin(), needle.end());
    require(found != data.end(), "test pattern not found");
    return static_cast<std::size_t>(found - data.begin());
}

void format() {
    Fixture f;
    f.record.stale = true;
    f.record.password_generation = 9;
    const vault::Vault original{{f.record}};
    const auto data = vault::serialize(original);
    const auto parsed = vault::parse(data);
    require(vault::serialize(parsed) == data, "Round trip changed the vault");
    const auto* record = parsed.find(sid);
    require(record && record->stale && record->password_generation == 9 && record->wrappers.size() == 2 &&
            record->wrappers[1].label == L"Riserva" && record->wrappers[0].credential.sign_count == 1,
            "Parsed fields differ");
    require(!parsed.find("S-1-5-18"), "Unknown SID found");
    auto key = vault::unwrap_data_key(*record, record->wrappers[0], f.principale_secret);
    auto password = vault::open_password(*record, key.bytes());
    require(same(password.bytes(), utf16(first_password)), "Parsed vault does not open");

    auto corrupted = data;
    corrupted[20] ^= 1;
    rejects([&] { (void)vault::parse(corrupted); }, "Checksum mismatch accepted");
    rejects([&] { (void)vault::parse(std::span(data).first(data.size() - 1)); }, "Truncated vault accepted");
    auto trailing = data;
    trailing.insert(trailing.end() - 32, 0);
    rejects([&] { (void)vault::parse(reseal(trailing)); }, "Trailing data accepted");

    // Valid framing with altered authenticated content: parse succeeds, opening fails.
    auto ciphertext = data;
    const auto at = find(ciphertext, f.record.password.ciphertext);
    ciphertext[at] ^= 0x80;
    const auto altered = vault::parse(reseal(ciphertext));
    rejects([&] { (void)vault::open_password(altered.accounts[0], f.data_key.bytes()); }, "Altered payload opened");
    auto renamed = data;
    const std::string_view name = "utente";
    renamed[find(renamed, {reinterpret_cast<const std::uint8_t*>(name.data()), name.size()})] = 'U';
    const auto rebound = vault::parse(reseal(renamed));
    rejects([&] { (void)vault::unwrap_data_key(rebound.accounts[0], rebound.accounts[0].wrappers[0], f.principale_secret); },
            "Wrapper opened under another account name");

    vault::Vault duplicated{{f.record, f.record}};
    rejects([&] { (void)vault::serialize(duplicated); }, "Duplicate account accepted");
    vault::Vault empty_wrappers{{f.record}};
    empty_wrappers.accounts[0].wrappers.clear();
    rejects([&] { (void)vault::serialize(empty_wrappers); }, "Record without keys accepted");
    rejects([] { (void)vault::parse(Bytes(64, 0)); }, "Garbage accepted");
}

void files() {
    Fixture f;
    wchar_t temp[MAX_PATH + 1]{};
    require(GetTempPathW(MAX_PATH, temp) > 0, "temp path unavailable");
    const auto directory = std::filesystem::path(temp) /
        (L"hidfido-vault-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    const auto path = directory / L"vault.bin";
    const auto sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + current_user_sid() + L")";
    try {
        require(vault::load(path).accounts.empty(), "Missing vault is not empty");
        {
            vault::Lock lock(path, sddl);
            vault::save(path, vault::Vault{{f.record}}, sddl);
            const auto started = std::chrono::steady_clock::now();
            conflict([&] { vault::Lock second(path, sddl, std::chrono::milliseconds(80)); },
                     "Second vault lock was not bounded");
            require(std::chrono::steady_clock::now() - started < std::chrono::seconds(2),
                    "Vault lock timeout did not bound waiting");
        }
        auto loaded = vault::load(path);
        require(loaded.accounts.size() == 1 && loaded.find(sid), "Saved vault not loaded");
        loaded.accounts[0].stale = true;
        vault::save(path, loaded, sddl);
        require(vault::load(path).accounts[0].stale, "Atomic replacement lost an update");
        require(vault::default_path().filename() == L"vault.bin", "Unexpected default vault path");
        const auto backup = vault::create_backup(path, loaded.accounts[0], sddl);
        const auto another = vault::create_backup(path, loaded.accounts[0], sddl);
        require(backup.id.size() == 32 && backup.id != another.id && backup.created_at_unix > 0,
                "Backups did not get distinct immutable identities");
        const auto copies = vault::list_backups(path, sid);
        require(copies.size() == 2 && vault::list_backups(path, "S-1-5-18").empty(),
                "Backup list leaked another account or lost snapshots");
        const auto restored = vault::load_backup(path, backup.id, sid);
        require(restored.password.ciphertext == loaded.accounts[0].password.ciphertext,
                "Backup changed the encrypted password");
        rejects([&] { (void)vault::load_backup(path, "../vault", sid); }, "Backup path traversal accepted");
        rejects([&] { (void)vault::load_backup(path, backup.id, "S-1-5-18"); }, "Another account backup imported");
        rejects([&] { (void)vault::load_backup(path, std::string(32, '0'), sid); }, "Missing backup imported");
    } catch (...) {
        std::filesystem::remove_all(directory);
        throw;
    }
    std::filesystem::remove_all(directory);
}
}

int main() {
    try {
        two_independent_keys();
        password_change_keeps_wrappers();
        wrapper_management();
        unlock_order();
        machine_security_policy();
        authority_cas();
        rejected_password_generation();
        schema_migration_and_provenance();
        conservative_backup_restore();
        format();
        files();
        std::cout << "Machine vault tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
