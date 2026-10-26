#include "platform.hpp"
#include <wincrypt.h>
#include <algorithm>
#include <array>

namespace hidfido::management {
namespace {
void inspect_pe(const std::vector<std::uint8_t>& bytes, bool dll) {
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("PE file truncated");
    IMAGE_DOS_HEADER dos{}; memcpy(&dos, bytes.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || static_cast<std::size_t>(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes.size()) throw std::runtime_error("Invalid PE header");
    IMAGE_NT_HEADERS64 nt{}; memcpy(&nt, bytes.data() + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || ((nt.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0) != dll) throw std::runtime_error("Expected production AMD64 PE");
    if (dll) {
        const std::wstring marker = L"HidFido2CredentialProviderTest.dll";
        const auto* first = reinterpret_cast<const std::uint8_t*>(marker.data());
        if (std::search(bytes.begin(), bytes.end(), first, first + marker.size() * 2) != bytes.end()) throw std::runtime_error("Test provider cannot be packaged");
    }
}
std::vector<std::uint8_t> sign_manifest(std::span<const std::uint8_t> bytes, std::string_view pin) {
    for (const auto location : {CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}) {
        const auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, location | CERT_STORE_READONLY_FLAG, L"MY"); if (!store) continue;
        struct Close { HCERTSTORE value; ~Close() { CertCloseStore(value, 0); } } close{store};
        PCCERT_CONTEXT cursor{};
        while ((cursor = CertEnumCertificatesInStore(store, cursor))) {
            if (installer::sha256_hex({cursor->pbCertEncoded, cursor->cbCertEncoded}) != pin) continue;
            PCCERT_CONTEXT cert = CertDuplicateCertificateContext(cursor); CertFreeCertificateContext(cursor);
            struct Free { PCCERT_CONTEXT value; ~Free() { CertFreeCertificateContext(value); } } free{cert};
            CRYPT_SIGN_MESSAGE_PARA parameters{}; parameters.cbSize = sizeof(parameters); parameters.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING; parameters.pSigningCert = cert; parameters.HashAlgorithm.pszObjId = const_cast<LPSTR>(szOID_NIST_sha256); parameters.cMsgCert = 1; parameters.rgpMsgCert = &cert;
            const BYTE* content = bytes.data(); DWORD length = static_cast<DWORD>(bytes.size()), result_size{};
            if (!CryptSignMessage(&parameters, TRUE, 1, &content, &length, nullptr, &result_size)) win_error("Sign detached manifest");
            std::vector<std::uint8_t> result(result_size); if (!CryptSignMessage(&parameters, TRUE, 1, &content, &length, result.data(), &result_size)) win_error("Sign detached manifest"); result.resize(result_size); return result;
        }
    }
    throw std::runtime_error("Pinned signing certificate with private key unavailable");
}
}
std::string package_release(const std::filesystem::path& build, const std::filesystem::path& output, std::string_view version, std::string_view pin) {
    if (version.empty() || version.size() > 48 || version.front() == '.' || version.back() == '.' || version.find("..") != version.npos || std::count(version.begin(), version.end(), '.') != 2 || !std::all_of(version.begin(), version.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.'; })) throw std::runtime_error("Invalid release version");
    reject_reparse(build); reject_reparse(output); std::vector<std::vector<std::uint8_t>> payload;
    std::string files, identity = "HID-FIDO2-WinLogon/release/1\n" + std::string(version) + "\n8664";
    for (const auto relative : installer::native_payload_paths()) {
        auto bytes = read_bytes(build / std::filesystem::path(relative).filename()); inspect_pe(bytes, relative.ends_with(".dll"));
        const auto hash = installer::sha256_hex(bytes); identity += "\n" + std::string(relative) + "=" + hash;
        if (!files.empty()) files += ','; files += "{\"Path\":" + json_string(relative) + ",\"Length\":" + std::to_string(bytes.size()) + ",\"Sha256\":" + json_string(hash) + '}'; payload.push_back(std::move(bytes));
    }
    const auto id = installer::sha256_hex({reinterpret_cast<const std::uint8_t*>(identity.data()), identity.size()});
    const auto manifest = "{\"Schema\":1,\"ProjectId\":\"HID-FIDO2-WinLogon\",\"ProviderClsid\":" + json_string(narrow(provider_clsid)) + ",\"Architecture\":\"8664\",\"VaultSchema\":2,\"Version\":" + json_string(version) + ",\"ReleaseId\":" + json_string(id) + ",\"NativeManagement\":true,\"Files\":[" + files + "]}";
    const auto directory = std::filesystem::absolute(output) / widen(version) / widen(id);
    if (!std::filesystem::exists(directory)) {
        reject_reparse(directory); std::filesystem::create_directories(directory / L"bin"); const auto paths = installer::native_payload_paths();
        for (std::size_t i = 0; i < paths.size(); ++i) write_new(directory / widen(paths[i]), payload[i], false);
        write_new_text(directory / L"release.json", manifest, false);
        if (!pin.empty()) write_new(directory / L"release.p7s", sign_manifest({reinterpret_cast<const std::uint8_t*>(manifest.data()), manifest.size()}, pin), false);
    }
    installer::PinnedPackage verified(directory, pin, pin.empty()); if (!verified.manifest().native_management || verified.manifest().release_id != id) throw std::runtime_error("Native package verification failed");
    return narrow(directory.wstring());
}
}
