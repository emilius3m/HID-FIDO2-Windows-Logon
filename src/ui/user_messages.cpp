#include "hidfido/localization.hpp"
#include "hidfido/user_messages.hpp"
#include "hidfido/ctap_client.hpp"
#include "hidfido/hid_transport.hpp"
#include "hidfido/machine_vault.hpp"

#include <windows.h>

namespace hidfido::ui {
namespace {
using hidfido::ui::tr;
std::wstring ctap_status(std::uint8_t status) {
    switch (status) {
    case 0x19: return tr(L"Questa chiave è già registrata per l'account: collega una chiave diversa.");
    case 0x27: return tr(L"Operazione rifiutata dalla chiave.");
    case 0x2d: return tr(L"Operazione annullata.");
    case 0x2e: return tr(L"La chiave collegata non è registrata per questo account. Collega Principale o Riserva.");
    case 0x2f: return tr(L"Tempo scaduto: tocca la chiave quando lampeggia.");
    case 0x31: return tr(L"PIN errato. La chiave ha contato un tentativo fallito; nessun nuovo tentativo automatico.");
    case 0x32: return tr(L"PIN bloccato sulla chiave. Usa l'altra chiave registrata o la password Windows.");
    case 0x33: return tr(L"Verifica del PIN non riuscita. Ricomincia l'operazione.");
    case 0x34: return tr(L"Troppi PIN errati consecutivi: scollega e ricollega la chiave prima di riprovare.");
    case 0x35: return tr(L"La chiave non ha un PIN FIDO2 configurato.");
    default: return tr(L"La chiave ha restituito l'errore CTAP ") + std::to_wstring(status) + L".";
    }
}

std::wstring transport(std::uint32_t code) {
    switch (code) {
    case ERROR_ACCESS_DENIED:
        return tr(L"Accesso diretto alla chiave negato: serve un processo amministratore o SYSTEM.");
    case ERROR_TIMEOUT:
        return tr(L"La chiave non risponde: scollegala, ricollegala e riprova.");
    case ERROR_FILE_NOT_FOUND:
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_GEN_FAILURE:
        return tr(L"Chiave scollegata durante l'operazione.");
    default:
        return tr(L"Errore di comunicazione con la chiave (codice ") + std::to_wstring(code) + L").";
    }
}
}

std::wstring describe_failure(const std::exception& error) {
    if (const auto* status = dynamic_cast<const ctap::StatusError*>(&error)) return ctap_status(status->status());
    if (const auto* hid = dynamic_cast<const ctap::HidTransportError*>(&error)) return transport(hid->code());
    if (dynamic_cast<const vault::CredentialNotOnKey*>(&error)) return ctap_status(0x2e);
    return tr(L"Impossibile completare l'operazione. Controlla la chiave collegata e riprova. Se il problema continua, usa la password Windows e consulta la guida di recupero.");
}

std::wstring describe_logon_error(unsigned long code) {
    switch (code) {
    case ERROR_LOGON_FAILURE: return tr(L"Password Windows errata. Nulla è stato salvato.");
    case ERROR_PASSWORD_EXPIRED: return tr(L"La password Windows è scaduta: cambiala in Windows, poi riprova.");
    case ERROR_PASSWORD_MUST_CHANGE: return tr(L"La password Windows deve essere cambiata: cambiala in Windows, poi riprova.");
    case ERROR_ACCOUNT_LOCKED_OUT: return tr(L"Account Windows bloccato.");
    case ERROR_ACCOUNT_DISABLED: return tr(L"Account Windows disabilitato.");
    case ERROR_ACCOUNT_RESTRICTION: return tr(L"Restrizioni dell'account impediscono l'accesso (orari, workstation o password vuota).");
    case ERROR_LOGON_TYPE_NOT_GRANTED: return tr(L"L'account non ha il diritto di accesso locale.");
    default: return tr(L"Verifica della password non riuscita (errore Windows ") + std::to_wstring(code) + L").";
    }
}
}
