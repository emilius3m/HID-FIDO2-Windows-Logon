// Localized descriptions of file-encryption failures for the command line and
// the graphical helper. Messages name files and lines, never key material.
#include "hidfido/age_desktop.hpp"
#include "hidfido/age_webauthn.hpp"
#include "hidfido/localization.hpp"

namespace hidfido::age::desktop {
namespace {
using ui::tr;

std::wstring problem(const files::Error& error) {
    const auto path = error.path().wstring();
    const auto line = std::to_wstring(error.line());
    switch (error.problem()) {
    case files::Problem::profile_missing:
        return tr(L"Non ci sono ancora chiavi per i file: aggiungi una chiave di sicurezza o una chiave di recupero.");
    case files::Problem::profile_unreadable: return tr(L"Impossibile leggere il profilo dei destinatari: ") + path;
    case files::Problem::profile_line: return tr(L"Riga non riconosciuta nel profilo, riga ") + line + L": " + path;
    case files::Problem::profile_secret:
        return tr(L"Il profilo contiene una chiave SEGRETA di recupero alla riga ") + line +
               tr(L". Toglila dal file: il profilo deve contenere solo dati pubblici.");
    case files::Problem::profile_empty: return tr(L"Il profilo non contiene destinatari: ") + path;
    case files::Problem::profile_label: return tr(L"Etichetta della chiave non valida.");
    case files::Problem::no_recipients: return tr(L"Il profilo non contiene destinatari: ") + path;
    case files::Problem::input_missing: return tr(L"File o cartella non trovati: ") + path;
    case files::Problem::output_exists: return tr(L"Esiste già: ") + path + tr(L". Nessun file è stato sovrascritto.");
    case files::Problem::output_inside_input:
        return tr(L"Il file cifrato non può stare dentro la cartella da cifrare: scegli un altro --output.");
    case files::Problem::not_age_name: return tr(L"Il file non termina con .age: indica il nome del risultato con --output.");
    case files::Problem::read_failed: return tr(L"Impossibile leggere: ") + path;
    case files::Problem::write_failed: return tr(L"Errore di scrittura: ") + path;
    case files::Problem::cancelled: return tr(L"Operazione annullata. Nessun risultato parziale è stato conservato.");
    }
    return tr(L"Impossibile completare l'operazione.");
}
}

std::wstring describe(const std::exception& error) {
    if (const auto* failure = dynamic_cast<const files::Error*>(&error)) return problem(*failure);
    if (dynamic_cast<const NoIdentityMatched*>(&error)) return tr(L"Nessuna delle chiavi indicate può aprire questo file.");
    if (const auto* key = dynamic_cast<const webauthn::Error*>(&error)) {
        if (key->already_registered()) return tr(L"Questa chiave è già nel profilo con un'altra etichetta: collega una chiave fisica diversa.");
        if (key->cancelled()) return tr(L"Operazione annullata o chiave non registrata per questo file.");
        if (!webauthn::prf_available()) {
            return tr(L"Questa versione di Windows non permette di usare le chiavi di sicurezza per cifrare file (serve Windows 11 22H2 o successivo). La chiave di recupero funziona comunque.");
        }
        return tr(L"Errore della chiave di sicurezza: ") + widen(key->what());
    }
    if (const auto* format = dynamic_cast<const FormatError*>(&error)) {
        return tr(L"Il file è danneggiato, manomesso o non valido (") + widen(format->what()) +
               tr(L"). Nessun risultato parziale è stato conservato.");
    }
    return widen(error.what());
}
}
