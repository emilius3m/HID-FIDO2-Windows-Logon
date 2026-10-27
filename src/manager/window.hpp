#pragma once
#include "platform.hpp"
#include "hidfido/guidance_view.hpp"
namespace hidfido::management {
struct WindowOptions {
    bool demo{};
    std::wstring demo_state;
    std::filesystem::path snapshot;
    std::optional<ui::GuideStep> preview_step;
    std::string signer_pin;
    bool compact_preview{};
};
bool confirm(HWND parent, const wchar_t* text);
void error(HWND parent, const wchar_t* text);
void technical_error(HWND parent, const wchar_t* details);
int show_manager(WindowOptions options, std::filesystem::path package, std::wstring sid, HINSTANCE instance, int show);
}
