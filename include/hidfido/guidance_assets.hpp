#pragma once
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <memory>
#include <algorithm>

namespace hidfido::ui::detail {
class GuideAtlas {
public:
    GuideAtlas() {
        Gdiplus::GdiplusStartupInput input; if (Gdiplus::GdiplusStartup(&token_, &input, nullptr) != Gdiplus::Ok) { token_ = 0; return; }
        const auto module = GetModuleHandleW(nullptr); const auto resource = FindResourceW(module, MAKEINTRESOURCEW(1100), RT_RCDATA);
        if (!resource) return; const auto length = SizeofResource(module, resource); const auto loaded = LoadResource(module, resource); const auto bytes = loaded ? LockResource(loaded) : nullptr;
        if (!bytes || !length || length > 8 * 1024 * 1024) return;
        const auto memory = GlobalAlloc(GMEM_MOVEABLE, length); if (!memory) return;
        const auto target = GlobalLock(memory); if (!target) { GlobalFree(memory); return; }
        CopyMemory(target, bytes, length); GlobalUnlock(memory);
        if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &stream_))) { GlobalFree(memory); return; }
        image_.reset(Gdiplus::Bitmap::FromStream(stream_, FALSE));
        if (!image_ || image_->GetLastStatus() != Gdiplus::Ok || image_->GetWidth() < 2 || image_->GetHeight() < 2) image_.reset();
    }
    ~GuideAtlas() { image_.reset(); if (stream_) stream_->Release(); if (token_) Gdiplus::GdiplusShutdown(token_); }
    bool draw(HDC dc, RECT bounds, unsigned quadrant) {
        if (!image_ || quadrant > 3) return false;
        const auto cell_width = static_cast<int>(image_->GetWidth() / 2), cell_height = static_cast<int>(image_->GetHeight() / 2);
        const int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
        if (width < 1 || height < 1 || cell_width < 1 || cell_height < 1) return false;
        int drawn_width = std::min(width, height * cell_width / cell_height), drawn_height = drawn_width * cell_height / cell_width;
        Gdiplus::Graphics graphics(dc); graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic); graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
        return graphics.DrawImage(image_.get(), Gdiplus::Rect(bounds.left + (width - drawn_width) / 2, bounds.top + (height - drawn_height) / 2, drawn_width, drawn_height), static_cast<int>(quadrant % 2) * cell_width, static_cast<int>(quadrant / 2) * cell_height, cell_width, cell_height, Gdiplus::UnitPixel) == Gdiplus::Ok;
    }
private:
    ULONG_PTR token_{}; IStream* stream_{}; std::unique_ptr<Gdiplus::Bitmap> image_;
};
inline bool draw_guide_asset(HDC dc, RECT bounds, unsigned quadrant) { static GuideAtlas atlas; return atlas.draw(dc, bounds, quadrant); }
}
