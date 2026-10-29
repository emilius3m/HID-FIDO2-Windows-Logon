// Portable primitives for the age format: SHA-256 (FIPS 180-4), HMAC (RFC 2104),
// HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439) and X25519 (RFC 7748).
// Windows CNG has no ChaCha20-Poly1305 or X25519 raw scalar multiplication on
// all supported releases, so one audited-by-test path is used everywhere.
// Secret-dependent operations are branch-free and table-free.
#include "hidfido/age.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

#include <algorithm>
#include <cstring>

namespace hidfido::age {
void wipe(std::span<std::uint8_t> bytes) noexcept {
    volatile std::uint8_t* data = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) data[i] = 0;
}

void random_bytes(std::span<std::uint8_t> output) {
#ifdef _WIN32
    while (!output.empty()) {
        const auto count = static_cast<ULONG>((std::min)(output.size(), std::size_t{1} << 20));
        if (BCryptGenRandom(nullptr, output.data(), count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            throw std::runtime_error("System random number generator failed");
        }
        output = output.subspan(count);
    }
#else
    while (!output.empty()) {
        const auto count = getrandom(output.data(), output.size(), 0);
        if (count <= 0) throw std::runtime_error("System random number generator failed");
        output = output.subspan(static_cast<std::size_t>(count));
    }
#endif
}

namespace crypto {
namespace {
std::uint32_t load32_le(const std::uint8_t* p) noexcept {
    return std::uint32_t{p[0]} | (std::uint32_t{p[1]} << 8) | (std::uint32_t{p[2]} << 16) | (std::uint32_t{p[3]} << 24);
}
void store32_le(std::uint8_t* p, std::uint32_t v) noexcept {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}
std::uint32_t rotr(std::uint32_t v, int n) noexcept { return (v >> n) | (v << (32 - n)); }
std::uint32_t rotl(std::uint32_t v, int n) noexcept { return (v << n) | (v >> (32 - n)); }

// ---- SHA-256 ----
constexpr std::array<std::uint32_t, 64> sha_k{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

class Sha256 {
public:
    void update(std::span<const std::uint8_t> data) noexcept {
        length_ += data.size();
        for (const auto byte : data) {
            block_[used_++] = byte;
            if (used_ == 64) { compress(); used_ = 0; }
        }
    }
    Hash finish() noexcept {
        const std::uint64_t bits = length_ * 8;
        block_[used_++] = 0x80;
        if (used_ > 56) {
            std::fill(block_.begin() + used_, block_.end(), std::uint8_t{0});
            compress();
            used_ = 0;
        }
        std::fill(block_.begin() + used_, block_.begin() + 56, std::uint8_t{0});
        for (int i = 0; i < 8; ++i) block_[56 + i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        compress();
        Hash out{};
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 4; ++j) out[4 * i + j] = static_cast<std::uint8_t>(state_[i] >> (24 - 8 * j));
        }
        wipe(block_);
        state_.fill(0);
        return out;
    }
private:
    void compress() noexcept {
        std::array<std::uint32_t, 64> w{};
        for (int i = 0; i < 16; ++i) {
            w[i] = (std::uint32_t{block_[4 * i]} << 24) | (std::uint32_t{block_[4 * i + 1]} << 16) |
                   (std::uint32_t{block_[4 * i + 2]} << 8) | block_[4 * i + 3];
        }
        for (int i = 16; i < 64; ++i) {
            const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        auto [a, b, c, d, e, f, g, h] = state_;
        for (int i = 0; i < 64; ++i) {
            const auto t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + sha_k[i] + w[i];
            const auto t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
        w.fill(0);
    }
    std::array<std::uint32_t, 8> state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::array<std::uint8_t, 64> block_{};
    std::size_t used_{};
    std::uint64_t length_{};
};

class Hmac {
public:
    explicit Hmac(std::span<const std::uint8_t> key) noexcept {
        std::array<std::uint8_t, 64> block{};
        if (key.size() > 64) {
            auto digest = sha256(key);
            std::copy(digest.begin(), digest.end(), block.begin());
            wipe(digest);
        } else {
            std::copy(key.begin(), key.end(), block.begin());
        }
        for (std::size_t i = 0; i < 64; ++i) {
            inner_key_[i] = block[i] ^ 0x36;
            outer_key_[i] = block[i] ^ 0x5c;
        }
        wipe(block);
        inner_.update(inner_key_);
    }
    ~Hmac() { wipe(inner_key_); wipe(outer_key_); }
    void update(std::span<const std::uint8_t> data) noexcept { inner_.update(data); }
    Hash finish() noexcept {
        auto inner = inner_.finish();
        Sha256 outer;
        outer.update(outer_key_);
        outer.update(inner);
        wipe(inner);
        return outer.finish();
    }
private:
    std::array<std::uint8_t, 64> inner_key_{}, outer_key_{};
    Sha256 inner_;
};

// ---- ChaCha20 ----
void quarter(std::array<std::uint32_t, 16>& x, int a, int b, int c, int d) noexcept {
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
}

void chacha20_block(std::span<const std::uint8_t, 32> key, std::uint32_t counter,
                    std::span<const std::uint8_t, 12> nonce, std::array<std::uint8_t, 64>& out) noexcept {
    std::array<std::uint32_t, 16> state{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; ++i) state[4 + i] = load32_le(key.data() + 4 * i);
    state[12] = counter;
    for (int i = 0; i < 3; ++i) state[13 + i] = load32_le(nonce.data() + 4 * i);
    auto x = state;
    for (int i = 0; i < 10; ++i) {
        quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13); quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12); quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) store32_le(out.data() + 4 * i, x[i] + state[i]);
    x.fill(0);
    state.fill(0);
}

void chacha20_xor(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                  std::uint32_t counter, std::span<const std::uint8_t> input, std::uint8_t* output) {
    std::array<std::uint8_t, 64> block{};
    for (std::size_t offset = 0; offset < input.size(); offset += 64, ++counter) {
        chacha20_block(key, counter, nonce, block);
        const auto count = (std::min)(std::size_t{64}, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) output[offset + i] = input[offset + i] ^ block[i];
    }
    wipe(block);
}

// ---- Poly1305 (26-bit limbs) ----
class Poly1305 {
public:
    explicit Poly1305(std::span<const std::uint8_t, 32> key) noexcept {
        r_[0] = load32_le(key.data() + 0) & 0x3ffffff;
        r_[1] = (load32_le(key.data() + 3) >> 2) & 0x3ffff03;
        r_[2] = (load32_le(key.data() + 6) >> 4) & 0x3ffc0ff;
        r_[3] = (load32_le(key.data() + 9) >> 6) & 0x3f03fff;
        r_[4] = (load32_le(key.data() + 12) >> 8) & 0x00fffff;
        for (int i = 0; i < 4; ++i) pad_[i] = load32_le(key.data() + 16 + 4 * i);
    }
    ~Poly1305() { r_.fill(0); h_.fill(0); pad_.fill(0); wipe(buffer_); }
    void update(std::span<const std::uint8_t> data) noexcept {
        for (const auto byte : data) {
            buffer_[used_++] = byte;
            if (used_ == 16) { block(buffer_.data(), 1u << 24); used_ = 0; }
        }
    }
    std::array<std::uint8_t, 16> finish() noexcept {
        if (used_) {
            buffer_[used_] = 1;
            std::fill(buffer_.begin() + used_ + 1, buffer_.end(), std::uint8_t{0});
            block(buffer_.data(), 0);
        }
        auto [h0, h1, h2, h3, h4] = h_;
        std::uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
        h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
        h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
        h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;
        std::uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        std::uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        std::uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        std::uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        std::uint32_t g4 = h4 + c - (1u << 26);
        std::uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
        h0 = h0 | (h1 << 26);
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);
        std::uint64_t f = std::uint64_t{h0} + pad_[0]; h0 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h1} + pad_[1] + (f >> 32); h1 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h2} + pad_[2] + (f >> 32); h2 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h3} + pad_[3] + (f >> 32); h3 = static_cast<std::uint32_t>(f);
        std::array<std::uint8_t, 16> tag{};
        store32_le(tag.data(), h0); store32_le(tag.data() + 4, h1);
        store32_le(tag.data() + 8, h2); store32_le(tag.data() + 12, h3);
        return tag;
    }
private:
    void block(const std::uint8_t* m, std::uint32_t hibit) noexcept {
        const auto [r0, r1, r2, r3, r4] = r_;
        const std::uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        auto& h = h_;
        h[0] += load32_le(m + 0) & 0x3ffffff;
        h[1] += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h[2] += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h[3] += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h[4] += (load32_le(m + 12) >> 8) | hibit;
        using U = std::uint64_t;
        U d0 = U{h[0]} * r0 + U{h[1]} * s4 + U{h[2]} * s3 + U{h[3]} * s2 + U{h[4]} * s1;
        U d1 = U{h[0]} * r1 + U{h[1]} * r0 + U{h[2]} * s4 + U{h[3]} * s3 + U{h[4]} * s2;
        U d2 = U{h[0]} * r2 + U{h[1]} * r1 + U{h[2]} * r0 + U{h[3]} * s4 + U{h[4]} * s3;
        U d3 = U{h[0]} * r3 + U{h[1]} * r2 + U{h[2]} * r1 + U{h[3]} * r0 + U{h[4]} * s4;
        U d4 = U{h[0]} * r4 + U{h[1]} * r3 + U{h[2]} * r2 + U{h[3]} * r1 + U{h[4]} * r0;
        std::uint32_t c = static_cast<std::uint32_t>(d0 >> 26); h[0] = static_cast<std::uint32_t>(d0) & 0x3ffffff;
        d1 += c; c = static_cast<std::uint32_t>(d1 >> 26); h[1] = static_cast<std::uint32_t>(d1) & 0x3ffffff;
        d2 += c; c = static_cast<std::uint32_t>(d2 >> 26); h[2] = static_cast<std::uint32_t>(d2) & 0x3ffffff;
        d3 += c; c = static_cast<std::uint32_t>(d3 >> 26); h[3] = static_cast<std::uint32_t>(d3) & 0x3ffffff;
        d4 += c; c = static_cast<std::uint32_t>(d4 >> 26); h[4] = static_cast<std::uint32_t>(d4) & 0x3ffffff;
        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += c;
    }
    std::array<std::uint32_t, 5> r_{}, h_{};
    std::array<std::uint32_t, 4> pad_{};
    std::array<std::uint8_t, 16> buffer_{};
    std::size_t used_{};
};

std::array<std::uint8_t, 16> aead_tag(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                                      std::span<const std::uint8_t> ciphertext, std::span<const std::uint8_t> aad) {
    std::array<std::uint8_t, 64> block{};
    chacha20_block(key, 0, nonce, block);
    Poly1305 mac(std::span<const std::uint8_t, 32>(block.data(), 32));
    wipe(block);
    static constexpr std::array<std::uint8_t, 16> zeros{};
    mac.update(aad);
    mac.update(std::span(zeros).first((16 - aad.size() % 16) % 16));
    mac.update(ciphertext);
    mac.update(std::span(zeros).first((16 - ciphertext.size() % 16) % 16));
    std::array<std::uint8_t, 16> lengths{};
    for (int i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::uint8_t>(std::uint64_t{aad.size()} >> (8 * i));
        lengths[8 + i] = static_cast<std::uint8_t>(std::uint64_t{ciphertext.size()} >> (8 * i));
    }
    mac.update(lengths);
    return mac.finish();
}

// ---- X25519 (field elements in 16 signed 64-bit limbs of 16 bits) ----
using Field = std::array<std::int64_t, 16>;

void carry(Field& o) noexcept {
    for (int i = 0; i < 16; ++i) {
        o[i] += std::int64_t{1} << 16;
        const std::int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;
    }
}
void select(Field& p, Field& q, std::int64_t bit) noexcept {
    const std::int64_t mask = ~(bit - 1);
    for (int i = 0; i < 16; ++i) {
        const std::int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}
void pack(std::uint8_t* out, const Field& n) noexcept {
    Field t = n, m{};
    carry(t); carry(t); carry(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const std::int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        select(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        out[2 * i] = static_cast<std::uint8_t>(t[i] & 0xff);
        out[2 * i + 1] = static_cast<std::uint8_t>((t[i] >> 8) & 0xff);
    }
    t.fill(0); m.fill(0);
}
void unpack(Field& o, const std::uint8_t* n) noexcept {
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + (std::int64_t{n[2 * i + 1]} << 8);
    o[15] &= 0x7fff;
}
void add(Field& o, const Field& a, const Field& b) noexcept { for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i]; }
void sub(Field& o, const Field& a, const Field& b) noexcept { for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i]; }
void mul(Field& o, const Field& a, const Field& b) noexcept {
    std::array<std::int64_t, 31> t{};
    for (int i = 0; i < 16; ++i) for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    carry(o); carry(o);
}
void square(Field& o, const Field& a) noexcept { mul(o, a, a); }
void invert(Field& o, const Field& in) noexcept {
    Field c = in;
    for (int a = 253; a >= 0; --a) {
        square(c, c);
        if (a != 2 && a != 4) mul(c, c, in);
    }
    o = c;
}
}

Hash sha256(std::span<const std::uint8_t> data) {
    Sha256 hash;
    hash.update(data);
    return hash.finish();
}

Hash hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    Hmac mac(key);
    mac.update(data);
    return mac.finish();
}

Hash hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm) {
    static constexpr std::array<std::uint8_t, 32> zero_salt{};
    return hmac_sha256(salt.empty() ? std::span<const std::uint8_t>(zero_salt) : salt, ikm);
}

Bytes hkdf_sha256(std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> salt,
                  std::span<const std::uint8_t> info, std::size_t length) {
    if (length == 0 || length > 255 * 32) throw std::invalid_argument("Invalid HKDF output length");
    auto prk = hkdf_extract(salt, ikm);
    Bytes output;
    output.reserve(length);
    Hash previous{};
    for (std::uint8_t counter = 1; output.size() < length; ++counter) {
        Hmac mac(prk);
        if (counter > 1) mac.update(previous);
        mac.update(info);
        mac.update(std::span<const std::uint8_t>(&counter, 1));
        previous = mac.finish();
        const auto count = (std::min)(previous.size(), length - output.size());
        output.insert(output.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(count));
    }
    wipe(prk);
    wipe(previous);
    return output;
}

Bytes chacha20poly1305_seal(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                            std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad) {
    Bytes output(plaintext.size() + 16);
    chacha20_xor(key, nonce, 1, plaintext, output.data());
    const auto tag = aead_tag(key, nonce, std::span(output).first(plaintext.size()), aad);
    std::copy(tag.begin(), tag.end(), output.end() - 16);
    return output;
}

std::optional<Bytes> chacha20poly1305_open(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> ciphertext,
                                           std::span<const std::uint8_t> aad) {
    if (ciphertext.size() < 16) return std::nullopt;
    const auto body = ciphertext.first(ciphertext.size() - 16);
    const auto expected = aead_tag(key, nonce, body, aad);
    if (!equal_constant_time(expected, ciphertext.last(16))) return std::nullopt;
    Bytes plaintext(body.size());
    chacha20_xor(key, nonce, 1, body, plaintext.data());
    return plaintext;
}

std::array<std::uint8_t, 32> x25519(std::span<const std::uint8_t, 32> scalar, std::span<const std::uint8_t, 32> point) {
    std::array<std::uint8_t, 32> z{};
    std::copy(scalar.begin(), scalar.end(), z.begin());
    z[31] = static_cast<std::uint8_t>((z[31] & 127) | 64);
    z[0] &= 248;
    static constexpr Field k121665{0xDB41, 1};
    Field x{}, a{}, b{}, c{}, d{}, e{}, f{};
    unpack(x, point.data());
    b = x;
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        const std::int64_t bit = (z[i >> 3] >> (i & 7)) & 1;
        select(a, b, bit);
        select(c, d, bit);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        square(d, e);
        square(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        square(b, a);
        sub(c, d, f);
        mul(a, c, k121665);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        square(b, e);
        select(a, b, bit);
        select(c, d, bit);
    }
    invert(c, c);
    mul(a, a, c);
    std::array<std::uint8_t, 32> out{};
    pack(out.data(), a);
    wipe(z);
    for (auto* value : {&x, &a, &b, &c, &d, &e, &f}) value->fill(0);
    return out;
}

std::array<std::uint8_t, 32> x25519_base(std::span<const std::uint8_t, 32> scalar) {
    static constexpr std::array<std::uint8_t, 32> base{9};
    return x25519(scalar, base);
}

bool equal_constant_time(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) noexcept {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i) difference |= static_cast<std::uint8_t>(left[i] ^ right[i]);
    return difference == 0;
}
}
}
