// ICU comparison row for the conformance report.
//
// Runs ICU4C over the same pinned Unicode test files the Lean tree closes and
// counts, per suite, how many published rows ICU reproduces. The result is one
// JSON object on stdout: ICU's own version and the Unicode version it carries,
// and per suite the rows judged, passed and failed. Nothing here touches the
// Lean result; the report prints the two side by side.
//
// Suites and the ICU surface each is judged through:
//   BidiTest.txt            ubidi with a class callback over the row's classes
//   BidiCharacterTest.txt   ubidi over the row's codepoints
//   NormalizationTest.txt   unorm2 NFC / NFD / NFKC / NFKD instances
//   GraphemeBreakTest.txt   ubrk UBRK_CHARACTER, root locale
//   WordBreakTest.txt       ubrk UBRK_WORD, root locale
//   SentenceBreakTest.txt   ubrk UBRK_SENTENCE, root locale
//   LineBreakTest.txt       ubrk UBRK_LINE, root locale
//   IdnaTestV2.txt          uidna UTS #46, nontransitional and transitional
//   CollationTest_*_SHORT   ucol root collator, identical strength,
//                           NON_IGNORABLE / SHIFTED alternate handling
//
// A row counts as passed only when every field the file publishes for it
// agrees with ICU; a row ICU cannot be asked about is counted as skipped and
// the reason is named in the JSON.

#include <unicode/ubidi.h>
#include <unicode/ubrk.h>
#include <unicode/ucol.h>
#include <unicode/uidna.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>
#include <unicode/uversion.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct SuiteResult {
    long total = 0;
    long passed = 0;
    long failed = 0;
    long skipped = 0;
    // Bidi suites only: rows whose visual order agrees but whose published
    // levels ICU does not reproduce digit for digit. ICU flattens a
    // unidirectional paragraph to the paragraph level (an AN or EN in
    // left-to-right text keeps level 0 rather than 2), which leaves the
    // display order unchanged; ICU's own conformance driver compares levels
    // up to parity for that reason. `failed` above counts the strict reading;
    // this counts how much of it is the flattening.
    long levelsDifferSameOrder = 0;
    std::string skippedWhy;
};

// Rows to print per suite when a failure is worth reading; set from argv.
long gDumpFailures = 0;

void dumpFailure(const char* suite, const std::string& row, const std::string& why, long& printed) {
    if (printed >= gDumpFailures) return;
    printed++;
    std::fprintf(stderr, "%s: %s\n    %s\n", suite, row.c_str(), why.c_str());
}

// BidiTest.txt publishes Bidi classes, not characters. Each class is fed to
// ICU as one representative character that carries exactly that class in the
// UCD and no bracket pairing, the reading ICU's own conformance driver takes,
// so the published class is what reaches the algorithm and nothing else does.
const std::map<std::string, UChar32> kCharOfClass = {
    {"L", 0x006C},   {"R", 0x05D0},   {"AL", 0x0627},  {"EN", 0x0033},  {"ES", 0x002D},
    {"ET", 0x0025},  {"AN", 0x0660},  {"CS", 0x002C},  {"NSM", 0x0300}, {"BN", 0x200B},
    {"B", 0x2029},   {"S", 0x0009},   {"WS", 0x0020},  {"ON", 0x003D},  {"LRE", 0x202A},
    {"LRO", 0x202D}, {"RLE", 0x202B}, {"RLO", 0x202E}, {"PDF", 0x202C}, {"LRI", 0x2066},
    {"RLI", 0x2067}, {"FSI", 0x2068}, {"PDI", 0x2069},
};

std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t')) a++;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

std::vector<std::string> splitOn(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> words(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string w;
    while (in >> w) out.push_back(w);
    return out;
}

std::string stripComment(const std::string& line) {
    size_t hash = line.find('#');
    return hash == std::string::npos ? line : line.substr(0, hash);
}

std::vector<UChar32> parseHexSequence(const std::string& field) {
    std::vector<UChar32> cps;
    for (const std::string& w : words(field)) {
        cps.push_back(static_cast<UChar32>(std::strtoul(w.c_str(), nullptr, 16)));
    }
    return cps;
}

std::vector<UChar> toUtf16(const std::vector<UChar32>& cps) {
    std::vector<UChar> out;
    for (UChar32 cp : cps) {
        if (cp <= 0xFFFF) {
            out.push_back(static_cast<UChar>(cp));
        } else {
            out.push_back(static_cast<UChar>(U16_LEAD(cp)));
            out.push_back(static_cast<UChar>(U16_TRAIL(cp)));
        }
    }
    return out;
}

std::vector<UChar32> fromUtf16(const std::vector<UChar>& units) {
    std::vector<UChar32> out;
    int32_t i = 0;
    int32_t n = static_cast<int32_t>(units.size());
    while (i < n) {
        UChar32 c;
        U16_NEXT(units.data(), i, n, c);
        out.push_back(c);
    }
    return out;
}

std::vector<UChar32> normalize(const UNormalizer2* norm, const std::vector<UChar32>& cps) {
    std::vector<UChar> in = toUtf16(cps);
    std::vector<UChar> out(in.size() * 4 + 16);
    UErrorCode status = U_ZERO_ERROR;
    int32_t len = unorm2_normalize(norm, in.data(), static_cast<int32_t>(in.size()), out.data(),
                                   static_cast<int32_t>(out.size()), &status);
    if (status == U_BUFFER_OVERFLOW_ERROR) {
        out.assign(static_cast<size_t>(len), 0);
        status = U_ZERO_ERROR;
        len = unorm2_normalize(norm, in.data(), static_cast<int32_t>(in.size()), out.data(),
                               static_cast<int32_t>(out.size()), &status);
    }
    if (U_FAILURE(status)) return {};
    out.resize(static_cast<size_t>(len));
    return fromUtf16(out);
}

// ── NormalizationTest.txt ───────────────────────────────────────────────────

SuiteResult runNormalization(const std::string& path) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    const UNormalizer2* nfc = unorm2_getNFCInstance(&status);
    const UNormalizer2* nfd = unorm2_getNFDInstance(&status);
    const UNormalizer2* nfkc = unorm2_getNFKCInstance(&status);
    const UNormalizer2* nfkd = unorm2_getNFKDInstance(&status);
    if (U_FAILURE(status)) {
        r.skippedWhy = "normalizer instances unavailable";
        return r;
    }
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty() || body[0] == '@') continue;
        std::vector<std::string> fields = splitOn(body, ';');
        if (fields.size() < 5) continue;
        std::vector<UChar32> c[5];
        for (int i = 0; i < 5; i++) c[i] = parseHexSequence(fields[static_cast<size_t>(i)]);
        r.total++;
        bool ok = true;
        // NFC: c2 == toNFC(c1) == toNFC(c2) == toNFC(c3); c4 == toNFC(c4) == toNFC(c5)
        for (int i = 0; i < 3; i++) ok = ok && normalize(nfc, c[i]) == c[1];
        for (int i = 3; i < 5; i++) ok = ok && normalize(nfc, c[i]) == c[3];
        // NFD: c3 == toNFD(c1) == toNFD(c2) == toNFD(c3); c5 == toNFD(c4) == toNFD(c5)
        for (int i = 0; i < 3; i++) ok = ok && normalize(nfd, c[i]) == c[2];
        for (int i = 3; i < 5; i++) ok = ok && normalize(nfd, c[i]) == c[4];
        // NFKC: c4 == toNFKC(c1..c5); NFKD: c5 == toNFKD(c1..c5)
        for (int i = 0; i < 5; i++) ok = ok && normalize(nfkc, c[i]) == c[3];
        for (int i = 0; i < 5; i++) ok = ok && normalize(nfkd, c[i]) == c[4];
        if (ok) r.passed++; else r.failed++;
    }
    return r;
}

// ── Break tests ─────────────────────────────────────────────────────────────

// LineBreakTest.txt writes `×` at position 0 (LB2: never break at the start
// of text) where the other break files write `÷`; an iterator reports 0 as
// its first boundary in both readings, so position 0 is not judged for the
// line suite.
SuiteResult runBreak(const char* name, const std::string& path, UBreakIteratorType type) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    UBreakIterator* bi = ubrk_open(type, "", nullptr, 0, &status);
    if (U_FAILURE(status) || bi == nullptr) {
        r.skippedWhy = "break iterator unavailable";
        return r;
    }
    const bool judgeStart = type != UBRK_LINE;
    long printed = 0;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty()) continue;
        std::vector<std::string> toks = words(body);
        std::vector<UChar> text;
        std::vector<bool> expectedBreakAt;  // index = UTF-16 offset
        std::vector<int32_t> offsets;       // offsets the row makes a statement about
        std::vector<bool> breakHere;
        bool malformed = false;
        for (const std::string& t : toks) {
            if (t == "\xC3\xB7") {          // ÷
                offsets.push_back(static_cast<int32_t>(text.size()));
                breakHere.push_back(true);
            } else if (t == "\xC3\x97") {   // ×
                offsets.push_back(static_cast<int32_t>(text.size()));
                breakHere.push_back(false);
            } else {
                UChar32 cp = static_cast<UChar32>(std::strtoul(t.c_str(), nullptr, 16));
                std::vector<UChar> units = toUtf16({cp});
                text.insert(text.end(), units.begin(), units.end());
            }
        }
        if (malformed || offsets.empty()) continue;
        r.total++;
        ubrk_setText(bi, text.data(), static_cast<int32_t>(text.size()), &status);
        if (U_FAILURE(status)) {
            r.failed++;
            status = U_ZERO_ERROR;
            continue;
        }
        std::vector<bool> icuBreak(text.size() + 1, false);
        for (int32_t b = ubrk_first(bi); b != UBRK_DONE; b = ubrk_next(bi)) {
            if (b >= 0 && static_cast<size_t>(b) < icuBreak.size()) icuBreak[static_cast<size_t>(b)] = true;
        }
        bool ok = true;
        std::string why;
        for (size_t i = 0; i < offsets.size(); i++) {
            size_t off = static_cast<size_t>(offsets[i]);
            if (off == 0 && !judgeStart) continue;
            if (off >= icuBreak.size() || icuBreak[off] != breakHere[i]) {
                ok = false;
                why = "at offset " + std::to_string(off) + ": icu "
                    + (off < icuBreak.size() && icuBreak[off] ? "break" : "no break")
                    + " expected " + (breakHere[i] ? "break" : "no break");
                break;
            }
        }
        if (ok) {
            r.passed++;
        } else {
            r.failed++;
            dumpFailure(name, body, why, printed);
        }
    }
    ubrk_close(bi);
    return r;
}

// ── BidiCharacterTest.txt ───────────────────────────────────────────────────

SuiteResult runBidiCharacter(const std::string& path) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    UBiDi* bidi = ubidi_open();
    std::ifstream in(path);
    std::string line;
    long printed = 0;
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty()) continue;
        std::vector<std::string> fields = splitOn(body, ';');
        if (fields.size() < 5) continue;
        std::vector<UChar32> cps = parseHexSequence(fields[0]);
        int direction = std::atoi(trim(fields[1]).c_str());
        int expectedParaLevel = std::atoi(trim(fields[2]).c_str());
        std::vector<std::string> levelToks = words(fields[3]);
        std::vector<std::string> orderToks = words(fields[4]);
        r.total++;
        std::vector<UChar> text = toUtf16(cps);
        UBiDiLevel paraLevel = direction == 0 ? 0 : direction == 1 ? 1 : UBIDI_DEFAULT_LTR;
        status = U_ZERO_ERROR;
        ubidi_setPara(bidi, text.data(), static_cast<int32_t>(text.size()), paraLevel, nullptr, &status);
        if (U_FAILURE(status)) {
            r.failed++;
            continue;
        }
        bool ok = ubidi_getParaLevel(bidi) == expectedParaLevel;
        const UBiDiLevel* levels = ubidi_getLevels(bidi, &status);
        if (U_FAILURE(status) || levels == nullptr) {
            r.failed++;
            continue;
        }
        // Levels are published per codepoint; ICU reports per UTF-16 unit.
        std::vector<int32_t> cpStart;
        {
            int32_t unit = 0;
            for (UChar32 cp : cps) {
                cpStart.push_back(unit);
                unit += cp <= 0xFFFF ? 1 : 2;
            }
        }
        std::string why = "paragraph level: icu " + std::to_string(ubidi_getParaLevel(bidi));
        bool levelsExact = true;
        if (levelToks.size() != cps.size()) ok = false;
        for (size_t i = 0; ok && i < levelToks.size(); i++) {
            if (levelToks[i] == "x") continue;
            int expected = std::atoi(levelToks[i].c_str());
            if (levels[cpStart[i]] != expected) {
                levelsExact = false;
                why = "level at " + std::to_string(i) + ": icu " + std::to_string(levels[cpStart[i]])
                    + " expected " + levelToks[i];
            }
        }
        bool orderOk = ok;
        if (ok) {
            int32_t length = ubidi_getProcessedLength(bidi);
            std::vector<int32_t> visual(static_cast<size_t>(length) + 1);
            ubidi_getVisualMap(bidi, visual.data(), &status);
            if (U_FAILURE(status)) orderOk = false;
            std::map<int32_t, size_t> cpIndexOfUnit;
            for (size_t i = 0; i < cpStart.size(); i++) cpIndexOfUnit[cpStart[i]] = i;
            std::vector<std::string> icuOrder;
            for (int32_t v = 0; orderOk && v < length; v++) {
                auto it = cpIndexOfUnit.find(visual[static_cast<size_t>(v)]);
                if (it == cpIndexOfUnit.end()) continue;  // trail surrogate unit
                size_t cpIdx = it->second;
                if (levelToks[cpIdx] == "x") continue;      // removed by X9
                icuOrder.push_back(std::to_string(cpIdx));
            }
            if (icuOrder != orderToks) {
                orderOk = false;
                why = "order: icu";
                for (const std::string& t : icuOrder) why += " " + t;
            }
        }
        if (ok && orderOk && levelsExact) {
            r.passed++;
        } else {
            r.failed++;
            if (ok && orderOk) r.levelsDifferSameOrder++;
            else dumpFailure("BidiCharacterTest", body, why, printed);
        }
    }
    ubidi_close(bidi);
    return r;
}

// ── BidiTest.txt ────────────────────────────────────────────────────────────

SuiteResult runBidiTest(const std::string& path) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    UBiDi* bidi = ubidi_open();
    std::ifstream in(path);
    std::string line;
    std::vector<std::string> levelToks;
    std::vector<std::string> orderToks;
    long printed = 0;
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty()) continue;
        if (body.rfind("@Levels:", 0) == 0) {
            levelToks = words(body.substr(8));
            continue;
        }
        if (body.rfind("@Reorder:", 0) == 0) {
            orderToks = words(body.substr(9));
            continue;
        }
        if (body[0] == '@') continue;
        std::vector<std::string> fields = splitOn(body, ';');
        if (fields.size() < 2) continue;
        std::vector<UChar> text;
        bool known = true;
        for (const std::string& name : words(fields[0])) {
            auto it = kCharOfClass.find(name);
            if (it == kCharOfClass.end()) { known = false; break; }
            text.push_back(static_cast<UChar>(it->second));
        }
        int bitset = std::atoi(trim(fields[1]).c_str());
        if (!known || text.size() != levelToks.size()) {
            r.total++;
            r.failed++;
            continue;
        }
        const int paraOptions[3] = {1, 2, 4};
        const UBiDiLevel paraLevels[3] = {UBIDI_DEFAULT_LTR, 0, 1};
        const char* paraNames[3] = {"auto", "LTR", "RTL"};
        for (int k = 0; k < 3; k++) {
            if ((bitset & paraOptions[k]) == 0) continue;
            r.total++;
            status = U_ZERO_ERROR;
            ubidi_setPara(bidi, text.data(), static_cast<int32_t>(text.size()), paraLevels[k], nullptr, &status);
            if (U_FAILURE(status)) { r.failed++; continue; }
            const UBiDiLevel* levels = ubidi_getLevels(bidi, &status);
            bool ok = U_SUCCESS(status) && levels != nullptr;
            bool levelsExact = true;
            std::string why;
            for (size_t i = 0; ok && i < levelToks.size(); i++) {
                if (levelToks[i] == "x") continue;
                if (levels[i] != std::atoi(levelToks[i].c_str())) {
                    levelsExact = false;
                    why = "level at " + std::to_string(i) + ": icu " + std::to_string(levels[i])
                        + " expected " + levelToks[i];
                }
            }
            bool orderOk = ok;
            if (ok) {
                int32_t length = ubidi_getProcessedLength(bidi);
                std::vector<int32_t> visual(static_cast<size_t>(length) + 1);
                ubidi_getVisualMap(bidi, visual.data(), &status);
                if (U_FAILURE(status)) orderOk = false;
                std::vector<std::string> icuOrder;
                for (int32_t v = 0; orderOk && v < length; v++) {
                    int32_t logical = visual[static_cast<size_t>(v)];
                    if (levelToks[static_cast<size_t>(logical)] == "x") continue;
                    icuOrder.push_back(std::to_string(logical));
                }
                if (icuOrder != orderToks) {
                    orderOk = false;
                    why = "order: icu";
                    for (const std::string& t : icuOrder) why += " " + t;
                }
            }
            if (ok && orderOk && levelsExact) {
                r.passed++;
            } else {
                r.failed++;
                if (ok && orderOk) r.levelsDifferSameOrder++;
                else dumpFailure("BidiTest", body + " [" + paraNames[k] + "]", why, printed);
            }
        }
    }
    ubidi_close(bidi);
    return r;
}

// ── IdnaTestV2.txt ──────────────────────────────────────────────────────────

std::string utf8Of(const std::vector<UChar>& units) {
    std::string out;
    int32_t i = 0;
    int32_t n = static_cast<int32_t>(units.size());
    while (i < n) {
        UChar32 c;
        U16_NEXT(units.data(), i, n, c);
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

// The test file writes non-ASCII as literal UTF-8 and escapes a few code
// points as \uXXXX; both forms occur.
std::vector<UChar> idnaField(const std::string& field) {
    std::string s = trim(field);
    std::string unescaped;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\\' && i + 5 < s.size() + 0 && s[i + 1] == 'u') {
            UChar32 cp = static_cast<UChar32>(std::strtoul(s.substr(i + 2, 4).c_str(), nullptr, 16));
            std::vector<UChar> units = toUtf16({cp});
            unescaped += utf8Of(units);
            i += 6;
        } else {
            unescaped.push_back(s[i]);
            i++;
        }
    }
    std::vector<UChar> out(unescaped.size() + 1);
    UErrorCode status = U_ZERO_ERROR;
    int32_t len = 0;
    u_strFromUTF8(out.data(), static_cast<int32_t>(out.size()), &len, unescaped.data(),
                  static_cast<int32_t>(unescaped.size()), &status);
    if (U_FAILURE(status)) return {};
    out.resize(static_cast<size_t>(len));
    return out;
}

bool statusHasError(const std::string& field) {
    std::string s = trim(field);
    if (s.empty() || s == "[]") return false;
    return true;
}

SuiteResult runIdna(const std::string& path) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    UIDNA* nontrans = uidna_openUTS46(UIDNA_USE_STD3_RULES | UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ
                                          | UIDNA_NONTRANSITIONAL_TO_ASCII | UIDNA_NONTRANSITIONAL_TO_UNICODE,
                                      &status);
    UIDNA* trans = uidna_openUTS46(UIDNA_USE_STD3_RULES | UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ, &status);
    if (U_FAILURE(status) || nontrans == nullptr || trans == nullptr) {
        r.skippedWhy = "UTS #46 instances unavailable";
        return r;
    }
    std::ifstream in(path);
    std::string line;
    long printed = 0;
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty()) continue;
        std::vector<std::string> f = splitOn(body, ';');
        if (f.size() < 7) continue;
        r.total++;
        std::vector<UChar> source = idnaField(f[0]);
        std::string toUnicodeExpected = trim(f[1]).empty() ? trim(f[0]) : trim(f[1]);
        std::string toUnicodeStatus = trim(f[2]);
        std::string toAsciiNExpected = trim(f[3]).empty() ? toUnicodeExpected : trim(f[3]);
        std::string toAsciiNStatus = trim(f[4]).empty() ? toUnicodeStatus : trim(f[4]);
        std::string toAsciiTExpected = trim(f[5]).empty() ? toAsciiNExpected : trim(f[5]);
        std::string toAsciiTStatus = trim(f[6]).empty() ? toAsciiNStatus : trim(f[6]);

        auto judge = [&](UIDNA* idna, bool toAscii, const std::string& expected,
                         const std::string& statusField) -> bool {
            std::vector<UChar> out(source.size() * 4 + 64);
            UIDNAInfo info = UIDNA_INFO_INITIALIZER;
            UErrorCode st = U_ZERO_ERROR;
            int32_t len = toAscii
                ? uidna_nameToASCII(idna, source.data(), static_cast<int32_t>(source.size()), out.data(),
                                    static_cast<int32_t>(out.size()), &info, &st)
                : uidna_nameToUnicode(idna, source.data(), static_cast<int32_t>(source.size()), out.data(),
                                      static_cast<int32_t>(out.size()), &info, &st);
            if (U_FAILURE(st)) return false;
            out.resize(static_cast<size_t>(len));
            std::string got = utf8Of(out);
            bool expectError = statusHasError(statusField);
            bool gotError = info.errors != 0;
            if (expectError != gotError) return false;
            if (expectError) return true;  // the file publishes no result string on error rows
            std::string expectedText = utf8Of(idnaField(expected));
            return got == expectedText;
        };
        bool ok = judge(nontrans, false, toUnicodeExpected, toUnicodeStatus)
               && judge(nontrans, true, toAsciiNExpected, toAsciiNStatus)
               && judge(trans, true, toAsciiTExpected, toAsciiTStatus);
        if (ok) {
            r.passed++;
        } else {
            r.failed++;
            dumpFailure("IdnaTestV2", body, "a column's result or error status differs", printed);
        }
    }
    uidna_close(nontrans);
    uidna_close(trans);
    return r;
}

// ── CollationTest_*_SHORT.txt ───────────────────────────────────────────────

SuiteResult runCollation(const std::string& path, UColAttributeValue alternate) {
    SuiteResult r;
    UErrorCode status = U_ZERO_ERROR;
    UCollator* coll = ucol_open("root", &status);
    if (U_FAILURE(status) || coll == nullptr) {
        r.skippedWhy = "root collator unavailable";
        return r;
    }
    ucol_setAttribute(coll, UCOL_STRENGTH, UCOL_IDENTICAL, &status);
    ucol_setAttribute(coll, UCOL_ALTERNATE_HANDLING, alternate, &status);
    std::ifstream in(path);
    std::string line;
    std::vector<UChar> previous;
    std::string previousBody;
    bool havePrevious = false;
    long printed = 0;
    const char* name = alternate == UCOL_SHIFTED ? "CollationTest_SHIFTED_SHORT"
                                                 : "CollationTest_NON_IGNORABLE_SHORT";
    while (std::getline(in, line)) {
        std::string body = trim(stripComment(line));
        if (body.empty()) continue;
        std::vector<UChar> current = toUtf16(parseHexSequence(body));
        if (havePrevious) {
            r.total++;
            UCollationResult order = ucol_strcoll(coll, previous.data(), static_cast<int32_t>(previous.size()),
                                                  current.data(), static_cast<int32_t>(current.size()));
            if (order != UCOL_GREATER) {
                r.passed++;
            } else {
                r.failed++;
                dumpFailure(name, previousBody + "  <  " + body, "icu sorts the earlier line after the later one", printed);
            }
        }
        previous = current;
        previousBody = body;
        havePrevious = true;
    }
    ucol_close(coll);
    return r;
}

void emit(std::ostringstream& out, const char* name, const SuiteResult& r, bool& first) {
    if (!first) out << ",\n";
    first = false;
    out << "    \"" << name << "\": {\"total\": " << r.total << ", \"passed\": " << r.passed
        << ", \"failed\": " << r.failed << ", \"skipped\": " << r.skipped;
    if (r.levelsDifferSameOrder > 0) {
        out << ", \"levels_differ_same_order\": " << r.levelsDifferSameOrder;
    }
    if (!r.skippedWhy.empty()) out << ", \"skipped_why\": \"" << r.skippedWhy << "\"";
    out << "}";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        std::fprintf(stderr, "usage: icu_conformance <Unicode/Ucd directory> [failures-to-print-per-suite]\n");
        return 2;
    }
    std::string dir = argv[1];
    if (argc == 3) gDumpFailures = std::atol(argv[2]);
    UVersionInfo icuVersion;
    UVersionInfo unicodeVersion;
    char icuVersionText[U_MAX_VERSION_STRING_LENGTH];
    char unicodeVersionText[U_MAX_VERSION_STRING_LENGTH];
    u_getVersion(icuVersion);
    u_versionToString(icuVersion, icuVersionText);
    u_getUnicodeVersion(unicodeVersion);
    u_versionToString(unicodeVersion, unicodeVersionText);

    std::ostringstream out;
    out << "{\n  \"icu_version\": \"" << icuVersionText << "\",\n";
    out << "  \"icu_unicode_version\": \"" << unicodeVersionText << "\",\n";
    out << "  \"suites\": {\n";
    bool first = true;
    emit(out, "BidiTest", runBidiTest(dir + "/BidiTest.txt"), first);
    emit(out, "BidiCharacterTest", runBidiCharacter(dir + "/BidiCharacterTest.txt"), first);
    emit(out, "NormalizationTest", runNormalization(dir + "/NormalizationTest.txt"), first);
    emit(out, "GraphemeBreakTest",
         runBreak("GraphemeBreakTest", dir + "/GraphemeBreakTest.txt", UBRK_CHARACTER), first);
    emit(out, "WordBreakTest", runBreak("WordBreakTest", dir + "/WordBreakTest.txt", UBRK_WORD), first);
    emit(out, "SentenceBreakTest",
         runBreak("SentenceBreakTest", dir + "/SentenceBreakTest.txt", UBRK_SENTENCE), first);
    emit(out, "LineBreakTest", runBreak("LineBreakTest", dir + "/LineBreakTest.txt", UBRK_LINE), first);
    emit(out, "IdnaTestV2", runIdna(dir + "/IdnaTestV2.txt"), first);
    emit(out, "CollationTest_NON_IGNORABLE_SHORT",
         runCollation(dir + "/CollationTest_NON_IGNORABLE_SHORT.txt", UCOL_NON_IGNORABLE), first);
    emit(out, "CollationTest_SHIFTED_SHORT",
         runCollation(dir + "/CollationTest_SHIFTED_SHORT.txt", UCOL_SHIFTED), first);
    out << "\n  }\n}\n";
    std::fputs(out.str().c_str(), stdout);
    return 0;
}
