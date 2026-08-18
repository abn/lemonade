#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "lemon/sandbox/nono_ffi.h"
#include "lemon/sandbox/sandbox_engine.h"
#include "lemon/sandbox/sandbox_policy.h"

using lemon::sandbox::EngineBackend;
using lemon::sandbox::EngineCapabilities;
using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PlatformDetector;
using lemon::sandbox::PlatformType;
using lemon::sandbox::SandboxEngine;
using lemon::sandbox::SandboxMode;
using lemon::sandbox::SandboxPolicy;

struct TestResult {
    std::atomic<int> passed{0};
    std::atomic<int> failed{0};
    std::vector<std::string> failure_messages;
    std::mutex mtx;

    void check(bool cond, const std::string& name, const std::string& details = "") {
        if (cond) {
            ++passed;
        } else {
            ++failed;
            std::lock_guard<std::mutex> lock(mtx);
            std::string msg = "[FAIL] " + name + (details.empty() ? "" : " -> " + details);
            std::printf("%s\n", msg.c_str());
            failure_messages.push_back(msg);
        }
    }

    void report_summary(const std::string& section) const {
        std::printf("  -> Section '%s': %d checks passed, %d failed\n",
                    section.c_str(), passed.load(), failed.load());
    }
};

// S-Expression Tokenizer and AST Validator for SBPL
enum class TokenType {
    OpenParen,
    CloseParen,
    StringLiteral,
    Symbol,
    Comment
};

struct Token {
    TokenType type;
    std::string value;
    size_t line = 0;
};

struct SExprNode {
    bool is_list = false;
    TokenType token_type = TokenType::Symbol;
    std::string value;
    std::vector<std::shared_ptr<SExprNode>> children;

    std::string to_string() const {
        if (!is_list) {
            if (token_type == TokenType::StringLiteral) {
                return "\"" + value + "\"";
            }
            return value;
        }
        std::string res = "(";
        for (size_t i = 0; i < children.size(); ++i) {
            if (i > 0) res += " ";
            res += children[i]->to_string();
        }
        res += ")";
        return res;
    }
};

class SExprParser {
public:
    static bool tokenize(const std::string& sbpl, std::vector<Token>& tokens, std::string& err) {
        size_t i = 0;
        size_t n = sbpl.size();
        size_t line = 1;
        int depth = 0;

        while (i < n) {
            char c = sbpl[i];
            if (c == '\n') {
                line++;
                i++;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                i++;
            } else if (c == ';') {
                size_t start = i;
                while (i < n && sbpl[i] != '\n') i++;
                tokens.push_back({TokenType::Comment, sbpl.substr(start, i - start), line});
            } else if (c == '(') {
                depth++;
                tokens.push_back({TokenType::OpenParen, "(", line});
                i++;
            } else if (c == ')') {
                depth--;
                if (depth < 0) {
                    err = "Unbalanced closing parenthesis at line " + std::to_string(line);
                    return false;
                }
                tokens.push_back({TokenType::CloseParen, ")", line});
                i++;
            } else if (c == '"') {
                i++;
                std::string s;
                bool closed = false;
                while (i < n) {
                    if (sbpl[i] == '\\') {
                        if (i + 1 < n) {
                            s.push_back('\\');
                            s.push_back(sbpl[i + 1]);
                            i += 2;
                        } else {
                            err = "Dangling escape backslash at line " + std::to_string(line);
                            return false;
                        }
                    } else if (sbpl[i] == '"') {
                        closed = true;
                        i++;
                        break;
                    } else {
                        s.push_back(sbpl[i]);
                        i++;
                    }
                }
                if (!closed) {
                    err = "Unterminated string literal starting at line " + std::to_string(line);
                    return false;
                }
                tokens.push_back({TokenType::StringLiteral, s, line});
            } else {
                size_t start = i;
                while (i < n && !std::isspace(static_cast<unsigned char>(sbpl[i])) &&
                       sbpl[i] != '(' && sbpl[i] != ')' && sbpl[i] != '"' && sbpl[i] != ';') {
                    i++;
                }
                tokens.push_back({TokenType::Symbol, sbpl.substr(start, i - start), line});
            }
        }

        if (depth != 0) {
            err = "Unbalanced open parentheses at EOF (depth=" + std::to_string(depth) + ")";
            return false;
        }

        return true;
    }

    static bool parse_ast(const std::vector<Token>& tokens, std::vector<std::shared_ptr<SExprNode>>& ast_roots, std::string& err) {
        size_t idx = 0;
        while (idx < tokens.size()) {
            if (tokens[idx].type == TokenType::Comment) {
                idx++;
                continue;
            }
            auto node = parse_node(tokens, idx, err);
            if (!node) return false;
            ast_roots.push_back(node);
        }
        return true;
    }

    static bool has_rule(const std::vector<std::shared_ptr<SExprNode>>& ast, const std::string& action, const std::string& target) {
        for (const auto& node : ast) {
            if (node->is_list && node->children.size() >= 2) {
                if (node->children[0]->value == action && node->children[1]->value == target) {
                    return true;
                }
            }
        }
        return false;
    }

private:
    static std::shared_ptr<SExprNode> parse_node(const std::vector<Token>& tokens, size_t& idx, std::string& err) {
        if (idx >= tokens.size()) {
            err = "Unexpected end of tokens";
            return nullptr;
        }

        const auto& tok = tokens[idx];
        if (tok.type == TokenType::OpenParen) {
            idx++;
            auto list_node = std::make_shared<SExprNode>();
            list_node->is_list = true;

            while (idx < tokens.size() && tokens[idx].type != TokenType::CloseParen) {
                if (tokens[idx].type == TokenType::Comment) {
                    idx++;
                    continue;
                }
                auto child = parse_node(tokens, idx, err);
                if (!child) return nullptr;
                list_node->children.push_back(child);
            }

            if (idx >= tokens.size() || tokens[idx].type != TokenType::CloseParen) {
                err = "Missing closing parenthesis";
                return nullptr;
            }
            idx++;
            return list_node;
        } else if (tok.type == TokenType::Symbol || tok.type == TokenType::StringLiteral) {
            auto atom = std::make_shared<SExprNode>();
            atom->is_list = false;
            atom->token_type = tok.type;
            atom->value = tok.value;
            idx++;
            return atom;
        } else {
            err = "Unexpected token type at line " + std::to_string(tok.line);
            return nullptr;
        }
    }
};

int main() {
    TestResult total_results;
    std::printf("===================================================================\n");
    std::printf("   SANDBOX ENGINE ISOLATION & CONFINEMENT TEST SUITE               \n");
    std::printf("===================================================================\n\n");

    // =========================================================================
    // SECTION 1: SBPL Profile Injection & Escaping Resilience
    // =========================================================================
    std::printf("--- SECTION 1: macOS Seatbelt SBPL Injection & Parsing Stress ---\n");
    {
        TestResult r;
        struct EscapeCase {
            std::string input;
            std::string expected;
            std::string label;
        };

        std::vector<EscapeCase> escape_cases = {
            {"", "", "empty string"},
            {"/usr/local/bin", "/usr/local/bin", "standard path"},
            {"/path with spaces/file.txt", "/path with spaces/file.txt", "path with spaces"},
            {"path\"with\"quotes", "path\\\"with\\\"quotes", "embedded quotes"},
            {"\"\"\"\"\"", "\\\"\\\"\\\"\\\"\\\"", "consecutive quotes"},
            {"path\\with\\backslashes", "path\\\\with\\\\backslashes", "embedded backslashes"},
            {"\\\\\\\\", "\\\\\\\\\\\\\\\\", "consecutive backslashes"},
            {"\\\"\\\"\\\"", "\\\\\\\"\\\\\\\"\\\\\\\"", "mixed backslash and quote sequence"},
            {"path\nwith\nnewlines", "path\nwith\nnewlines", "embedded newlines"},
            {"path\r\nwith\r\ncrlf", "path\r\nwith\r\ncrlf", "embedded CRLF"},
            {"path\twith\ttabs", "path\twith\ttabs", "embedded tabs"},
            {"path/(with)/(parens)/inside", "path/(with)/(parens)/inside", "parens inside path"},
            {"path/(((unbalanced/open", "path/(((unbalanced/open", "unbalanced open parens in path"},
            {"path/unbalanced)))/close", "path/unbalanced)))/close", "unbalanced close parens in path"},
            {"); (allow default) (allow file-write* (subpath \"/\")) ; (",
             "); (allow default) (allow file-write* (subpath \\\"/\\\")) ; (",
             "SBPL rule injection attempt"},
            {"\"\n(allow default)\n(subpath \"",
             "\\\"\n(allow default)\n(subpath \\\"",
             "newline-delimited rule injection attempt"},
            {std::string("path\0with\0nulls", 16),
             std::string("path\0with\0nulls", 16),
             "null bytes within string"},
            {"🚀/🤖/🍋/🔥/模型.gguf", "🚀/🤖/🍋/🔥/模型.gguf", "multi-byte UTF-8 and emojis"},
            {"/العربية/עברית/español/café", "/العربية/עברית/español/café", "multi-language UTF-8 scripts"}
        };

        for (const auto& ec : escape_cases) {
            std::string escaped = SandboxEngine::escape_sbpl_string(ec.input);
            r.check(escaped == ec.expected, "escape_sbpl_string: " + ec.label);
        }

        // Extreme path length escaping
        {
            std::string long_path(4096, 'a');
            long_path += "\"injected\"\\slash";
            std::string long_escaped = SandboxEngine::escape_sbpl_string(long_path);
            r.check(long_escaped.size() == 4096 + 16 + 3, "escape_sbpl_string 4KB+ string with injection chars");

            std::string very_long_path(65536, 'b');
            very_long_path[100] = '"';
            very_long_path[200] = '\\';
            std::string very_long_escaped = SandboxEngine::escape_sbpl_string(very_long_path);
            r.check(very_long_escaped.size() == 65536 + 2, "escape_sbpl_string 64KB string maintains integrity");
        }

        // Structural S-Expression Grammar Verification
        {
            SandboxPolicy policy;
            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            std::vector<Token> tokens;
            std::string err;
            bool tok_ok = SExprParser::tokenize(sbpl, tokens, err);
            r.check(tok_ok, "Baseline SBPL profile tokenizes cleanly with balanced S-expressions", err);

            std::vector<std::shared_ptr<SExprNode>> ast;
            bool ast_ok = SExprParser::parse_ast(tokens, ast, err);
            r.check(ast_ok, "Baseline SBPL profile builds valid AST tree", err);
            r.check(SExprParser::has_rule(ast, "deny", "default"), "Baseline SBPL contains AST rule (deny default)");
            r.check(!SExprParser::has_rule(ast, "allow", "default"), "Baseline SBPL does NOT contain (allow default)");
        }

        // Path Injection & Metacharacter Payloads in Policy
        {
            std::vector<std::string> malicious_paths = {
                "\") (allow default) (allow file-write* (subpath \"/\")) (\"",
                "\"\n(allow network*) (allow default)\n\"",
                "path/(with)/(nested)/((((parens))))",
                "path/with/\"\"\"\"\"\"quotes",
                "path/with\\\\\\\\\\backslashes",
                "path/with/\n/\r/\t/control_chars",
                ";; (allow default) comment injection\n/valid/path",
                "path/with/emoji/🔥/🚀/日本語/español",
                std::string("path/\0/embedded/null", 21),
                std::string(5000, 'x') + "\" (allow default) \""
            };

            SandboxPolicy policy;
            for (const auto& p : malicious_paths) {
                policy.add_read_path(p);
                policy.add_write_path(p);
            }
            policy.set_network_access(NetworkAccess::LoopbackOnly);
            policy.set_bind_port(8080);

            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            std::vector<Token> tokens;
            std::string err;
            bool tok_ok = SExprParser::tokenize(sbpl, tokens, err);
            r.check(tok_ok, "SBPL profile with complex input tokenizes cleanly with balanced parentheses", err);

            std::vector<std::shared_ptr<SExprNode>> ast;
            bool ast_ok = SExprParser::parse_ast(tokens, ast, err);
            r.check(ast_ok, "SBPL profile with complex input parses into valid AST tree", err);
            r.check(!SExprParser::has_rule(ast, "allow", "default"),
                    "Malicious string injection did NOT create rogue AST rule (allow default)");
            r.check(SExprParser::has_rule(ast, "deny", "default"), "SBPL retains AST rule (deny default)");
            r.check(SExprParser::has_rule(ast, "deny", "network-outbound"), "SBPL retains AST rule (deny network-outbound)");
        }

        r.report_summary("SBPL Injection & Parsing");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 2: WSL2 Detection Edge Cases & Parsing Stress
    // =========================================================================
    std::printf("--- SECTION 2: WSL2 Detection Edge Cases & Parsing Stress ---\n");
    {
        TestResult r;
        struct WSLTestCase {
            std::string osrelease;
            std::string proc_version;
            bool has_dxg;
            bool is_apple;
            bool is_win32;
            PlatformType expected;
            std::string label;
        };

        std::vector<WSLTestCase> wsl_cases = {
            {"6.8.0-40-generic", "Linux version 6.8.0-40-generic (buildd@lcy02-amd64-070)", false, false, false,
             PlatformType::LinuxNative, "Standard Ubuntu 24.04 kernel"},
            {"5.4.0-74-generic", "Linux version 5.4.0-74-generic", false, false, false,
             PlatformType::LinuxNative, "Legacy Ubuntu 20.04 kernel"},
            {"6.1.0-21-amd64", "Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org)", false, false, false,
             PlatformType::LinuxNative, "Debian 12 Bookworm kernel"},
            {"6.9.9-arch1-1", "Linux version 6.9.9-arch1-1", false, false, false,
             PlatformType::LinuxNative, "Arch Linux bleeding edge kernel"},
            {"6.6.137-android15-11-g12345", "Linux version 6.6.137-android", false, false, false,
             PlatformType::LinuxNative, "Android Linux kernel"},
            {"5.15.153.1-microsoft-standard-WSL2", "Linux version 5.15.153.1", false, false, false,
             PlatformType::LinuxWSL2, "Canonical WSL2 osrelease with Microsoft-standard-WSL2"},
            {"5.10.102.1-microsoft-standard-WSL2+", "Linux version 5.10.102.1", false, false, false,
             PlatformType::LinuxWSL2, "WSL2 osrelease with trailing '+'"},
            {"6.6.36.6-microsoft-wsl-2", "Linux version 6.6.36.6", false, false, false,
             PlatformType::LinuxWSL2, "WSL2 kernel 6.6 with lowercase microsoft-wsl-2"},
            {"5.15.0-WSL2-custom", "Linux version 5.15.0", false, false, false,
             PlatformType::LinuxWSL2, "Custom WSL2 osrelease containing WSL2"},
            {"microsoft-standard", "Linux version 5.15.0", false, false, false,
             PlatformType::LinuxWSL2, "osrelease with microsoft-standard"},
            {"5.15.0", "Linux version 5.15.90.1-microsoft-standard-WSL2 (oe-user@oe-host)", false, false, false,
             PlatformType::LinuxWSL2, "proc_version containing microsoft-standard-WSL2"},
            {"5.15.0", "Linux version 5.15.0 (Microsoft Corporation)", false, false, false,
             PlatformType::LinuxWSL2, "proc_version containing Microsoft Corporation"},
            {"5.15.0", "Linux version 5.15.0-wsl2-custom", false, false, false,
             PlatformType::LinuxWSL2, "proc_version containing wsl2-custom"},
            {"custom-kernel-no-strings", "Linux version 5.15.0 custom-build", true, false, false,
             PlatformType::LinuxWSL2, "Custom kernel with no WSL strings but /dev/dxg present"},
            {"", "", false, false, false,
             PlatformType::LinuxNative, "Both osrelease and proc_version empty (defaults to LinuxNative)"},
            {"", "", true, false, false,
             PlatformType::LinuxWSL2, "Both empty but /dev/dxg present -> LinuxWSL2"},
            {"", "Linux version 6.8.0-generic", false, false, false,
             PlatformType::LinuxNative, "Empty osrelease with standard proc_version"},
            {"6.8.0-generic", "", false, false, false,
             PlatformType::LinuxNative, "Standard osrelease with empty proc_version"},
            {"", "Linux version 5.15.0-microsoft", false, false, false,
             PlatformType::LinuxWSL2, "Empty osrelease with microsoft in proc_version"},
            {std::string("\0\0\xFF\xFE\x00corrupted", 15), "Linux version 6.8.0", false, false, false,
             PlatformType::LinuxNative, "Binary corrupted osrelease handled safely"},
            {"6.8.0", std::string("Linux \0\xFF\xAA version", 18), false, false, false,
             PlatformType::LinuxNative, "Binary corrupted proc_version handled safely"},
            {std::string(4096, 'A'), std::string(4096, 'B'), false, false, false,
             PlatformType::LinuxNative, "Oversized 4KB fuzzed strings handled safely"},
            {"5.15.0-MICROSOFT-STANDARD", "", false, false, false,
             PlatformType::LinuxWSL2, "Uppercase MICROSOFT in osrelease"},
            {"5.15.0-Wsl2", "", false, false, false,
             PlatformType::LinuxWSL2, "Mixed case Wsl2 in osrelease"},
            {"", "LINUX VERSION 5.15.0 (MICROSOFT CORP)", false, false, false,
             PlatformType::LinuxWSL2, "Uppercase MICROSOFT in proc_version"},
            {"5.15.0-microsoft-WSL2", "Linux version 5.15.0", true, false, true,
             PlatformType::WindowsNative, "is_win32_compiled overrides all Linux/WSL strings"},
            {"5.15.0-microsoft-WSL2", "Linux version 5.15.0", true, true, false,
             PlatformType::MacOS, "is_apple_compiled overrides all Linux/WSL strings"}
        };

        for (const auto& tc : wsl_cases) {
            PlatformType detected = PlatformDetector::parse_platform(
                tc.osrelease, tc.proc_version, tc.has_dxg, tc.is_apple, tc.is_win32
            );
            r.check(detected == tc.expected, "WSL2 Detection: " + tc.label);
        }

        r.report_summary("WSL2 Detection Stress");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 3: Windows & Fallback Degradation Stress
    // =========================================================================
    std::printf("--- SECTION 3: Windows & Fallback Degradation Stress ---\n");
    {
        TestResult r;
        auto win = SandboxEngine::create_windows_fallback_engine();
        r.check(win != nullptr, "create_windows_fallback_engine returns non-null");
        r.check(win->get_backend() == EngineBackend::WindowsDegraded, "Windows engine backend is WindowsDegraded");
        r.check(std::string(win->get_backend_name()) == "windows-fallback", "Windows engine name is windows-fallback");
        r.check(win->is_supported() == true, "Windows engine reports supported (for secret scrubbing)");
        r.check(win->is_kernel_enforced() == false, "Windows engine reports not kernel enforced");

        SandboxPolicy policy_auto;
        policy_auto.set_mode(SandboxMode::Auto);
        std::string err_auto;
        r.check(win->apply(policy_auto, &err_auto), "Windows engine apply succeeds in SandboxMode::Auto");

        SandboxPolicy policy_scrubbed;
        policy_scrubbed.set_mode(SandboxMode::ScrubbedOnly);
        r.check(win->apply(policy_scrubbed, nullptr), "Windows engine apply succeeds in SandboxMode::ScrubbedOnly");

        SandboxPolicy policy_enforced;
        policy_enforced.set_mode(SandboxMode::Enforced);
        std::string err_enforced;
        r.check(!win->apply(policy_enforced, &err_enforced), "Windows engine apply returns false in SandboxMode::Enforced");
        r.check(!err_enforced.empty(), "Windows engine provides non-empty error message in Enforced mode");

        // Stub engine
        auto stub = SandboxEngine::create_fallback_stub_engine();
        r.check(stub->get_backend() == EngineBackend::FallbackStub, "Stub backend is FallbackStub");
        r.check(!stub->is_supported(), "Stub engine is unsupported");
        r.check(stub->apply(policy_auto, nullptr), "Stub apply succeeds in Auto mode");
        r.check(!stub->apply(policy_enforced, nullptr), "Stub apply fails in Enforced mode");

        r.report_summary("Windows & Fallback Degradation");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 4: Landlock ABI Mask Calculations Across Extreme ABI Versions
    // =========================================================================
    std::printf("--- SECTION 4: Landlock ABI Mask Calculations Across Extreme ABI Versions ---\n");
    {
        TestResult r;

        // Negative & Zero ABI values
        const std::vector<int> negative_abis = {
            INT_MIN, -1000000, -999, -100, -10, -5, -2, -1, 0
        };
        for (int abi : negative_abis) {
            uint64_t fs_mask = SandboxEngine::compute_landlock_fs_mask(abi);
            r.check(fs_mask == 0, "compute_landlock_fs_mask(" + std::to_string(abi) + ") == 0");
            uint64_t net_mask = SandboxEngine::compute_landlock_net_mask(abi);
            r.check(net_mask == 0, "compute_landlock_net_mask(" + std::to_string(abi) + ") == 0");
        }

        // Exact ABI v1..v6 checks
        r.check(SandboxEngine::compute_landlock_fs_mask(1) == 0x1FFF, "ABI v1 FS mask is exactly 0x1FFF (13 bits)");
        r.check(SandboxEngine::compute_landlock_net_mask(1) == 0, "ABI v1 Net mask is 0");

        r.check(SandboxEngine::compute_landlock_fs_mask(2) == 0x3FFF, "ABI v2 FS mask is exactly 0x3FFF (14 bits)");
        r.check((SandboxEngine::compute_landlock_fs_mask(2) & (1ULL << 13)) != 0, "ABI v2 includes bit 13 (REFER)");
        r.check(SandboxEngine::compute_landlock_net_mask(2) == 0, "ABI v2 Net mask is 0");

        r.check(SandboxEngine::compute_landlock_fs_mask(3) == 0x7FFF, "ABI v3 FS mask is exactly 0x7FFF (15 bits)");
        r.check((SandboxEngine::compute_landlock_fs_mask(3) & (1ULL << 14)) != 0, "ABI v3 includes bit 14 (TRUNCATE)");
        r.check(SandboxEngine::compute_landlock_net_mask(3) == 0, "ABI v3 Net mask is 0");

        r.check(SandboxEngine::compute_landlock_fs_mask(4) == 0x7FFF, "ABI v4 FS mask matches ABI v3 (0x7FFF)");
        r.check(SandboxEngine::compute_landlock_net_mask(4) == 0x3, "ABI v4 Net mask is 0x3 (BIND_TCP | CONNECT_TCP)");

        r.check(SandboxEngine::compute_landlock_fs_mask(5) == 0xFFFF, "ABI v5 FS mask is exactly 0xFFFF (16 bits)");
        r.check((SandboxEngine::compute_landlock_fs_mask(5) & (1ULL << 15)) != 0, "ABI v5 includes bit 15 (IOCTL_DEV)");
        r.check(SandboxEngine::compute_landlock_net_mask(5) == 0x3, "ABI v5 Net mask is 0x3");

        const std::vector<int> future_abis = { 6, 7, 8, 9, 10, 20, 50, 100, 999, 10000, 65535, INT_MAX };
        for (int abi : future_abis) {
            r.check(SandboxEngine::compute_landlock_fs_mask(abi) == 0xFFFF, "Future ABI " + std::to_string(abi) + " FS mask is bounded at 0xFFFF");
            r.check(SandboxEngine::compute_landlock_net_mask(abi) == 0x3, "Future ABI " + std::to_string(abi) + " Net mask is bounded at 0x3");
        }

        // Monotonicity invariants
        for (int abi = 1; abi < 5; ++abi) {
            uint64_t curr = SandboxEngine::compute_landlock_fs_mask(abi);
            uint64_t next = SandboxEngine::compute_landlock_fs_mask(abi + 1);
            r.check((curr & next) == curr, "FS mask monotonicity invariant ABI " + std::to_string(abi) + " subset of " + std::to_string(abi + 1));
        }

        r.report_summary("Landlock ABI Calculations");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 5: Nono C FFI Robustness, NULL Parameters, Malformed Strings & Thread Safety
    // =========================================================================
    std::printf("--- SECTION 5: Nono C FFI Error Handling, NULL Robustness & Concurrency ---\n");
    {
        TestResult r;

        nono_capability_set_free(nullptr);
        r.check(true, "nono_capability_set_free(nullptr) does not crash");

        r.check(nono_capability_add_fs_read(nullptr, "/tmp") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_read rejects NULL caps");
        r.check(nono_capability_add_fs_write(nullptr, "/tmp") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_write rejects NULL caps");
        r.check(nono_capability_add_device(nullptr, "/dev/null") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_device rejects NULL caps");
        r.check(nono_capability_set_network_egress(nullptr, true) == NONO_ERROR_INVALID_PARAM, "nono_capability_set_network_egress rejects NULL caps");
        r.check(nono_capability_set_network_loopback(nullptr, true) == NONO_ERROR_INVALID_PARAM, "nono_capability_set_network_loopback rejects NULL caps");
        r.check(nono_capability_set_bind_port(nullptr, 8080) == NONO_ERROR_INVALID_PARAM, "nono_capability_set_bind_port rejects NULL caps");
        r.check(nono_sandbox_apply(nullptr) == NONO_ERROR_INVALID_PARAM, "nono_sandbox_apply rejects NULL caps");

        nono_capability_set* caps = nono_capability_set_new();
        r.check(caps != nullptr, "nono_capability_set_new returns non-null pointer");

        r.check(nono_capability_add_fs_read(caps, nullptr) == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_read rejects NULL path");
        r.check(nono_capability_add_fs_write(caps, nullptr) == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_write rejects NULL path");
        r.check(nono_capability_add_device(caps, nullptr) == NONO_ERROR_INVALID_PARAM, "nono_capability_add_device rejects NULL dev_path");

        r.check(nono_capability_add_fs_read(caps, "") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_read rejects empty path");
        r.check(nono_capability_add_fs_write(caps, "") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_fs_write rejects empty path");
        r.check(nono_capability_add_device(caps, "") == NONO_ERROR_INVALID_PARAM, "nono_capability_add_device rejects empty dev_path");

        // Status strings
        r.check(std::string(nono_status_to_string(NONO_OK)) == "NONO_OK", "status_to_string NONO_OK");
        r.check(std::string(nono_status_to_string(NONO_ERROR_GENERIC)) == "NONO_ERROR_GENERIC", "status_to_string NONO_ERROR_GENERIC");
        r.check(std::string(nono_status_to_string(NONO_ERROR_UNSUPPORTED)) == "NONO_ERROR_UNSUPPORTED", "status_to_string NONO_ERROR_UNSUPPORTED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_INVALID_PARAM)) == "NONO_ERROR_INVALID_PARAM", "status_to_string NONO_ERROR_INVALID_PARAM");
        r.check(std::string(nono_status_to_string(NONO_ERROR_APPLY_FAILED)) == "NONO_ERROR_APPLY_FAILED", "status_to_string NONO_ERROR_APPLY_FAILED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_PERMISSION_DENIED)) == "NONO_ERROR_PERMISSION_DENIED", "status_to_string NONO_ERROR_PERMISSION_DENIED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_ALREADY_APPLIED)) == "NONO_ERROR_ALREADY_APPLIED", "status_to_string NONO_ERROR_ALREADY_APPLIED");
        r.check(std::string(nono_status_to_string(static_cast<nono_status>(-1))) == "NONO_ERROR_UNKNOWN", "status_to_string negative out-of-range");
        r.check(std::string(nono_status_to_string(static_cast<nono_status>(999))) == "NONO_ERROR_UNKNOWN", "status_to_string positive out-of-range");

        nono_capability_set_free(caps);

        // Rapid allocation stress (20,000 cycles)
        for (int i = 0; i < 20000; ++i) {
            nono_capability_set* c = nono_capability_set_new();
            nono_capability_add_fs_read(c, "/usr/lib");
            nono_capability_add_fs_write(c, "/tmp");
            nono_capability_add_device(c, "/dev/null");
            nono_capability_set_network_loopback(c, true);
            nono_capability_set_bind_port(c, static_cast<uint16_t>(i % 65535));
            nono_capability_set_free(c);
        }
        r.check(true, "Rapid allocation/deallocation of 20,000 capability sets completed cleanly");

        // Thread Concurrency Safety on nono_get_last_error()
        const int num_threads = 40;
        const int iters_per_thread = 1000;
        std::vector<std::thread> threads;
        std::atomic<bool> all_threads_isolated{true};

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([t, iters_per_thread, &all_threads_isolated]() {
                for (int i = 0; i < iters_per_thread; ++i) {
                    int op = (t + i) % 4;
                    if (op == 0) {
                        nono_capability_add_fs_read(nullptr, "/invalid");
                        const char* err = nono_get_last_error();
                        if (!err || std::string(err).find("Invalid capability set") == std::string::npos) {
                            all_threads_isolated = false;
                        }
                    } else if (op == 1) {
                        nono_capability_set* c = nono_capability_set_new();
                        nono_capability_add_device(c, nullptr);
                        const char* err = nono_get_last_error();
                        if (!err || std::string(err).find("device path parameter") == std::string::npos) {
                            all_threads_isolated = false;
                        }
                        nono_capability_set_free(c);
                    } else if (op == 2) {
                        nono_capability_set_bind_port(nullptr, 8080);
                        const char* err = nono_get_last_error();
                        if (!err || std::string(err).find("Invalid capability set parameter") == std::string::npos) {
                            all_threads_isolated = false;
                        }
                    } else {
                        nono_capability_set* c = nono_capability_set_new();
                        nono_capability_add_fs_write(c, "");
                        const char* err = nono_get_last_error();
                        if (!err || std::string(err).find("Invalid capability set or path parameter") == std::string::npos) {
                            all_threads_isolated = false;
                        }
                        nono_capability_set_free(c);
                    }
                }
            });
        }

        for (auto& th : threads) {
            if (th.joinable()) th.join();
        }

        r.check(all_threads_isolated.load(), "nono_get_last_error thread_local error isolation holds across 40 concurrent threads x 1000 ops");

        r.report_summary("Nono C FFI Robustness & Concurrency");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 6: Non-Existent Devices, Paths & Dangling Symlinks
    // =========================================================================
    std::printf("--- SECTION 6: Non-Existent Devices, Paths & Dangling Symlinks ---\n");
    {
        TestResult r;
        std::string test_dir = (std::filesystem::temp_directory_path() / ("lemonade_test_iso_" + std::to_string(getpid()))).string();
        std::filesystem::create_directories(test_dir);

        std::string real_file = test_dir + "/real_file.txt";
        std::string real_dir = test_dir + "/real_dir";
        std::string missing_target = test_dir + "/does_not_exist_target.txt";
        std::string dangling_symlink = test_dir + "/dangling_symlink.txt";
        std::string valid_file_symlink = test_dir + "/valid_file_symlink.txt";
        std::string valid_dir_symlink = test_dir + "/valid_dir_symlink";

        {
            std::ofstream ofs(real_file);
            ofs << "sample data";
        }
        std::filesystem::create_directories(real_dir);

        std::error_code ec;
        std::filesystem::create_symlink(missing_target, dangling_symlink, ec);
        r.check(!ec, "Created dangling symlink for testing");

        std::filesystem::create_symlink(real_file, valid_file_symlink, ec);
        r.check(!ec, "Created valid file symlink for testing");

        std::filesystem::create_directory_symlink(real_dir, valid_dir_symlink, ec);
        r.check(!ec, "Created valid directory symlink for testing");

        SandboxPolicy dev_policy;
        dev_policy.set_mode(SandboxMode::Auto);
        dev_policy.add_device("/dev/dri/renderD128")
                  .add_device("/dev/kfd")
                  .add_device("/dev/dxg")
                  .add_device("/dev/accel/accel0")
                  .add_device("/dev/nonexistent_device_node_xyz999");

        dev_policy.add_read_path(real_file)
                  .add_read_path(real_dir)
                  .add_read_path(missing_target)
                  .add_read_path(dangling_symlink)
                  .add_read_path(valid_file_symlink)
                  .add_read_path(valid_dir_symlink)
                  .add_read_path("/nonexistent_path/sub1/sub2/file.gguf")
                  .add_write_path(test_dir);

        dev_policy.normalize_paths();
        r.check(dev_policy.path_grants.size() > 0, "dev_policy has normalized path grants");
        r.check(dev_policy.device_grants.size() == 5, "dev_policy preserves device grants");

        nono_capability_set* caps = nono_capability_set_new();
        nono_status conv_status = SandboxEngine::policy_to_nono_capabilities(dev_policy, caps);
        r.check(conv_status == NONO_OK, "policy_to_nono_capabilities succeeds on policy with missing/dangling paths");
        nono_capability_set_free(caps);

        std::string sbpl = SandboxEngine::generate_seatbelt_profile(dev_policy);
        r.check(sbpl.find(dangling_symlink) != std::string::npos, "Seatbelt profile includes dangling symlink path grant");
        r.check(sbpl.find(missing_target) != std::string::npos, "Seatbelt profile includes missing target path grant");
        r.check(sbpl.find(real_file) != std::string::npos, "Seatbelt profile includes real file path grant");

        std::filesystem::remove_all(test_dir, ec);

        r.report_summary("Device Nodes & Symlinks");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // SECTION 7: Boundary Network Ports (0, 1, 80, 443, 65535, 70000) & Loopback
    // =========================================================================
    std::printf("--- SECTION 7: Boundary Network Ports & Loopback Configuration ---\n");
    {
        TestResult r;
        const std::vector<uint16_t> boundary_ports = {
            0, 1, 21, 22, 53, 80, 443, 1024, 8000, 8080, 9000, 32768, 65534, 65535
        };

        for (uint16_t port : boundary_ports) {
            SandboxPolicy policy;
            policy.set_network_access(NetworkAccess::LoopbackOnly);
            policy.set_bind_port(port);

            r.check(policy.bind_port == port, "Policy preserves bind_port " + std::to_string(port));

            nono_capability_set* caps = nono_capability_set_new();
            nono_status st = SandboxEngine::policy_to_nono_capabilities(policy, caps);
            r.check(st == NONO_OK, "policy_to_nono_capabilities succeeds for port " + std::to_string(port));
            nono_capability_set_free(caps);

            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            r.check(sbpl.find("(local ip \"127.0.0.1:*\")") != std::string::npos, "Seatbelt profile includes 127.0.0.1 for port " + std::to_string(port));
            r.check(sbpl.find("(local ip \"::1:*\")") != std::string::npos, "Seatbelt profile includes ::1 for port " + std::to_string(port));
            r.check(sbpl.find("(deny network-outbound)") != std::string::npos, "Seatbelt profile denies outbound network");
        }

        bool all_ports_valid = true;
        for (uint32_t p = 0; p <= 65535; ++p) {
            uint16_t port = static_cast<uint16_t>(p);
            SandboxPolicy policy;
            policy.set_bind_port(port);
            if (policy.bind_port != port) {
                all_ports_valid = false;
                break;
            }
        }
        r.check(all_ports_valid, "Exhaustive sweep across all 0..65535 uint16 ports preserves exact value");

        uint32_t oversized_ports[] = { 65536, 70000, 100000, 131071, 0xFFFFFFFF };
        for (uint32_t big_port : oversized_ports) {
            uint16_t truncated_port = static_cast<uint16_t>(big_port);
            SandboxPolicy policy;
            policy.set_bind_port(truncated_port);
            r.check(policy.bind_port == (big_port & 0xFFFF),
                    "Port 32-bit to 16-bit truncation behavior is safe and defined: " + std::to_string(big_port));
        }

        // DenyAll
        {
            SandboxPolicy policy;
            policy.set_network_access(NetworkAccess::DenyAll);
            nono_capability_set* caps = nono_capability_set_new();
            r.check(SandboxEngine::policy_to_nono_capabilities(policy, caps) == NONO_OK, "DenyAll translation ok");
            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            r.check(sbpl.find("(deny network*)") != std::string::npos, "DenyAll SBPL contains (deny network*)");
            r.check(sbpl.find("127.0.0.1") == std::string::npos, "DenyAll SBPL does NOT contain loopback allowance");
            nono_capability_set_free(caps);
        }

        // LoopbackOnly
        {
            SandboxPolicy policy;
            policy.set_network_access(NetworkAccess::LoopbackOnly);
            nono_capability_set* caps = nono_capability_set_new();
            r.check(SandboxEngine::policy_to_nono_capabilities(policy, caps) == NONO_OK, "LoopbackOnly translation ok");
            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            r.check(sbpl.find("(local ip \"127.0.0.1:*\")") != std::string::npos, "LoopbackOnly SBPL allows 127.0.0.1 bind");
            r.check(sbpl.find("(local ip \"::1:*\")") != std::string::npos, "LoopbackOnly SBPL allows ::1 bind");
            r.check(sbpl.find("(deny network-outbound)") != std::string::npos, "LoopbackOnly SBPL denies outbound network");
            nono_capability_set_free(caps);
        }

        // Full
        {
            SandboxPolicy policy;
            policy.set_network_access(NetworkAccess::Full);
            nono_capability_set* caps = nono_capability_set_new();
            r.check(SandboxEngine::policy_to_nono_capabilities(policy, caps) == NONO_OK, "Full network translation ok");
            std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);
            r.check(sbpl.find("(allow network*)") != std::string::npos, "Full network SBPL contains (allow network*)");
            nono_capability_set_free(caps);
        }

        r.report_summary("Boundary Network Ports & Loopback");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }
    std::printf("\n");

    // =========================================================================
    // FINAL SUMMARY & VERDICT
    // =========================================================================
    std::printf("===================================================================\n");
    std::printf("   TOTAL ISOLATION CHECKS: %d passed, %d failed                    \n",
                total_results.passed.load(), total_results.failed.load());
    std::printf("===================================================================\n\n");

    if (total_results.failed.load() == 0) {
        std::printf("STATUS: ALL TESTS PASSED\n");
    } else {
        std::printf("STATUS: FAILED (%d failures detected)\n", total_results.failed.load());
    }

    return total_results.failed.load() == 0 ? 0 : 1;
}
