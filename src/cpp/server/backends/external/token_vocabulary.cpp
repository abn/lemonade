#include "lemon/external/token_vocabulary.h"

#include <algorithm>
#include <cctype>

namespace lemon {
namespace external {

const std::vector<std::string>& fixed_token_names() {
    static const std::vector<std::string> kNames = {
        "port", "host", "pid", "log_level", "recipe", "model_name",
        "resolved_path", "model_relative_path", "model_dir", "exe_dir",
        "hf_cache", "cache_dir",
        "rocm_arch", "cuda_arch", "target_device", "hip_visible_devices",
        "cuda_visible_devices", "rocr_visible_devices", "ggml_vk_visible_devices",
        "ze_affinity_mask",
        "ctx_size", "batch_size", "ubatch_size", "threads", "cache_type_k",
        "cache_type_v",
        "custom_args",
    };
    return kNames;
}

namespace {

bool is_name(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '_' || c == '-')) return false;
    }
    return true;
}

// Validates the part after a known prefix. Only custom: and env: accept a
// `:-DEFAULT`, because only those two have a value source to fall back on.
bool valid_prefixed_spec(const std::string& rest, bool allow_default, std::string& error) {
    if (rest.empty()) {
        error = "token is missing its name";
        return false;
    }
    size_t sep = rest.find(":-");
    if (sep != std::string::npos && !allow_default) {
        error = "token '" + rest.substr(0, sep) + "' does not take a default";
        return false;
    }
    std::string name = (sep != std::string::npos) ? rest.substr(0, sep) : rest;
    if (!is_name(name)) {
        error = "invalid token name '" + name + "'";
        return false;
    }
    return true;
}

}  // namespace

bool is_known_token(const std::string& inner, std::string& error) {
    error.clear();
    if (inner.empty()) {
        error = "empty token";
        return false;
    }

    struct Prefix {
        const char* text;
        bool allow_default;
    };
    static const Prefix kPrefixed[] = {
        {"checkpoint_relative:", false},
        {"checkpoint:", false},
        {"custom:", true},
        {"env:", true},
    };
    for (const auto& prefix : kPrefixed) {
        size_t len = std::char_traits<char>::length(prefix.text);
        if (inner.compare(0, len, prefix.text) == 0) {
            return valid_prefixed_spec(inner.substr(len), prefix.allow_default, error);
        }
    }

    if (std::find(fixed_token_names().begin(), fixed_token_names().end(), inner) !=
        fixed_token_names().end()) {
        return true;
    }

    error = "unknown token '{" + inner + "}'";
    return false;
}

bool validate_tokens_in_string(const std::string& text, std::string& error) {
    error.clear();
    size_t pos = 0;
    while (pos < text.size()) {
        size_t open = text.find('{', pos);
        if (open == std::string::npos) break;
        size_t close = text.find('}', open + 1);
        if (close == std::string::npos) {
            error = "unterminated token in \"" + text + "\"";
            return false;
        }
        std::string inner = text.substr(open + 1, close - open - 1);
        if (inner.find('{') != std::string::npos) {
            error = "nested token in \"" + text + "\"";
            return false;
        }
        if (!is_known_token(inner, error)) {
            error = error + " in \"" + text + "\"";
            return false;
        }
        pos = close + 1;
    }
    return true;
}

}  // namespace external
}  // namespace lemon
