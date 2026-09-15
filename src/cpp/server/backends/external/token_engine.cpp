#include "lemon/external/token_engine.h"

#include <algorithm>
#include <cctype>

#include "lemon/external/token_vocabulary.h"

namespace lemon {
namespace external {

namespace {

bool fail(std::string& error, const std::string& message) {
    error = message;
    return false;
}

// Splits "NAME" or "NAME:-DEFAULT" into name and default. `has_default` is set
// true only when the ":-DEFAULT" form is present.
void split_default(const std::string& spec, std::string& name, std::string& default_value,
                   bool& has_default) {
    has_default = false;
    size_t sep = spec.find(":-");
    if (sep == std::string::npos) {
        name = spec;
        default_value.clear();
        return;
    }
    name = spec.substr(0, sep);
    default_value = spec.substr(sep + 2);
    has_default = true;
}

bool value_from_fixed(const std::string& key,
                      const TokenSources& sources,
                      std::string& value,
                      bool& found) {
    auto it = sources.fixed.find(key);
    found = it != sources.fixed.end();
    if (found) value = it->second;
    return true;
}

// Resolves the text between braces. Returns false with `error` on a bad token or
// a token that has no value and no default.
bool resolve_token(const std::string& inner,
                   const TokenSources& sources,
                   std::string& value,
                   std::string& error) {
    if (inner.rfind("custom:", 0) == 0) {
        std::string name;
        std::string default_value;
        bool has_default = false;
        split_default(inner.substr(7), name, default_value, has_default);
        if (sources.custom_option) {
            std::string resolved;
            if (sources.custom_option(name, resolved)) {
                value = resolved;
                return true;
            }
        }
        if (has_default) {
            value = default_value;
            return true;
        }
        return fail(error, "recipe option '" + name + "' has no value");
    }

    if (inner.rfind("env:", 0) == 0) {
        std::string name;
        std::string default_value;
        bool has_default = false;
        split_default(inner.substr(4), name, default_value, has_default);
        if (!env_name_allowed(name)) {
            return fail(error, "environment variable '" + name + "' is not resolvable");
        }
        if (sources.env) {
            std::string resolved;
            if (sources.env(name, resolved)) {
                value = resolved;
                return true;
            }
        }
        if (has_default) {
            value = default_value;
            return true;
        }
        return fail(error, "environment variable '" + name + "' is not set");
    }

    // checkpoint:*, checkpoint_relative:*, and all fixed tokens share the map.
    bool found = false;
    value_from_fixed(inner, sources, value, found);
    if (found) return true;
    return fail(error, "token '{" + inner + "}' has no value");
}

bool check_negative(const std::string& value,
                    const std::string& token,
                    std::string& error) {
    if (!value.empty() && value[0] == '-' && !is_negative_number(value)) {
        return fail(error, "token '" + token + "' resolved to a value starting with '-'");
    }
    return true;
}

}  // namespace

const std::set<std::string>& default_env_allowlist() {
    // Credential-free cache and CA locations only. Proxy variables are excluded
    // because their values may embed credentials that would land in argv.
    static const std::set<std::string> kAllowlist = {
        "HF_HOME",
        "HF_HUB_CACHE",
        "TRANSFORMERS_CACHE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    };
    return kAllowlist;
}

bool env_name_allowed(const std::string& name) {
    if (name.rfind("LEMONADE_", 0) == 0) return false;
    static const std::vector<std::string> kSecretShapes = {"API_KEY", "TOKEN", "SECRET",
                                                           "PASS", "AUTH"};
    for (const auto& shape : kSecretShapes) {
        if (name.find(shape) != std::string::npos) return false;
    }
    return default_env_allowlist().count(name) > 0;
}

bool is_negative_number(const std::string& value) {
    if (value.size() < 2 || value[0] != '-') return false;
    size_t i = 1;
    bool has_digits = false;
    while (i < value.size() && value[i] >= '0' && value[i] <= '9') {
        has_digits = true;
        ++i;
    }
    if (i < value.size() && value[i] == '.') {
        ++i;
        while (i < value.size() && value[i] >= '0' && value[i] <= '9') {
            has_digits = true;
            ++i;
        }
    }
    if (!has_digits) return false;
    if (i < value.size() && (value[i] == 'e' || value[i] == 'E')) {
        ++i;
        if (i < value.size() && (value[i] == '-' || value[i] == '+')) ++i;
        bool has_exp_digits = false;
        while (i < value.size() && value[i] >= '0' && value[i] <= '9') {
            has_exp_digits = true;
            ++i;
        }
        if (!has_exp_digits) return false;
    }
    return i == value.size();
}

bool resolve_template(const std::string& template_text,
                      const TokenSources& sources,
                      std::string& out,
                      std::string& error) {
    out.clear();
    error.clear();

    size_t pos = 0;
    while (pos < template_text.size()) {
        size_t open = template_text.find('{', pos);
        if (open == std::string::npos) {
            out.append(template_text.substr(pos));
            break;
        }
        out.append(template_text.substr(pos, open - pos));
        size_t close = template_text.find('}', open + 1);
        if (close == std::string::npos) {
            return fail(error, "unterminated token in \"" + template_text + "\"");
        }
        const std::string inner = template_text.substr(open + 1, close - open - 1);
        std::string token_error;
        if (!is_known_token(inner, token_error)) {
            return fail(error, token_error + " in \"" + template_text + "\"");
        }
        std::string value;
        if (!resolve_token(inner, sources, value, error)) {
            return false;
        }
        if (!check_negative(value, "{" + inner + "}", error)) {
            return false;
        }
        out.append(value);
        pos = close + 1;
    }
    return true;
}

bool resolve_args(const std::vector<std::string>& template_args,
                  const TokenSources& sources,
                  std::vector<std::string>& out,
                  std::string& error) {
    out.clear();
    error.clear();

    for (const auto& arg : template_args) {
        if (arg == "{custom_args}") {
            for (const auto& custom : sources.custom_args) {
                std::string flag = custom;
                size_t eq = flag.find('=');
                if (eq != std::string::npos) flag = flag.substr(0, eq);
                if (sources.reserved_args.count(flag) > 0) {
                    return fail(error, "custom argument '" + flag +
                                           "' collides with a reserved argument");
                }
            }
            out.insert(out.end(), sources.custom_args.begin(), sources.custom_args.end());
            continue;
        }
        std::string resolved;
        if (!resolve_template(arg, sources, resolved, error)) {
            return false;
        }
        out.push_back(std::move(resolved));
    }
    return true;
}

bool resolve_env_block(const std::map<std::string, std::string>& env_template,
                       const TokenSources& sources,
                       std::map<std::string, std::string>& out,
                       std::string& error) {
    out.clear();
    error.clear();
    for (const auto& [key, value] : env_template) {
        std::string resolved;
        if (!resolve_template(value, sources, resolved, error)) {
            error = "env." + key + ": " + error;
            return false;
        }
        out[key] = std::move(resolved);
    }
    return true;
}

}  // namespace external
}  // namespace lemon
