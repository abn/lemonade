#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lemon {
namespace external {

// Host-provided value sources for launch-time token resolution. The server
// fills `fixed` with already-resolved runtime/hardware/model facts and supplies
// lookups for recipe options and allowlisted environment variables.
struct TokenSources {
    std::map<std::string, std::string> fixed;

    // Recipe option lookup. Returns true and sets `value` when the option exists.
    std::function<bool(const std::string& name, std::string& value)> custom_option;

    // Environment lookup, called only for names that pass env_name_allowed().
    std::function<bool(const std::string& name, std::string& value)> env;

    // Tokenized user arguments that {custom_args} expands to.
    std::vector<std::string> custom_args;

    // Flags checked against every element of custom_args.
    std::set<std::string> reserved_args;
};

// Default-deny environment allowlist for the {env:NAME} token.
const std::set<std::string>& default_env_allowlist();
bool env_name_allowed(const std::string& name);

// Resolve every token in one template into a single string.
bool resolve_template(const std::string& template_text,
                      const TokenSources& sources,
                      std::string& out,
                      std::string& error);

// Resolve a command's argv. {custom_args} expands to multiple elements; every
// other template produces exactly one. A substituted value that begins with '-'
// is rejected unless it is a validated negative number.
bool resolve_args(const std::vector<std::string>& template_args,
                  const TokenSources& sources,
                  std::vector<std::string>& out,
                  std::string& error);

// Resolve a manifest env block (keys are literal, values are templates).
bool resolve_env_block(const std::map<std::string, std::string>& env_template,
                       const TokenSources& sources,
                       std::map<std::string, std::string>& out,
                       std::string& error);

// True if `value` is a well-formed signed decimal number (e.g. -0, -12, -1.5, -2e3).
bool is_negative_number(const std::string& value);

}  // namespace external
}  // namespace lemon
