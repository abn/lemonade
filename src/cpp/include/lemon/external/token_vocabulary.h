#pragma once

#include <string>
#include <vector>

namespace lemon {
namespace external {

// The normative launch-time token vocabulary for api_contract_version 1.
// Fixed tokens are matched exactly inside `{...}`; prefixed tokens are
// `checkpoint:NAME`, `checkpoint_relative:NAME`, `custom:NAME`,
// `custom:NAME:-DEFAULT`, `env:NAME`, and `env:NAME:-DEFAULT`.
const std::vector<std::string>& fixed_token_names();

// True if the inner text between braces is a known token. `error` carries the
// reason when false.
bool is_known_token(const std::string& inner, std::string& error);

// Validate every `{...}` occurrence in one string. Empty braces, nested braces,
// unknown names, and malformed `custom:`/`env:` specs are rejected. Returns
// false and sets `error` on the first problem.
bool validate_tokens_in_string(const std::string& text, std::string& error);

}  // namespace external
}  // namespace lemon
