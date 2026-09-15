#pragma once

#include <string>
#include <vector>

#include "lemon/model_types.h"

namespace lemon {
namespace external {

// How a manifest capability relates to the core contract.
enum class CapabilityKind {
    Core,       // the closed set the RFC defines
    Extension,  // additive, kept from the prototype
    Plumbing    // no deployment mode (slots, tokenize)
};

// A manifest capability and its mapping onto Lemonade's route and mode model.
// The manifest name is deliberately not the deployment-mode label: the mapping
// is explicit so a manifest can never imply a mode the code does not have.
struct CapabilityInfo {
    const char* name;         // manifest name, e.g. "chat_completion"
    const char* mode_label;   // code deployment-mode label, e.g. "chat" ("" if none)
    const char* route;        // human-readable primary route(s)
    CapabilityKind kind;
    bool has_mode;            // false for plumbing capabilities
    bool variant_of_only;     // passthrough cannot serve it
};

const std::vector<CapabilityInfo>& all_capabilities();

// Metadata for a manifest capability name, or nullptr if unknown.
const CapabilityInfo* capability_info(const std::string& name);

bool is_capability(const std::string& name);

// The code deployment-mode label for a capability, or "" when it has no mode
// (unknown name or plumbing).
std::string capability_mode_label(const std::string& name);

// The deployment modes (code labels) served by a capability set, de-duplicated,
// in registry order. Plumbing capabilities contribute nothing.
std::vector<std::string> deployment_modes_for_capabilities(
    const std::vector<std::string>& capabilities);

}  // namespace external
}  // namespace lemon
