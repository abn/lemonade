#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace lemon {
namespace external {

// Supported manifest contract major for this build.
constexpr const char* kSupportedContractVersion = "1";

struct HealthProbe {
    std::string type = "http";  // http | tcp | process
    std::string endpoint = "/health";
    int expected_status = 200;
    int timeout_seconds = 90;
    int poll_interval_ms = 100;
};

// A partial platform block used as an arch-specific override. A present field
// replaces the base field; env merges key-wise. Every field is optional so an
// override only has to name its deltas.
struct ExecOverride {
    std::optional<std::string> command;
    std::optional<std::vector<std::string>> args;
    std::optional<std::string> working_dir;
    std::optional<std::string> stop_command;
    std::optional<std::vector<std::string>> stop_command_args;
    std::optional<std::map<std::string, std::string>> env;
    std::optional<std::string> binary;
    std::optional<std::string> source;
    std::optional<std::string> sha256;
    std::optional<std::string> version_policy;
    std::optional<std::vector<std::string>> argv_extra;
    std::optional<std::vector<std::string>> reserved_args;
};

// One platform's launch specification. A passthrough recipe sets command+args;
// a variant_of recipe sets binary (the executable inside the fetched artifact).
// source/sha256/version_policy override the top-level provenance for this block,
// so a project that publishes one artifact per platform can be described once.
// `arch` holds further overrides selected by the detected hardware arch.
struct ExecBlock {
    std::string command;
    std::vector<std::string> args;
    std::string working_dir;
    std::string stop_command;
    std::vector<std::string> stop_command_args;
    std::map<std::string, std::string> env;
    std::string binary;
    std::string source;
    std::string sha256;
    std::string version_policy;
    std::vector<std::string> argv_extra;
    std::vector<std::string> reserved_args;
    std::map<std::string, ExecOverride> arch;
};

// host OS -> accelerator -> launch spec.
struct PlatformMatrix {
    std::map<std::string, std::map<std::string, ExecBlock>> by_os;
};

struct CustomOption {
    std::string name;
    std::string cli_flag;
    nlohmann::json default_value;
    std::string type_name;
    std::string help;
    std::string group;
};

// A parsed, validated external backend manifest. Plain data; the registry owns
// instances, the server reads them. See rfc/v3/rfc-01 for the contract.
struct BackendManifest {
    std::string recipe;
    std::string display_name;
    std::string api_contract_version;
    std::string extends_recipe;
    std::string variant_of;
    std::vector<std::string> capabilities;
    std::map<std::string, std::vector<std::string>> capability_enable_args;
    HealthProbe health_probe;
    int requested_ports = 1;
    std::vector<std::string> reserved_args;
    std::string slot_policy = "standard";
    std::string model_management = "lemond_managed";
    std::string default_accelerator;
    nlohmann::json recipe_options = nlohmann::json::object();
    std::string source;
    std::string sha256;
    std::string version_policy = "pinned";
    std::map<std::string, std::string> endpoints;
    std::vector<CustomOption> custom_options;
    std::string downsize_endpoint;
    nlohmann::json extensions = nlohmann::json::object();
    // Maps a detected arch (or arch glob) to a short alias; resolves {arch_alias}.
    std::map<std::string, std::string> arch_aliases;
    PlatformMatrix platforms;

    // Absolute path the manifest was loaded from ("" when parsed directly).
    std::string source_path;

    bool is_variant_of() const { return !variant_of.empty(); }
};

// Strict parse of a manifest document. Returns true and fills `out` on success;
// false and a message naming the offending field on failure. Rejects a contract
// version above kSupportedContractVersion, unknown fields, unknown capability
// names, and provenance used without variant_of.
bool parse_backend_manifest(const nlohmann::json& doc,
                            BackendManifest& out,
                            std::string& error);

// Resolve a hardware arch (gfx1151, sm_90, or a glob like gfx115*) against an
// arch override map. Exact match wins; otherwise the first glob match. Null when
// nothing matches.
const ExecOverride* match_arch_override(const std::map<std::string, ExecOverride>& overrides,
                                        const std::string& arch);

// Merge an arch override onto a base block. Present fields replace the base
// field; env merges key-wise. Shared by the loader and the installer so the argv
// and the artifact they pick cannot drift.
ExecBlock apply_arch_override(const ExecBlock& base, const ExecOverride& override);

// Convenience: match then merge. Returns `base` unchanged when nothing matches.
ExecBlock resolve_arch_block(const ExecBlock& base, const std::string& arch);

// The alias for a detected arch, using the same exact-then-glob rule. Empty when
// the arch is unmapped, so a template that needs it fails loudly rather than
// substituting an empty string.
std::string arch_alias_for(const std::map<std::string, std::string>& aliases,
                           const std::string& arch);

}  // namespace external
}  // namespace lemon
