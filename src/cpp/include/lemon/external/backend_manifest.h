#pragma once

#include <map>
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

// One platform's launch specification. A passthrough recipe sets command+args;
// a variant_of recipe sets binary (the executable inside the fetched artifact).
struct ExecBlock {
    std::string command;
    std::vector<std::string> args;
    std::string working_dir;
    std::string stop_command;
    std::vector<std::string> stop_command_args;
    std::map<std::string, std::string> env;
    std::string binary;
    std::vector<std::string> argv_extra;
    std::vector<std::string> reserved_args;
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

}  // namespace external
}  // namespace lemon
