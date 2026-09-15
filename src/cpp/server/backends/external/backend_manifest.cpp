#include "lemon/external/backend_manifest.h"

#include <algorithm>
#include <initializer_list>
#include <regex>
#include <set>
#include <string>

#include "lemon/external/capability_registry.h"
#include "lemon/external/token_vocabulary.h"

namespace lemon {
namespace external {

namespace {

using nlohmann::json;

bool fail(std::string& error, const std::string& message) {
    error = message;
    return false;
}

bool check_allowed_keys(const json& obj,
                        std::initializer_list<const char*> allowed,
                        const std::string& where,
                        std::string& error) {
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        bool ok = false;
        for (const char* key : allowed) {
            if (it.key() == key) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            return fail(error, "unknown field '" + it.key() + "' in " + where);
        }
    }
    return true;
}

bool string_array(const json& value) {
    if (!value.is_array()) return false;
    for (const auto& item : value) {
        if (!item.is_string()) return false;
    }
    return true;
}

// Loader/interpose variables let a manifest inject code or shadow libraries in
// the child, so they are not accepted through the declarative env block.
const std::set<std::string>& forbidden_env_keys() {
    static const std::set<std::string> kKeys = {
        "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH"};
    return kKeys;
}

bool valid_recipe_id(const std::string& id) {
    static const std::regex kPattern("^[a-z0-9][a-z0-9_-]{1,63}$");
    return std::regex_match(id, kPattern);
}

bool parse_string_array(const json& value,
                        std::vector<std::string>& out,
                        const std::string& where,
                        std::string& error) {
    if (!string_array(value)) {
        return fail(error, "'" + where + "' must be an array of strings");
    }
    for (const auto& item : value) out.push_back(item.get<std::string>());
    return true;
}

bool parse_health_probe(const json& value, HealthProbe& out, std::string& error) {
    if (!value.is_object()) return fail(error, "'health_probe' must be an object");
    if (!check_allowed_keys(value,
                            {"type", "endpoint", "expected_status", "timeout_seconds",
                             "poll_interval_ms"},
                            "'health_probe'", error)) {
        return false;
    }
    if (value.contains("type")) {
        if (!value["type"].is_string()) return fail(error, "'health_probe.type' must be a string");
        const std::string type = value["type"].get<std::string>();
        if (type != "http" && type != "tcp" && type != "process") {
            return fail(error, "'health_probe.type' must be http, tcp, or process");
        }
        out.type = type;
    }
    if (value.contains("endpoint")) {
        if (!value["endpoint"].is_string()) return fail(error, "'health_probe.endpoint' must be a string");
        const std::string endpoint = value["endpoint"].get<std::string>();
        if (endpoint.empty() || endpoint[0] != '/') {
            return fail(error, "'health_probe.endpoint' must start with '/'");
        }
        out.endpoint = endpoint;
    }
    if (value.contains("expected_status")) {
        if (!value["expected_status"].is_number_integer()) {
            return fail(error, "'health_probe.expected_status' must be an integer");
        }
        out.expected_status = value["expected_status"].get<int>();
        if (out.expected_status < 100 || out.expected_status > 599) {
            return fail(error, "'health_probe.expected_status' must be between 100 and 599");
        }
    }
    if (value.contains("timeout_seconds")) {
        if (!value["timeout_seconds"].is_number_integer()) {
            return fail(error, "'health_probe.timeout_seconds' must be an integer");
        }
        out.timeout_seconds = value["timeout_seconds"].get<int>();
        if (out.timeout_seconds < 1 || out.timeout_seconds > 600) {
            return fail(error, "'health_probe.timeout_seconds' must be between 1 and 600");
        }
    }
    if (value.contains("poll_interval_ms")) {
        if (!value["poll_interval_ms"].is_number_integer()) {
            return fail(error, "'health_probe.poll_interval_ms' must be an integer");
        }
        out.poll_interval_ms = value["poll_interval_ms"].get<int>();
        if (out.poll_interval_ms < 10 || out.poll_interval_ms > 5000) {
            return fail(error, "'health_probe.poll_interval_ms' must be between 10 and 5000");
        }
    }
    return true;
}

bool parse_custom_option(const json& value, CustomOption& out, std::string& error) {
    if (!value.is_object()) return fail(error, "'custom_options' entries must be objects");
    if (!check_allowed_keys(value,
                            {"name", "cli_flag", "default_value", "type_name", "help",
                             "group"},
                            "a 'custom_options' entry", error)) {
        return false;
    }
    for (const char* required : {"name", "cli_flag", "default_value", "help"}) {
        if (!value.contains(required)) {
            return fail(error, std::string("'custom_options' entry is missing '") + required + "'");
        }
    }
    if (!value["name"].is_string() || !value["cli_flag"].is_string() ||
        !value["help"].is_string()) {
        return fail(error, "'custom_options' name, cli_flag, and help must be strings");
    }
    static const std::regex kFlagPattern("^--[a-z0-9-]+$");
    static const std::regex kNamePattern("^[a-z0-9_]+$");
    out.name = value["name"].get<std::string>();
    out.cli_flag = value["cli_flag"].get<std::string>();
    if (!std::regex_match(out.name, kNamePattern)) {
        return fail(error, "invalid 'custom_options.name': " + out.name);
    }
    if (!std::regex_match(out.cli_flag, kFlagPattern)) {
        return fail(error, "invalid 'custom_options.cli_flag': " + out.cli_flag);
    }
    out.default_value = value["default_value"];
    out.help = value["help"].get<std::string>();
    if (value.contains("type_name") && value["type_name"].is_string()) {
        out.type_name = value["type_name"].get<std::string>();
    }
    if (value.contains("group") && value["group"].is_string()) {
        out.group = value["group"].get<std::string>();
    }
    return true;
}

bool validate_block_tokens(const ExecBlock& block, const std::string& where, std::string& error) {
    auto scan = [&](const std::string& text, const std::string& field) {
        if (!validate_tokens_in_string(text, error)) {
            error = where + "." + field + ": " + error;
            return false;
        }
        return true;
    };
    if (!scan(block.command, "command")) return false;
    if (!scan(block.working_dir, "working_dir")) return false;
    if (!scan(block.stop_command, "stop_command")) return false;
    for (const auto& arg : block.args) {
        if (!scan(arg, "args")) return false;
    }
    for (const auto& arg : block.stop_command_args) {
        if (!scan(arg, "stop_command_args")) return false;
    }
    for (const auto& arg : block.argv_extra) {
        if (!scan(arg, "argv_extra")) return false;
    }
    for (const auto& [key, value] : block.env) {
        if (!scan(value, "env." + key)) return false;
    }
    return true;
}

bool parse_exec_block(const json& value,
                      bool variant_of,
                      const std::string& where,
                      ExecBlock& out,
                      std::string& error) {
    if (!value.is_object()) return fail(error, where + " must be an object");
    if (!check_allowed_keys(value,
                            {"command", "args", "working_dir", "stop_command",
                             "stop_command_args", "env", "binary", "argv_extra",
                             "reserved_args"},
                            where, error)) {
        return false;
    }

    const bool has_command = value.contains("command");
    const bool has_args = value.contains("args");
    const bool has_binary = value.contains("binary");

    if (has_command != has_args) {
        return fail(error, where + " must set 'command' and 'args' together");
    }

    if (variant_of) {
        if (!has_binary) return fail(error, where + " must set 'binary' for a variant_of recipe");
        if (!value["binary"].is_string()) return fail(error, where + ".binary must be a string");
        static const std::regex kBinaryPattern("^[A-Za-z0-9][A-Za-z0-9._-]*$");
        out.binary = value["binary"].get<std::string>();
        if (!std::regex_match(out.binary, kBinaryPattern)) {
            return fail(error, where + ".binary must be a bare executable name");
        }
    } else {
        if (has_binary) return fail(error, where + ".binary is only valid with 'variant_of'");
        if (!has_command) return fail(error, where + " must set 'command' and 'args'");
    }

    if (has_command) {
        if (!value["command"].is_string() || value["command"].get<std::string>().empty()) {
            return fail(error, where + ".command must be a non-empty string");
        }
        out.command = value["command"].get<std::string>();
    }
    if (has_args) {
        if (!parse_string_array(value["args"], out.args, where + ".args", error)) return false;
    }
    if (value.contains("working_dir")) {
        if (!value["working_dir"].is_string()) return fail(error, where + ".working_dir must be a string");
        out.working_dir = value["working_dir"].get<std::string>();
    }
    if (value.contains("stop_command")) {
        if (!value["stop_command"].is_string()) return fail(error, where + ".stop_command must be a string");
        out.stop_command = value["stop_command"].get<std::string>();
    }
    if (value.contains("stop_command_args")) {
        if (!parse_string_array(value["stop_command_args"], out.stop_command_args,
                                where + ".stop_command_args", error)) {
            return false;
        }
    }
    if (value.contains("env")) {
        if (!value["env"].is_object()) return fail(error, where + ".env must be an object");
        for (auto it = value["env"].begin(); it != value["env"].end(); ++it) {
            if (!it.value().is_string()) return fail(error, where + ".env values must be strings");
            if (forbidden_env_keys().count(it.key()) > 0) {
                return fail(error, where + ".env must not set loader variable '" + it.key() + "'");
            }
            out.env[it.key()] = it.value().get<std::string>();
        }
    }
    if (value.contains("argv_extra")) {
        if (!parse_string_array(value["argv_extra"], out.argv_extra, where + ".argv_extra", error)) {
            return false;
        }
    }
    if (value.contains("reserved_args")) {
        if (!parse_string_array(value["reserved_args"], out.reserved_args,
                                where + ".reserved_args", error)) {
            return false;
        }
    }

    return validate_block_tokens(out, where, error);
}

bool parse_platforms(const json& value,
                     bool variant_of,
                     PlatformMatrix& out,
                     std::string& error) {
    if (!value.is_object() || value.empty()) {
        return fail(error, "'platforms' must be a non-empty object");
    }
    static const std::set<std::string> kOsKeys = {"linux", "darwin", "windows"};
    static const std::set<std::string> kAccelKeys = {
        "cpu", "gpu", "rocm", "cuda", "vulkan", "metal", "oneapi", "npu", "tpu"};

    for (auto os_it = value.begin(); os_it != value.end(); ++os_it) {
        const std::string& os = os_it.key();
        if (kOsKeys.find(os) == kOsKeys.end()) {
            return fail(error, "unknown host OS '" + os + "' in 'platforms'");
        }
        if (!os_it.value().is_object() || os_it.value().empty()) {
            return fail(error, "'platforms." + os + "' must be a non-empty object");
        }
        for (auto accel_it = os_it.value().begin(); accel_it != os_it.value().end(); ++accel_it) {
            const std::string& accel = accel_it.key();
            if (kAccelKeys.find(accel) == kAccelKeys.end()) {
                return fail(error, "unknown accelerator '" + accel + "' in 'platforms." + os + "'");
            }
            ExecBlock block;
            const std::string where = "platforms." + os + "." + accel;
            if (!parse_exec_block(accel_it.value(), variant_of, where, block, error)) {
                return false;
            }
            out.by_os[os][accel] = block;
        }
    }
    return true;
}

}  // namespace

bool parse_backend_manifest(const json& doc, BackendManifest& out, std::string& error) {
    error.clear();
    if (!doc.is_object()) return fail(error, "manifest must be a JSON object");

    if (!check_allowed_keys(doc,
                            {"recipe", "display_name", "api_contract_version", "extends",
                             "variant_of", "capabilities", "capability_enable_args",
                             "health_probe", "requested_ports", "reserved_args",
                             "slot_policy", "model_management", "default_accelerator",
                             "recipe_options", "source", "sha256", "version_policy",
                             "endpoints", "custom_options", "downsize_endpoint",
                             "extensions", "platforms"},
                            "manifest", error)) {
        return false;
    }

    for (const char* required : {"recipe", "display_name", "api_contract_version",
                                 "capabilities", "platforms"}) {
        if (!doc.contains(required)) {
            return fail(error, std::string("missing required field '") + required + "'");
        }
    }

    if (!doc["recipe"].is_string()) return fail(error, "'recipe' must be a string");
    out.recipe = doc["recipe"].get<std::string>();
    if (!valid_recipe_id(out.recipe)) return fail(error, "invalid 'recipe' id: " + out.recipe);

    if (!doc["display_name"].is_string() || doc["display_name"].get<std::string>().empty()) {
        return fail(error, "'display_name' must be a non-empty string");
    }
    out.display_name = doc["display_name"].get<std::string>();

    if (!doc["api_contract_version"].is_string()) {
        return fail(error, "'api_contract_version' must be a string");
    }
    out.api_contract_version = doc["api_contract_version"].get<std::string>();
    if (out.api_contract_version != kSupportedContractVersion) {
        return fail(error, "unsupported api_contract_version '" + out.api_contract_version +
                               "' (this build supports '" +
                               std::string(kSupportedContractVersion) + "')");
    }

    if (doc.contains("extends")) {
        if (!doc["extends"].is_string()) return fail(error, "'extends' must be a string");
        out.extends_recipe = doc["extends"].get<std::string>();
        if (!valid_recipe_id(out.extends_recipe)) {
            return fail(error, "invalid 'extends' recipe id: " + out.extends_recipe);
        }
    }
    if (doc.contains("variant_of")) {
        if (!doc["variant_of"].is_string()) return fail(error, "'variant_of' must be a string");
        out.variant_of = doc["variant_of"].get<std::string>();
        if (!valid_recipe_id(out.variant_of)) {
            return fail(error, "invalid 'variant_of' recipe id: " + out.variant_of);
        }
    }
    if (!out.extends_recipe.empty() && !out.variant_of.empty()) {
        return fail(error, "'extends' and 'variant_of' are mutually exclusive");
    }

    if (!doc["capabilities"].is_array() || doc["capabilities"].empty()) {
        return fail(error, "'capabilities' must be a non-empty array");
    }
    std::set<std::string> seen_caps;
    for (const auto& cap : doc["capabilities"]) {
        if (!cap.is_string()) return fail(error, "'capabilities' entries must be strings");
        const std::string name = cap.get<std::string>();
        const CapabilityInfo* info = capability_info(name);
        if (info == nullptr) return fail(error, "unknown capability '" + name + "'");
        if (!seen_caps.insert(name).second) {
            return fail(error, "duplicate capability '" + name + "'");
        }
        if (info->variant_of_only && out.variant_of.empty()) {
            return fail(error, "capability '" + name + "' is only available to variant_of manifests");
        }
        out.capabilities.push_back(name);
    }

    if (doc.contains("capability_enable_args")) {
        const json& enable = doc["capability_enable_args"];
        if (!enable.is_object()) return fail(error, "'capability_enable_args' must be an object");
        for (auto it = enable.begin(); it != enable.end(); ++it) {
            if (seen_caps.find(it.key()) == seen_caps.end()) {
                return fail(error, "'capability_enable_args' key '" + it.key() +
                                       "' is not a declared capability");
            }
            std::vector<std::string> args;
            if (!parse_string_array(it.value(), args, "capability_enable_args." + it.key(), error)) {
                return false;
            }
            for (const auto& arg : args) {
                std::string token_error;
                if (!validate_tokens_in_string(arg, token_error)) {
                    return fail(error, "capability_enable_args." + it.key() + ": " + token_error);
                }
            }
            out.capability_enable_args[it.key()] = std::move(args);
        }
    }

    if (doc.contains("health_probe") &&
        !parse_health_probe(doc["health_probe"], out.health_probe, error)) {
        return false;
    }

    if (doc.contains("requested_ports")) {
        if (!doc["requested_ports"].is_number_integer()) {
            return fail(error, "'requested_ports' must be an integer");
        }
        out.requested_ports = doc["requested_ports"].get<int>();
        if (out.requested_ports != 1) {
            return fail(error, "v1 supports 'requested_ports' = 1 only");
        }
    }

    if (doc.contains("reserved_args") &&
        !parse_string_array(doc["reserved_args"], out.reserved_args, "reserved_args", error)) {
        return false;
    }

    if (doc.contains("slot_policy")) {
        if (!doc["slot_policy"].is_string()) return fail(error, "'slot_policy' must be a string");
        const std::string policy = doc["slot_policy"].get<std::string>();
        if (policy != "standard" && policy != "exclusive_npu" &&
            policy != "coexist_by_type" && policy != "unmetered") {
            return fail(error, "invalid 'slot_policy': " + policy);
        }
        out.slot_policy = policy;
    }
    if (doc.contains("model_management")) {
        if (!doc["model_management"].is_string()) {
            return fail(error, "'model_management' must be a string");
        }
        const std::string management = doc["model_management"].get<std::string>();
        if (management != "lemond_managed" && management != "self_managed") {
            return fail(error, "invalid 'model_management': " + management);
        }
        out.model_management = management;
    }
    if (doc.contains("default_accelerator")) {
        if (!doc["default_accelerator"].is_string()) {
            return fail(error, "'default_accelerator' must be a string");
        }
        static const std::set<std::string> kAccel = {
            "cpu", "gpu", "rocm", "cuda", "vulkan", "metal", "oneapi", "npu", "tpu"};
        const std::string accel = doc["default_accelerator"].get<std::string>();
        if (kAccel.find(accel) == kAccel.end()) {
            return fail(error, "invalid 'default_accelerator': " + accel);
        }
        out.default_accelerator = accel;
    }

    if (doc.contains("recipe_options")) {
        if (!doc["recipe_options"].is_object()) {
            return fail(error, "'recipe_options' must be an object");
        }
        out.recipe_options = doc["recipe_options"];
    }

    if (doc.contains("source")) {
        if (!doc["source"].is_string()) return fail(error, "'source' must be a string");
        out.source = doc["source"].get<std::string>();
        if (out.source.rfind("https://", 0) != 0) {
            return fail(error, "'source' must be an absolute https:// URL");
        }
        if (out.variant_of.empty()) {
            return fail(error, "'source' is only valid with 'variant_of'");
        }
    }
    if (doc.contains("sha256")) {
        if (!doc["sha256"].is_string()) return fail(error, "'sha256' must be a string");
        out.sha256 = doc["sha256"].get<std::string>();
        static const std::regex kHashPattern("^sha256:[0-9a-f]{64}$");
        if (!std::regex_match(out.sha256, kHashPattern)) {
            return fail(error, "'sha256' must be 'sha256:<64 lowercase hex>'");
        }
        if (out.variant_of.empty()) {
            return fail(error, "'sha256' is only valid with 'variant_of'");
        }
    }
    if (doc.contains("version_policy")) {
        if (!doc["version_policy"].is_string()) return fail(error, "'version_policy' must be a string");
        const std::string policy = doc["version_policy"].get<std::string>();
        if (policy != "pinned" && policy != "roll_forward") {
            return fail(error, "invalid 'version_policy': " + policy);
        }
        out.version_policy = policy;
        if (out.variant_of.empty()) {
            return fail(error, "'version_policy' is only valid with 'variant_of'");
        }
    }
    if (!out.variant_of.empty() && out.version_policy != "roll_forward" &&
        out.sha256.empty()) {
        return fail(error, "variant_of with version_policy 'pinned' requires 'sha256'");
    }

    if (doc.contains("endpoints")) {
        const json& endpoints = doc["endpoints"];
        if (!endpoints.is_object()) return fail(error, "'endpoints' must be an object");
        for (auto it = endpoints.begin(); it != endpoints.end(); ++it) {
            if (seen_caps.find(it.key()) == seen_caps.end()) {
                return fail(error, "'endpoints' key '" + it.key() +
                                       "' is not a declared capability");
            }
            if (!it.value().is_string()) return fail(error, "'endpoints' values must be strings");
            const std::string path = it.value().get<std::string>();
            if (path.empty() || path[0] != '/') {
                return fail(error, "'endpoints' value for '" + it.key() + "' must start with '/'");
            }
            out.endpoints[it.key()] = path;
        }
    }

    if (doc.contains("custom_options")) {
        if (!doc["custom_options"].is_array()) {
            return fail(error, "'custom_options' must be an array");
        }
        for (const auto& entry : doc["custom_options"]) {
            CustomOption option;
            if (!parse_custom_option(entry, option, error)) return false;
            out.custom_options.push_back(std::move(option));
        }
    }

    if (doc.contains("downsize_endpoint")) {
        if (!doc["downsize_endpoint"].is_string()) {
            return fail(error, "'downsize_endpoint' must be a string");
        }
        out.downsize_endpoint = doc["downsize_endpoint"].get<std::string>();
        if (out.downsize_endpoint.empty() || out.downsize_endpoint[0] != '/') {
            return fail(error, "'downsize_endpoint' must start with '/'");
        }
    }

    if (doc.contains("extensions")) {
        if (!doc["extensions"].is_object()) return fail(error, "'extensions' must be an object");
        out.extensions = doc["extensions"];
    }

    if (!parse_platforms(doc["platforms"], !out.variant_of.empty(), out.platforms, error)) {
        return false;
    }

    return true;
}

}  // namespace external
}  // namespace lemon
