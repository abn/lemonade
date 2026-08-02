#include "lemon/config_file.h"
#include "lemon/backends/backend_descriptor_registry.h"
#include "lemon/utils/json_utils.h"
#include "lemon/utils/path_utils.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>

#include <lemon/utils/aixlog.hpp>

namespace fs = std::filesystem;

namespace lemon {

std::shared_mutex ConfigFile::file_mutex_;

static json load_json_file(const fs::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open " + utils::path_to_utf8(path));
    }

    try {
        return json::parse(file);
    } catch (const json::parse_error& e) {
        throw std::runtime_error("Failed to parse " + utils::path_to_utf8(path) + ": " + e.what());
    }
}

json ConfigFile::base_defaults() {
    json defaults = load_json_file(utils::path_from_utf8(
        utils::get_resource_path("resources/defaults.json")));

    // Seed each backend's config.json section from its descriptor.
    // resources/defaults.json is the generated, committed mirror; re-seeding here
    // keeps the descriptor authoritative even if that file lags.
    for (const auto* d : backends::all_descriptors()) {
        json block = d->config_defaults();
        if (!block.empty()) {
            defaults[d->effective_config_section()] = block;
        }
    }

    return defaults;
}

json ConfigFile::get_defaults() {
    json defaults = base_defaults();

#ifndef _WIN32
    fs::path distro_defaults = "/usr/share/lemonade/defaults.json";
    if (fs::exists(distro_defaults)) {
        defaults = utils::JsonUtils::merge(defaults, load_json_file(distro_defaults));
    }
#endif

    // Packagers on non-FHS distros (Nix, Guix) can't write the /usr/share
    // file above; this seeds the same defaults from any path.
    if (const char* env = std::getenv("LEMONADE_DEFAULTS_PATH"); env && *env && fs::exists(env)) {
        defaults = utils::JsonUtils::merge(defaults, load_json_file(env));
    }

    return defaults;
}

json ConfigFile::load(const std::string& cache_dir) {
    json defaults = get_defaults();
    fs::path config_path = utils::path_from_utf8(cache_dir) / "config.json";

    if (!fs::exists(config_path)) {
        fs::path cache_path = utils::path_from_utf8(cache_dir);
        if (!fs::exists(cache_path)) {
            fs::create_directories(cache_path);
        }
        save(cache_dir, defaults);
        return defaults;
    }

    // Clean up stale temp file from a previous interrupted save
    {
        std::unique_lock lock(file_mutex_);
        std::error_code ec;
        fs::remove(fs::path(config_path).concat(".tmp"), ec);
    }

    // Read and parse config under shared lock
    bool corrupt = false;
    std::string parse_error_msg;
    json loaded;
    {
        std::shared_lock lock(file_mutex_);

        std::ifstream file(config_path);
        if (!file.is_open()) {
            LOG(WARNING) << "Could not open " << config_path.string()
                        << ", using defaults" << std::endl;
            return defaults;
        }

        try {
            loaded = json::parse(file);
        } catch (const json::parse_error& e) {
            corrupt = true;
            parse_error_msg = e.what();
        }
    } // shared lock released

    if (corrupt) {
        LOG(WARNING) << "Failed to parse " << config_path.string()
                     << ": " << parse_error_msg << std::endl;

        // Back up the corrupt file so the user can inspect it
        fs::path backup = config_path;
        backup += ".corrupted";
        std::error_code ec;
        fs::rename(config_path, backup, ec);
        if (!ec) {
            LOG(WARNING) << "  Renamed to " << backup.string() << std::endl;
        }

        LOG(WARNING) << "  Using defaults." << std::endl;
        save(cache_dir, defaults);
        return defaults;
    }

    // Deep-merge: user values override defaults, missing fields filled from defaults.
    json merged = utils::JsonUtils::merge(defaults, loaded);

    // Capture the original config version BEFORE merge, so that migration
    // can see past the defaults-injected version number.
    int original_version = config_get_version(loaded);

    // Apply migrations if the config is older than the current version.
    // The inline config_migrate() handles version bumping and field removal.
    bool migrated = config_migrate(merged, defaults, original_version);
    if (migrated) {
        // Log migration details for user visibility.
        if (original_version < config_get_version(defaults)) {
            if (loaded.contains("ctx_size") && loaded["ctx_size"].is_number_integer()
                && loaded["ctx_size"].get<int>() == 4096) {
                LOG(INFO) << "Migrating config: ctx_size 4096 -> -1 (auto-tune enabled)"
                          << std::endl;
            }
        }
        save(cache_dir, merged);
    }

    return merged;
}

void ConfigFile::save(const std::string& cache_dir, const json& config) {
    std::unique_lock lock(file_mutex_);

    fs::path cache_path = utils::path_from_utf8(cache_dir);
    if (!fs::exists(cache_path)) {
        fs::create_directories(cache_path);
    }

    fs::path config_path = cache_path / "config.json";
    fs::path temp_path = cache_path / "config.json.tmp";

    {
        std::ofstream file(temp_path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to write " + temp_path.string());
        }
        file << config.dump(2) << std::endl;
    }

    std::error_code ec;
    fs::rename(temp_path, config_path, ec);
    if (ec) {
        // On some systems (cross-device), rename fails. Fall back to copy + remove.
        std::error_code copy_ec;
        fs::copy_file(temp_path, config_path, fs::copy_options::overwrite_existing, copy_ec);
        if (copy_ec) {
            fs::remove(temp_path);
            throw std::runtime_error("Failed to save " + config_path.string()
                                     + ": " + copy_ec.message());
        }
        fs::remove(temp_path);
    }
}

SandboxPolicy SandboxPolicy::from_json(const json& config) {
    SandboxPolicy policy;
    const json* s = nullptr;

    if (config.contains("sandbox") && config["sandbox"].is_object()) {
        s = &config["sandbox"];
    } else if (config.is_object() && (config.contains("enabled") || config.contains("engine"))) {
        s = &config;
    }

    if (!s) {
        return policy;
    }

    if (s->contains("enabled")) {
        const auto& val = (*s)["enabled"];
        if (val.is_boolean()) {
            policy.enabled = val.get<bool>() ? SandboxMode::Enabled : SandboxMode::Disabled;
        } else if (val.is_string()) {
            std::string str = val.get<std::string>();
            if (str == "auto") {
                policy.enabled = SandboxMode::Auto;
            } else if (str == "true" || str == "1" || str == "enabled") {
                policy.enabled = SandboxMode::Enabled;
            } else if (str == "false" || str == "0" || str == "disabled") {
                policy.enabled = SandboxMode::Disabled;
            }
        }
    }

    if (s->contains("engine") && (*s)["engine"].is_string()) {
        policy.engine = (*s)["engine"].get<std::string>();
    }
    if (s->contains("nono_path") && (*s)["nono_path"].is_string()) {
        policy.nono_path = (*s)["nono_path"].get<std::string>();
    }
    if (s->contains("block_outbound_network") && (*s)["block_outbound_network"].is_boolean()) {
        policy.block_outbound_network = (*s)["block_outbound_network"].get<bool>();
    }
    if (s->contains("allow_gpu_devices") && (*s)["allow_gpu_devices"].is_boolean()) {
        policy.allow_gpu_devices = (*s)["allow_gpu_devices"].get<bool>();
    }
    if (s->contains("sandbox_external_only") && (*s)["sandbox_external_only"].is_boolean()) {
        policy.sandbox_external_only = (*s)["sandbox_external_only"].get<bool>();
    }
    if (s->contains("max_memory_mb") && (*s)["max_memory_mb"].is_number_integer()) {
        policy.max_memory_mb = (*s)["max_memory_mb"].get<int>();
    }

    auto parse_string_list = [](const json& parent, const std::string& key, std::vector<std::string>& dest) {
        if (parent.contains(key) && parent[key].is_array()) {
            dest.clear();
            for (const auto& item : parent[key]) {
                if (item.is_string()) {
                    dest.push_back(item.get<std::string>());
                }
            }
        }
    };

    parse_string_list(*s, "allowed_network_hosts", policy.allowed_network_hosts);
    parse_string_list(*s, "allowed_read_paths", policy.allowed_read_paths);
    parse_string_list(*s, "allowed_write_paths", policy.allowed_write_paths);

    return policy;
}

json SandboxPolicy::to_json() const {
    std::string enabled_str = "auto";
    if (enabled == SandboxMode::Enabled) {
        enabled_str = "true";
    } else if (enabled == SandboxMode::Disabled) {
        enabled_str = "false";
    }

    return {
        {"enabled", enabled_str},
        {"engine", engine},
        {"nono_path", nono_path},
        {"block_outbound_network", block_outbound_network},
        {"allowed_network_hosts", allowed_network_hosts},
        {"allow_gpu_devices", allow_gpu_devices},
        {"sandbox_external_only", sandbox_external_only},
        {"max_memory_mb", max_memory_mb},
        {"allowed_read_paths", allowed_read_paths},
        {"allowed_write_paths", allowed_write_paths}
    };
}

SandboxPolicy ConfigFile::get_sandbox_policy(const json& config) {
    SandboxPolicy policy = SandboxPolicy::from_json(config);

    // 12-Factor Environment Variable Overrides
    if (const char* env = std::getenv("LEMONADE_SANDBOX_ENABLED"); env && *env) {
        std::string str(env);
        if (str == "auto") {
            policy.enabled = SandboxMode::Auto;
        } else if (str == "true" || str == "1" || str == "enabled") {
            policy.enabled = SandboxMode::Enabled;
        } else if (str == "false" || str == "0" || str == "disabled") {
            policy.enabled = SandboxMode::Disabled;
        }
    }
    if (const char* env = std::getenv("LEMONADE_SANDBOX_NONO_PATH"); env && *env) {
        policy.nono_path = std::string(env);
    }
    if (const char* env = std::getenv("LEMONADE_SANDBOX_ALLOW_GPU"); env && *env) {
        std::string str(env);
        policy.allow_gpu_devices = (str == "1" || str == "true" || str == "TRUE");
    }
    if (const char* env = std::getenv("LEMONADE_SANDBOX_BLOCK_OUTBOUND"); env && *env) {
        std::string str(env);
        policy.block_outbound_network = (str == "1" || str == "true" || str == "TRUE");
    }

    return policy;
}


} // namespace lemon
