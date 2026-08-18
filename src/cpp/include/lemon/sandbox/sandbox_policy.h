#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace lemon::sandbox {

enum class NetworkAccess {
    DenyAll,
    LoopbackOnly,
    Full
};

inline const char* network_access_to_string(NetworkAccess access) {
    switch (access) {
        case NetworkAccess::DenyAll:      return "deny_all";
        case NetworkAccess::LoopbackOnly: return "loopback_only";
        case NetworkAccess::Full:         return "full";
    }
    return "unknown";
}

enum class SandboxMode {
    Auto,
    Enforced,
    Disabled,
    ScrubbedOnly
};

inline const char* sandbox_mode_to_string(SandboxMode mode) {
    switch (mode) {
        case SandboxMode::Auto:         return "auto";
        case SandboxMode::Enforced:     return "enforced";
        case SandboxMode::Disabled:     return "disabled";
        case SandboxMode::ScrubbedOnly: return "scrubbed_only";
    }
    return "unknown";
}

inline SandboxMode parse_sandbox_mode(const std::string& str) {
    std::string lowered = str;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "enforced" || lowered == "strict") {
        return SandboxMode::Enforced;
    }
    if (lowered == "disabled" || lowered == "off" || lowered == "false" ||
        lowered == "none" || lowered == "0") {
        return SandboxMode::Disabled;
    }
    if (lowered == "scrubbed_only" || lowered == "scrubbed") {
        return SandboxMode::ScrubbedOnly;
    }
    return SandboxMode::Auto;
}

struct PathGrant {
    std::string path;
    bool write_allowed{false};

    PathGrant() = default;
    PathGrant(std::string p, bool write = false)
        : path(std::move(p)), write_allowed(write) {}

    static PathGrant read_only(std::string p) {
        return {std::move(p), false};
    }

    static PathGrant read_write(std::string p) {
        return {std::move(p), true};
    }

    bool operator==(const PathGrant& other) const noexcept {
        return path == other.path && write_allowed == other.write_allowed;
    }
};

struct SandboxPolicy {
    std::vector<PathGrant> path_grants;
    std::vector<std::string> device_grants;
    std::vector<std::string> allowed_env_vars;
    std::vector<std::pair<std::string, std::string>> explicit_env_vars;
    NetworkAccess network_access{NetworkAccess::LoopbackOnly};
    SandboxMode mode{SandboxMode::Auto};
    uint16_t bind_port{0};

    SandboxPolicy& add_path(const std::string& path, bool write_allowed = false) {
        if (!path.empty()) {
            path_grants.push_back({path, write_allowed});
        }
        return *this;
    }

    SandboxPolicy& add_read_path(const std::string& path) {
        return add_path(path, false);
    }

    SandboxPolicy& add_write_path(const std::string& path) {
        return add_path(path, true);
    }

    SandboxPolicy& add_device(const std::string& dev_path) {
        if (!dev_path.empty()) {
            device_grants.push_back(dev_path);
        }
        return *this;
    }

    SandboxPolicy& allow_env_var(const std::string& var_name) {
        if (!var_name.empty()) {
            allowed_env_vars.push_back(var_name);
        }
        return *this;
    }

    SandboxPolicy& allow_env_vars(const std::vector<std::string>& var_names) {
        for (const auto& var : var_names) {
            allow_env_var(var);
        }
        return *this;
    }

    SandboxPolicy& set_env_var(const std::string& key, const std::string& value) {
        if (!key.empty()) {
            explicit_env_vars.push_back({key, value});
        }
        return *this;
    }

    SandboxPolicy& set_network_access(NetworkAccess access) {
        network_access = access;
        return *this;
    }

    SandboxPolicy& set_mode(SandboxMode m) {
        mode = m;
        return *this;
    }

    SandboxPolicy& set_bind_port(uint16_t port) {
        bind_port = port;
        return *this;
    }

    bool has_read_path(const std::string& target_path) const {
        for (const auto& grant : path_grants) {
            if (grant.path == target_path) return true;
        }
        return false;
    }

    bool has_write_path(const std::string& target_path) const {
        for (const auto& grant : path_grants) {
            if (grant.path == target_path && grant.write_allowed) return true;
        }
        return false;
    }

    bool has_device(const std::string& dev) const {
        return std::find(device_grants.begin(), device_grants.end(), dev) != device_grants.end();
    }

    bool has_allowed_env(const std::string& var_name) const {
        return std::find(allowed_env_vars.begin(), allowed_env_vars.end(), var_name) != allowed_env_vars.end();
    }

    void normalize_paths() {
        std::vector<PathGrant> normalized;
        for (const auto& grant : path_grants) {
            if (grant.path.empty()) continue;
            std::filesystem::path p(grant.path);
            std::string norm_path = p.lexically_normal().string();

            auto it = std::find_if(normalized.begin(), normalized.end(),
                [&](const PathGrant& pg) { return pg.path == norm_path; });

            if (it != normalized.end()) {
                it->write_allowed = it->write_allowed || grant.write_allowed;
            } else {
                normalized.push_back({norm_path, grant.write_allowed});
            }
        }
        path_grants = std::move(normalized);
    }

    std::string to_debug_string() const {
        std::ostringstream ss;
        ss << "mode=" << sandbox_mode_to_string(mode)
           << ", network=" << network_access_to_string(network_access);
        if (bind_port > 0) {
            ss << " (bind_port=" << bind_port << ")";
        }
        ss << ", paths=[" << path_grants.size() << " entries]"
           << ", devices=[";
        for (size_t i = 0; i < device_grants.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << device_grants[i];
        }
        ss << "], allowed_env=[" << allowed_env_vars.size() << " vars]";
        return ss.str();
    }

    std::string to_detailed_string() const {
        std::ostringstream ss;
        ss << "SandboxPolicy {\n"
           << "  mode: " << sandbox_mode_to_string(mode) << "\n"
           << "  network: " << network_access_to_string(network_access);
        if (bind_port > 0) {
            ss << " (bind_port: " << bind_port << ")";
        }
        ss << "\n  path_grants (" << path_grants.size() << "):\n";
        for (const auto& g : path_grants) {
            ss << "    " << (g.write_allowed ? "[RW] " : "[RO] ") << g.path << "\n";
        }
        ss << "  devices: [";
        for (size_t i = 0; i < device_grants.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << device_grants[i];
        }
        ss << "]\n  allowed_env: [";
        for (size_t i = 0; i < allowed_env_vars.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << allowed_env_vars[i];
        }
        ss << "]\n}";
        return ss.str();
    }
};

class PolicyPresets {
public:
    static std::vector<PathGrant> get_standard_system_paths() {
        return {
            {"/usr", false},
            {"/bin", false},
            {"/sbin", false},
            {"/lib", false},
            {"/lib64", false},
            {"/etc/ld.so.cache", false},
            {"/etc/ld.so.conf", false},
            {"/etc/ld.so.conf.d", false},
            {"/etc/alternatives", false},
            {"/proc/cpuinfo", false},
            {"/proc/meminfo", false},
            {"/proc/self", false},
            {"/sys/devices/system/cpu", false},
            {"/dev/null", true},
            {"/dev/zero", false},
            {"/dev/urandom", false},
            {"/dev/random", false},
            {"/dev/shm", true}
        };
    }

    static std::vector<std::string> get_standard_gpu_devices() {
        return {
            "/dev/dri",
            "/dev/kfd",
            "/dev/dxg",
            "/dev/nvidiactl",
            "/dev/nvidia-uvm"
        };
    }

    static std::vector<std::string> get_standard_npu_devices() {
        return {
            "/dev/accel",
            "/dev/amdxdna",
            "/sys/class/accel",
            "/dev/dri",
            "/dev/kfd"
        };
    }

    static std::vector<std::string> get_standard_allowed_env_vars() {
        return {
            "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
            "TERM", "TMPDIR", "TEMP", "TMP", "TZ",
            "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
            "HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES", "HSA_OVERRIDE_GFX_VERSION",
            "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES",
            "VK_ICD_FILENAMES", "VK_LAYER_PATH",
            "XILINX_XRT", "XLNX_VART_FIRMWARE",
            "FLM_CACHE_DIR", "FASTFLOWLM_CACHE_DIR", "XRT_LOG_LEVEL", "XRT_TPC_LOG_LEVEL"
        };
    }

    static SandboxPolicy create_for_llamacpp(
        const std::string& executable,
        const std::string& model_path,
        uint16_t bind_port,
        const std::string& backend_type = "cpu",
        const std::vector<std::string>& extra_paths = {}) {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        if (!model_path.empty()) {
            policy.add_read_path(model_path);
            std::filesystem::path mp(model_path);
            if (mp.has_parent_path()) {
                policy.add_read_path(mp.parent_path().string());
            }
        }

        for (const auto& ep : extra_paths) {
            policy.add_read_path(ep);
        }

        if (backend_type == "vulkan" || backend_type == "rocm" || backend_type == "cuda") {
            for (const auto& dev : get_standard_gpu_devices()) {
                policy.add_device(dev);
            }
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.normalize_paths();
        return policy;
    }

    static SandboxPolicy create_for_fastflowlm(
        const std::string& executable,
        const std::string& model_dir,
        uint16_t bind_port) {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        // FastFlowLM temp runtime directory
        policy.add_write_path("/tmp");

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        if (!model_dir.empty()) {
            policy.add_read_path(model_dir);
        }

        // FastFlowLM home caches & directories
        const char* home = std::getenv("HOME");
#ifdef _WIN32
        if (!home) {
            home = std::getenv("USERPROFILE");
        }
#endif
        if (home) {
            std::filesystem::path h(home);
            policy.add_write_path((h / ".fastflowlm").string());
            policy.add_write_path((h / ".cache" / "fastflowlm").string());
            policy.add_write_path((h / ".cache" / "flm").string());
            policy.add_write_path((h / ".config" / "flm").string());
        }
        if (const char* flm_cache = std::getenv("FLM_CACHE_DIR")) {
            policy.add_write_path(flm_cache);
        }
        if (const char* xdg_config = std::getenv("XDG_CONFIG_HOME")) {
            std::filesystem::path xc(xdg_config);
            policy.add_write_path((xc / "flm").string());
        }

        // XRT runtime & NPU hardware discovery paths
        policy.add_read_path("/opt/xilinx");
        policy.add_read_path("/opt/amd");
        policy.add_read_path("/etc/xrt");
        policy.add_read_path("/sys/class/accel");
        policy.add_read_path("/sys/bus/pci");
        policy.add_read_path("/sys/devices");

        for (const auto& dev : get_standard_npu_devices()) {
            policy.add_device(dev);
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.normalize_paths();
        return policy;
    }

    static SandboxPolicy create_for_vllm(
        const std::string& executable,
        const std::string& model_path,
        uint16_t bind_port,
        const std::string& rocm_shim_dir = "",
        const std::string& triton_cache_dir = "") {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        if (!model_path.empty()) {
            policy.add_read_path(model_path);
            std::filesystem::path mp(model_path);
            if (mp.has_parent_path()) {
                policy.add_read_path(mp.parent_path().string());
            }
        }

        if (!rocm_shim_dir.empty()) {
            policy.add_read_path(rocm_shim_dir);
        }

        if (!triton_cache_dir.empty()) {
            policy.add_write_path(triton_cache_dir);
        } else {
            policy.add_write_path("/tmp");
        }

        for (const auto& dev : get_standard_gpu_devices()) {
            policy.add_device(dev);
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.allow_env_var("PYTHONPATH");
        policy.allow_env_var("PYTHONHOME");
        policy.allow_env_var("VIRTUAL_ENV");
        policy.allow_env_var("VLLM_USAGE_SOURCE");
        policy.allow_env_var("FLASH_ATTENTION_TRITON_AMD_ENABLE");
        policy.allow_env_var("PYTHONNOUSERSITE");

        policy.normalize_paths();
        return policy;
    }

    static SandboxPolicy create_for_whispercpp(
        const std::string& executable,
        const std::string& model_path,
        uint16_t bind_port,
        const std::string& backend_type = "cpu") {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        if (!model_path.empty()) {
            policy.add_read_path(model_path);
            std::filesystem::path mp(model_path);
            if (mp.has_parent_path()) {
                policy.add_read_path(mp.parent_path().string());
            }
        }

        if (backend_type == "npu") {
            for (const auto& dev : get_standard_npu_devices()) {
                policy.add_device(dev);
            }
        } else if (backend_type == "vulkan" || backend_type == "rocm" || backend_type == "cuda") {
            for (const auto& dev : get_standard_gpu_devices()) {
                policy.add_device(dev);
            }
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.normalize_paths();
        return policy;
    }

    static SandboxPolicy create_for_sdcpp(
        const std::string& executable,
        const std::string& model_path,
        uint16_t bind_port,
        const std::string& output_dir = "",
        const std::string& backend_type = "cpu") {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        if (!model_path.empty()) {
            policy.add_read_path(model_path);
            std::filesystem::path mp(model_path);
            if (mp.has_parent_path()) {
                policy.add_read_path(mp.parent_path().string());
            }
        }

        if (!output_dir.empty()) {
            policy.add_write_path(output_dir);
        }

        if (backend_type == "vulkan" || backend_type == "rocm" || backend_type == "cuda") {
            for (const auto& dev : get_standard_gpu_devices()) {
                policy.add_device(dev);
            }
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.normalize_paths();
        return policy;
    }

    static SandboxPolicy create_for_generic(
        const std::string& executable,
        uint16_t bind_port) {

        SandboxPolicy policy;
        policy.bind_port = bind_port;
        policy.network_access = NetworkAccess::LoopbackOnly;
        policy.mode = SandboxMode::Auto;

        for (const auto& sp : get_standard_system_paths()) {
            policy.path_grants.push_back(sp);
        }

        if (!executable.empty()) {
            policy.add_read_path(executable);
            std::filesystem::path p(executable);
            if (p.has_parent_path()) {
                policy.add_read_path(p.parent_path().string());
            }
        }

        policy.allow_env_vars(get_standard_allowed_env_vars());
        policy.normalize_paths();
        return policy;
    }
};

} // namespace lemon::sandbox
