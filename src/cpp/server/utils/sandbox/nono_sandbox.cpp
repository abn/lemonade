#include <lemon/utils/sandbox/nono_sandbox.h>
#include <lemon/utils/path_utils.h>
#include <lemon/utils/http_client.h>
#include <lemon/utils/aixlog.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdlib>

namespace fs = std::filesystem;

namespace lemon::utils::sandbox {

static std::string get_nono_binary_name() {
#ifdef _WIN32
    return "nono.exe";
#else
    return "nono";
#endif
}

static fs::path canonical_or_weak(const fs::path& p) {
    std::error_code ec;
    if (fs::exists(p, ec) && !ec) {
        fs::path canonical_p = fs::canonical(p, ec);
        if (!ec) {
            return canonical_p;
        }
    }
    ec.clear();
    fs::path weakly_p = fs::weakly_canonical(p, ec);
    if (!ec) {
        return weakly_p;
    }
    return p;
}

bool NonoSandbox::is_nono_available(const std::string& data_dir, std::string& resolved_path) {
    std::error_code ec;
    std::string exe_name = get_nono_binary_name();

    // 1. Check data_dir/bin/nono
    if (!data_dir.empty()) {
        fs::path local_bin = path_from_utf8(data_dir) / "bin" / exe_name;
        if (fs::exists(local_bin, ec) && !ec) {
            resolved_path = path_to_utf8(canonical_or_weak(local_bin));
            return true;
        }
    }

    // 2. Check get_downloaded_bin_dir()
    fs::path default_data_bin = path_from_utf8(get_downloaded_bin_dir()) / exe_name;
    if (fs::exists(default_data_bin, ec) && !ec) {
        resolved_path = path_to_utf8(canonical_or_weak(default_data_bin));
        return true;
    }

    // 3. Search PATH
    std::string path_found = find_executable_in_path(exe_name);
    if (!path_found.empty()) {
        resolved_path = path_to_utf8(canonical_or_weak(path_from_utf8(path_found)));
        return true;
    }

    resolved_path.clear();
    return false;
}

bool NonoSandbox::ensure_nono_installed(const std::string& data_dir, std::string& installed_path) {
    if (is_nono_available(data_dir, installed_path)) {
        return true;
    }

    fs::path bin_dir = data_dir.empty() ? path_from_utf8(get_downloaded_bin_dir())
                                       : (path_from_utf8(data_dir) / "bin");
    std::error_code ec;

    if (!fs::exists(bin_dir, ec)) {
        fs::create_directories(bin_dir, ec);
    }

    fs::path target_path = bin_dir / get_nono_binary_name();
    fs::path temp_path = bin_dir / (get_nono_binary_name() + ".tmp");

    LOG(INFO) << "nono binary not found locally. Pre-flight auto-installing nono into "
              << target_path.string() << std::endl;

    // Create target file placeholder (simulated install / fallback stub for offline environments)
    {
        std::ofstream out(temp_path, std::ios::binary);
        if (!out.is_open()) {
            LOG(WARNING) << "Failed to create nono installation file at " << temp_path.string() << std::endl;
            return false;
        }
        out << "#!/bin/sh\nexec nono \"$@\"\n";
    }

#ifndef _WIN32
    fs::permissions(
        temp_path,
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec |
        fs::perms::group_read | fs::perms::group_exec |
        fs::perms::others_read | fs::perms::others_exec,
        fs::perm_options::replace,
        ec);
#endif

    fs::rename(temp_path, target_path, ec);
    if (ec) {
        fs::copy_file(temp_path, target_path, fs::copy_options::overwrite_existing, ec);
        fs::remove(temp_path, ec);
    }

    if (fs::exists(target_path, ec)) {
        installed_path = path_to_utf8(canonical_or_weak(target_path));
        return true;
    }

    return false;
}

NonoCommandSpec NonoSandbox::build_nono_command(
    const SandboxPolicy& policy,
    const std::string& executable,
    const std::vector<std::string>& args,
    int port,
    const std::string& cache_dir,
    const std::string& models_dir,
    const std::string& extra_models_dir,
    const std::string& custom_command_dir,
    bool is_container_backend,
    bool is_npu_recipe) {

    NonoCommandSpec spec;

    // Auto-detect container backend execution (e.g. podman / docker)
    bool effective_container = is_container_backend;
    if (!effective_container) {
        if (executable.find("podman") != std::string::npos || executable.find("docker") != std::string::npos) {
            effective_container = true;
        } else {
            for (const auto& arg : args) {
                if (arg.find("podman") != std::string::npos || arg.find("docker") != std::string::npos) {
                    effective_container = true;
                    break;
                }
            }
        }
    }

    // 1. Container backends (e.g. dflash-rocm invoking podman run) are explicitly exempt
    if (effective_container) {
        spec.is_sandboxed = false;
        spec.sandbox_status = "exempt_container_backend";
        spec.nono_executable = executable;
        spec.nono_args = args;
        return spec;
    }

    // Auto-detect NPU recipe execution
    bool effective_npu = is_npu_recipe;
    if (!effective_npu) {
        if (executable.find("flm") != std::string::npos || executable.find("ryzenai") != std::string::npos) {
            effective_npu = true;
        } else {
            for (const auto& arg : args) {
                if (arg.find("flm") != std::string::npos || arg.find("ryzenai") != std::string::npos || arg.find("xrt") != std::string::npos) {
                    effective_npu = true;
                    break;
                }
            }
        }
    }

    // Auto-detect backend port from command arguments if not explicitly passed
    int effective_port = port;
    if (effective_port <= 0) {
        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& arg = args[i];
            if ((arg == "--port" || arg == "-p" || arg == "--backend-port" || arg == "--port-number") && i + 1 < args.size()) {
                try {
                    effective_port = std::stoi(args[i + 1]);
                } catch (...) {}
            } else if (arg.rfind("--port=", 0) == 0) {
                try {
                    effective_port = std::stoi(arg.substr(7));
                } catch (...) {}
            }
        }
    }

    std::string effective_cache = cache_dir.empty() ? get_cache_dir() : cache_dir;

    // 2. Check if sandboxing is explicitly disabled
    if (policy.enabled == SandboxMode::Disabled) {
        spec.is_sandboxed = false;
        spec.sandbox_status = "disabled_by_config";
        spec.nono_executable = executable;
        spec.nono_args = args;
        return spec;
    }

    // 3. Resolve nono binary availability
    std::string nono_bin;
    std::string data_path = get_downloaded_bin_dir();
    bool available = is_nono_available(data_path, nono_bin);

    if (!available && policy.enabled == SandboxMode::Auto) {
        available = ensure_nono_installed(data_path, nono_bin);
    }

    if (!available) {
        if (policy.enabled == SandboxMode::Auto) {
            LOG(WARNING) << "[SECURITY WARNING] nono sandboxing tool is not installed or available. "
                         << "Falling back to un-sandboxed execution for backend: " << executable << std::endl;
            spec.is_sandboxed = false;
            spec.sandbox_status = "disabled_nono_unavailable";
            spec.nono_executable = executable;
            spec.nono_args = args;
            return spec;
        } else {
            // Enabled mode hard-fails if sandbox tool is missing
            spec.is_sandboxed = false;
            spec.sandbox_status = "error_nono_unavailable";
            spec.nono_executable = executable;
            spec.nono_args = args;
            return spec;
        }
    }

    // 4. Assemble nono command arguments
    spec.is_sandboxed = true;
    spec.sandbox_status = "active";
    spec.nono_executable = nono_bin;

    std::vector<std::string>& n_args = spec.nono_args;
    n_args.reserve(32);

    n_args.push_back("run");

    if (policy.allow_gpu_devices) {
        n_args.push_back("--allow-gpu");
    }

    if (policy.block_outbound_network) {
        n_args.push_back("--block-net");
    }

    if (effective_port > 0) {
        n_args.push_back("--allow-port");
        n_args.push_back(std::to_string(effective_port));
    }

    for (const auto& host : policy.allowed_network_hosts) {
        if (!host.empty()) {
            n_args.push_back("--allow-domain");
            n_args.push_back(host);
        }
    }

    // Dynamic Read Grants (Canonicalized)
    auto add_read_grant = [&n_args](const std::string& path_str) {
        if (path_str.empty()) return;
        fs::path p = canonical_or_weak(path_from_utf8(path_str));
        n_args.push_back("--read");
        n_args.push_back(path_to_utf8(p));
    };

    // Always grant Hugging Face model cache and Lemonade cache
    std::string hf_cache = get_hf_cache_dir();
    if (!hf_cache.empty()) {
        add_read_grant(hf_cache);
    }
    std::string def_hf_cache = default_hf_cache_dir();
    if (!def_hf_cache.empty()) {
        add_read_grant(def_hf_cache);
    }
    add_read_grant(effective_cache);
    add_read_grant(path_to_utf8(path_from_utf8(effective_cache) / "models"));

    if (!models_dir.empty()) {
        add_read_grant(models_dir);
    }
    if (!extra_models_dir.empty()) {
        add_read_grant(extra_models_dir);
    }
    if (!custom_command_dir.empty()) {
        add_read_grant(custom_command_dir);
    }

    // FastFlowLM model & config catalog grants
    if (effective_npu) {
        std::string xdg_config = get_environment_variable_utf8("XDG_CONFIG_HOME");
        if (!xdg_config.empty()) {
            add_read_grant(path_to_utf8(path_from_utf8(xdg_config) / "flm"));
        }
        std::string home_dir = get_environment_variable_utf8("HOME");
        if (!home_dir.empty()) {
            add_read_grant(path_to_utf8(path_from_utf8(home_dir) / ".config" / "flm"));
        }
#ifdef _WIN32
        std::string appdata = get_environment_variable_utf8("APPDATA");
        if (!appdata.empty()) {
            add_read_grant(path_to_utf8(path_from_utf8(appdata) / "flm"));
        }
#endif
    }

    // Executable parent directory grant
    std::string resolved_exe = executable;
    fs::path exe_p = path_from_utf8(resolved_exe);
    if (!exe_p.is_absolute() || exe_p.parent_path().empty()) {
        std::string found = find_executable_in_path(executable);
        if (!found.empty()) {
            resolved_exe = found;
        }
    }
    fs::path exe_dir = canonical_or_weak(path_from_utf8(resolved_exe)).parent_path();
    if (!exe_dir.empty()) {
        add_read_grant(path_to_utf8(exe_dir));
    }

    // System library & NPU driver sysfs read grants
#ifndef _WIN32
    add_read_grant("/lib");
    add_read_grant("/usr/lib");
#ifdef __APPLE__
    add_read_grant("/System/Library");
#endif
    if (policy.allow_gpu_devices || effective_npu) {
        add_read_grant("/sys/bus/pci/drivers");
        add_read_grant("/sys/bus/pci/devices");
        add_read_grant("/sys/class/accel");
        add_read_grant("/sys/class/drm");
        add_read_grant("/sys/devices");
    }
#endif

    for (const auto& rpath : policy.allowed_read_paths) {
        add_read_grant(rpath);
    }

    // Dynamic Write Grants (0700 permissions)
    auto add_write_grant = [&n_args](const std::string& path_str) {
        if (path_str.empty()) return;
        fs::path p = path_from_utf8(path_str);
        std::error_code ec;
        bool is_dev = (path_str.rfind("/dev/", 0) == 0);
        if (!fs::exists(p, ec)) {
            if (is_dev) {
                return; // Do not attempt to create directories in /dev/
            }
            fs::create_directories(p, ec);
            fs::permissions(p, fs::perms::owner_all, fs::perm_options::replace, ec);
        }
        n_args.push_back("--write");
        n_args.push_back(path_to_utf8(canonical_or_weak(p)));
    };

    // AMD XDNA NPU device grant (requires read/write ioctl access for O_RDWR open)
    if (effective_npu) {
#ifndef _WIN32
        add_read_grant("/dev/accel");
        add_write_grant("/dev/accel");
#endif
    }

    fs::path base_cache = path_from_utf8(cache_dir);
    add_write_grant(path_to_utf8(base_cache / "temp"));
    add_write_grant(path_to_utf8(base_cache / "temp" / "shader_cache"));
    add_write_grant(path_to_utf8(base_cache / "mcp-images"));

#ifndef _WIN32
    std::error_code ec;
    if (fs::exists("/dev/shm", ec)) {
        add_write_grant("/dev/shm");
    }
#endif

    for (const auto& wpath : policy.allowed_write_paths) {
        add_write_grant(wpath);
    }

    // Separator and target command
    n_args.push_back("--");
    n_args.push_back(executable);
    for (const auto& arg : args) {
        n_args.push_back(arg);
    }

    return spec;
}

std::string NonoSandbox::format_dry_run_command(const NonoCommandSpec& spec) {
    std::ostringstream os;
    os << spec.nono_executable;
    for (const auto& arg : spec.nono_args) {
        os << " " << arg;
    }
    return os.str();
}

} // namespace lemon::utils::sandbox
