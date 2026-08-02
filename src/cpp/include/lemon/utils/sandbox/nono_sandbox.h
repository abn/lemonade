#pragma once

#include <lemon/config_file.h>
#include <string>
#include <vector>
#include <filesystem>

namespace lemon::utils::sandbox {

struct NonoCommandSpec {
    std::string nono_executable;
    std::vector<std::string> nono_args;
    bool is_sandboxed = false;
    std::string sandbox_status;
};

class NonoSandbox {
public:
    /// Check if nono binary is available on PATH or under data_dir/bin.
    static bool is_nono_available(const std::string& data_dir, std::string& resolved_path);

    /// Pre-flight download nono binary for target OS/arch into data_dir/bin/nono if missing,
    /// verify SHA-256 checksum, set 0755 executable permissions, and perform atomic rename.
    static bool ensure_nono_installed(const std::string& data_dir, std::string& installed_path);

    /// Build nono execution spec for an inference backend command.
    /// Canonicalizes all paths, adds --allow-gpu, sets loopback IPC port binding,
    /// configures shader/temp write grants, and exempts container backends.
    static NonoCommandSpec build_nono_command(
        const SandboxPolicy& policy,
        const std::string& executable,
        const std::vector<std::string>& args,
        int port,
        const std::string& cache_dir,
        const std::string& models_dir = "",
        const std::string& extra_models_dir = "",
        const std::string& custom_command_dir = "",
        bool is_container_backend = false,
        bool is_npu_recipe = false);

    /// Perform a dry-run invocation of nono command formatting for testing & validation.
    static std::string format_dry_run_command(const NonoCommandSpec& spec);
};

} // namespace lemon::utils::sandbox
