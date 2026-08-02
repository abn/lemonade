#include <lemon/utils/process_manager.h>
#include <lemon/utils/process_platform.h>
#include <lemon/utils/sandbox/nono_sandbox.h>
#include <lemon/utils/path_utils.h>
#include <lemon/utils/aixlog.hpp>
#include <lemon/config_file.h>

namespace lemon {
namespace utils {

ProcessHandle ProcessManager::start_process(
    const std::string& executable,
    const std::vector<std::string>& args,
    const std::string& working_dir,
    bool inherit_output,
    bool filter_health_logs,
    const std::vector<std::pair<std::string, std::string>>& env_vars,
    const SandboxPolicy* sandbox_policy,
    int port,
    const std::string& cache_dir,
    const std::string& models_dir,
    const std::string& extra_models_dir,
    const std::string& custom_command_dir,
    bool is_container_backend,
    bool is_npu_recipe) {

    auto platform = create_process_platform();

    SandboxPolicy auto_policy;
    const SandboxPolicy* policy_to_use = sandbox_policy;
    if (!policy_to_use) {
        std::string effective_cache = cache_dir.empty() ? get_cache_dir() : cache_dir;
        json cfg = ConfigFile::load(effective_cache);
        auto_policy = ConfigFile::get_sandbox_policy(cfg);
        policy_to_use = &auto_policy;
    }

    if (policy_to_use && policy_to_use->enabled != SandboxMode::Disabled) {
        auto spec = sandbox::NonoSandbox::build_nono_command(
            *policy_to_use,
            executable,
            args,
            port,
            cache_dir,
            models_dir,
            extra_models_dir,
            custom_command_dir,
            is_container_backend,
            is_npu_recipe);

        if (spec.is_sandboxed) {
            LOG(INFO) << "[SANDBOX] Engaged nono sandboxing for backend: " << executable
                      << " (status: " << spec.sandbox_status << ")" << std::endl;
            return platform->spawn(spec.nono_executable, spec.nono_args, working_dir, inherit_output, filter_health_logs, env_vars);
        } else {
            LOG(INFO) << "[SANDBOX] Backend process launch unwrapped: " << executable
                      << " (reason: " << spec.sandbox_status << ")" << std::endl;
        }
    }

    return platform->spawn(executable, args, working_dir, inherit_output, filter_health_logs, env_vars);
}

void ProcessManager::stop_process(ProcessHandle handle) {
    auto platform = create_process_platform();
    platform->terminate(handle);
}

bool ProcessManager::is_running(ProcessHandle handle) {
    auto platform = create_process_platform();
    return platform->is_running(handle);
}

int ProcessManager::get_exit_code(ProcessHandle handle) {
    auto platform = create_process_platform();
    return platform->get_exit_code(handle);
}

int ProcessManager::wait_for_exit(ProcessHandle handle, int timeout_seconds) {
    auto platform = create_process_platform();
    return platform->wait_for_exit(handle, timeout_seconds);
}

int ProcessManager::reap_process(ProcessHandle handle) {
    auto platform = create_process_platform();
    return platform->reap(handle);
}

std::string ProcessManager::read_output(ProcessHandle handle, int max_bytes) {
    // Note: This is a simplified version. Full implementation would need pipes
    // for stdout/stderr capture during process creation.
    return "";
}

int ProcessManager::run_process_with_output(
    const std::string& executable,
    const std::vector<std::string>& args,
    OutputLineCallback on_line,
    const std::string& working_dir,
    int timeout_seconds,
    bool capture_stderr) {

    auto platform = create_process_platform();
    return platform->run_with_output(executable, args, on_line, working_dir, timeout_seconds, capture_stderr);
}

void ProcessManager::kill_process(ProcessHandle handle) {
    auto platform = create_process_platform();
    platform->kill(handle);
}

void ProcessManager::terminate_process(ProcessHandle handle) {
    auto platform = create_process_platform();
    platform->terminate_without_cleanup(handle);
}

int ProcessManager::find_free_port(int start_port) {
    auto platform = create_process_platform();
    return platform->find_free_port(start_port);
}

int ProcessManager::run_command(const std::string& command, std::string& output, int timeout_seconds) {
    auto platform = create_process_platform();
    return platform->run_command(command, output, timeout_seconds);
}

} // namespace utils
} // namespace lemon
