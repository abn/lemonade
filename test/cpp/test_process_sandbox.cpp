#include <lemon/sandbox/env_scrubber.h>
#include <lemon/sandbox/sandbox_engine.h>
#include <lemon/sandbox/sandbox_policy.h>
#include <lemon/utils/process_manager.h>
#include <lemon/utils/process_platform.h>
#include <lemon/wrapped_server.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using lemon::WrappedServer;
using lemon::sandbox::EnvScrubber;
using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PathGrant;
using lemon::sandbox::PolicyPresets;
using lemon::sandbox::SandboxEngine;
using lemon::sandbox::SandboxMode;
using lemon::sandbox::SandboxPolicy;
using lemon::utils::ProcessHandle;
using lemon::utils::ProcessManager;

// Release-build safe assertion framework (Zero C assert())
struct TestResult {
    int passed = 0;
    int failed = 0;

    void check(bool cond, const std::string& name, const std::string& details = "") {
        if (cond) {
            std::printf("[PASS] %s\n", name.c_str());
            ++passed;
        } else {
            std::printf("[FAIL] %s\n", name.c_str());
            if (!details.empty()) {
                std::printf("       Details: %s\n", details.c_str());
            }
            ++failed;
        }
    }
};

class TempSandboxFixture {
public:
    TempSandboxFixture() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        temp_dir_ = fs::temp_directory_path() / ("lemonade_proc_sb_test_" + std::to_string(now));
        fs::create_directories(temp_dir_ / "hf_home" / "hub" / "models--test--model" / "snapshots" / "s1");
        fs::create_directories(temp_dir_ / "allowed_dir");
        fs::create_directories(temp_dir_ / "forbidden_dir");

        try {
            temp_dir_ = fs::canonical(temp_dir_);
        } catch (...) {}

        // Create Canary Token
        std::ofstream token_f(temp_dir_ / "hf_home" / "token");
        token_f << "SUPER_SECRET_HF_TOKEN";
        token_f.close();

        // Create Model Weights
        std::ofstream model_f(temp_dir_ / "hf_home" / "hub" / "models--test--model" / "snapshots" / "s1" / "model.gguf");
        model_f << "GGUF_TEST_BYTES";
        model_f.close();

        // Create Allowed & Forbidden Canaries
        std::ofstream allowed_f(temp_dir_ / "allowed_dir" / "allowed.txt");
        allowed_f << "ALLOWED_CONTENT";
        allowed_f.close();

        std::ofstream forbidden_f(temp_dir_ / "forbidden_dir" / "secret.txt");
        forbidden_f << "FORBIDDEN_CONTENT";
        forbidden_f.close();
    }

    ~TempSandboxFixture() {
        std::error_code ec;
        fs::remove_all(temp_dir_, ec);
    }

    fs::path root() const { return temp_dir_; }
    fs::path hf_home() const { return temp_dir_ / "hf_home"; }
    fs::path hf_token() const { return temp_dir_ / "hf_home" / "token"; }
    fs::path hf_model() const { return temp_dir_ / "hf_home" / "hub" / "models--test--model" / "snapshots" / "s1" / "model.gguf"; }
    fs::path allowed_dir() const { return temp_dir_ / "allowed_dir"; }
    fs::path allowed_file() const { return temp_dir_ / "allowed_dir" / "allowed.txt"; }
    fs::path forbidden_dir() const { return temp_dir_ / "forbidden_dir"; }
    fs::path forbidden_file() const { return temp_dir_ / "forbidden_dir" / "secret.txt"; }

private:
    fs::path temp_dir_;
};

int main() {
    TestResult r;
    std::printf("=== ProcessPlatform & WrappedServer Sandbox Integration Tests ===\n\n");

    TempSandboxFixture fixture;

    // -------------------------------------------------------------
    // Suite A: ProcessPlatform / ProcessManager Spawning Lifecycle
    // -------------------------------------------------------------
    {
        std::printf("--- Suite A: Process Spawning Lifecycle ---\n");
#ifndef _WIN32
        // A1. Standard baseline spawn (std::nullopt policy)
        ProcessHandle h1 = ProcessManager::start_process(
            "/bin/sh", {"-c", "exit 0"}, "", false, false, {});
        r.check(h1.pid > 0, "start_process returns valid pid for baseline spawn");
        int exit1 = ProcessManager::wait_for_exit(h1, 5);
        r.check(exit1 == 0, "baseline spawn exits with code 0");

        // A2. Spawn with explicit SandboxPolicy in Auto mode
        SandboxPolicy policy;
        policy.add_read_path("/bin")
              .add_read_path("/usr/bin")
              .add_read_path("/lib")
              .add_read_path("/usr/lib")
              .add_read_path("/lib64")
              .add_read_path("/usr/lib64")
              .set_mode(SandboxMode::Auto);

        ProcessHandle h2 = ProcessManager::start_process(
            "/bin/sh", {"-c", "exit 42"}, "", false, false, {}, policy);
        r.check(h2.pid > 0, "start_process returns valid pid with SandboxPolicy");
        int exit2 = ProcessManager::wait_for_exit(h2, 5);
        r.check(exit2 == 42, "spawn with SandboxPolicy preserves exit code 42");

        // A3. Process termination & lifecycle cleanup
        ProcessHandle h3 = ProcessManager::start_process(
            "/bin/sh", {"-c", "sleep 30"}, "", false, false, {}, policy);
        r.check(h3.pid > 0, "start_process spawned sleeping child");
        r.check(ProcessManager::is_running(h3), "is_running reports true for active child");
        ProcessManager::stop_process(h3);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        r.check(!ProcessManager::is_running(h3), "is_running reports false after stop_process");
#else
        // Windows baseline
        ProcessHandle h1 = ProcessManager::start_process(
            "cmd.exe", {"/c", "exit 0"}, "", false, false, {});
        r.check(h1.pid > 0 || h1.handle != nullptr, "Windows start_process returns handle");
        int exit1 = ProcessManager::wait_for_exit(h1, 5);
        r.check(exit1 == 0, "Windows baseline spawn exits with code 0");
#endif
    }

    // -------------------------------------------------------------
    // Suite B: Child Secret Scrubbing Verification
    // -------------------------------------------------------------
    {
        std::printf("\n--- Suite B: Child Environment Secret Scrubbing ---\n");
#ifndef _WIN32
        // Set ambient sensitive secrets in parent
        setenv("LEMONADE_ADMIN_API_KEY", "super_secret_admin_key_123", 1);
        setenv("LEMONADE_API_KEY", "lemon_api_key_456", 1);
        setenv("OPENAI_API_KEY", "sk-proj-secret-openai-789", 1);
        setenv("AWS_SECRET_ACCESS_KEY", "aws_secret_key_abc", 1);
        setenv("HF_TOKEN", "hf_token_secret_xyz", 1);
        setenv("CUDA_VISIBLE_DEVICES", "0,1", 1);

        fs::path env_dump_file = fixture.root() / "env_dump.txt";
        std::string cmd = "env > \"" + env_dump_file.string() + "\"";

        ProcessHandle h_env = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd}, "", false, false, {});
        ProcessManager::wait_for_exit(h_env, 5);

        // Read output
        std::ifstream dump_in(env_dump_file);
        std::string dump_content((std::istreambuf_iterator<char>(dump_in)),
                                  std::istreambuf_iterator<char>());

        r.check(dump_content.find("super_secret_admin_key_123") == std::string::npos,
                "child environment stripped LEMONADE_ADMIN_API_KEY");
        r.check(dump_content.find("lemon_api_key_456") == std::string::npos,
                "child environment stripped LEMONADE_API_KEY");
        r.check(dump_content.find("sk-proj-secret-openai-789") == std::string::npos,
                "child environment stripped OPENAI_API_KEY");
        r.check(dump_content.find("aws_secret_key_abc") == std::string::npos,
                "child environment stripped AWS_SECRET_ACCESS_KEY");
        r.check(dump_content.find("hf_token_secret_xyz") == std::string::npos,
                "child environment stripped HF_TOKEN");
        r.check(dump_content.find("CUDA_VISIBLE_DEVICES=0,1") != std::string::npos,
                "child environment preserved allowlisted CUDA_VISIBLE_DEVICES");
        r.check(dump_content.find("PATH=") != std::string::npos,
                "child environment preserved PATH");

        // Explicit env_vars parameter scrubbing
        fs::path custom_dump_file = fixture.root() / "custom_env_dump.txt";
        std::string custom_cmd = "env > \"" + custom_dump_file.string() + "\"";
        std::vector<std::pair<std::string, std::string>> custom_env = {
            {"LEMONADE_DYNAMIC_TOKEN", "leak_me_not"},
            {"MY_EXPLICIT_VAR", "preserved_value"}
        };

        ProcessHandle h_custom = ProcessManager::start_process(
            "/bin/sh", {"-c", custom_cmd}, "", false, false, custom_env);
        ProcessManager::wait_for_exit(h_custom, 5);

        std::ifstream custom_in(custom_dump_file);
        std::string custom_content((std::istreambuf_iterator<char>(custom_in)),
                                    std::istreambuf_iterator<char>());

        r.check(custom_content.find("leak_me_not") == std::string::npos,
                "explicit custom LEMONADE_* variable stripped from child");
        r.check(custom_content.find("MY_EXPLICIT_VAR=preserved_value") != std::string::npos,
                "explicit custom non-sensitive variable preserved in child");
#endif
    }

    // -------------------------------------------------------------
    // Suite C: WrappedServer Policy Generation Verification
    // -------------------------------------------------------------
    {
        std::printf("\n--- Suite C: WrappedServer Policy Generation ---\n");

        // C1. Model in Hugging Face Hub cache
        std::string model_path = fixture.hf_model().string();
        SandboxPolicy policy = WrappedServer::build_default_sandbox_policy(
            model_path, "/usr/bin/llama-server", 8080, "vulkan");

        r.check(policy.bind_port == 8080, "policy bind_port set to 8080");
        r.check(policy.network_access == NetworkAccess::LoopbackOnly, "network_access is LoopbackOnly");
        r.check(policy.has_read_path("/usr/bin/llama-server"), "executable read grant added");
        r.check(policy.has_device("/dev/dri"), "vulkan backend includes /dev/dri device grant");

        r.check(!policy.has_read_path(fixture.hf_token().string()), "token file path not in grants");
        r.check(!policy.has_read_path(fixture.hf_home().string()), "cache root directory not in grants");

        // C2. ROCm Device Grants
        SandboxPolicy rocm_policy = WrappedServer::build_default_sandbox_policy(
            model_path, "/usr/bin/llama-server", 8080, "rocm");
        r.check(rocm_policy.has_device("/dev/kfd"), "rocm backend includes /dev/kfd");
        r.check(rocm_policy.has_device("/dev/dri"), "rocm backend includes /dev/dri");

        // C3. NPU Device Grants
        SandboxPolicy npu_policy = WrappedServer::build_default_sandbox_policy(
            model_path, "/usr/bin/flm", 8081, "npu");
        r.check(npu_policy.has_device("/dev/accel"), "npu backend includes /dev/accel");
        r.check(npu_policy.has_device("/dev/amdxdna"), "npu backend includes /dev/amdxdna");

        // C4. CPU Device Grants (No extra GPU/NPU device nodes)
        SandboxPolicy cpu_policy = WrappedServer::build_default_sandbox_policy(
            model_path, "/usr/bin/koko", 8082, "cpu");
        r.check(!cpu_policy.has_device("/dev/kfd"), "cpu backend omits /dev/kfd");
    }

    // -------------------------------------------------------------
    // Suite D: Sandbox Modes & Landlock Containment
    // -------------------------------------------------------------
    {
        std::printf("\n--- Suite D: Sandbox Modes & Containment ---\n");

#ifndef _WIN32
        // D1. ScrubbedOnly Mode
        SandboxPolicy scrubbed_policy;
        scrubbed_policy.set_mode(SandboxMode::ScrubbedOnly);
        ProcessHandle h_scrub = ProcessManager::start_process(
            "/bin/sh", {"-c", "exit 0"}, "", false, false, {}, scrubbed_policy);
        r.check(h_scrub.pid > 0, "ScrubbedOnly mode spawns cleanly");
        r.check(ProcessManager::wait_for_exit(h_scrub, 5) == 0, "ScrubbedOnly exits 0");

        // D2. Auto Mode
        SandboxPolicy auto_policy;
        auto_policy.set_mode(SandboxMode::Auto);
        auto_policy.add_read_path("/bin")
                   .add_read_path("/usr/bin")
                   .add_read_path("/lib")
                   .add_read_path("/usr/lib")
                   .add_read_path("/lib64")
                   .add_read_path("/usr/lib64");
        ProcessHandle h_auto = ProcessManager::start_process(
            "/bin/sh", {"-c", "exit 0"}, "", false, false, {}, auto_policy);
        r.check(h_auto.pid > 0, "Auto mode spawns cleanly");
        r.check(ProcessManager::wait_for_exit(h_auto, 5) == 0, "Auto mode exits 0");

        // D3. Enforced Mode & Path Confinement
        if (SandboxEngine::is_platform_supported()) {
            SandboxPolicy enforced_policy;
            enforced_policy.set_mode(SandboxMode::Enforced);
            for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
                enforced_policy.path_grants.push_back(sp);
            }
            enforced_policy.add_read_path("/bin")
                           .add_write_path("/dev")
                           .add_read_path(fixture.allowed_dir().string());

            // Script tests reading allowed file (must succeed) and forbidden file (must fail)
            std::string containment_script =
                "cat \"" + fixture.allowed_file().string() + "\" >/dev/null 2>&1 || exit 10; "
                "if cat \"" + fixture.forbidden_file().string() + "\" >/dev/null 2>&1; then "
                "  exit 20; " // Failure: forbidden file was readable!
                "else "
                "  exit 0; "  // Success: forbidden file access was blocked!
                "fi";

            ProcessHandle h_enf = ProcessManager::start_process(
                "/bin/sh", {"-c", containment_script}, "", false, false, {}, enforced_policy);
            r.check(h_enf.pid > 0, "Enforced mode spawned containment test child");
            int enf_exit = ProcessManager::wait_for_exit(h_enf, 5);

            r.check(enf_exit == 0, "Enforced sandbox successfully blocked unauthorized file access (exit 0)",
                    "Child exit code was " + std::to_string(enf_exit));
        } else {
            std::printf("[INFO] Kernel sandboxing unsupported on this host; skipping live Landlock containment test\n");
        }
#endif
    }

    std::printf("\n=== Summary: %d passed, %d failed ===\n", r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
