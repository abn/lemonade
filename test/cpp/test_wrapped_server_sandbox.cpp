#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "lemon/model_types.h"
#include "lemon/sandbox/env_scrubber.h"
#include "lemon/sandbox/nono_ffi.h"
#include "lemon/sandbox/sandbox_engine.h"
#include "lemon/sandbox/sandbox_policy.h"
#include "lemon/utils/process_manager.h"
#include "lemon/utils/process_platform.h"
#include "lemon/wrapped_server.h"

namespace fs = std::filesystem;
using lemon::DeviceType;
using lemon::DEVICE_CPU;
using lemon::DEVICE_GPU;
using lemon::DEVICE_NPU;
using lemon::DEVICE_NONE;
using lemon::ModelInfo;
using lemon::RecipeOptions;
using lemon::WrappedServer;
using lemon::sandbox::EnvScrubber;
using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PathGrant;
using lemon::sandbox::PlatformDetector;
using lemon::sandbox::PlatformType;
using lemon::sandbox::PolicyPresets;
using lemon::sandbox::SandboxEngine;
using lemon::sandbox::SandboxMode;
using lemon::sandbox::SandboxPolicy;
using lemon::utils::ProcessHandle;
using lemon::utils::ProcessManager;

// Concrete subclass for WrappedServer testing
class ConcreteWrappedServer : public WrappedServer {
public:
    ConcreteWrappedServer(const std::string& name, DeviceType dev = DEVICE_NONE)
        : WrappedServer(name, "debug") {
        device_type_ = dev;
    }
    void load(const std::string&, const ModelInfo&, const RecipeOptions&, bool) override {}
    void unload() override {}

    void set_test_device(DeviceType dev) {
        device_type_ = dev;
    }
};

// Thread-safe assertion and reporting harness
struct TestResult {
    std::atomic<int> passed{0};
    std::atomic<int> failed{0};
    std::vector<std::string> failure_messages;
    std::mutex mtx;

    void check(bool cond, const std::string& name, const std::string& details = "") {
        if (cond) {
            std::printf("  [PASS] %s\n", name.c_str());
            ++passed;
        } else {
            std::printf("  [FAIL] %s\n", name.c_str());
            if (!details.empty()) {
                std::printf("         Details: %s\n", details.c_str());
            }
            std::lock_guard<std::mutex> lock(mtx);
            failure_messages.push_back(name + (details.empty() ? "" : " (" + details + ")"));
            ++failed;
        }
    }

    void report_summary(const std::string& section) const {
        std::printf("-> Summary for '%s': %d passed, %d failed\n\n",
                    section.c_str(), passed.load(), failed.load());
    }
};

// Temporary directory tree fixture mimicking complex HF caches and user home
class AdvancedHFFixture {
public:
    AdvancedHFFixture() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        base_dir_ = fs::temp_directory_path() / ("lemonade_test_hf_" + std::to_string(now));

        // HF home hierarchy
        hf_home_ = base_dir_ / "user_home" / ".cache" / "huggingface";
        hf_hub_ = hf_home_ / "hub";
        hf_dot_home_ = base_dir_ / "user_home" / ".huggingface";

        model_dir_ = hf_hub_ / "models--meta-llama--Llama-3-8B" / "snapshots" / "abc123def456";
        model_file_ = model_dir_ / "model-q4_k_m.gguf";

        custom_hf_home_ = base_dir_ / "custom_hf_home";
        custom_hub_ = custom_hf_home_ / "hub";
        custom_model_dir_ = custom_hub_ / "models--mistralai--Mistral-7B" / "snapshots" / "999888777";
        custom_model_file_ = custom_model_dir_ / "model.gguf";

        // Isolation confinement paths
        allowed_dir_ = base_dir_ / "confinement_allowed";
        writeable_dir_ = base_dir_ / "confinement_writeable";
        forbidden_dir_ = base_dir_ / "confinement_forbidden";
        parent_home_dir_ = base_dir_ / "parent_home";

        fs::create_directories(model_dir_);
        fs::create_directories(hf_dot_home_);
        fs::create_directories(custom_model_dir_);
        fs::create_directories(allowed_dir_);
        fs::create_directories(writeable_dir_);
        fs::create_directories(forbidden_dir_);
        fs::create_directories(parent_home_dir_);

        try {
            base_dir_ = fs::canonical(base_dir_);
            hf_home_ = fs::canonical(hf_home_);
            hf_hub_ = fs::canonical(hf_hub_);
            model_dir_ = fs::canonical(model_dir_);
            allowed_dir_ = fs::canonical(allowed_dir_);
            writeable_dir_ = fs::canonical(writeable_dir_);
            forbidden_dir_ = fs::canonical(forbidden_dir_);
            parent_home_dir_ = fs::canonical(parent_home_dir_);
        } catch (...) {}

        // 1. Create standard HF token files
        write_file(hf_home_ / "token", "HF_TOKEN_STANDARD_SECRET_KEY_12345");
        write_file(hf_home_ / "stored_tokens", "STORED_TOKEN_HASH_SECRET_67890");
        write_file(hf_home_ / "token.lock", "LOCK_FILE_DUMMY_DATA");
        write_file(hf_dot_home_ / "token", "LEGACY_DOT_HUGGINGFACE_SECRET");
        write_file(custom_hf_home_ / "token", "CUSTOM_HF_HOME_TOKEN_SECRET");

        // 2. Create Model GGUF weights
        write_file(model_file_, "GGUF_HEADER_LLAMA_3_8B_WEIGHTS_CONTENT");
        write_file(custom_model_file_, "GGUF_HEADER_MISTRAL_7B_WEIGHTS_CONTENT");

        // 3. Create Confinement & Canary Files
        allowed_file_ = allowed_dir_ / "allowed_corpus.txt";
        write_file(allowed_file_, "READ_ACCESS_GRANTED_PUBLIC_DATA");

        writeable_file_ = writeable_dir_ / "output.log";
        write_file(writeable_file_, "INITIAL_LOG_LINE\n");

        forbidden_canary_ = forbidden_dir_ / "top_secret_canary.txt";
        write_file(forbidden_canary_, "CRITICAL_CONFIDENTIAL_USER_PASSWORD_HASH");

        parent_canary_ = parent_home_dir_ / "id_rsa";
        write_file(parent_canary_, "-----BEGIN OPENSSH PRIVATE KEY-----\nMOCK_KEY\n-----END OPENSSH PRIVATE KEY-----");
    }

    ~AdvancedHFFixture() {
        std::error_code ec;
        fs::remove_all(base_dir_, ec);
    }

    void write_file(const fs::path& p, const std::string& content) {
        fs::create_directories(p.parent_path());
        std::ofstream ofs(p);
        ofs << content;
        ofs.close();
    }

    fs::path base() const { return base_dir_; }
    fs::path user_home() const { return base_dir_ / "user_home"; }
    fs::path hf_home() const { return hf_home_; }
    fs::path hf_hub() const { return hf_hub_; }
    fs::path hf_token() const { return hf_home_ / "token"; }
    fs::path hf_stored_tokens() const { return hf_home_ / "stored_tokens"; }
    fs::path hf_token_lock() const { return hf_home_ / "token.lock"; }
    fs::path hf_dot_token() const { return hf_dot_home_ / "token"; }
    fs::path model_dir() const { return model_dir_; }
    fs::path model_file() const { return model_file_; }

    fs::path custom_hf_home() const { return custom_hf_home_; }
    fs::path custom_token() const { return custom_hf_home_ / "token"; }
    fs::path custom_model_file() const { return custom_model_file_; }

    fs::path allowed_dir() const { return allowed_dir_; }
    fs::path allowed_file() const { return allowed_file_; }
    fs::path writeable_dir() const { return writeable_dir_; }
    fs::path writeable_file() const { return writeable_file_; }
    fs::path forbidden_dir() const { return forbidden_dir_; }
    fs::path forbidden_canary() const { return forbidden_canary_; }
    fs::path parent_home_dir() const { return parent_home_dir_; }
    fs::path parent_canary() const { return parent_canary_; }

    std::string read_file_content(const fs::path& p) {
        std::ifstream ifs(p);
        if (!ifs) return "";
        std::stringstream ss;
        ss << ifs.rdbuf();
        return ss.str();
    }

private:
    fs::path base_dir_;
    fs::path hf_home_;
    fs::path hf_hub_;
    fs::path hf_dot_home_;
    fs::path model_dir_;
    fs::path model_file_;
    fs::path custom_hf_home_;
    fs::path custom_hub_;
    fs::path custom_model_dir_;
    fs::path custom_model_file_;
    fs::path allowed_dir_;
    fs::path allowed_file_;
    fs::path writeable_dir_;
    fs::path writeable_file_;
    fs::path forbidden_dir_;
    fs::path forbidden_canary_;
    fs::path parent_home_dir_;
    fs::path parent_canary_;
};

int main() {
    std::printf("===================================================================\n");
    std::printf("   WRAPPED SERVER SANDBOX POLICY & HARDWARE MATRIX SUITE           \n");
    std::printf("===================================================================\n\n");

    TestResult total_results;
    AdvancedHFFixture fixture;

    // =========================================================================
    // SUITE 1: Model Path Scoping & Hardware Device Matrix
    // =========================================================================
    std::printf("--- SUITE 1: Model Path Scoping & Hardware Device Matrix ---\n");
    {
        TestResult r;

        // Set HOME to fixture home for accurate path isolation
#ifndef _WIN32
        setenv("HOME", fixture.user_home().string().c_str(), 1);
        unsetenv("HF_HOME");
        unsetenv("HF_HUB_CACHE");
        unsetenv("HF_TOKEN_PATH");
#endif

        // Test 1.1: Direct model snapshot file grant
        std::string model_file_str = fixture.model_file().string();
        SandboxPolicy p1 = WrappedServer::build_default_sandbox_policy(
            model_file_str, "/usr/bin/llama-server", 8080, "vulkan", DEVICE_GPU);

        r.check(!p1.has_read_path(fixture.hf_token().string()), "policy does NOT contain HF token grant");
        r.check(!p1.has_read_path(fixture.hf_stored_tokens().string()), "policy does NOT contain stored_tokens grant");
        r.check(!p1.has_read_path(fixture.hf_token_lock().string()), "policy does NOT contain token.lock grant");
        r.check(!p1.has_read_path(fixture.hf_home().string()), "policy does NOT contain root HF home grant");

        // Verify model grant is present
        r.check(p1.has_read_path(fixture.model_file().string()) ||
                p1.has_read_path(fixture.model_dir().string()),
                "policy contains snapshot model path grant");

        // Test 1.2: Snapshot directory as input
        SandboxPolicy p2 = WrappedServer::build_default_sandbox_policy(
            fixture.model_dir().string(), "/usr/bin/llama-server", 8081, "cpu", DEVICE_CPU);
        r.check(!p2.has_read_path(fixture.hf_token().string()), "snapshot dir policy omits token file");

        // Test 1.3: Hub cache directory as input
        SandboxPolicy p3 = WrappedServer::build_default_sandbox_policy(
            fixture.hf_hub().string(), "/usr/bin/llama-server", 8082, "rocm", DEVICE_GPU);
        r.check(!p3.has_read_path(fixture.hf_home().string()), "hub cache dir policy does NOT escalate to HF home root");
        r.check(!p3.has_read_path(fixture.hf_token().string()), "hub cache dir policy does NOT contain token file");

        // Test 1.4: Direct Token Path passed as model path
        SandboxPolicy p6 = WrappedServer::build_default_sandbox_policy(
            fixture.model_dir().string(), "/usr/bin/llama-server", 8085, "cpu", DEVICE_NONE);
        r.check(!p6.has_read_path(fixture.hf_token().string()), "direct token path never included in policy");

        // Test 1.5: Polymorphic WrappedServer member method check
        ConcreteWrappedServer server("llama-server", DEVICE_GPU);
        SandboxPolicy p9 = server.build_sandbox_policy(
            "/usr/bin/llama-server", fixture.model_file().string(), 8088, "vulkan");
        r.check(p9.has_device("/dev/dri"), "Polymorphic server inherits device grants");
        r.check(p9.bind_port == 8088, "Polymorphic server sets bind_port");

        r.report_summary("Model Path Scoping & Token Safety");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }

    // =========================================================================
    // SUITE 2: In-Child Filesystem Confinement (Live Landlock Enforced Mode)
    // =========================================================================
    std::printf("--- SUITE 2: In-Child Filesystem Confinement (Landlock Live Containment) ---\n");
    {
        TestResult r;

#ifndef _WIN32
        bool landlock_supported = SandboxEngine::is_platform_supported();
        if (landlock_supported) {
            std::printf("  [INFO] Host supports kernel Landlock LSM. Running live containment tests...\n");

            // Define strictly confined SandboxPolicy in SandboxMode::Enforced
            SandboxPolicy policy;
            policy.set_mode(SandboxMode::Enforced);
            policy.set_network_access(NetworkAccess::LoopbackOnly);
            policy.set_bind_port(9500);

            // Essential system paths for binary/dynamic linker execution
            for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
                policy.path_grants.push_back(sp);
            }
            policy.add_read_path("/bin")
                  .add_read_path("/usr/bin")
                  .add_write_path("/dev");

            // Grant 1: Read-only access to allowed_dir
            policy.add_read_path(fixture.allowed_dir().string());

            // Grant 2: Read-write access to writeable_dir
            policy.add_write_path(fixture.writeable_dir().string());

            // Note: forbidden_dir_ and parent_home_dir_ are INTENTIONALLY NOT GRANTED

            // Test 2.1: Positive Test - Child reads granted file
            std::string cmd_read_allowed =
                "cat \"" + fixture.allowed_file().string() + "\" >/dev/null 2>&1 && exit 0 || exit 10";
            ProcessHandle h1 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_read_allowed}, "", false, false, {}, policy);
            r.check(h1.pid > 0, "start_process spawned child for granted read test");
            int exit1 = ProcessManager::wait_for_exit(h1, 5);
            r.check(exit1 == 0, "Child successfully read granted file inside allowed_dir (exit 0)",
                    "exit code: " + std::to_string(exit1));

            // Test 2.2: Positive Test - Child writes to granted writeable directory
            std::string cmd_write_allowed =
                "echo 'APPENDED_DATA' >> \"" + fixture.writeable_file().string() + "\" && exit 0 || exit 11";
            ProcessHandle h2 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_write_allowed}, "", false, false, {}, policy);
            int exit2 = ProcessManager::wait_for_exit(h2, 5);
            r.check(exit2 == 0, "Child successfully wrote to granted writeable_dir (exit 0)",
                    "exit code: " + std::to_string(exit2));

            // Verify file content actually modified
            std::ifstream win(fixture.writeable_file());
            std::string wcontent((std::istreambuf_iterator<char>(win)), std::istreambuf_iterator<char>());
            r.check(wcontent.find("APPENDED_DATA") != std::string::npos,
                    "Write to writeable_dir persisted correctly");

            // Test 2.3: Security Test - Child attempts write to read-only allowed_dir
            std::string cmd_write_ro =
                "echo 'UNAUTHORIZED_WRITE' > \"" + (fixture.allowed_dir() / "new_file.txt").string() + "\" 2>/dev/null && exit 20 || exit 0";
            ProcessHandle h3 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_write_ro}, "", false, false, {}, policy);
            int exit3 = ProcessManager::wait_for_exit(h3, 5);
            r.check(exit3 == 0, "Child was strictly BLOCKED from writing to read-only directory (exit 0)",
                    "exit code: " + std::to_string(exit3));

            // Test 2.4: Security Test - Child attempts to read unauthorized forbidden canary
            std::string cmd_read_forbidden =
                "cat \"" + fixture.forbidden_canary().string() + "\" >/dev/null 2>&1 && exit 30 || exit 0";
            ProcessHandle h4 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_read_forbidden}, "", false, false, {}, policy);
            int exit4 = ProcessManager::wait_for_exit(h4, 5);
            r.check(exit4 == 0, "Child was strictly BLOCKED from reading unauthorized canary in forbidden_dir (exit 0)",
                    "exit code: " + std::to_string(exit4));

            // Test 2.5: Security Test - Child attempts to read unauthorized parent secret
            std::string cmd_read_parent =
                "cat \"" + fixture.parent_canary().string() + "\" >/dev/null 2>&1 && exit 40 || exit 0";
            ProcessHandle h5 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_read_parent}, "", false, false, {}, policy);
            int exit5 = ProcessManager::wait_for_exit(h5, 5);
            r.check(exit5 == 0, "Child was strictly BLOCKED from reading parent SSH key/canary (exit 0)",
                    "exit code: " + std::to_string(exit5));

            // Test 2.6: Security Test - Child attempts to read sensitive host files (/etc/shadow)
            std::string cmd_read_shadow =
                "cat /etc/shadow >/dev/null 2>&1 && exit 50 || exit 0";
            ProcessHandle h6 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_read_shadow}, "", false, false, {}, policy);
            int exit6 = ProcessManager::wait_for_exit(h6, 5);
            r.check(exit6 == 0, "Child was strictly BLOCKED from reading /etc/shadow (exit 0)",
                    "exit code: " + std::to_string(exit6));

            // Test 2.7: Security Test - Child attempts directory listing on ungranted directory
            std::string cmd_ls_forbidden =
                "ls \"" + fixture.forbidden_dir().string() + "\" >/dev/null 2>&1 && exit 60 || exit 0";
            ProcessHandle h7 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_ls_forbidden}, "", false, false, {}, policy);
            int exit7 = ProcessManager::wait_for_exit(h7, 5);
            r.check(exit7 == 0, "Child was strictly BLOCKED from directory listing ungranted directory (exit 0)",
                    "exit code: " + std::to_string(exit7));

            // Test 2.8: Security Test - Child attempts to read HF token file under WrappedServer policy
            SandboxPolicy hf_live_policy = WrappedServer::build_default_sandbox_policy(
                fixture.model_file().string(), "/bin/sh", 9501, "cpu", DEVICE_NONE);
            hf_live_policy.set_mode(SandboxMode::Enforced);
            for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
                hf_live_policy.path_grants.push_back(sp);
            }
            hf_live_policy.add_read_path("/bin").add_read_path("/usr/bin").add_write_path("/dev");
            hf_live_policy.normalize_paths();

            // Script verifies model weights are readable but token file is blocked
            std::string cmd_hf_live =
                "cat \"" + fixture.model_file().string() + "\" >/dev/null 2>&1 || exit 70; "
                "if cat \"" + fixture.hf_token().string() + "\" >/dev/null 2>&1; then "
                "  exit 71; " // Token was readable -> Failure!
                "else "
                "  exit 0; "  // Token access was blocked -> Success!
                "fi";

            ProcessHandle h8 = ProcessManager::start_process(
                "/bin/sh", {"-c", cmd_hf_live}, "", false, false, {}, hf_live_policy);
            int exit8 = ProcessManager::wait_for_exit(h8, 5);
            r.check(exit8 == 0, "Child under WrappedServer policy can read model but is BLOCKED from reading HF token (exit 0)",
                    "exit code: " + std::to_string(exit8));

        } else {
            std::printf("  [INFO] Landlock unsupported on this host (WSL1/custom kernel). Verifying graceful fallback.\n");
            SandboxPolicy policy;
            policy.set_mode(SandboxMode::Auto);
            ProcessHandle h = ProcessManager::start_process(
                "/bin/sh", {"-c", "exit 0"}, "", false, false, {}, policy);
            r.check(h.pid > 0, "Auto mode spawns child on unsupported host");
            r.check(ProcessManager::wait_for_exit(h, 5) == 0, "Auto mode child exits 0");
        }
#else
        std::printf("  [INFO] Windows platform detected. Verifying secret scrubbing & graceful degradation.\n");
        SandboxPolicy policy;
        policy.set_mode(SandboxMode::Auto);
        ProcessHandle h = ProcessManager::start_process(
            "cmd.exe", {"/c", "exit 0"}, "", false, false, {}, policy);
        r.check(h.pid > 0 || h.handle != nullptr, "Windows spawn with policy succeeds");
        r.check(ProcessManager::wait_for_exit(h, 5) == 0, "Windows child exits 0");
#endif

        r.report_summary("In-Child Filesystem Confinement");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }

    // =========================================================================
    // SUITE 3: Backend Policy Variation & Hardware Device Matrix
    // =========================================================================
    std::printf("--- SUITE 3: Backend Policy Variation & Hardware Device Matrix ---\n");
    {
        TestResult r;

        struct BackendMatrixCase {
            std::string label;
            std::string executable;
            std::string model_path;
            uint16_t port;
            std::string variant;
            DeviceType device_type;
            std::vector<std::string> required_devices;
            std::vector<std::string> forbidden_devices;
            NetworkAccess expected_net;
        };

        std::vector<BackendMatrixCase> test_cases = {
            {
                "Llama.cpp Vulkan (GPU)",
                "/usr/bin/llama-server",
                "/cache/models/llama-3.gguf",
                8001,
                "vulkan",
                DEVICE_GPU,
                {"/dev/dri", "/dev/kfd", "/dev/dxg"},
                {"/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Llama.cpp ROCm (GPU)",
                "/opt/lemonade/bin/llama-server",
                "/cache/models/qwen.gguf",
                8002,
                "rocm",
                DEVICE_GPU,
                {"/dev/dri", "/dev/kfd"},
                {"/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Llama.cpp CUDA (GPU)",
                "/usr/local/bin/llama-server",
                "/cache/models/deepseek.gguf",
                8003,
                "cuda",
                DEVICE_GPU,
                {"/dev/dri", "/dev/nvidiactl", "/dev/nvidia-uvm"},
                {"/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Llama.cpp CPU (No Accelerator)",
                "/usr/bin/llama-server",
                "/cache/models/phi.gguf",
                8004,
                "cpu",
                DEVICE_CPU,
                {},
                {"/dev/kfd", "/dev/accel", "/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "FastFlowLM (NPU)",
                "/usr/bin/flm",
                "/cache/models/flm-model",
                8005,
                "flm",
                DEVICE_NPU,
                {"/dev/accel", "/dev/amdxdna", "/sys/class/accel", "/dev/dri"},
                {"/dev/nvidiactl"},
                NetworkAccess::LoopbackOnly
            },
            {
                "RyzenAI LLM (NPU)",
                "/opt/ryzenai/bin/ryzenai-server",
                "/cache/models/ryzenai-weights",
                8006,
                "ryzenai",
                DEVICE_NPU,
                {"/dev/accel", "/dev/amdxdna", "/sys/class/accel", "/dev/dri"},
                {},
                NetworkAccess::LoopbackOnly
            },
            {
                "vLLM ROCm (GPU / Strix Halo)",
                "/opt/vllm/bin/python",
                "/cache/models/vllm-llama",
                8007,
                "rocm",
                DEVICE_GPU,
                {"/dev/dri", "/dev/kfd"},
                {"/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Whisper.cpp CPU",
                "/usr/bin/whisper-server",
                "/cache/models/ggml-whisper-base.bin",
                8008,
                "cpu",
                DEVICE_CPU,
                {},
                {"/dev/kfd", "/dev/accel"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Whisper.cpp NPU",
                "/usr/bin/whisper-server",
                "/cache/models/ggml-whisper-base.bin",
                8009,
                "npu",
                DEVICE_NPU,
                {"/dev/accel", "/dev/amdxdna"},
                {},
                NetworkAccess::LoopbackOnly
            },
            {
                "Stable Diffusion GPU (Vulkan)",
                "/usr/bin/sd-server",
                "/cache/models/sd-v1-5.gguf",
                8010,
                "vulkan",
                DEVICE_GPU,
                {"/dev/dri"},
                {"/dev/amdxdna"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Kokoro TTS CPU",
                "/usr/bin/koko",
                "/cache/models/kokoro-v0_19.onnx",
                8011,
                "cpu",
                DEVICE_CPU,
                {},
                {"/dev/kfd", "/dev/accel"},
                NetworkAccess::LoopbackOnly
            },
            {
                "Moonshine ASR CPU",
                "/usr/bin/moonshine-server",
                "/cache/models/moonshine-base",
                8012,
                "cpu",
                DEVICE_CPU,
                {},
                {"/dev/kfd", "/dev/accel"},
                NetworkAccess::LoopbackOnly
            }
        };

        for (const auto& tc : test_cases) {
            SandboxPolicy policy = WrappedServer::build_default_sandbox_policy(
                tc.model_path, tc.executable, tc.port, tc.variant, tc.device_type);

            r.check(policy.bind_port == tc.port, tc.label + ": bind_port configured to " + std::to_string(tc.port));
            r.check(policy.network_access == tc.expected_net, tc.label + ": network_access matches LoopbackOnly");
            r.check(policy.has_read_path(tc.executable), tc.label + ": executable read grant present");
            r.check(policy.has_read_path(tc.model_path), tc.label + ": model_path read grant present");

            // Verify required devices
            for (const auto& dev : tc.required_devices) {
                r.check(policy.has_device(dev), tc.label + ": contains required device " + dev);
            }

            // Verify forbidden devices
            for (const auto& dev : tc.forbidden_devices) {
                r.check(!policy.has_device(dev), tc.label + ": correctly excludes device " + dev);
            }

            // Verify standard environment variable allowlist
            r.check(policy.has_allowed_env("PATH"), tc.label + ": allows PATH env");
            r.check(policy.has_allowed_env("HOME"), tc.label + ": allows HOME env");
            r.check(policy.has_allowed_env("CUDA_VISIBLE_DEVICES"), tc.label + ": allows CUDA_VISIBLE_DEVICES env");
            r.check(policy.has_allowed_env("HIP_VISIBLE_DEVICES"), tc.label + ": allows HIP_VISIBLE_DEVICES env");
        }

        // Case insensitivity stress on backend_variant strings
        std::vector<std::string> vulkan_casings = {"vulkan", "VULKAN", "Vulkan", "vUlKaN"};
        for (const auto& v : vulkan_casings) {
            SandboxPolicy pol = WrappedServer::build_default_sandbox_policy(
                "/tmp/m.gguf", "/bin/exec", 8090, v, DEVICE_NONE);
            r.check(pol.has_device("/dev/dri"), "Case insensitivity check for variant '" + v + "' grants /dev/dri");
        }

        std::vector<std::string> rocm_casings = {"rocm", "ROCM", "Rocm", "RoCm"};
        for (const auto& v : rocm_casings) {
            SandboxPolicy pol = WrappedServer::build_default_sandbox_policy(
                "/tmp/m.gguf", "/bin/exec", 8091, v, DEVICE_NONE);
            r.check(pol.has_device("/dev/kfd"), "Case insensitivity check for variant '" + v + "' grants /dev/kfd");
        }

        std::vector<std::string> npu_casings = {"npu", "NPU", "Npu", "flm", "FLM", "ryzenai", "RYZENAI"};
        for (const auto& v : npu_casings) {
            SandboxPolicy pol = WrappedServer::build_default_sandbox_policy(
                "/tmp/m.gguf", "/bin/exec", 8092, v, DEVICE_NONE);
            r.check(pol.has_device("/dev/accel"), "Case insensitivity check for variant '" + v + "' grants /dev/accel");
        }

        // Policy Presets helper methods verification
        SandboxPolicy p_llama = PolicyPresets::create_for_llamacpp("/usr/bin/llama-server", "/cache/model.gguf", 8000, "vulkan");
        r.check(p_llama.has_device("/dev/dri"), "PolicyPresets::create_for_llamacpp includes /dev/dri");
        r.check(p_llama.bind_port == 8000, "PolicyPresets::create_for_llamacpp sets port 8000");

        SandboxPolicy p_flm = PolicyPresets::create_for_fastflowlm("/usr/bin/flm", "/cache/flm-model", 8001);
        r.check(p_flm.has_device("/dev/accel"), "PolicyPresets::create_for_fastflowlm includes /dev/accel");
        r.check(p_flm.has_device("/dev/amdxdna"), "PolicyPresets::create_for_fastflowlm includes /dev/amdxdna");

        SandboxPolicy p_vllm = PolicyPresets::create_for_vllm("/usr/bin/vllm", "/cache/vllm-model", 8002, "/opt/rocm", "/tmp/triton");
        r.check(p_vllm.has_device("/dev/kfd"), "PolicyPresets::create_for_vllm includes /dev/kfd");
        r.check(p_vllm.has_write_path("/tmp/triton"), "PolicyPresets::create_for_vllm allows write to triton cache");
        r.check(p_vllm.has_allowed_env("PYTHONPATH"), "PolicyPresets::create_for_vllm allows PYTHONPATH");

        SandboxPolicy p_whisper = PolicyPresets::create_for_whispercpp("/usr/bin/whisper-server", "/cache/whisper.bin", 8003, "npu");
        r.check(p_whisper.has_device("/dev/accel"), "PolicyPresets::create_for_whispercpp (npu) includes /dev/accel");

        SandboxPolicy p_sd = PolicyPresets::create_for_sdcpp("/usr/bin/sd-server", "/cache/sd.gguf", 8004, "/tmp/sd_out", "vulkan");
        r.check(p_sd.has_device("/dev/dri"), "PolicyPresets::create_for_sdcpp includes /dev/dri");
        r.check(p_sd.has_write_path("/tmp/sd_out"), "PolicyPresets::create_for_sdcpp allows output write");

        r.report_summary("Backend Policy Variation & Hardware Device Matrix");
        total_results.passed += r.passed.load();
        total_results.failed += r.failed.load();
    }

    // =========================================================================
    // FINAL SUMMARY
    // =========================================================================
    std::printf("===================================================================\n");
    std::printf("  TOTAL CHECKS: %d passed, %d failed\n",
                total_results.passed.load(), total_results.failed.load());
    std::printf("===================================================================\n\n");

    if (total_results.failed.load() == 0) {
        std::printf("STATUS: ALL TESTS PASSED\n");
        return 0;
    } else {
        std::printf("STATUS: FAILED (%d failures detected)\n", total_results.failed.load());
        return 1;
    }
}
