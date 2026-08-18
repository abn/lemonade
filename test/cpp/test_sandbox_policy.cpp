#include <cstdio>
#include <string>
#include <vector>

#include "lemon/sandbox/sandbox_policy.h"

using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PathGrant;
using lemon::sandbox::PolicyPresets;
using lemon::sandbox::SandboxMode;
using lemon::sandbox::SandboxPolicy;

struct TestResult {
    int passed = 0;
    int failed = 0;

    void check(bool cond, const std::string& name) {
        if (cond) {
            std::printf("[PASS] %s\n", name.c_str());
            ++passed;
        } else {
            std::printf("[FAIL] %s\n", name.c_str());
            ++failed;
        }
    }
};

int main() {
    TestResult r;
    std::printf("=== SandboxPolicy Model Unit Tests ===\n\n");

    // 1. Default Policy Initialization Invariants
    {
        SandboxPolicy policy;
        r.check(policy.network_access == NetworkAccess::LoopbackOnly,
                "default policy sets network_access to LoopbackOnly");
        r.check(policy.mode == SandboxMode::Auto,
                "default policy sets mode to Auto");
        r.check(policy.bind_port == 0,
                "default policy sets bind_port to 0");
        r.check(policy.path_grants.empty(),
                "default policy has empty path_grants");
        r.check(policy.device_grants.empty(),
                "default policy has empty device_grants");
        r.check(policy.allowed_env_vars.empty(),
                "default policy has empty allowed_env_vars");
        r.check(policy.explicit_env_vars.empty(),
                "default policy has empty explicit_env_vars");
    }

    // 2. Path Grants Configuration & Fluent Builder
    {
        SandboxPolicy policy;
        policy.add_read_path("/usr/lib")
              .add_write_path("/tmp/lemonade_runtime");

        r.check(policy.path_grants.size() == 2, "path_grants tracks added grants");
        r.check(policy.has_read_path("/usr/lib"), "has_read_path finds read path");
        r.check(!policy.has_write_path("/usr/lib"), "has_write_path returns false for read-only grant");
        r.check(policy.has_write_path("/tmp/lemonade_runtime"), "has_write_path finds write path");
        r.check(policy.has_read_path("/tmp/lemonade_runtime"), "has_read_path finds write-allowed path");
    }

    // 3. Device Grants Configuration
    {
        SandboxPolicy policy;
        policy.add_device("/dev/dri/renderD128")
              .add_device("/dev/kfd")
              .add_device("/dev/dxg")
              .add_device("/dev/accel/accel0")
              .add_device("/dev/null")
              .add_device("/dev/urandom");

        r.check(policy.device_grants.size() == 6, "device_grants tracks all GPU/NPU/system devices");
        r.check(policy.has_device("/dev/dri/renderD128"), "DRI render device recorded");
        r.check(policy.has_device("/dev/kfd"), "ROCm KFD device recorded");
        r.check(policy.has_device("/dev/dxg"), "WSL2 DirectX device recorded");
        r.check(policy.has_device("/dev/accel/accel0"), "XDNA NPU device recorded");
        r.check(!policy.has_device("/dev/sda"), "unadded device returns false");
    }

    // 4. Network Policy Modes & Port Binding
    {
        SandboxPolicy policy;
        policy.set_network_access(NetworkAccess::DenyAll);
        r.check(policy.network_access == NetworkAccess::DenyAll, "network_access DenyAll supported");
        r.check(std::string(lemon::sandbox::network_access_to_string(policy.network_access)) == "deny_all",
                "network_access_to_string matches deny_all");

        policy.set_network_access(NetworkAccess::LoopbackOnly);
        policy.set_bind_port(8001);
        r.check(policy.network_access == NetworkAccess::LoopbackOnly, "network_access LoopbackOnly supported");
        r.check(policy.bind_port == 8001, "bind_port configured correctly");
        r.check(std::string(lemon::sandbox::network_access_to_string(policy.network_access)) == "loopback_only",
                "network_access_to_string matches loopback_only");

        policy.set_network_access(NetworkAccess::Full);
        r.check(policy.network_access == NetworkAccess::Full, "network_access Full supported");
        r.check(std::string(lemon::sandbox::network_access_to_string(policy.network_access)) == "full",
                "network_access_to_string matches full");
    }

    // 5. Sandbox Execution Modes
    {
        SandboxPolicy policy;
        policy.set_mode(SandboxMode::Enforced);
        r.check(policy.mode == SandboxMode::Enforced, "SandboxMode::Enforced supported");
        r.check(std::string(lemon::sandbox::sandbox_mode_to_string(policy.mode)) == "enforced",
                "sandbox_mode_to_string matches enforced");

        policy.set_mode(SandboxMode::ScrubbedOnly);
        r.check(policy.mode == SandboxMode::ScrubbedOnly, "SandboxMode::ScrubbedOnly supported");
        r.check(std::string(lemon::sandbox::sandbox_mode_to_string(policy.mode)) == "scrubbed_only",
                "sandbox_mode_to_string matches scrubbed_only");

        policy.set_mode(SandboxMode::Auto);
        r.check(policy.mode == SandboxMode::Auto, "SandboxMode::Auto supported");
        r.check(std::string(lemon::sandbox::sandbox_mode_to_string(policy.mode)) == "auto",
                "sandbox_mode_to_string matches auto");

        policy.set_mode(SandboxMode::Disabled);
        r.check(policy.mode == SandboxMode::Disabled, "SandboxMode::Disabled supported");
        r.check(std::string(lemon::sandbox::sandbox_mode_to_string(policy.mode)) == "disabled",
                "sandbox_mode_to_string matches disabled");

        // Test parse_sandbox_mode
        r.check(lemon::sandbox::parse_sandbox_mode("auto") == SandboxMode::Auto, "parse_sandbox_mode('auto')");
        r.check(lemon::sandbox::parse_sandbox_mode("enforced") == SandboxMode::Enforced, "parse_sandbox_mode('enforced')");
        r.check(lemon::sandbox::parse_sandbox_mode("disabled") == SandboxMode::Disabled, "parse_sandbox_mode('disabled')");
        r.check(lemon::sandbox::parse_sandbox_mode("off") == SandboxMode::Disabled, "parse_sandbox_mode('off')");
        r.check(lemon::sandbox::parse_sandbox_mode("0") == SandboxMode::Disabled, "parse_sandbox_mode('0')");
        r.check(lemon::sandbox::parse_sandbox_mode("scrubbed_only") == SandboxMode::ScrubbedOnly, "parse_sandbox_mode('scrubbed_only')");
    }

    // 5b. SandboxPolicy Debug String Representations
    {
        SandboxPolicy policy;
        policy.add_read_path("/usr/lib")
              .add_write_path("/tmp/test")
              .add_device("/dev/dri")
              .allow_env_var("PATH");
        policy.set_bind_port(8002);

        std::string dbg = policy.to_debug_string();
        r.check(!dbg.empty(), "to_debug_string is non-empty");
        r.check(dbg.find("mode=auto") != std::string::npos, "to_debug_string contains mode");
        r.check(dbg.find("bind_port=8002") != std::string::npos, "to_debug_string contains bind_port");
        r.check(dbg.find("/dev/dri") != std::string::npos, "to_debug_string contains device");

        std::string detail = policy.to_detailed_string();
        r.check(!detail.empty(), "to_detailed_string is non-empty");
        r.check(detail.find("[RO] /usr/lib") != std::string::npos, "to_detailed_string contains [RO] path");
        r.check(detail.find("[RW] /tmp/test") != std::string::npos, "to_detailed_string contains [RW] path");
        r.check(detail.find("/dev/dri") != std::string::npos, "to_detailed_string contains device");
    }

    // 6. Environment Allowlist & Explicit Environment Pairs
    {
        SandboxPolicy policy;
        policy.allow_env_vars({"PATH", "LD_LIBRARY_PATH", "ROCM_PATH"});
        policy.set_env_var("CUDA_VISIBLE_DEVICES", "0")
              .set_env_var("PYTHONNOUSERSITE", "1");

        r.check(policy.allowed_env_vars.size() == 3, "allowed_env_vars populated");
        r.check(policy.has_allowed_env("PATH"), "has_allowed_env finds PATH");
        r.check(!policy.has_allowed_env("SECRET_TOKEN"), "has_allowed_env returns false for unknown");
        r.check(policy.explicit_env_vars.size() == 2, "explicit_env_vars populated");
        r.check(policy.explicit_env_vars[0].first == "CUDA_VISIBLE_DEVICES" && policy.explicit_env_vars[0].second == "0",
                "explicit environment key-value preserved");
    }

    // 7. Path Normalization & Deduplication
    {
        SandboxPolicy policy;
        policy.add_read_path("/usr/lib")
              .add_write_path("/usr/lib") // Should upgrade to write
              .add_read_path("/usr/lib/../lib")
              .add_read_path("/tmp/run/.")
              .add_read_path(""); // Should be discarded

        policy.normalize_paths();
        r.check(policy.path_grants.size() == 2, "normalize_paths deduplicates overlapping paths");
        r.check(policy.has_write_path("/usr/lib"), "write permission takes precedence on duplicate");
    }

    // 8. Policy Presets Factory Helpers
    {
        // llamacpp CPU vs Vulkan
        auto llama_cpu = PolicyPresets::create_for_llamacpp("/bin/llama-server", "/models/test.gguf", 8080, "cpu");
        r.check(llama_cpu.bind_port == 8080, "llamacpp bind_port set");
        r.check(llama_cpu.has_read_path("/bin/llama-server"), "llamacpp executable path granted");
        r.check(llama_cpu.has_read_path("/models/test.gguf"), "llamacpp model path granted");
        r.check(llama_cpu.device_grants.empty() || !llama_cpu.has_device("/dev/kfd"), "llamacpp cpu has no kfd device");

        auto llama_vk = PolicyPresets::create_for_llamacpp("/bin/llama-server", "/models/test.gguf", 8080, "vulkan");
        r.check(llama_vk.has_device("/dev/dri"), "llamacpp vulkan has dri device");

        // fastflowlm NPU
        auto flm_policy = PolicyPresets::create_for_fastflowlm("/bin/flm", "/models/flm_model", 8081);
        r.check(flm_policy.has_device("/dev/accel"), "fastflowlm has accel device");
        r.check(flm_policy.has_device("/dev/amdxdna"), "fastflowlm has amdxdna device");
        r.check(flm_policy.has_read_path("/models/flm_model"), "fastflowlm model dir granted");

        // vllm ROCm
        auto vllm_policy = PolicyPresets::create_for_vllm("/bin/vllm", "/models/hf_repo", 8000, "/opt/rocm/shim", "/tmp/triton");
        r.check(vllm_policy.has_device("/dev/kfd"), "vllm has kfd device");
        r.check(vllm_policy.has_read_path("/opt/rocm/shim"), "vllm has rocm shim granted");
        r.check(vllm_policy.has_write_path("/tmp/triton"), "vllm has triton cache write grant");
        r.check(vllm_policy.has_allowed_env("FLASH_ATTENTION_TRITON_AMD_ENABLE"), "vllm allows flash attention env");

        // whispercpp
        auto whisper_npu = PolicyPresets::create_for_whispercpp("/bin/whisper-server", "/models/whisper.bin", 8082, "npu");
        r.check(whisper_npu.has_device("/dev/accel"), "whisper npu has accel device");

        // sdcpp
        auto sd_policy = PolicyPresets::create_for_sdcpp("/bin/sd-server", "/models/sd.safetensors", 8083, "/tmp/sd_out", "vulkan");
        r.check(sd_policy.has_write_path("/tmp/sd_out"), "sdcpp has output dir write grant");
        r.check(sd_policy.has_device("/dev/dri"), "sdcpp vulkan has dri device");
    }

    std::printf("\n=== %d passed, %d failed ===\n", r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
