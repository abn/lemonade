#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "lemon/sandbox/nono_ffi.h"
#include "lemon/sandbox/sandbox_engine.h"
#include "lemon/sandbox/sandbox_policy.h"

using lemon::sandbox::EngineBackend;
using lemon::sandbox::EngineCapabilities;
using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PlatformDetector;
using lemon::sandbox::PlatformType;
using lemon::sandbox::PolicyPresets;
using lemon::sandbox::SandboxEngine;
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
    std::printf("=== SandboxEngine Unit Tests ===\n\n");

    // 1. Platform Detection & WSL2 Logic
    {
        // Linux Native
        auto p1 = PlatformDetector::parse_platform("6.5.0-35-generic", "Linux version 6.5.0-35-generic (buildd@lcy02-amd64-070)", false, false, false);
        r.check(p1 == PlatformType::LinuxNative, "parse_platform identifies standard Linux");

        // WSL2 via osrelease
        auto p2 = PlatformDetector::parse_platform("5.15.153.1-microsoft-standard-WSL2", "Linux version 5.15.153.1", false, false, false);
        r.check(p2 == PlatformType::LinuxWSL2, "parse_platform identifies WSL2 from osrelease");

        // WSL2 via proc_version
        auto p3 = PlatformDetector::parse_platform("5.15.0", "Linux version 5.15.90.1-microsoft-standard-WSL2 (oe-user@oe-host)", false, false, false);
        r.check(p3 == PlatformType::LinuxWSL2, "parse_platform identifies WSL2 from proc_version");

        // WSL2 via /dev/dxg device presence
        auto p4 = PlatformDetector::parse_platform("5.15.0", "Linux version 5.15.0-generic", true, false, false);
        r.check(p4 == PlatformType::LinuxWSL2, "parse_platform identifies WSL2 from /dev/dxg presence");

        // Windows Native compile simulation
        auto p5 = PlatformDetector::parse_platform("", "", false, false, true);
        r.check(p5 == PlatformType::WindowsNative, "parse_platform identifies Windows Native");

        // macOS compile simulation
        auto p6 = PlatformDetector::parse_platform("", "", false, true, false);
        r.check(p6 == PlatformType::MacOS, "parse_platform identifies macOS");

        // String conversions
        r.check(std::string(lemon::sandbox::platform_type_to_string(PlatformType::LinuxNative)) == "linux_native",
                "platform_type_to_string linux_native");
        r.check(std::string(lemon::sandbox::platform_type_to_string(PlatformType::LinuxWSL2)) == "linux_wsl2",
                "platform_type_to_string linux_wsl2");
        r.check(std::string(lemon::sandbox::platform_type_to_string(PlatformType::MacOS)) == "macos",
                "platform_type_to_string macos");
        r.check(std::string(lemon::sandbox::platform_type_to_string(PlatformType::WindowsNative)) == "windows_native",
                "platform_type_to_string windows_native");
        r.check(std::string(lemon::sandbox::platform_type_to_string(PlatformType::Unknown)) == "unknown",
                "platform_type_to_string unknown");
    }

    // 2. Linux Landlock Helper Calculations
    {
        r.check(SandboxEngine::compute_landlock_fs_mask(0) == 0, "compute_landlock_fs_mask(0) is 0");
        r.check(SandboxEngine::compute_landlock_fs_mask(1) == 0x1FFF, "compute_landlock_fs_mask(1) has ABI v1 bits");
        r.check((SandboxEngine::compute_landlock_fs_mask(2) & (1ULL << 13)) != 0, "compute_landlock_fs_mask(2) has REFER bit");
        r.check((SandboxEngine::compute_landlock_fs_mask(3) & (1ULL << 14)) != 0, "compute_landlock_fs_mask(3) has TRUNCATE bit");
        r.check((SandboxEngine::compute_landlock_fs_mask(5) & (1ULL << 15)) != 0, "compute_landlock_fs_mask(5) has IOCTL_DEV bit");

        r.check(SandboxEngine::compute_landlock_net_mask(1) == 0, "compute_landlock_net_mask(1) is 0");
        r.check(SandboxEngine::compute_landlock_net_mask(3) == 0, "compute_landlock_net_mask(3) is 0");
        r.check(SandboxEngine::compute_landlock_net_mask(4) == 0x3, "compute_landlock_net_mask(4) has BIND and CONNECT bits");
        r.check(SandboxEngine::compute_landlock_net_mask(5) == 0x3, "compute_landlock_net_mask(5) has BIND and CONNECT bits");

        int abi = SandboxEngine::get_landlock_abi_version();
        r.check(abi >= 0, "get_landlock_abi_version returns non-negative ABI integer");
    }

    // 3. macOS Seatbelt SBPL Profile Generation & Escaping
    {
        // String escaping
        r.check(SandboxEngine::escape_sbpl_string("plain_path") == "plain_path", "escape_sbpl_string leaves plain path intact");
        r.check(SandboxEngine::escape_sbpl_string("path with \"quotes\"") == "path with \\\"quotes\\\"", "escape_sbpl_string escapes quotes");
        r.check(SandboxEngine::escape_sbpl_string("path\\with\\slashes") == "path\\\\with\\\\slashes", "escape_sbpl_string escapes backslashes");

        // SBPL profile content
        SandboxPolicy policy;
        policy.add_read_path("/opt/lemonade/models/llama-3.gguf")
              .add_write_path("/tmp/lemonade_runtime")
              .set_network_access(NetworkAccess::LoopbackOnly)
              .set_bind_port(8000);

        std::string sbpl = SandboxEngine::generate_seatbelt_profile(policy);

        r.check(sbpl.find("(version 1)") != std::string::npos, "SBPL contains version header");
        r.check(sbpl.find("(deny default)") != std::string::npos, "SBPL contains default-deny rule");
        r.check(sbpl.find("(allow process-exec*)") != std::string::npos, "SBPL permits process execution");
        r.check(sbpl.find("(subpath \"/usr/lib\")") != std::string::npos, "SBPL grants /usr/lib");
        r.check(sbpl.find("(subpath \"/System/Library\")") != std::string::npos, "SBPL grants /System/Library");
        r.check(sbpl.find("(literal \"/dev/null\")") != std::string::npos, "SBPL grants /dev/null");
        r.check(sbpl.find("(literal \"/dev/urandom\")") != std::string::npos, "SBPL grants /dev/urandom");

        // Metal Mach services
        r.check(sbpl.find("com.apple.metal.MTLCompilerService") != std::string::npos,
                "SBPL preserves MTLCompilerService Mach service");
        r.check(sbpl.find("com.apple.AGXCompilerService") != std::string::npos,
                "SBPL preserves AGXCompilerService Mach service");
        r.check(sbpl.find("com.apple.gpu.compilation") != std::string::npos,
                "SBPL preserves gpu.compilation Mach service");

        // Metal IOKit user clients
        r.check(sbpl.find("IOAcceleratorUserClient") != std::string::npos, "SBPL grants IOAcceleratorUserClient");
        r.check(sbpl.find("AGXDeviceUserClient") != std::string::npos, "SBPL grants AGXDeviceUserClient");
        r.check(sbpl.find("IOSurfaceRootUserClient") != std::string::npos, "SBPL grants IOSurfaceRootUserClient");

        // Dynamic path grants
        r.check(sbpl.find("/opt/lemonade/models/llama-3.gguf") != std::string::npos, "SBPL contains read path");
        r.check(sbpl.find("/tmp/lemonade_runtime") != std::string::npos, "SBPL contains write path");
        r.check(sbpl.find("(allow file-write*") != std::string::npos, "SBPL contains file-write grant block");

        // Network isolation
        r.check(sbpl.find("127.0.0.1:*") != std::string::npos, "SBPL LoopbackOnly allows 127.0.0.1 loopback");
        r.check(sbpl.find("::1:*") != std::string::npos, "SBPL LoopbackOnly allows ::1 loopback");
        r.check(sbpl.find("(deny network-outbound)") != std::string::npos, "SBPL LoopbackOnly denies outbound network");

        // DenyAll network profile
        policy.set_network_access(NetworkAccess::DenyAll);
        std::string deny_sbpl = SandboxEngine::generate_seatbelt_profile(policy);
        r.check(deny_sbpl.find("(deny network*)") != std::string::npos, "SBPL DenyAll sets (deny network*)");

        // Full network profile
        policy.set_network_access(NetworkAccess::Full);
        std::string full_sbpl = SandboxEngine::generate_seatbelt_profile(policy);
        r.check(full_sbpl.find("(allow network*)") != std::string::npos, "SBPL Full sets (allow network*)");
    }

    // 4. Windows Fallback Engine (Graceful Degradation)
    {
        auto win_engine = SandboxEngine::create_windows_fallback_engine();
        r.check(win_engine != nullptr, "create_windows_fallback_engine returns valid instance");
        r.check(win_engine->get_backend() == EngineBackend::WindowsDegraded, "windows engine backend is WindowsDegraded");
        r.check(std::string(win_engine->get_backend_name()) == "windows-fallback", "windows engine backend name is windows-fallback");
        r.check(win_engine->is_supported() == true, "windows fallback engine reports supported (for secret scrubbing)");
        r.check(win_engine->is_kernel_enforced() == false, "windows fallback engine is not kernel enforced");

        SandboxPolicy policy;
        policy.set_mode(SandboxMode::Auto);
        r.check(win_engine->apply(policy) == true, "windows fallback apply succeeds in Auto mode");

        policy.set_mode(SandboxMode::ScrubbedOnly);
        r.check(win_engine->apply(policy) == true, "windows fallback apply succeeds in ScrubbedOnly mode");

        policy.set_mode(SandboxMode::Enforced);
        std::string err;
        r.check(win_engine->apply(policy, &err) == false, "windows fallback apply returns false in Enforced mode");
        r.check(!err.empty(), "windows fallback apply provides error message in Enforced mode");
    }

    // 5. Fallback Stub Engine
    {
        auto stub = SandboxEngine::create_fallback_stub_engine();
        r.check(stub != nullptr, "create_fallback_stub_engine returns valid instance");
        r.check(stub->get_backend() == EngineBackend::FallbackStub, "stub backend is FallbackStub");
        r.check(std::string(stub->get_backend_name()) == "fallback_stub", "stub backend name is fallback_stub");
        r.check(stub->is_supported() == false, "stub engine reports unsupported");
        r.check(stub->is_kernel_enforced() == false, "stub engine is not kernel enforced");

        SandboxPolicy policy;
        policy.set_mode(SandboxMode::Auto);
        r.check(stub->apply(policy) == true, "stub apply succeeds in Auto mode");

        policy.set_mode(SandboxMode::ScrubbedOnly);
        r.check(stub->apply(policy) == true, "stub apply succeeds in ScrubbedOnly mode");

        policy.set_mode(SandboxMode::Enforced);
        std::string err;
        r.check(stub->apply(policy, &err) == false, "stub apply returns false in Enforced mode");
        r.check(!err.empty(), "stub apply provides error message in Enforced mode");
    }

    // 6. Nono C FFI API & Lifecycle
    {
        // Allocation & lifecycle
        nono_capability_set* caps = nono_capability_set_new();
        r.check(caps != nullptr, "nono_capability_set_new allocates handle");

        // Path additions
        r.check(nono_capability_add_fs_read(caps, "/models/llama.gguf") == NONO_OK,
                "nono_capability_add_fs_read succeeds");
        r.check(nono_capability_add_fs_write(caps, "/tmp/out") == NONO_OK,
                "nono_capability_add_fs_write succeeds");

        // Device additions
        r.check(nono_capability_add_device(caps, "/dev/dri/renderD128") == NONO_OK,
                "nono_capability_add_device succeeds");

        // Network settings
        r.check(nono_capability_set_network_egress(caps, false) == NONO_OK,
                "nono_capability_set_network_egress succeeds");
        r.check(nono_capability_set_network_loopback(caps, true) == NONO_OK,
                "nono_capability_set_network_loopback succeeds");
        r.check(nono_capability_set_bind_port(caps, 8080) == NONO_OK,
                "nono_capability_set_bind_port succeeds");

        // Error handling with NULL parameters
        r.check(nono_capability_add_fs_read(nullptr, "/path") == NONO_ERROR_INVALID_PARAM,
                "nono_capability_add_fs_read rejects NULL caps");
        r.check(nono_capability_add_fs_read(caps, nullptr) == NONO_ERROR_INVALID_PARAM,
                "nono_capability_add_fs_read rejects NULL path");
        r.check(nono_capability_add_fs_read(caps, "") == NONO_ERROR_INVALID_PARAM,
                "nono_capability_add_fs_read rejects empty path");
        r.check(nono_capability_add_fs_write(nullptr, "/path") == NONO_ERROR_INVALID_PARAM,
                "nono_capability_add_fs_write rejects NULL caps");
        r.check(nono_capability_add_device(nullptr, "/dev/null") == NONO_ERROR_INVALID_PARAM,
                "nono_capability_add_device rejects NULL caps");
        r.check(nono_capability_set_network_egress(nullptr, true) == NONO_ERROR_INVALID_PARAM,
                "nono_capability_set_network_egress rejects NULL caps");
        r.check(nono_capability_set_network_loopback(nullptr, true) == NONO_ERROR_INVALID_PARAM,
                "nono_capability_set_network_loopback rejects NULL caps");
        r.check(nono_capability_set_bind_port(nullptr, 8080) == NONO_ERROR_INVALID_PARAM,
                "nono_capability_set_bind_port rejects NULL caps");
        r.check(nono_sandbox_apply(nullptr) == NONO_ERROR_INVALID_PARAM,
                "nono_sandbox_apply rejects NULL caps");

        // Error message retrieval
        const char* err_str = nono_get_last_error();
        r.check(err_str != nullptr && std::string(err_str).find("Invalid") != std::string::npos,
                "nono_get_last_error returns last error");

        // Status string conversion
        r.check(std::string(nono_status_to_string(NONO_OK)) == "NONO_OK", "nono_status_to_string NONO_OK");
        r.check(std::string(nono_status_to_string(NONO_ERROR_GENERIC)) == "NONO_ERROR_GENERIC", "nono_status_to_string NONO_ERROR_GENERIC");
        r.check(std::string(nono_status_to_string(NONO_ERROR_UNSUPPORTED)) == "NONO_ERROR_UNSUPPORTED", "nono_status_to_string NONO_ERROR_UNSUPPORTED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_INVALID_PARAM)) == "NONO_ERROR_INVALID_PARAM", "nono_status_to_string NONO_ERROR_INVALID_PARAM");
        r.check(std::string(nono_status_to_string(NONO_ERROR_APPLY_FAILED)) == "NONO_ERROR_APPLY_FAILED", "nono_status_to_string NONO_ERROR_APPLY_FAILED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_PERMISSION_DENIED)) == "NONO_ERROR_PERMISSION_DENIED", "nono_status_to_string NONO_ERROR_PERMISSION_DENIED");
        r.check(std::string(nono_status_to_string(NONO_ERROR_ALREADY_APPLIED)) == "NONO_ERROR_ALREADY_APPLIED", "nono_status_to_string NONO_ERROR_ALREADY_APPLIED");

        // Backend name and support
        const char* bname = nono_get_backend_name();
        r.check(bname != nullptr && std::strlen(bname) > 0, "nono_get_backend_name returns non-empty string");

        nono_capability_set_free(caps);
    }

    // 7. Policy-to-Nono Capability Set Translation
    {
        SandboxPolicy policy;
        policy.add_read_path("/usr/lib")
              .add_write_path("/tmp/cache")
              .add_device("/dev/kfd")
              .set_network_access(NetworkAccess::LoopbackOnly)
              .set_bind_port(9000);

        nono_capability_set* caps = nono_capability_set_new();
        r.check(caps != nullptr, "caps allocated for translation test");

        nono_status s = SandboxEngine::policy_to_nono_capabilities(policy, caps);
        r.check(s == NONO_OK, "policy_to_nono_capabilities succeeds");

        nono_capability_set_free(caps);
    }

    // 8. Factory Engine Instantiation
    {
        auto platform_engine = SandboxEngine::create_for_platform();
        r.check(platform_engine != nullptr, "create_for_platform returns valid instance");
        r.check(std::strlen(platform_engine->get_backend_name()) > 0, "platform engine has valid backend name");

        EngineCapabilities caps = platform_engine->get_capabilities();
        r.check(caps.backend != EngineBackend::None, "engine capabilities has non-None backend");

        auto default_engine = SandboxEngine::create_default();
        r.check(default_engine != nullptr, "create_default returns valid instance");

        auto nono_engine = SandboxEngine::create_nono_ffi_engine();
        r.check(nono_engine != nullptr, "create_nono_ffi_engine returns valid instance");

        // Engine description formatting
        std::string desc_auto = SandboxEngine::get_platform_engine_description(SandboxMode::Auto);
        r.check(!desc_auto.empty(), "get_platform_engine_description(Auto) non-empty");

        std::string desc_disabled = SandboxEngine::get_platform_engine_description(SandboxMode::Disabled);
        r.check(desc_disabled == "disabled (by configuration)", "get_platform_engine_description(Disabled) matches exact string");

        std::string desc_enforced = SandboxEngine::get_platform_engine_description(SandboxMode::Enforced);
        r.check(!desc_enforced.empty(), "get_platform_engine_description(Enforced) non-empty");
    }

    std::printf("\n=== %d passed, %d failed ===\n", r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
