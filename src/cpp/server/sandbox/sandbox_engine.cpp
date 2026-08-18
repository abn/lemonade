#include "lemon/sandbox/sandbox_engine.h"
#include "lemon/utils/aixlog.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#elif defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#elif defined(__i386__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#elif defined(__riscv)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif
#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
};

struct landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};
#endif

#if defined(__APPLE__)
#include <sandbox.h>
#endif

namespace lemon::sandbox {

namespace {

std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

#if defined(__linux__)
bool landlock_add_path_grant(
    int ruleset_fd,
    const std::string& path,
    bool write_allowed,
    uint64_t handled_fs_mask,
    int abi) {

    int fd = open(path.c_str(), O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return true;
        }
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    bool is_dir = S_ISDIR(st.st_mode);
    uint64_t access = 0;

    if (is_dir) {
        if (write_allowed) {
            access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                     LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                     LANDLOCK_ACCESS_FS_MAKE_SYM;
            if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
            if (abi >= 3) access |= LANDLOCK_ACCESS_FS_TRUNCATE;
            if (abi >= 5) access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        } else {
            access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                     LANDLOCK_ACCESS_FS_EXECUTE;
            if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
        }
    } else {
        if (write_allowed) {
            access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                     LANDLOCK_ACCESS_FS_EXECUTE;
            if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
            if (abi >= 3) access |= LANDLOCK_ACCESS_FS_TRUNCATE;
            if (abi >= 5) access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        } else {
            access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
            if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
        }
    }

    access &= handled_fs_mask;

    struct landlock_path_beneath_attr attr;
    attr.allowed_access = access;
    attr.parent_fd = fd;

    int ret = static_cast<int>(syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0));
    close(fd);
    return ret == 0;
}

bool landlock_add_net_rule(int ruleset_fd, uint64_t access, uint16_t port) {
    struct landlock_net_port_attr attr;
    attr.allowed_access = access;
    attr.port = port;
    return static_cast<int>(syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT, &attr, 0)) == 0;
}
#endif

} // namespace

// PlatformDetector implementation
PlatformType PlatformDetector::parse_platform(
    const std::string& osrelease,
    const std::string& proc_version,
    bool has_dxg,
    bool is_apple_compiled,
    bool is_win32_compiled) {

    if (is_win32_compiled) {
        return PlatformType::WindowsNative;
    }
    if (is_apple_compiled) {
        return PlatformType::MacOS;
    }

    std::string rel_lower = to_lower_ascii(osrelease);
    std::string ver_lower = to_lower_ascii(proc_version);

    bool is_wsl = (rel_lower.find("microsoft") != std::string::npos ||
                   rel_lower.find("wsl") != std::string::npos ||
                   ver_lower.find("microsoft") != std::string::npos ||
                   ver_lower.find("wsl") != std::string::npos ||
                   has_dxg);

    if (is_wsl) {
        return PlatformType::LinuxWSL2;
    }

    return PlatformType::LinuxNative;
}

PlatformType PlatformDetector::detect_platform() {
#if defined(_WIN32)
    return PlatformType::WindowsNative;
#elif defined(__APPLE__)
    return PlatformType::MacOS;
#elif defined(__linux__)
    std::string osrelease;
    std::string proc_version;

    std::ifstream osr_file("/proc/sys/kernel/osrelease");
    if (osr_file.is_open()) {
        std::getline(osr_file, osrelease);
    }

    std::ifstream ver_file("/proc/version");
    if (ver_file.is_open()) {
        std::getline(ver_file, proc_version);
    }

    bool has_dxg = std::filesystem::exists("/dev/dxg");

    return parse_platform(osrelease, proc_version, has_dxg, false, false);
#else
    return PlatformType::Unknown;
#endif
}

bool PlatformDetector::is_wsl2() {
    return detect_platform() == PlatformType::LinuxWSL2;
}

bool PlatformDetector::is_native_windows() {
    return detect_platform() == PlatformType::WindowsNative;
}

bool PlatformDetector::is_macos() {
    return detect_platform() == PlatformType::MacOS;
}

bool PlatformDetector::is_linux_native() {
    return detect_platform() == PlatformType::LinuxNative;
}

bool PlatformDetector::has_dxg_device() {
#if defined(__linux__)
    return std::filesystem::exists("/dev/dxg");
#else
    return false;
#endif
}

// macOS Seatbelt profile generation & escaping
std::string SandboxEngine::escape_sbpl_string(const std::string& input) {
    std::string result;
    result.reserve(input.size() + 8);
    for (char c : input) {
        if (c == '\\' || c == '\"') {
            result.push_back('\\');
        }
        result.push_back(c);
    }
    return result;
}

std::string SandboxEngine::generate_seatbelt_profile(const SandboxPolicy& policy) {
    std::ostringstream ss;
    ss << "(version 1)\n";
    ss << "(deny default)\n\n";

    ss << ";; Process & signal control\n";
    ss << "(allow process-exec*)\n";
    ss << "(allow process-fork)\n";
    ss << "(allow sysctl-read)\n";
    ss << "(allow signal (target self))\n";
    ss << "(allow ipc-posix-shm*)\n\n";

    ss << ";; Darwin core system libraries & standard devices\n";
    ss << "(allow file-read*\n";
    ss << "    (subpath \"/usr/lib\")\n";
    ss << "    (subpath \"/usr/share\")\n";
    ss << "    (subpath \"/System/Library\")\n";
    ss << "    (subpath \"/System/DriverKit\")\n";
    ss << "    (subpath \"/Library/Preferences\")\n";
    ss << "    (subpath \"/Library/Managed Preferences\")\n";
    ss << "    (subpath \"/private/var/db/timezone\")\n";
    ss << "    (literal \"/dev/null\")\n";
    ss << "    (literal \"/dev/zero\")\n";
    ss << "    (literal \"/dev/urandom\")\n";
    ss << "    (literal \"/dev/random\")\n";
    ss << "    (literal \"/dev/autofs_nowait\")\n";
    ss << "    (literal \"/dev/dtracehelper\")\n";
    ss << ")\n\n";

    ss << ";; Metal GPU acceleration Mach-port services\n";
    ss << "(allow mach-lookup\n";
    ss << "    (global-name \"com.apple.system.logger\")\n";
    ss << "    (global-name \"com.apple.system.notification_center\")\n";
    ss << "    (global-name \"com.apple.diagnosticd\")\n";
    ss << "    (global-name \"com.apple.analyticsd\")\n";
    ss << "    (global-name \"com.apple.logd\")\n";
    ss << "    (global-name \"com.apple.logd.events\")\n";
    ss << "    (global-name \"com.apple.coreservices.launchservicesd\")\n";
    ss << "    (global-name \"com.apple.SecurityServer\")\n";
    ss << "    (global-name \"com.apple.metal.MTLCompilerService\")\n";
    ss << "    (global-name \"com.apple.AGXCompilerService\")\n";
    ss << "    (global-name \"com.apple.gpu.compilation\")\n";
    ss << ")\n\n";

    ss << ";; Metal & Apple Silicon IOKit user clients\n";
    ss << "(allow iokit-open\n";
    ss << "    (iokit-user-client-class \"IOAcceleratorUserClient\")\n";
    ss << "    (iokit-user-client-class \"AGXDeviceUserClient\")\n";
    ss << "    (iokit-user-client-class \"AGXCommandQueueUserClient\")\n";
    ss << "    (iokit-user-client-class \"AGXDeviceMemoryTokenUserClient\")\n";
    ss << "    (iokit-user-client-class \"IOSurfaceRootUserClient\")\n";
    ss << "    (iokit-user-client-class \"IGAccelDeviceUserClient\")\n";
    ss << "    (iokit-user-client-class \"AppleIntelMEUserClient\")\n";
    ss << "    (iokit-user-client-class \"AppleJPEGDriverUserClient\")\n";
    ss << ")\n";
    ss << "(allow iokit-get-properties)\n\n";

    std::vector<std::string> read_paths;
    std::vector<std::string> write_paths;
    for (const auto& grant : policy.path_grants) {
        if (grant.path.empty()) continue;
        std::string escaped = escape_sbpl_string(grant.path);
        read_paths.push_back(escaped);
        if (grant.write_allowed) {
            write_paths.push_back(escaped);
        }
    }

    if (!read_paths.empty()) {
        ss << ";; Dynamic read path grants\n";
        ss << "(allow file-read*\n";
        for (const auto& p : read_paths) {
            ss << "    (literal \"" << p << "\")\n";
            ss << "    (subpath \"" << p << "\")\n";
        }
        ss << ")\n\n";
    }

    if (!write_paths.empty()) {
        ss << ";; Dynamic write path grants\n";
        ss << "(allow file-write*\n";
        for (const auto& p : write_paths) {
            ss << "    (literal \"" << p << "\")\n";
            ss << "    (subpath \"" << p << "\")\n";
        }
        ss << ")\n\n";
    }

    ss << ";; Network access policy\n";
    if (policy.network_access == NetworkAccess::DenyAll) {
        ss << "(deny network*)\n";
    } else if (policy.network_access == NetworkAccess::LoopbackOnly) {
        ss << "(allow network-bind (local ip \"127.0.0.1:*\") (local ip \"::1:*\"))\n";
        ss << "(allow network-outbound (to ip \"127.0.0.1:*\") (to ip \"::1:*\") (literal \"/private/var/run/mDNSResponder\"))\n";
        ss << "(allow network-inbound (local ip \"127.0.0.1:*\") (local ip \"::1:*\"))\n";
        ss << "(deny network-outbound)\n";
    } else {
        ss << "(allow network*)\n";
    }

    return ss.str();
}

// Landlock helper methods
int SandboxEngine::get_landlock_abi_version() {
#if defined(__linux__) && defined(__NR_landlock_create_ruleset)
    int abi = static_cast<int>(syscall(__NR_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION));
    if (abi < 0) {
        return 0;
    }
    return abi;
#else
    return 0;
#endif
}

uint64_t SandboxEngine::compute_landlock_fs_mask(int abi) {
    if (abi <= 0) return 0;
    uint64_t mask = 0x1FFF; // ABI v1
#if defined(__linux__)
    if (abi >= 2) mask |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#else
    if (abi >= 2) mask |= (1ULL << 13);
    if (abi >= 3) mask |= (1ULL << 14);
    if (abi >= 5) mask |= (1ULL << 15);
#endif
    return mask;
}

uint64_t SandboxEngine::compute_landlock_net_mask(int abi) {
    if (abi < 4) return 0;
#if defined(__linux__)
    return LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
#else
    return (1ULL << 0) | (1ULL << 1);
#endif
}

// Concrete Engine Classes
class LinuxLandlockEngine : public SandboxEngine {
public:
    bool is_supported() const override {
        return SandboxEngine::get_landlock_abi_version() > 0;
    }

    bool is_kernel_enforced() const override {
        return is_supported();
    }

    EngineBackend get_backend() const override {
        return EngineBackend::Landlock;
    }

    const char* get_backend_name() const override {
        return "landlock";
    }

    EngineCapabilities get_capabilities() const override {
        EngineCapabilities caps;
        int abi = SandboxEngine::get_landlock_abi_version();
        caps.supports_fs_read_isolation = abi >= 1;
        caps.supports_fs_write_isolation = abi >= 1;
        caps.supports_device_isolation = abi >= 1;
        caps.supports_network_isolation = abi >= 4;
        caps.supports_port_binding = abi >= 4;
        caps.backend = EngineBackend::Landlock;
        caps.backend_name = "landlock";
        caps.description = "Linux Landlock LSM sandboxing engine";
        return caps;
    }

    bool apply(const SandboxPolicy& in_policy, std::string* error_msg = nullptr) override {
        if (in_policy.mode == SandboxMode::Disabled || in_policy.mode == SandboxMode::ScrubbedOnly) {
            return true;
        }

#if defined(__linux__) && defined(__NR_landlock_create_ruleset)
        SandboxPolicy policy = in_policy;
        if (PlatformDetector::is_wsl2()) {
            policy.add_device("/dev/dxg");
            if (std::filesystem::exists("/usr/lib/wsl/lib")) {
                policy.add_read_path("/usr/lib/wsl/lib");
            }
            if (std::filesystem::exists("/usr/lib/wsl/drivers")) {
                policy.add_read_path("/usr/lib/wsl/drivers");
            }
        }
        policy.normalize_paths();

        int abi = SandboxEngine::get_landlock_abi_version();
        if (abi <= 0) {
            if (policy.mode == SandboxMode::Enforced) {
                if (error_msg) {
                    *error_msg = "Landlock LSM is not supported or enabled on this Linux kernel";
                }
                return false;
            }
            return true;
        }

        uint64_t handled_fs = SandboxEngine::compute_landlock_fs_mask(abi);
        uint64_t handled_net = 0;
        if (abi >= 4 && policy.network_access != NetworkAccess::Full) {
            handled_net = SandboxEngine::compute_landlock_net_mask(abi);
        }

        struct landlock_ruleset_attr attr;
        std::memset(&attr, 0, sizeof(attr));
        attr.handled_access_fs = handled_fs;
        attr.handled_access_net = handled_net;

        int ruleset_fd = static_cast<int>(syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0));
        if (ruleset_fd < 0) {
            if (policy.mode == SandboxMode::Enforced) {
                if (error_msg) {
                    *error_msg = std::string("landlock_create_ruleset failed: ") + std::strerror(errno);
                }
                return false;
            }
            return true;
        }

        for (const auto& grant : policy.path_grants) {
            landlock_add_path_grant(ruleset_fd, grant.path, grant.write_allowed, handled_fs, abi);
        }

        for (const auto& dev : policy.device_grants) {
            landlock_add_path_grant(ruleset_fd, dev, true, handled_fs, abi);
        }

        if (abi >= 4 && policy.network_access == NetworkAccess::LoopbackOnly && policy.bind_port > 0) {
            landlock_add_net_rule(ruleset_fd, LANDLOCK_ACCESS_NET_BIND_TCP, policy.bind_port);
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            close(ruleset_fd);
            if (policy.mode == SandboxMode::Enforced) {
                if (error_msg) {
                    *error_msg = std::string("prctl(PR_SET_NO_NEW_PRIVS) failed: ") + std::strerror(errno);
                }
                return false;
            }
            return true;
        }

        if (static_cast<int>(syscall(__NR_landlock_restrict_self, ruleset_fd, 0)) != 0) {
            close(ruleset_fd);
            if (policy.mode == SandboxMode::Enforced) {
                if (error_msg) {
                    *error_msg = std::string("landlock_restrict_self failed: ") + std::strerror(errno);
                }
                return false;
            }
            return true;
        }

        close(ruleset_fd);
        return true;
#else
        if (in_policy.mode == SandboxMode::Enforced) {
            if (error_msg) {
                *error_msg = "Landlock sandboxing not available on this platform";
            }
            return false;
        }
        return true;
#endif
    }
};

class MacOSSeatbeltEngine : public SandboxEngine {
public:
    bool is_supported() const override {
#if defined(__APPLE__)
        return true;
#else
        return false;
#endif
    }

    bool is_kernel_enforced() const override {
        return is_supported();
    }

    EngineBackend get_backend() const override {
        return EngineBackend::Seatbelt;
    }

    const char* get_backend_name() const override {
        return "seatbelt";
    }

    EngineCapabilities get_capabilities() const override {
        EngineCapabilities caps;
        caps.supports_fs_read_isolation = true;
        caps.supports_fs_write_isolation = true;
        caps.supports_device_isolation = true;
        caps.supports_network_isolation = true;
        caps.supports_port_binding = true;
        caps.backend = EngineBackend::Seatbelt;
        caps.backend_name = "seatbelt";
        caps.description = "macOS Seatbelt kernel sandboxing engine";
        return caps;
    }

    bool apply(const SandboxPolicy& policy, std::string* error_msg = nullptr) override {
        if (policy.mode == SandboxMode::Disabled || policy.mode == SandboxMode::ScrubbedOnly) {
            return true;
        }

#if defined(__APPLE__)
        std::string profile = SandboxEngine::generate_seatbelt_profile(policy);
        char* error_buf = nullptr;
        int rc = sandbox_init(profile.c_str(), 0, &error_buf);
        if (rc != 0) {
            std::string err_str = error_buf ? error_buf : "unknown sandbox_init error";
            if (error_buf) {
                sandbox_free_error(error_buf);
            }
            if (policy.mode == SandboxMode::Enforced) {
                if (error_msg) *error_msg = err_str;
                return false;
            }
            return true;
        }
        return true;
#else
        if (policy.mode == SandboxMode::Enforced) {
            if (error_msg) *error_msg = "macOS Seatbelt not supported on non-Apple platform";
            return false;
        }
        return true;
#endif
    }
};

class WindowsFallbackEngine : public SandboxEngine {
public:
    bool is_supported() const override {
        return true;
    }

    bool is_kernel_enforced() const override {
        return false;
    }

    EngineBackend get_backend() const override {
        return EngineBackend::WindowsDegraded;
    }

    const char* get_backend_name() const override {
        return "windows-fallback";
    }

    EngineCapabilities get_capabilities() const override {
        EngineCapabilities caps;
        caps.supports_fs_read_isolation = false;
        caps.supports_fs_write_isolation = false;
        caps.supports_device_isolation = false;
        caps.supports_network_isolation = false;
        caps.supports_port_binding = false;
        caps.backend = EngineBackend::WindowsDegraded;
        caps.backend_name = "windows-fallback";
        caps.description = "Windows native fallback engine (secret scrubbing only)";
        return caps;
    }

    bool apply(const SandboxPolicy& policy, std::string* error_msg = nullptr) override {
        if (policy.mode == SandboxMode::Disabled || policy.mode == SandboxMode::ScrubbedOnly) {
            return true;
        }
        if (policy.mode == SandboxMode::Enforced) {
            if (error_msg) {
                *error_msg = "Kernel sandboxing requested (SandboxMode::Enforced) but not supported on native Windows";
            }
            return false;
        }
        return true;
    }
};

class FallbackStubEngine : public SandboxEngine {
public:
    bool is_supported() const override {
        return false;
    }

    bool is_kernel_enforced() const override {
        return false;
    }

    EngineBackend get_backend() const override {
        return EngineBackend::FallbackStub;
    }

    const char* get_backend_name() const override {
        return "fallback_stub";
    }

    EngineCapabilities get_capabilities() const override {
        EngineCapabilities caps;
        caps.supports_fs_read_isolation = false;
        caps.supports_fs_write_isolation = false;
        caps.supports_device_isolation = false;
        caps.supports_network_isolation = false;
        caps.supports_port_binding = false;
        caps.backend = EngineBackend::FallbackStub;
        caps.backend_name = "fallback_stub";
        caps.description = "Fallback stub engine for unsupported environments";
        return caps;
    }

    bool apply(const SandboxPolicy& policy, std::string* error_msg = nullptr) override {
        if (policy.mode == SandboxMode::Disabled || policy.mode == SandboxMode::ScrubbedOnly) {
            return true;
        }
        if (policy.mode == SandboxMode::Enforced) {
            if (error_msg) {
                *error_msg = "Enforced sandboxing requested but no supported kernel engine is available";
            }
            return false;
        }
        return true;
    }
};

class NonoFFIEngine : public SandboxEngine {
public:
    bool is_supported() const override {
        return nono_is_supported();
    }

    bool is_kernel_enforced() const override {
        return nono_is_supported();
    }

    EngineBackend get_backend() const override {
        return EngineBackend::NonoFFI;
    }

    const char* get_backend_name() const override {
        return nono_get_backend_name();
    }

    EngineCapabilities get_capabilities() const override {
        EngineCapabilities caps;
        caps.supports_fs_read_isolation = true;
        caps.supports_fs_write_isolation = true;
        caps.supports_device_isolation = true;
        caps.supports_network_isolation = true;
        caps.supports_port_binding = true;
        caps.backend = EngineBackend::NonoFFI;
        caps.backend_name = nono_get_backend_name();
        caps.description = "nono C FFI sandboxing engine";
        return caps;
    }

    bool apply(const SandboxPolicy& policy, std::string* error_msg = nullptr) override {
        if (policy.mode == SandboxMode::Disabled || policy.mode == SandboxMode::ScrubbedOnly) {
            return true;
        }

        nono_capability_set* caps = nono_capability_set_new();
        if (!caps) {
            if (error_msg) *error_msg = "Failed to allocate nono_capability_set";
            return false;
        }

        nono_status status = SandboxEngine::policy_to_nono_capabilities(policy, caps);
        if (status != NONO_OK) {
            if (error_msg) *error_msg = nono_get_last_error();
            nono_capability_set_free(caps);
            return false;
        }

        status = nono_sandbox_apply(caps);
        nono_capability_set_free(caps);

        if (status != NONO_OK) {
            if (policy.mode == SandboxMode::Auto && status == NONO_ERROR_UNSUPPORTED) {
                return true;
            }
            if (error_msg) {
                *error_msg = nono_get_last_error();
                if (error_msg->empty()) {
                    *error_msg = nono_status_to_string(status);
                }
            }
            return false;
        }
        return true;
    }
};

bool SandboxEngine::is_wsl2_environment() {
    return PlatformDetector::is_wsl2();
}

bool SandboxEngine::is_platform_supported() {
#if defined(__linux__)
    struct utsname uts;
    if (uname(&uts) == 0) {
        int major = 0;
        int minor = 0;
        if (sscanf(uts.release, "%d.%d", &major, &minor) >= 2) {
            if (major > 5 || (major == 5 && minor >= 13)) {
                return true;
            }
        }
    }
    return false;
#elif defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

nono_status SandboxEngine::policy_to_nono_capabilities(
    const SandboxPolicy& policy,
    nono_capability_set* caps) {

    if (!caps) return NONO_ERROR_INVALID_PARAM;

    for (const auto& grant : policy.path_grants) {
        if (grant.path.empty()) continue;
        nono_status s;
        if (grant.write_allowed) {
            s = nono_capability_add_fs_write(caps, grant.path.c_str());
        } else {
            s = nono_capability_add_fs_read(caps, grant.path.c_str());
        }
        if (s != NONO_OK) return s;
    }

    for (const auto& dev : policy.device_grants) {
        if (dev.empty()) continue;
        nono_status s = nono_capability_add_device(caps, dev.c_str());
        if (s != NONO_OK) return s;
    }

    switch (policy.network_access) {
        case NetworkAccess::DenyAll:
            nono_capability_set_network_egress(caps, false);
            nono_capability_set_network_loopback(caps, false);
            break;
        case NetworkAccess::LoopbackOnly:
            nono_capability_set_network_egress(caps, false);
            nono_capability_set_network_loopback(caps, true);
            break;
        case NetworkAccess::Full:
            nono_capability_set_network_egress(caps, true);
            nono_capability_set_network_loopback(caps, true);
            break;
    }

    if (policy.bind_port > 0) {
        nono_capability_set_bind_port(caps, policy.bind_port);
    }

    return NONO_OK;
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_linux_landlock_engine() {
    return std::make_unique<LinuxLandlockEngine>();
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_macos_seatbelt_engine() {
    return std::make_unique<MacOSSeatbeltEngine>();
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_windows_fallback_engine() {
    return std::make_unique<WindowsFallbackEngine>();
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_fallback_stub_engine() {
    return std::make_unique<FallbackStubEngine>();
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_nono_ffi_engine() {
    return std::make_unique<NonoFFIEngine>();
}

std::unique_ptr<SandboxEngine> SandboxEngine::create_for_platform() {
#if defined(_WIN32)
    return create_windows_fallback_engine();
#elif defined(__APPLE__)
    return create_macos_seatbelt_engine();
#elif defined(__linux__)
    return create_linux_landlock_engine();
#else
    return create_fallback_stub_engine();
#endif
}

std::string SandboxEngine::get_platform_engine_description(SandboxMode mode) {
    if (mode == SandboxMode::Disabled) {
        return "disabled (by configuration)";
    }
#if defined(_WIN32)
    return "degraded (native Windows fallback mode, secret scrubbing active)";
#elif defined(__APPLE__)
    return std::string("Seatbelt (") + (mode == SandboxMode::Enforced ? "enforced" : "active") + ")";
#elif defined(__linux__)
    bool is_wsl = is_wsl2_environment();
    int abi = get_landlock_abi_version();
    if (abi > 0) {
        std::string label = is_wsl ? "WSL2 Landlock ABI " : "Landlock ABI ";
        label += std::to_string(abi) + " (" + (mode == SandboxMode::Enforced ? "enforced" : "active") + ")";
        return label;
    }
    return "degraded (Landlock not supported by kernel, running in fallback mode)";
#else
    return "degraded (fallback stub engine, secret scrubbing active)";
#endif
}

} // namespace lemon::sandbox
