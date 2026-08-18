#include "lemon/sandbox/nono_ffi.h"
#include "lemon/sandbox/sandbox_engine.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

struct nono_capability_set {
    std::vector<std::string> read_paths;
    std::vector<std::string> write_paths;
    std::vector<std::string> devices;
    bool allow_egress{false};
    bool allow_loopback{true};
    uint16_t bind_port{0};
};

namespace {

thread_local std::string g_last_error;

void set_last_error(const std::string& err) {
    g_last_error = err;
}

void clear_last_error() {
    g_last_error.clear();
}

} // namespace

extern "C" {

nono_capability_set* nono_capability_set_new(void) {
    clear_last_error();
    return new (std::nothrow) nono_capability_set();
}

void nono_capability_set_free(nono_capability_set* caps) {
    delete caps;
}

nono_status nono_capability_add_fs_read(nono_capability_set* caps, const char* path) {
    if (!caps || !path || path[0] == '\0') {
        set_last_error("Invalid capability set or path parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->read_paths.emplace_back(path);
    return NONO_OK;
}

nono_status nono_capability_add_fs_write(nono_capability_set* caps, const char* path) {
    if (!caps || !path || path[0] == '\0') {
        set_last_error("Invalid capability set or path parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->write_paths.emplace_back(path);
    return NONO_OK;
}

nono_status nono_capability_add_device(nono_capability_set* caps, const char* dev_path) {
    if (!caps || !dev_path || dev_path[0] == '\0') {
        set_last_error("Invalid capability set or device path parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->devices.emplace_back(dev_path);
    return NONO_OK;
}

nono_status nono_capability_set_network_egress(nono_capability_set* caps, bool allow_egress) {
    if (!caps) {
        set_last_error("Invalid capability set parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->allow_egress = allow_egress;
    return NONO_OK;
}

nono_status nono_capability_set_network_loopback(nono_capability_set* caps, bool allow_loopback) {
    if (!caps) {
        set_last_error("Invalid capability set parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->allow_loopback = allow_loopback;
    return NONO_OK;
}

nono_status nono_capability_set_bind_port(nono_capability_set* caps, uint16_t port) {
    if (!caps) {
        set_last_error("Invalid capability set parameter");
        return NONO_ERROR_INVALID_PARAM;
    }
    caps->bind_port = port;
    return NONO_OK;
}

nono_status nono_sandbox_apply(const nono_capability_set* caps) {
    if (!caps) {
        set_last_error("Invalid capability set parameter");
        return NONO_ERROR_INVALID_PARAM;
    }

    if (lemon::sandbox::SandboxEngine::is_platform_supported()) {
        auto engine = lemon::sandbox::SandboxEngine::create_for_platform();
        if (engine && engine->is_supported()) {
            lemon::sandbox::SandboxPolicy policy;
            for (const auto& p : caps->read_paths) {
                policy.add_read_path(p);
            }
            for (const auto& p : caps->write_paths) {
                policy.add_write_path(p);
            }
            for (const auto& d : caps->devices) {
                policy.add_device(d);
            }
            if (caps->allow_egress) {
                policy.set_network_access(lemon::sandbox::NetworkAccess::Full);
            } else if (caps->allow_loopback) {
                policy.set_network_access(lemon::sandbox::NetworkAccess::LoopbackOnly);
            } else {
                policy.set_network_access(lemon::sandbox::NetworkAccess::DenyAll);
            }
            policy.set_bind_port(caps->bind_port);
            policy.set_mode(lemon::sandbox::SandboxMode::Enforced);

            std::string err;
            if (!engine->apply(policy, &err)) {
                set_last_error(err.empty() ? "Sandbox application failed" : err);
                return NONO_ERROR_APPLY_FAILED;
            }
            clear_last_error();
            return NONO_OK;
        }
    }

    set_last_error("Kernel sandboxing unsupported on this operating system or configuration");
    return NONO_ERROR_UNSUPPORTED;
}

bool nono_is_supported(void) {
    return lemon::sandbox::SandboxEngine::is_platform_supported();
}

const char* nono_get_backend_name(void) {
#if defined(__linux__)
    return "landlock";
#elif defined(__APPLE__)
    return "seatbelt";
#else
    return "fallback_stub";
#endif
}

const char* nono_status_to_string(nono_status status) {
    switch (status) {
        case NONO_OK:                     return "NONO_OK";
        case NONO_ERROR_GENERIC:          return "NONO_ERROR_GENERIC";
        case NONO_ERROR_UNSUPPORTED:      return "NONO_ERROR_UNSUPPORTED";
        case NONO_ERROR_INVALID_PARAM:    return "NONO_ERROR_INVALID_PARAM";
        case NONO_ERROR_APPLY_FAILED:     return "NONO_ERROR_APPLY_FAILED";
        case NONO_ERROR_PERMISSION_DENIED:return "NONO_ERROR_PERMISSION_DENIED";
        case NONO_ERROR_ALREADY_APPLIED:  return "NONO_ERROR_ALREADY_APPLIED";
    }
    return "NONO_ERROR_UNKNOWN";
}

const char* nono_get_last_error(void) {
    return g_last_error.c_str();
}

} // extern "C"
