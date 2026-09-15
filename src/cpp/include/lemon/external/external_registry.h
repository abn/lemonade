#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "lemon/external/backend_manifest.h"

namespace lemon {
namespace external {

struct DiscoveryPaths {
    std::vector<std::string> user_config;
    std::vector<std::string> user_cache;
    std::vector<std::string> system;
};

struct RejectedDescriptor {
    std::string path;
    std::string reason;
};

// Integrity check for a descriptor file before it is parsed. On POSIX this
// rejects symlinks, any group/world-write bit, a wrong owner, and group/world
// writable ancestors without the sticky bit. On Windows it rejects owners
// outside the process user/administrators and DACLs that grant write to
// Everyone or Users. Returns true when the file is trusted.
bool descriptor_path_is_trusted(const std::string& path,
                                bool is_system_path,
                                std::string& reason);

// Default search paths derived from the environment (XDG / HOME / APPDATA /
// ProgramData). Independent of lemond's configured cache so the CLI can use it.
DiscoveryPaths default_discovery_paths();

// Runtime registry of external backend manifests. Manifests are shared-owned so
// a caller can hold one across a refresh (the watcher refreshes in the
// background). Manifests are coalesced by recipe with higher-priority paths
// winning; a recipe reserved by a built-in (via the injected predicate) or
// already claimed is rejected, not merged.
class ExternalRegistry {
public:
    using ReservedPredicate = std::function<bool(const std::string&)>;
    using ManifestPtr = std::shared_ptr<const BackendManifest>;

    static ExternalRegistry& instance();

    ~ExternalRegistry();

    // Load the default search paths once per process. Later calls are no-ops;
    // the first predicate passed wins.
    void ensure_loaded(const ReservedPredicate& is_reserved = {});

    void refresh(const DiscoveryPaths& paths, const ReservedPredicate& is_reserved = {});
    void refresh(const ReservedPredicate& is_reserved = {}) {
        refresh(default_discovery_paths(), is_reserved);
    }

    ManifestPtr manifest_for(const std::string& recipe) const;
    std::vector<ManifestPtr> all() const;
    std::vector<RejectedDescriptor> rejected() const;
    bool empty() const;

    // Poll the last-used search paths and refresh when a descriptor changes.
    // Safe to call more than once; stop_watcher() joins the thread.
    void start_watcher();
    void stop_watcher();

private:
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<BackendManifest>> manifests_;
    std::vector<RejectedDescriptor> rejected_;
    DiscoveryPaths last_paths_;
    ReservedPredicate last_predicate_;
    std::thread watcher_thread_;
    std::atomic<bool> watcher_running_{false};
};

}  // namespace external
}  // namespace lemon
