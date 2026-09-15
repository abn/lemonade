#include "lemon/external/external_registry.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#endif

namespace lemon {
namespace external {

namespace fs = std::filesystem;

namespace {

std::string env_or_empty(const char* name) {
    const char* value = std::getenv(name);
    return (value != nullptr && value[0] != '\0') ? std::string(value) : std::string();
}

std::string home_dir() {
#ifdef _WIN32
    std::string profile = env_or_empty("USERPROFILE");
    if (!profile.empty()) return profile;
    std::string drive = env_or_empty("HOMEDRIVE");
    std::string path = env_or_empty("HOMEPATH");
    return drive + path;
#else
    return env_or_empty("HOME");
#endif
}

bool is_regular_json_file(const fs::path& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec) && path.extension() == ".json";
}

void add_user_dirs(DiscoveryPaths& paths) {
#ifdef _WIN32
    std::string app_data = env_or_empty("APPDATA");
    if (!app_data.empty()) {
        paths.user_config.push_back((fs::path(app_data) / "Lemonade" / "backends").string());
    }
    std::string profile = home_dir();
    if (!profile.empty()) {
        paths.user_cache.push_back(
            (fs::path(profile) / ".cache" / "lemonade" / "backends").string());
    }
#else
    std::string xdg_config = env_or_empty("XDG_CONFIG_HOME");
    if (!xdg_config.empty()) {
        paths.user_config.push_back((fs::path(xdg_config) / "lemonade" / "backends").string());
    } else {
        std::string home = home_dir();
        if (!home.empty()) {
            paths.user_config.push_back(
                (fs::path(home) / ".config" / "lemonade" / "backends").string());
        }
    }
    std::string xdg_cache = env_or_empty("XDG_CACHE_HOME");
    if (!xdg_cache.empty()) {
        paths.user_cache.push_back((fs::path(xdg_cache) / "lemonade" / "backends").string());
    } else {
        std::string home = home_dir();
        if (!home.empty()) {
            paths.user_cache.push_back(
                (fs::path(home) / ".cache" / "lemonade" / "backends").string());
        }
    }
#endif
}

void add_system_dirs(DiscoveryPaths& paths) {
#ifdef _WIN32
    std::string program_data = env_or_empty("ProgramData");
    if (!program_data.empty()) {
        paths.system.push_back((fs::path(program_data) / "Lemonade" / "backends").string());
    }
#else
    paths.system.push_back("/usr/share/lemonade-server/backends");
    paths.system.push_back("/usr/local/share/lemonade-server/backends");
    paths.system.push_back("/Library/Application Support/Lemonade/backends");
    paths.system.push_back("/etc/lemonade/backends");
#endif
}

// Fold a base manifest's declarative options into a child. Child keys win.
void merge_manifest_into(BackendManifest& child, const BackendManifest& base) {
    nlohmann::json merged = base.recipe_options.is_object() ? base.recipe_options
                                                            : nlohmann::json::object();
    for (auto it = child.recipe_options.begin(); it != child.recipe_options.end(); ++it) {
        merged[it.key()] = it.value();
    }
    child.recipe_options = std::move(merged);

    std::map<std::string, CustomOption> options;
    for (const auto& opt : base.custom_options) options[opt.name] = opt;
    for (const auto& opt : child.custom_options) options[opt.name] = opt;
    child.custom_options.clear();
    for (auto& [name, opt] : options) child.custom_options.push_back(std::move(opt));
}

}  // namespace

bool descriptor_path_is_trusted(const std::string& path,
                                bool is_system_path,
                                std::string& reason) {
    reason.clear();
#ifndef _WIN32
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) {
        reason = "cannot stat file";
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        reason = "symlinked descriptor files are not permitted";
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        reason = "not a regular file";
        return false;
    }
    if ((st.st_mode & 0022) != 0) {
        reason = "file is group or world writable (mode & 0022)";
        return false;
    }
    if (is_system_path) {
        if (st.st_uid != 0) {
            reason = "system descriptor is not owned by root (UID 0)";
            return false;
        }
    } else if (st.st_uid != geteuid()) {
        reason = "descriptor owner UID does not match the current user";
        return false;
    }

    std::error_code ec;
    fs::path target = fs::weakly_canonical(path, ec);
    if (ec) target = path;
    fs::path parent = target.parent_path();
    while (!parent.empty() && parent != parent.root_path()) {
        struct stat parent_st;
        if (::lstat(parent.c_str(), &parent_st) == 0) {
            if (S_ISLNK(parent_st.st_mode)) {
                reason = "ancestor directory '" + parent.string() + "' is a symlink";
                return false;
            }
            if (parent_st.st_uid != geteuid() && (parent_st.st_mode & 0022) != 0 &&
                (parent_st.st_mode & S_ISVTX) == 0) {
                reason = "ancestor directory '" + parent.string() +
                         "' is group/world writable without the sticky bit";
                return false;
            }
        }
        parent = parent.parent_path();
    }
#else
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    DWORD result = GetNamedSecurityInfoW(
        fs::path(path).wstring().c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &owner, nullptr, &dacl,
        nullptr, &descriptor);
    if (result != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        if (descriptor != nullptr) LocalFree(descriptor);
        reason = "cannot read Windows security descriptor (error " + std::to_string(result) + ")";
        return false;
    }

    bool owner_ok = false;
    if (owner != nullptr) {
        HANDLE token = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            BYTE buffer[SECURITY_MAX_SID_SIZE];
            DWORD size = sizeof(buffer);
            auto* user = reinterpret_cast<TOKEN_USER*>(buffer);
            if (GetTokenInformation(token, TokenUser, user, size, &size) &&
                EqualSid(owner, user->User.Sid)) {
                owner_ok = true;
            }
            CloseHandle(token);
        }
        if (!owner_ok && IsWellKnownSid(owner, WinBuiltinAdministratorsSid)) owner_ok = true;
        if (!owner_ok && is_system_path && IsWellKnownSid(owner, WinLocalSystemSid)) owner_ok = true;
    }
    if (!owner_ok) {
        LocalFree(descriptor);
        reason = "descriptor owner SID is not authorized for this process";
        return false;
    }

    ACL_SIZE_INFORMATION acl_info;
    if (!GetAclInformation(dacl, &acl_info, sizeof(acl_info), AclSizeInformation)) {
        LocalFree(descriptor);
        reason = "cannot read Windows ACL information";
        return false;
    }
    for (DWORD i = 0; i < acl_info.AceCount; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        auto* header = static_cast<ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        ACCESS_MASK mask = allowed->Mask;
        PSID sid = reinterpret_cast<PSID>(&allowed->SidStart);
        if ((mask & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | WRITE_DAC |
                     WRITE_OWNER)) != 0 &&
            IsValidSid(sid) &&
            (IsWellKnownSid(sid, WinWorldSid) || IsWellKnownSid(sid, WinBuiltinUsersSid))) {
            LocalFree(descriptor);
            reason = "Windows ACL grants write access to Everyone or Users";
            return false;
        }
    }
    LocalFree(descriptor);
#endif
    return true;
}

DiscoveryPaths default_discovery_paths() {
    DiscoveryPaths paths;
    add_user_dirs(paths);
    add_system_dirs(paths);
    return paths;
}

ExternalRegistry& ExternalRegistry::instance() {
    static ExternalRegistry registry;
    return registry;
}

void ExternalRegistry::refresh(const DiscoveryPaths& paths,
                               const ReservedPredicate& is_reserved) {
    std::vector<RejectedDescriptor> rejected;
    std::set<std::string> claimed;
    std::map<std::string, std::shared_ptr<BackendManifest>> by_recipe;

    auto process_dir = [&](const std::string& dir, bool is_system) {
        std::error_code ec;
        fs::path dir_path(dir);
        if (!fs::is_directory(dir_path, ec)) return;
        for (const auto& entry : fs::directory_iterator(dir_path, ec)) {
            if (ec) break;
            if (!is_regular_json_file(entry.path())) continue;
            const std::string file = entry.path().string();
            std::string reason;
            if (!descriptor_path_is_trusted(file, is_system, reason)) {
                rejected.push_back({file, reason});
                continue;
            }
            std::ifstream stream(entry.path());
            if (!stream.is_open()) {
                rejected.push_back({file, "cannot open file"});
                continue;
            }
            std::stringstream buffer;
            buffer << stream.rdbuf();
            nlohmann::json doc = nlohmann::json::parse(buffer.str(), nullptr, false);
            if (doc.is_discarded() || !doc.is_object()) {
                rejected.push_back({file, "invalid JSON"});
                continue;
            }
            BackendManifest manifest;
            std::string parse_error;
            if (!parse_backend_manifest(doc, manifest, parse_error)) {
                rejected.push_back({file, parse_error});
                continue;
            }
            if (is_reserved && is_reserved(manifest.recipe)) {
                rejected.push_back({file, "recipe '" + manifest.recipe +
                                             "' collides with a built-in backend"});
                continue;
            }
            if (!claimed.insert(manifest.recipe).second) {
                rejected.push_back({file, "recipe '" + manifest.recipe +
                                             "' already provided by a higher-priority path"});
                continue;
            }
            manifest.source_path = file;
            // Capture the key before the move; the assignment's right operand is
            // sequenced first, so reading manifest.recipe after it would key on
            // the moved-from string.
            const std::string recipe = manifest.recipe;
            by_recipe[recipe] = std::make_shared<BackendManifest>(std::move(manifest));
        }
    };

    for (const auto& dir : paths.user_config) process_dir(dir, false);
    for (const auto& dir : paths.user_cache) process_dir(dir, false);
    for (const auto& dir : paths.system) process_dir(dir, true);

    // Resolve `extends` after discovery so a base may live in any search path.
    // Cycles and missing bases drop the child with a recorded reason.
    std::set<std::string> extended;
    std::vector<std::string> unresolved;
    std::function<bool(BackendManifest&, std::set<std::string>&)> resolve =
        [&](BackendManifest& manifest, std::set<std::string>& stack) -> bool {
        if (manifest.extends_recipe.empty()) return true;
        if (extended.count(manifest.recipe)) return true;
        if (stack.count(manifest.recipe)) return false;
        stack.insert(manifest.recipe);
        auto base = by_recipe.find(manifest.extends_recipe);
        if (base == by_recipe.end()) return false;
        if (!resolve(*base->second, stack)) return false;
        merge_manifest_into(manifest, *base->second);
        stack.erase(manifest.recipe);
        extended.insert(manifest.recipe);
        return true;
    };
    for (auto& [recipe, manifest] : by_recipe) {
        if (manifest->extends_recipe.empty()) continue;
        std::set<std::string> stack;
        if (!resolve(*manifest, stack)) {
            rejected.push_back({manifest->source_path,
                                "cannot resolve extends '" + manifest->extends_recipe + "'"});
            unresolved.push_back(recipe);
        }
    }
    for (const auto& recipe : unresolved) by_recipe.erase(recipe);

    std::vector<std::shared_ptr<BackendManifest>> loaded;
    loaded.reserve(by_recipe.size());
    for (auto& [recipe, manifest] : by_recipe) loaded.push_back(std::move(manifest));

    std::lock_guard<std::mutex> lock(mutex_);
    manifests_ = std::move(loaded);
    rejected_ = std::move(rejected);
    last_paths_ = paths;
    last_predicate_ = is_reserved;
}

const BackendManifest* ExternalRegistry::manifest_for(const std::string& recipe) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& manifest : manifests_) {
        if (manifest->recipe == recipe) return manifest.get();
    }
    return nullptr;
}

std::vector<const BackendManifest*> ExternalRegistry::all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const BackendManifest*> result;
    result.reserve(manifests_.size());
    for (const auto& manifest : manifests_) result.push_back(manifest.get());
    return result;
}

const std::vector<RejectedDescriptor>& ExternalRegistry::rejected() const {
    return rejected_;
}

bool ExternalRegistry::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return manifests_.empty();
}

namespace {

uint64_t search_paths_signature(const DiscoveryPaths& paths) {
    uint64_t signature = 0;
    std::error_code ec;
    auto accumulate = [&](const std::string& dir) {
        fs::path dir_path(dir);
        if (!fs::is_directory(dir_path, ec)) return;
        auto dir_mtime = fs::last_write_time(dir_path, ec);
        if (!ec) {
            signature += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(dir_mtime.time_since_epoch())
                    .count());
        }
        for (const auto& entry : fs::directory_iterator(dir_path, ec)) {
            if (ec) break;
            if (!is_regular_json_file(entry.path())) continue;
            auto file_mtime = entry.last_write_time(ec);
            if (!ec) {
                signature += static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        file_mtime.time_since_epoch())
                        .count());
            }
        }
    };
    for (const auto& dir : paths.user_config) accumulate(dir);
    for (const auto& dir : paths.user_cache) accumulate(dir);
    for (const auto& dir : paths.system) accumulate(dir);
    return signature;
}

}  // namespace

void ExternalRegistry::start_watcher() {
    if (watcher_running_.exchange(true)) return;
    std::thread([this]() {
        DiscoveryPaths paths;
        ReservedPredicate predicate;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            paths = last_paths_;
            predicate = last_predicate_;
        }
        uint64_t last_signature = search_paths_signature(paths);
        while (watcher_running_.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            if (!watcher_running_.load()) break;
            uint64_t current = search_paths_signature(paths);
            if (current != last_signature) {
                last_signature = current;
                refresh(paths, predicate);
            }
        }
    }).detach();
}

void ExternalRegistry::stop_watcher() { watcher_running_.store(false); }

}  // namespace external
}  // namespace lemon
