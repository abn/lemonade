#include "lemon/external/external_installer.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <set>

#include "lemon/utils/archive_platform.h"
#include "lemon/utils/http_client.h"
#include "lemon/utils/path_utils.h"

namespace lemon {
namespace external {

namespace fs = std::filesystem;

namespace {

std::string url_basename(const std::string& url) {
    std::string path = url;
    size_t query = path.find_first_of("?#");
    if (query != std::string::npos) path = path.substr(0, query);
    size_t slash = path.find_last_of('/');
    std::string name = (slash == std::string::npos) ? path : path.substr(slash + 1);
    return name.empty() ? "artifact" : name;
}

bool ends_with(const std::string& value, const std::string& suffix) {
    if (value.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), value.rbegin(),
                      [](char a, char b) {
                          return std::tolower(static_cast<unsigned char>(a)) ==
                                 std::tolower(static_cast<unsigned char>(b));
                      });
}

std::set<std::string> candidate_binary_names(const BackendManifest& manifest) {
    std::set<std::string> names;
    for (const auto& [os, accelerators] : manifest.platforms.by_os) {
        (void)os;
        for (const auto& [accelerator, block] : accelerators) {
            (void)accelerator;
            if (!block.binary.empty()) names.insert(block.binary);
        }
    }
    return names;
}

// The host-OS block an install should fetch. Returns null with an empty error
// when there is nothing pinned to fetch (a user-provided binary).
const ExecBlock* select_install_block(const BackendManifest& manifest,
                                      const std::string& accelerator,
                                      std::string& error) {
    const std::string os = host_os_name();
    auto os_it = manifest.platforms.by_os.find(os);
    if (os_it == manifest.platforms.by_os.end()) {
        error = "manifest has no platform block for host OS '" + os + "'";
        return nullptr;
    }

    std::map<std::string, const ExecBlock*> candidates;
    for (const auto& [accel, block] : os_it->second) {
        if (!block.source.empty() || !manifest.source.empty()) {
            candidates[accel] = &block;
        }
    }

    if (!accelerator.empty()) {
        auto it = candidates.find(accelerator);
        if (it == candidates.end()) {
            error = "no installable artifact for accelerator '" + accelerator + "'";
            return nullptr;
        }
        return it->second;
    }
    if (candidates.empty()) return nullptr;
    if (candidates.size() == 1) return candidates.begin()->second;

    std::string names;
    for (const auto& [accel, block] : candidates) {
        (void)block;
        if (!names.empty()) names += ", ";
        names += accel;
    }
    error = "manifest publishes per-platform artifacts; pick one with --accelerator (" +
            names + ")";
    return nullptr;
}

std::string find_binary(const fs::path& root, const std::set<std::string>& names) {
    std::error_code ec;
    std::string fallback;
    for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const std::string filename = entry.path().filename().string();
        if (names.empty()) {
            if (fallback.empty()) fallback = entry.path().string();
        } else if (names.count(filename) > 0) {
            return entry.path().string();
        }
    }
    return fallback;
}

}  // namespace

std::string host_os_name() {
#ifdef _WIN32
    return "windows";
#elif defined(__APPLE__)
    return "darwin";
#else
    return "linux";
#endif
}

std::string external_install_dir(const std::string& recipe) {
    return (fs::path(utils::get_cache_dir()) / "external" / recipe).string();
}

std::string resolve_installed_binary(const std::string& recipe, const std::string& binary) {
    if (binary.empty()) return "";
    const fs::path install_dir(external_install_dir(recipe));
    const fs::path exact = install_dir / binary;
    if (fs::exists(exact)) return exact.string();
    return find_binary(install_dir, {binary});
}

InstallOutcome install_external_binary(const BackendManifest& manifest,
                                       const std::string& accelerator) {
    InstallOutcome outcome;
    const fs::path install_dir(external_install_dir(manifest.recipe));

    std::string select_error;
    const ExecBlock* block = select_install_block(manifest, accelerator, select_error);
    if (block == nullptr) {
        if (!select_error.empty()) {
            outcome.message = select_error;
            return outcome;
        }
        outcome.ok = true;
        outcome.message = "no pinned source; binary is user-provided at " +
                          install_dir.string();
        const auto names = candidate_binary_names(manifest);
        if (!names.empty()) {
            outcome.binary_path = (install_dir / *names.begin()).string();
        }
        return outcome;
    }

    const std::string source = block->source.empty() ? manifest.source : block->source;
    const std::string policy =
        block->version_policy.empty() ? manifest.version_policy : block->version_policy;
    const std::string hash = block->sha256.empty() ? manifest.sha256 : block->sha256;
    const std::string wanted_binary =
        block->binary.empty()
            ? (candidate_binary_names(manifest).empty()
                   ? ""
                   : *candidate_binary_names(manifest).begin())
            : block->binary;

    std::error_code ec;
    fs::create_directories(install_dir, ec);

    const std::string archive_name = url_basename(source);
    const fs::path archive_path = install_dir / archive_name;

    utils::DownloadOptions options;
    if (policy != "roll_forward" && !hash.empty()) {
        options.expected_hash = hash;
        options.expected_hash_algorithm = "sha256";
    }
    utils::DownloadResult result = utils::HttpClient::download_file(
        source, archive_path.string(), nullptr, {}, options,
        utils::HttpSecurityPolicy::ExternalHttpsOnly);
    if (!result.success) {
        outcome.message = "download failed: " + result.error_message;
        return outcome;
    }

    if (ends_with(archive_name, ".tar.gz") || ends_with(archive_name, ".tgz") ||
        ends_with(archive_name, ".tar.xz") || ends_with(archive_name, ".tar.bz2")) {
        auto archive = utils::create_archive_platform();
        if (!archive->extract_tarball(archive_path.string(), install_dir.string(),
                                      manifest.recipe)) {
            outcome.message = "failed to extract " + archive_name;
            return outcome;
        }
    } else if (ends_with(archive_name, ".zip")) {
        auto archive = utils::create_archive_platform();
        if (!archive->extract_zip(archive_path.string(), install_dir.string(),
                                  manifest.recipe)) {
            outcome.message = "failed to extract " + archive_name;
            return outcome;
        }
    } else if (!wanted_binary.empty() && wanted_binary != archive_name) {
        // A bare binary: rename it to its declared name when we know one.
        const fs::path renamed = install_dir / wanted_binary;
        fs::rename(archive_path, renamed, ec);
        if (ec) {
            outcome.message = "failed to place binary: " + ec.message();
            return outcome;
        }
    }

    outcome.binary_path = resolve_installed_binary(manifest.recipe, wanted_binary);
    if (outcome.binary_path.empty()) {
        outcome.message = "no binary found in installed artifact";
        return outcome;
    }
#ifndef _WIN32
    fs::permissions(fs::path(outcome.binary_path),
                    fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                    fs::perm_options::add, ec);
#endif

    outcome.ok = true;
    outcome.message = "installed to " + outcome.binary_path;
    return outcome;
}

}  // namespace external
}  // namespace lemon
