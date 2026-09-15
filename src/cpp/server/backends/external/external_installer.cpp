#include "lemon/external/external_installer.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
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

InstallOutcome install_external_binary(const BackendManifest& manifest) {
    InstallOutcome outcome;
    const fs::path install_dir(external_install_dir(manifest.recipe));

    if (manifest.source.empty()) {
        outcome.ok = true;
        outcome.message = "no pinned source; binary is user-provided at " +
                          install_dir.string();
        const auto names = candidate_binary_names(manifest);
        if (!names.empty()) {
            outcome.binary_path = (install_dir / *names.begin()).string();
        }
        return outcome;
    }

    std::error_code ec;
    fs::create_directories(install_dir, ec);

    const std::string archive_name = url_basename(manifest.source);
    const fs::path archive_path = install_dir / archive_name;

    utils::DownloadOptions options;
    if (manifest.version_policy != "roll_forward" && !manifest.sha256.empty()) {
        options.expected_hash = manifest.sha256;
        options.expected_hash_algorithm = "sha256";
    }
    utils::DownloadResult result = utils::HttpClient::download_file(
        manifest.source, archive_path.string(), nullptr, {}, options,
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
    } else {
        // A bare binary: rename it to its declared name when we know one.
        const auto names = candidate_binary_names(manifest);
        if (!names.empty() && *names.begin() != archive_name) {
            const fs::path renamed = install_dir / *names.begin();
            fs::rename(archive_path, renamed, ec);
            if (ec) {
                outcome.message = "failed to place binary: " + ec.message();
                return outcome;
            }
        }
    }

    outcome.binary_path = resolve_installed_binary(manifest.recipe,
                                                    candidate_binary_names(manifest).empty()
                                                        ? ""
                                                        : *candidate_binary_names(manifest).begin());
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
