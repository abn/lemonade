#include <filesystem>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#include "lemon/backends/backend_descriptor_registry.h"
#include "lemon/external/external_installer.h"
#include "lemon/external/external_registry.h"

namespace lemon {

namespace {

namespace fs = std::filesystem;
using namespace lemon::external;

bool under_any(const std::string& path, const std::vector<std::string>& roots) {
    if (path.empty()) return false;
    std::error_code ec;
    fs::path canonical = fs::weakly_canonical(path, ec);
    if (ec) canonical = path;
    for (const auto& root : roots) {
        fs::path root_canonical = fs::weakly_canonical(root, ec);
        if (ec) root_canonical = root;
        auto rel = canonical.lexically_relative(root_canonical);
        if (!rel.empty() && *rel.begin() != "..") return true;
    }
    return false;
}

ExternalRegistry::ManifestPtr find_external(const std::string& recipe) {
    DiscoveryPaths paths = default_discovery_paths();
    ExternalRegistry::instance().refresh(
        paths, [](const std::string& candidate) { return backends::has_backend(candidate); });
    return ExternalRegistry::instance().manifest_for(recipe);
}

void print_provenance(const BackendManifest& manifest) {
    std::cout << "External backend: " << manifest.display_name << " (" << manifest.recipe << ")\n";
    if (manifest.is_variant_of()) {
        std::cout << "  variant_of: " << manifest.variant_of << "\n";
    }
    std::cout << "  source: " << (manifest.source.empty() ? "(user-provided binary)" : manifest.source) << "\n";
    if (!manifest.sha256.empty()) {
        std::cout << "  sha256: " << manifest.sha256 << "\n";
    }
    std::cout << "  version_policy: " << manifest.version_policy << "\n";
    std::cout << "  capabilities: ";
    for (size_t i = 0; i < manifest.capabilities.size(); ++i) {
        if (i) std::cout << ", ";
        std::cout << manifest.capabilities[i];
    }
    std::cout << "\n";
    std::cout << "  WARNING: this backend runs as an external subprocess. No process\n"
                 "           sandbox is enforced by this RFC; run only manifests you trust.\n";
}

bool confirm(bool assume_yes, const std::string& action) {
    if (assume_yes) return true;
    if (!isatty(fileno(stdin))) {
        std::cerr << "Refusing to " << action << " without --yes on a non-interactive terminal.\n";
        return false;
    }
    std::cout << "Proceed? [y/N] " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);
    return !answer.empty() && (answer[0] == 'y' || answer[0] == 'Y');
}

}  // namespace

int run_external_backend_install(const std::string& recipe, bool assume_yes) {
    auto manifest = find_external(recipe);
    if (manifest == nullptr) {
        std::cerr << "No external backend manifest found for recipe '" << recipe << "'.\n";
        return 1;
    }
    print_provenance(*manifest);
    if (!confirm(assume_yes, "install")) {
        std::cerr << "Aborted.\n";
        return 1;
    }
    InstallOutcome outcome = install_external_binary(*manifest);
    std::cout << outcome.message << "\n";
    return outcome.ok ? 0 : 1;
}

int run_external_backend_uninstall(const std::string& recipe, bool assume_yes) {
    auto manifest = find_external(recipe);
    if (manifest == nullptr) {
        std::cerr << "No external backend manifest found for recipe '" << recipe << "'.\n";
        return 1;
    }
    DiscoveryPaths paths = default_discovery_paths();
    std::vector<std::string> user_roots = paths.user_config;
    user_roots.insert(user_roots.end(), paths.user_cache.begin(), paths.user_cache.end());
    if (!under_any(manifest->source_path, user_roots)) {
        std::cerr << "Refusing to remove '" << manifest->source_path
                  << "': it is a system descriptor. Remove it with the package manager.\n";
        return 1;
    }
    print_provenance(*manifest);
    if (!confirm(assume_yes, "remove")) {
        std::cerr << "Aborted.\n";
        return 1;
    }

    std::error_code ec;
    fs::remove(manifest->source_path, ec);
    if (ec) {
        std::cerr << "Failed to remove " << manifest->source_path << ": " << ec.message() << "\n";
        return 1;
    }
    fs::remove_all(external_install_dir(recipe), ec);
    if (ec) {
        std::cerr << "Removed descriptor but failed to remove installed files: " << ec.message() << "\n";
        return 1;
    }
    std::cout << "Removed external backend '" << recipe << "'.\n";
    return 0;
}

}  // namespace lemon
