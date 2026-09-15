#pragma once

#include <string>

#include "lemon/external/backend_manifest.h"

namespace lemon {
namespace external {

struct InstallOutcome {
    bool ok = false;
    std::string message;
    std::string binary_path;
};

// Directory that holds an external recipe's installed binaries.
std::string external_install_dir(const std::string& recipe);

// Resolve an installed binary: the exact <install_dir>/<binary> when present,
// otherwise the first matching filename under the install directory (archives
// often nest a versioned top-level directory). Empty when not found. Shared by
// the installer and the loader so they agree on where the binary lives.
std::string resolve_installed_binary(const std::string& recipe, const std::string& binary);

// CLI-side install of a variant_of manifest's pinned binary. Downloads `source`
// (verifying `sha256` unless the version policy is roll_forward), extracts an
// archive when the artifact is one, and returns the resolved binary path.
// lemond never calls this; it only launches what the CLI installed.
InstallOutcome install_external_binary(const BackendManifest& manifest);

}  // namespace external
}  // namespace lemon
