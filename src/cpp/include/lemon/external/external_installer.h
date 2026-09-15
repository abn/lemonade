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

// CLI-side install of a variant_of manifest's pinned binary. Downloads `source`
// (verifying `sha256` unless the version policy is roll_forward), extracts an
// archive when the artifact is one, and returns the resolved binary path.
// lemond never calls this; it only launches what the CLI installed.
InstallOutcome install_external_binary(const BackendManifest& manifest);

}  // namespace external
}  // namespace lemon
