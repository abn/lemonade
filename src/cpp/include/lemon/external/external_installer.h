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

// The host OS key used by the platform matrix: "linux", "darwin", or "windows".
std::string host_os_name();

// Resolve an installed binary: the exact <install_dir>/<binary> when present,
// otherwise the first matching filename under the install directory (archives
// often nest a versioned top-level directory). Empty when not found. Shared by
// the installer and the loader so they agree on where the binary lives.
std::string resolve_installed_binary(const std::string& recipe, const std::string& binary);

// CLI-side install of a variant_of manifest's pinned binary. Downloads the
// artifact for the host platform (a block-level `source` overrides the
// top-level one), verifying `sha256` unless the effective version policy is
// roll_forward, extracts an archive when the artifact is one, and returns the
// resolved binary path. When the manifest publishes several artifacts for this
// host OS and `accelerator` is empty, the install fails and names the choices.
// lemond never calls this; it only launches what the CLI installed.
InstallOutcome install_external_binary(const BackendManifest& manifest,
                                       const std::string& accelerator = "");

}  // namespace external
}  // namespace lemon
