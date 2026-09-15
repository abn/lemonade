#include "lemon/backends/backend_registry.h"
#include "lemon/backends/external/external_backend_server.h"
#include "lemon/external/external_registry.h"
#include "lemon/wrapped_server.h"

// Generated from LEMON_BACKENDS at configure time. Defines
// lemon::backends::generated_registrations(), pairing each descriptor with its
// server class's create().
#include "backend_factories_generated.h"

namespace lemon {
namespace backends {

const std::vector<BackendRegistration>& all_registrations() {
    static const std::vector<BackendRegistration> kRegistrations = generated_registrations();
    return kRegistrations;
}

const BackendSpec* spec_for(const std::string& recipe) {
    for (const auto& reg : all_registrations()) {
        if (reg.descriptor->recipe == recipe) {
            return reg.spec;
        }
    }
    return nullptr;
}

const BackendOps* ops_for(const std::string& recipe) {
    for (const auto& reg : all_registrations()) {
        if (reg.descriptor->recipe == recipe) {
            return reg.ops;
        }
    }
    return default_backend_ops();
}

std::unique_ptr<WrappedServer> create_server(const std::string& recipe, const BackendContext& ctx) {
    for (const auto& reg : all_registrations()) {
        if (reg.descriptor->recipe == recipe) {
            std::unique_ptr<WrappedServer> server = reg.create(ctx);
            if (server) {
                server->set_descriptor(reg.descriptor);
            }
            return server;
        }
    }

    // External manifests are loaded at runtime; discover them once, treating
    // built-in recipes as reserved so an external descriptor cannot shadow one.
    lemon::external::ExternalRegistry::instance().ensure_loaded(
        [](const std::string& candidate) { return has_backend(candidate); });
    lemon::external::ExternalRegistry::instance().start_watcher();

    auto manifest = lemon::external::ExternalRegistry::instance().manifest_for(recipe);
    if (manifest != nullptr) {
        auto server = std::make_unique<ExternalBackendServer>(
            recipe, ctx.log_level, ctx.model_manager, ctx.backend_manager);
        server->set_manifest(manifest);
        return server;
    }
    return nullptr;
}

} // namespace backends
} // namespace lemon
