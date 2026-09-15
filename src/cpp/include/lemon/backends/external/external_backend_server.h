#pragma once

#include <string>
#include <vector>

#include "lemon/backends/backend_descriptor.h"
#include "lemon/external/backend_manifest.h"
#include "lemon/external/token_engine.h"
#include "lemon/server_capabilities.h"
#include "lemon/wrapped_server.h"

namespace lemon {

// A manifest-backed external backend. One instance per load; it launches the
// recipe's platform command as a subprocess, health-probes it, and proxies the
// fixed Lemonade routes onto it. Capability gating is per route, driven by the
// manifest's declared capability set.
class ExternalBackendServer : public WrappedServer,
                              public IEmbeddingsServer,
                              public IRerankingServer,
                              public ITranscriptionServer,
                              public IStreamingTranscriptionServer,
                              public ITextToSpeechServer,
                              public IClassificationServer,
                              public IImageServer,
                              public IAudioGenerationServer,
                              public IModel3DServer,
                              public ISlotsServer,
                              public ITokenizerServer {
public:
    ExternalBackendServer(const std::string& recipe,
                          const std::string& log_level,
                          ModelManager* model_manager,
                          BackendManager* backend_manager);
    ~ExternalBackendServer() override;

    void set_manifest(std::shared_ptr<const external::BackendManifest> manifest) {
        manifest_ = std::move(manifest);
    }

    void load(const std::string& model_name,
              const ModelInfo& model_info,
              const RecipeOptions& options,
              bool do_not_upgrade = false) override;
    void unload() override;
    bool wait_for_ready(const std::string& endpoint,
                        long timeout_seconds = 600,
                        long poll_interval_ms = 100) override;
    bool downsize() override;
    void restore() override;

    bool has_capability(const std::string& cap_name) const override;
    DeviceType effective_device(const RecipeOptions& options) const override;
    SlotPolicy effective_slot_policy(const RecipeOptions& options) const override;

    json chat_completion(const json& request) override;
    json completion(const json& request) override;
    json responses(const json& request) override;
    json embeddings(const json& request) override;
    json reranking(const json& request) override;
    json audio_transcriptions(const json& request) override;
    std::string get_streaming_address() override;
    void audio_speech(const json& request, httplib::DataSink& sink) override;
    json classify(const json& request) override;
    json image_generations(const json& request) override;
    json image_edits(const json& request) override;
    json image_variations(const json& request) override;
    void audio_generations(const json& request, httplib::DataSink& sink) override;
    void model_3d_generations(const json& request, httplib::DataSink& sink) override;
    json get_slots() override;
    json slots_action(int slot_id, const std::string& action, const json& request_body) override;
    json tokenize(const json& request_body) override;

private:
    std::string endpoint_for(const std::string& capability, const std::string& fallback) const;
    bool perform_health_probe(const external::HealthProbe& probe);
    bool select_platform_block(const RecipeOptions& options, external::ExecBlock& out, std::string& error);

    std::shared_ptr<const external::BackendManifest> manifest_;
    std::string selected_platform_;
    external::ExecBlock active_block_;
    external::TokenSources load_sources_;
    bool model_ready_ = false;
};

}  // namespace lemon
