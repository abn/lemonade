#pragma once

#include "lemon/backends/backend_registry.h"

#include "lemon/wrapped_server.h"
#include "lemon/server_capabilities.h"
#include "lemon/backends/backend_utils.h"
#include <string>
#include <filesystem>
#include <mutex>

namespace lemon {
namespace backends {

class WhisperServer : public WrappedServer, public ITranscriptionServer {
public:
    static InstallParams get_install_params(const std::string& backend, const std::string& version);


    explicit WhisperServer(const std::string& log_level,
                          ModelManager* model_manager,
                          BackendManager* backend_manager);

    ~WhisperServer() override;

    void load(const std::string& model_name,
             const ModelInfo& model_info,
             const RecipeOptions& options,
             bool do_not_upgrade = false) override;

    void unload() override;

    // Reuse the built-in argv construction against a variant_of fork binary.
    bool build_launch_plan(const ModelInfo& model_info,
                           const RecipeOptions& options,
                           int port,
                           LaunchPlan& out,
                           std::string& error) const override;

    // ICompletionServer implementation (not supported - return errors)
    json chat_completion(const json& request) override;
    json completion(const json& request) override;
    json responses(const json& request) override;

    // ITranscriptionServer implementation
    json audio_transcriptions(const json& request) override;

private:
    // whisper-server argv for a load, shared by load() and build_launch_plan().
    std::vector<std::string> build_server_args(const ModelInfo& model_info,
                                               const RecipeOptions& options,
                                               int port) const;

    // NPU compiled cache handling
    void download_npu_compiled_cache(const std::string& model_path,
                                      const ModelInfo& model_info,
                                      bool do_not_upgrade);

    // Audio file handling
    std::string save_audio_to_temp(const std::string& audio_data,
                                    const std::string& filename);
    void cleanup_temp_file(const std::string& path);
    void validate_audio_file(const std::string& path);

    // Build request for whisper-server
    json build_transcription_request(const json& request, bool translate = false);

    // Forward audio file using multipart form-data
    json forward_multipart_audio_request(const std::string& file_path,
                                         const json& params,
                                         bool translate);

    // Forward audio data directly (no file I/O) using multipart form-data
    json forward_multipart_audio_data(const std::string& audio_data,
                                      const std::string& filename,
                                      const json& params,
                                      bool translate);

    std::string model_path_;
    std::filesystem::path temp_dir_;  // Directory for temporary audio files
    std::mutex inference_mutex_;
};

namespace whispercpp {
// Factory for the whispercpp backend (constructs the server class — lemond only).
std::unique_ptr<WrappedServer> create(const BackendContext& ctx);
const BackendSpec* spec();
const BackendOps* ops();
constexpr uint32_t capabilities() { return capability_mask_of<WhisperServer>(); }
}  // namespace whispercpp
}  // namespace backends
}  // namespace lemon
