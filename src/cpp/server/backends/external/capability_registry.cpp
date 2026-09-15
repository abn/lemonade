#include "lemon/external/capability_registry.h"

#include <algorithm>

namespace lemon {
namespace external {

// Route strings are documentation; the routing layer keys on the capability
// name and mode, not on a parsed route. Keep them accurate to server.cpp.
static const std::vector<CapabilityInfo>& registry() {
    static const std::vector<CapabilityInfo> kRegistry = {
        {"chat_completion", "chat", "POST /v1/chat/completions", CapabilityKind::Core, true, false},
        {"completion", "chat", "POST /v1/completions", CapabilityKind::Core, true, false},
        {"embeddings", "embeddings", "POST /v1/embeddings", CapabilityKind::Core, true, false},
        {"reranking", "reranking", "POST /v1/rerank", CapabilityKind::Core, true, false},
        {"transcription", "transcription", "POST /v1/audio/transcriptions", CapabilityKind::Core, true, false},
        {"image", "image", "POST /v1/images/generations", CapabilityKind::Core, true, false},
        {"tts", "tts", "POST /v1/audio/speech", CapabilityKind::Core, true, false},
        {"responses", "chat", "POST /v1/responses", CapabilityKind::Extension, true, false},
        {"streaming_transcription", "transcription", "Realtime WS /realtime", CapabilityKind::Extension, true, true},
        {"classification", "classification", "POST /v1/classify", CapabilityKind::Extension, true, false},
        {"audio_generation", "audio-generation", "POST /v1/audio/generations", CapabilityKind::Extension, true, false},
        {"model_3d", "3d", "POST /v1/3d/generations", CapabilityKind::Extension, true, false},
        {"slots", "", "GET /v1/slots, POST /v1/slots/{id}", CapabilityKind::Plumbing, false, false},
        {"tokenize", "", "POST /v1/tokenize", CapabilityKind::Plumbing, false, false},
    };
    return kRegistry;
}

const std::vector<CapabilityInfo>& all_capabilities() { return registry(); }

const CapabilityInfo* capability_info(const std::string& name) {
    for (const auto& info : registry()) {
        if (name == info.name) return &info;
    }
    return nullptr;
}

bool is_capability(const std::string& name) { return capability_info(name) != nullptr; }

std::string capability_mode_label(const std::string& name) {
    const CapabilityInfo* info = capability_info(name);
    return info ? std::string(info->mode_label) : std::string();
}

std::vector<std::string> deployment_modes_for_capabilities(
    const std::vector<std::string>& capabilities) {
    std::vector<std::string> modes;
    for (const auto& name : capabilities) {
        const CapabilityInfo* info = capability_info(name);
        if (info == nullptr || !info->has_mode) continue;
        const std::string label(info->mode_label);
        if (std::find(modes.begin(), modes.end(), label) == modes.end()) {
            modes.push_back(label);
        }
    }
    return modes;
}

}  // namespace external
}  // namespace lemon
