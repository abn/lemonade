#include "lemon/backends/external/external_backend_server.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <thread>

#include "lemon/external/capability_registry.h"
#include "lemon/external/external_installer.h"
#include "lemon/external/external_registry.h"
#include "lemon/backends/backend_registry.h"
#include "lemon/system_info.h"
#include "lemon/utils/aixlog.hpp"
#include "lemon/utils/custom_args.h"
#include "lemon/utils/http_client.h"
#include "lemon/utils/network_utils.h"
#include "lemon/utils/path_utils.h"
#include "lemon/utils/process_manager.h"

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

namespace lemon {

namespace fs = std::filesystem;
using namespace external;

namespace {

std::string to_posix_path(const std::string& path) {
    std::string result = path;
    std::replace(result.begin(), result.end(), '\\', '/');
    return result;
}

// A one-shot status probe so the manifest's expected_status is honored
// (HttpClient::is_reachable hardcodes 200). A refused connection during
// startup is a "not ready yet", not an error.
bool http_status_matches(const std::string& url, int expected) {
    try {
        utils::HttpResponse response =
            utils::HttpClient::get(url, {}, 1, utils::HttpSecurityPolicy::TrustedLoopback);
        return response.status_code == expected;
    } catch (...) {
        return false;
    }
}

std::string option_string(const RecipeOptions& options, const std::string& key,
                          const std::string& fallback) {
    json value = options.get_option(key);
    if (value.is_null()) return fallback;
    if (value.is_string()) return value.get<std::string>();
    if (value.is_number_integer()) return std::to_string(value.get<int>());
    if (value.is_number_float()) return std::to_string(value.get<double>());
    if (value.is_boolean()) return value.get<bool>() ? "true" : "false";
    return value.dump();
}

bool safe_relative(const fs::path& relative) {
    if (relative.empty() || relative.is_absolute()) return false;
    if (relative.begin() != relative.end() && *relative.begin() == "..") return false;
    return true;
}

std::string relative_to_cache(const std::string& path, const std::string& cache_root) {
    if (path.empty()) return "";
    fs::path relative = fs::path(path).lexically_relative(fs::path(cache_root));
    if (safe_relative(relative)) return to_posix_path(relative.string());
    return to_posix_path(fs::path(path).filename().string());
}

}  // namespace

ExternalBackendServer::ExternalBackendServer(const std::string& recipe,
                                             const std::string& log_level,
                                             ModelManager* model_manager,
                                             BackendManager* backend_manager)
    : WrappedServer(recipe, log_level, model_manager, backend_manager) {}

ExternalBackendServer::~ExternalBackendServer() {
    try {
        unload();
    } catch (...) {
    }
}

bool ExternalBackendServer::has_capability(const std::string& cap_name) const {
    if (manifest_ == nullptr || manifest_->capabilities.empty()) return true;
    return std::find(manifest_->capabilities.begin(), manifest_->capabilities.end(), cap_name) !=
           manifest_->capabilities.end();
}

DeviceType ExternalBackendServer::effective_device(const RecipeOptions& options) const {
    (void)options;
    if (manifest_ != nullptr) {
        if (manifest_->default_accelerator == "cpu") return DEVICE_CPU;
        if (manifest_->default_accelerator == "npu") return DEVICE_NPU;
        if (!manifest_->default_accelerator.empty()) return DEVICE_GPU;
    }
    return DEVICE_GPU;
}

SlotPolicy ExternalBackendServer::effective_slot_policy(const RecipeOptions& options) const {
    (void)options;
    if (manifest_ == nullptr) return SlotPolicy::Standard;
    if (manifest_->slot_policy == "exclusive_npu") return SlotPolicy::ExclusiveNpu;
    if (manifest_->slot_policy == "coexist_by_type") return SlotPolicy::CoexistByType;
    if (manifest_->slot_policy == "unmetered") return SlotPolicy::Unmetered;
    return SlotPolicy::Standard;
}

bool ExternalBackendServer::select_platform_block(const RecipeOptions& options,
                                                  ExecBlock& out,
                                                  std::string& error) {
    const std::string os = host_os_name();
    auto os_it = manifest_->platforms.by_os.find(os);
    if (os_it == manifest_->platforms.by_os.end()) {
        error = "manifest has no platform block for host OS '" + os + "'";
        return false;
    }
    const auto& accelerators = os_it->second;

    std::string requested = option_string(options, "device", "");
    std::transform(requested.begin(), requested.end(), requested.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::string accelerator;
    if (accelerators.count(requested) > 0) {
        accelerator = requested;
    } else if (!manifest_->default_accelerator.empty() &&
               accelerators.count(manifest_->default_accelerator) > 0) {
        accelerator = manifest_->default_accelerator;
    } else {
#ifdef __APPLE__
        if (accelerators.count("metal") > 0) {
            accelerator = "metal";
        } else
#endif
        {
            const std::string cuda_arch = SystemInfo::get_cuda_arch();
            const std::string rocm_arch = SystemInfo::get_rocm_arch();
            if (!cuda_arch.empty() && accelerators.count("cuda") > 0) {
                accelerator = "cuda";
            } else if (!rocm_arch.empty() && accelerators.count("rocm") > 0) {
                accelerator = "rocm";
            } else if (accelerators.count("vulkan") > 0) {
                accelerator = "vulkan";
            } else if (accelerators.count("gpu") > 0) {
                accelerator = "gpu";
            } else if (accelerators.count("cpu") > 0) {
                accelerator = "cpu";
            } else {
                accelerator = accelerators.begin()->first;
            }
        }
    }

    selected_platform_ = os + "." + accelerator;
    out = accelerators.at(accelerator);
    if (out.command.empty() && out.binary.empty()) {
        error = "selected platform block '" + selected_platform_ + "' has no command";
        return false;
    }
    return true;
}

void ExternalBackendServer::load(const std::string& model_name,
                                 const ModelInfo& model_info,
                                 const RecipeOptions& options,
                                 bool do_not_upgrade) {
    (void)do_not_upgrade;

    if (manifest_ == nullptr) {
        manifest_ = ExternalRegistry::instance().manifest_for(model_info.recipe);
    }
    if (manifest_ == nullptr) {
        throw std::runtime_error("no external manifest registered for recipe '" +
                                 model_info.recipe + "'");
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if ((state_ == ModelState::READY || state_ == ModelState::IN_USE) && is_backend_alive()) {
            return;
        }
        state_ = ModelState::LOADING;
        state_cv_.notify_all();
    }

    struct LoadGuard {
        ExternalBackendServer* server;
        bool success = false;
        ~LoadGuard() noexcept {
            if (!success) {
                try {
                    server->unload();
                } catch (...) {
                }
            }
        }
    } guard{this, false};

    std::string selection_error;
    ExecBlock block;
    if (!select_platform_block(options, block, selection_error)) {
        throw std::invalid_argument("recipe '" + manifest_->recipe + "': " + selection_error);
    }
    const std::string detected_arch = SystemInfo::get_rocm_arch().empty()
                                          ? SystemInfo::get_cuda_arch()
                                          : SystemInfo::get_rocm_arch();
    block = resolve_arch_block(block, detected_arch);
    active_block_ = block;

    port_ = choose_port();
    DeviceType device = effective_device(options);
    set_model_metadata(model_name, model_info.checkpoint("main"), model_info.type, device, options);

    TokenSources sources;
    sources.fixed["port"] = std::to_string(port_);
    sources.fixed["host"] = "127.0.0.1";
    sources.fixed["log_level"] = log_level_;
    sources.fixed["recipe"] = manifest_->recipe;
    sources.fixed["model_name"] = model_name_;

    const std::string cache_root = utils::get_hf_cache_dir();
    std::string main_path = model_info.resolved_path("main");
    if (main_path.empty()) main_path = model_info.checkpoint("main");
    sources.fixed["resolved_path"] = main_path;
    sources.fixed["model_dir"] = main_path.empty()
                                     ? "."
                                     : to_posix_path(fs::path(main_path).parent_path().string());
    sources.fixed["exe_dir"] = block.command.empty()
                                   ? "."
                                   : to_posix_path(fs::path(block.command).parent_path().string());
    sources.fixed["hf_cache"] = to_posix_path(cache_root);
    sources.fixed["cache_dir"] = to_posix_path(utils::get_cache_dir());
    sources.fixed["model_relative_path"] = relative_to_cache(main_path, cache_root);

    for (const auto& [key, value] : model_info.checkpoints) {
        std::string resolved = model_info.resolved_path(key);
        if (resolved.empty()) resolved = value;
        sources.fixed["checkpoint:" + key] = resolved;
        sources.fixed["checkpoint_relative:" + key] = relative_to_cache(resolved, cache_root);
    }

    sources.fixed["ctx_size"] = option_string(options, "ctx_size", "2048");
    sources.fixed["batch_size"] = option_string(options, "batch_size", "512");
    sources.fixed["ubatch_size"] = option_string(options, "ubatch_size", "512");
    sources.fixed["threads"] = option_string(options, "threads", "4");
    sources.fixed["cache_type_k"] = option_string(options, "cache_type_k", "f16");
    sources.fixed["cache_type_v"] = option_string(options, "cache_type_v", "f16");
    const std::string gpu_id = option_string(options, "gpu_id", "0");
    sources.fixed["target_device"] = option_string(options, "target_device", gpu_id);
    sources.fixed["cuda_visible_devices"] = option_string(options, "cuda_visible_devices", gpu_id);
    sources.fixed["hip_visible_devices"] = option_string(options, "hip_visible_devices", gpu_id);
    sources.fixed["rocr_visible_devices"] = option_string(options, "rocr_visible_devices", gpu_id);
    sources.fixed["ggml_vk_visible_devices"] = option_string(options, "ggml_vk_visible_devices", gpu_id);
    sources.fixed["ze_affinity_mask"] = option_string(options, "ze_affinity_mask", gpu_id);
    sources.fixed["rocm_arch"] = SystemInfo::get_rocm_arch();
    sources.fixed["cuda_arch"] = SystemInfo::get_cuda_arch();
    {
        const std::string alias = arch_alias_for(manifest_->arch_aliases, detected_arch);
        if (!alias.empty()) sources.fixed["arch_alias"] = alias;
    }

    sources.custom_option = [options](const std::string& name, std::string& value) {
        json option = options.get_option(name);
        if (option.is_null()) return false;
        value = option.is_string() ? option.get<std::string>() : option.dump();
        return true;
    };
    sources.env = [](const std::string& name, std::string& value) {
        const char* env_value = std::getenv(name.c_str());
        if (env_value != nullptr && env_value[0] != '\0') {
            value = env_value;
            return true;
        }
        return false;
    };
    sources.reserved_args.insert(manifest_->reserved_args.begin(), manifest_->reserved_args.end());
    sources.reserved_args.insert(block.reserved_args.begin(), block.reserved_args.end());

    json custom_args_option = options.get_option("args");
    if (!custom_args_option.is_null()) {
        if (custom_args_option.is_array()) {
            for (const auto& item : custom_args_option) {
                sources.custom_args.push_back(item.is_string() ? item.get<std::string>() : item.dump());
            }
        } else {
            const std::string raw = custom_args_option.is_string()
                                        ? custom_args_option.get<std::string>()
                                        : custom_args_option.dump();
            sources.custom_args = utils::parse_custom_args(raw);
        }
    }

    std::string spawn_command;
    std::string working_dir;
    std::vector<std::string> final_args;
    std::string resolve_error;
    if (!resolve_template(block.command, sources, spawn_command, resolve_error)) {
        throw std::invalid_argument("recipe '" + manifest_->recipe + "': command: " + resolve_error);
    }
    if (!resolve_template(block.working_dir, sources, working_dir, resolve_error)) {
        throw std::invalid_argument("recipe '" + manifest_->recipe + "': working_dir: " + resolve_error);
    }
    std::map<std::string, std::string> env_map;
    if (!resolve_env_block(block.env, sources, env_map, resolve_error)) {
        throw std::invalid_argument("recipe '" + manifest_->recipe + "': " + resolve_error);
    }
    std::vector<std::pair<std::string, std::string>> env_vec(env_map.begin(), env_map.end());

    if (manifest_->is_variant_of()) {
        backends::BackendContext base_ctx;
        base_ctx.log_level = log_level_;
        base_ctx.model_manager = model_manager_;
        base_ctx.backend_manager = backend_manager_;
        base_ctx.model_info = &model_info;
        // variant_of must name a built-in backend. The registry only knows
        // external manifests, so an external recipe named here is caught
        // explicitly before create_server would hand back an external server.
        // Keep this list in step with the built-ins that override build_launch_plan.
        const std::string supported = "supported bases: llamacpp, whispercpp, sd-cpp";
        if (ExternalRegistry::instance().manifest_for(manifest_->variant_of) != nullptr) {
            throw std::invalid_argument("recipe '" + manifest_->recipe +
                                        "': variant_of must name a built-in backend; '" +
                                        manifest_->variant_of + "' is an external recipe (" +
                                        supported + ")");
        }
        auto base = backends::create_server(manifest_->variant_of, base_ctx);
        if (!base) {
            throw std::invalid_argument("recipe '" + manifest_->recipe + "': variant_of base '" +
                                        manifest_->variant_of + "' is not a built-in backend (" +
                                        supported + ")");
        }
        LaunchPlan plan;
        std::string plan_error;
        if (!base->build_launch_plan(model_info, options, port_, plan, plan_error)) {
            throw std::invalid_argument("recipe '" + manifest_->recipe + "': built-in '" +
                                        manifest_->variant_of +
                                        "' does not expose a launch plan yet; " + plan_error +
                                        " (" + supported + ")");
        }
        const std::string binary_name = block.binary.empty()
                                            ? fs::path(plan.executable).filename().string()
                                            : block.binary;
        const std::string external_path = resolve_installed_binary(manifest_->recipe, binary_name);
        if (external_path.empty()) {
            throw std::invalid_argument(
                "recipe '" + manifest_->recipe + "': binary is not installed. Run `lemonade backends " +
                "install-external " + manifest_->recipe + "` first.");
        }
        spawn_command = external_path;
#ifndef _WIN32
        // A fork ships its own shared libraries beside the binary.
        env_vec.emplace_back("LD_LIBRARY_PATH", fs::path(external_path).parent_path().string());
#endif
        final_args = plan.args;
        working_dir = plan.working_dir;
        for (const auto& [key, value] : plan.env) env_vec.emplace_back(key, value);

        std::vector<std::string> argv_extra;
        if (!resolve_args(block.argv_extra, sources, argv_extra, resolve_error)) {
            throw std::invalid_argument("recipe '" + manifest_->recipe + "': " + resolve_error);
        }
        final_args.insert(final_args.end(), argv_extra.begin(), argv_extra.end());
    } else if (!resolve_args(block.args, sources, final_args, resolve_error)) {
        throw std::invalid_argument("recipe '" + manifest_->recipe + "': " + resolve_error);
    }

    // A model deploys in exactly one mode, so enable args for every declared
    // capability that shares that mode are appended together.
    for (const auto& capability : manifest_->capabilities) {
        const CapabilityInfo* info = capability_info(capability);
        if (info == nullptr || !info->has_mode) continue;
        ModelType capability_mode = ModelType::LLM;
        if (!deployment_mode_of(info->mode_label, capability_mode)) continue;
        if (capability_mode != model_info.type) continue;
        auto enable = manifest_->capability_enable_args.find(capability);
        if (enable == manifest_->capability_enable_args.end()) continue;
        std::vector<std::string> enable_args;
        if (!resolve_args(enable->second, sources, enable_args, resolve_error)) {
            throw std::invalid_argument("recipe '" + manifest_->recipe +
                                        "': capability_enable_args." + capability + ": " +
                                        resolve_error);
        }
        final_args.insert(final_args.end(), enable_args.begin(), enable_args.end());
    }

    if (!block.stop_command.empty()) {
        std::vector<std::string> stop_args;
        std::string stop_error;
        if (resolve_args(block.stop_command_args, sources, stop_args, stop_error)) {
            std::vector<std::string> stop_command{block.stop_command};
            std::vector<std::string> resolved_stop;
            if (resolve_args(stop_command, sources, resolved_stop, stop_error) &&
                !resolved_stop.empty()) {
                std::string output;
                ProcessHandle handle = utils::ProcessManager::start_process(
                    resolved_stop[0], stop_args, "", false, false, env_vec);
                if (has_process_handle(handle)) {
                    utils::ProcessManager::wait_for_exit(handle, 15);
                    utils::ProcessManager::reap_process(handle);
                }
            }
        }
    }

    ProcessHandle handle = utils::ProcessManager::start_process(
        spawn_command, final_args, working_dir, true, true, env_vec);
    set_process_handle(handle, spawn_command, final_args);
    if (!utils::ProcessManager::is_running(handle)) {
        throw std::runtime_error("failed to spawn external backend '" + manifest_->recipe + "'");
    }

    if (has_process_handle(handle)) {
        sources.fixed["pid"] = std::to_string(handle.pid);
    }
    load_sources_ = sources;
    if (!perform_health_probe(manifest_->health_probe)) {
        throw std::runtime_error("health probe failed for external backend '" +
                                 manifest_->recipe + "'");
    }
    if (manifest_->health_probe.type == "http") {
        start_backend_watchdog(manifest_->health_probe.endpoint);
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        model_ready_ = true;
        state_ = ModelState::READY;
        state_cv_.notify_all();
    }
    guard.success = true;
}

bool ExternalBackendServer::perform_health_probe(const HealthProbe& probe) {
    const auto start = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(probe.timeout_seconds);
    const std::string url = "http://127.0.0.1:" + std::to_string(port_) + probe.endpoint;

    while (std::chrono::steady_clock::now() - start < timeout) {
        if (load_cancel_ != nullptr && load_cancel_->load(std::memory_order_relaxed)) {
            return false;
        }
        ProcessHandle handle = get_process_handle_snapshot();
        if (has_process_handle(handle) && !utils::ProcessManager::is_running(handle)) {
            LOG(ERROR, "ExternalBackendServer")
                << "subprocess for '" << manifest_->recipe << "' died during health probe";
            return false;
        }

        if (probe.type == "process") {
            return true;
        }
        if (probe.type == "tcp") {
            if (utils::is_tcp_listener_active(AF_INET, "127.0.0.1", port_)) return true;
        } else if (http_status_matches(url, probe.expected_status)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(probe.poll_interval_ms));
    }
    return false;
}

bool ExternalBackendServer::wait_for_ready(const std::string& endpoint,
                                           long timeout_seconds,
                                           long poll_interval_ms) {
    (void)endpoint;
    (void)poll_interval_ms;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        ModelState current = get_state();
        if (current == ModelState::READY || current == ModelState::IN_USE) return true;
        if (current == ModelState::UNLOADED) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void ExternalBackendServer::unload() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (state_ == ModelState::UNLOADED) return;
        state_ = ModelState::UNLOADED;
        state_cv_.notify_all();
    }

    stop_backend_watchdog();
    model_ready_ = false;

    if (!active_block_.stop_command.empty()) {
        std::string error;
        std::vector<std::string> stop_args;
        if (resolve_args(active_block_.stop_command_args, load_sources_, stop_args, error)) {
            std::vector<std::string> stop_command{active_block_.stop_command};
            std::vector<std::string> resolved_stop;
            if (resolve_args(stop_command, load_sources_, resolved_stop, error) &&
                !resolved_stop.empty()) {
                try {
                    ProcessHandle handle = utils::ProcessManager::start_process(
                        resolved_stop[0], stop_args, "", false, false, {});
                    if (has_process_handle(handle)) {
                        utils::ProcessManager::wait_for_exit(handle, 15);
                        utils::ProcessManager::reap_process(handle);
                    }
                } catch (const std::exception& e) {
                    LOG(WARNING, "ExternalBackendServer")
                        << "stop command failed for '" << (manifest_ ? manifest_->recipe : "")
                        << "': " << e.what();
                }
            }
        }
    }

    try {
        ProcessHandle handle = consume_process_handle_for_cleanup();
        if (has_process_handle(handle)) {
            utils::ProcessManager::stop_process(handle);
        }
    } catch (const std::exception& e) {
        LOG(WARNING, "ExternalBackendServer") << "process cleanup failed: " << e.what();
    }
}

std::string ExternalBackendServer::endpoint_for(const std::string& capability,
                                                const std::string& fallback) const {
    if (manifest_ != nullptr) {
        auto it = manifest_->endpoints.find(capability);
        if (it != manifest_->endpoints.end() && !it->second.empty()) return it->second;
    }
    return fallback;
}

json ExternalBackendServer::chat_completion(const json& request) {
    return forward_request(endpoint_for("chat_completion", "/v1/chat/completions"), request);
}

json ExternalBackendServer::completion(const json& request) {
    return forward_request(endpoint_for("completion", "/v1/completions"), request);
}

json ExternalBackendServer::responses(const json& request) {
    return forward_request(endpoint_for("responses", "/v1/responses"), request);
}

json ExternalBackendServer::embeddings(const json& request) {
    return forward_request(endpoint_for("embeddings", "/v1/embeddings"), request);
}

json ExternalBackendServer::reranking(const json& request) {
    return forward_request(endpoint_for("reranking", "/v1/rerank"), request);
}

json ExternalBackendServer::audio_transcriptions(const json& request) {
    return forward_request(endpoint_for("transcription", "/v1/audio/transcriptions"), request);
}

std::string ExternalBackendServer::get_streaming_address() {
    return "tcp://127.0.0.1:" + std::to_string(port_);
}

void ExternalBackendServer::audio_speech(const json& request, httplib::DataSink& sink) {
    forward_streaming_request(endpoint_for("tts", "/v1/audio/speech"), request.dump(), sink, false);
}

json ExternalBackendServer::classify(const json& request) {
    return forward_request(endpoint_for("classification", "/v1/classify"), request);
}

json ExternalBackendServer::image_generations(const json& request) {
    return forward_request(endpoint_for("image", "/v1/images/generations"), request);
}

json ExternalBackendServer::image_edits(const json& request) {
    return forward_request(endpoint_for("image", "/v1/images/edits"), request);
}

json ExternalBackendServer::image_variations(const json& request) {
    return forward_request(endpoint_for("image", "/v1/images/variations"), request);
}

void ExternalBackendServer::audio_generations(const json& request, httplib::DataSink& sink) {
    forward_streaming_request(endpoint_for("audio_generation", "/v1/audio/generations"),
                              request.dump(), sink, false);
}

void ExternalBackendServer::model_3d_generations(const json& request, httplib::DataSink& sink) {
    forward_streaming_request(endpoint_for("model_3d", "/v1/3d/generations"), request.dump(), sink,
                              false);
}

json ExternalBackendServer::get_slots() {
    return forward_get_request(endpoint_for("slots", "/v1/slots"));
}

json ExternalBackendServer::slots_action(int slot_id, const std::string& action,
                                         const json& request_body) {
    const std::string base = endpoint_for("slots", "/v1/slots");
    return forward_request(base + "/" + std::to_string(slot_id) + "?action=" + action, request_body);
}

json ExternalBackendServer::tokenize(const json& request_body) {
    return forward_request(endpoint_for("tokenize", "/v1/tokenize"), request_body);
}

bool ExternalBackendServer::downsize() {
    if (manifest_ == nullptr || manifest_->downsize_endpoint.empty()) {
        return true;
    }
    try {
        json response = forward_request(manifest_->downsize_endpoint, json::object());
        return !response.contains("error");
    } catch (...) {
        return false;
    }
}

void ExternalBackendServer::restore() {}

}  // namespace lemon
