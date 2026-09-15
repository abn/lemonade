#include "lemon/external/backend_manifest.h"
#include "lemon/external/capability_registry.h"
#include "lemon/external/external_registry.h"
#include "lemon/external/token_engine.h"
#include "lemon/external/token_vocabulary.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using nlohmann::json;
using namespace lemon::external;

namespace {

int failures = 0;

void check(const char* name, bool condition) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}

const char* kPassthrough = R"MANIFEST({
  "recipe": "llamacpp-vulkan-custom",
  "display_name": "llama.cpp (Vulkan Custom)",
  "api_contract_version": "1",
  "capabilities": ["chat_completion", "completion"],
  "slot_policy": "standard",
  "health_probe": {"type": "http", "endpoint": "/health", "expected_status": 200,
                   "timeout_seconds": 60, "poll_interval_ms": 200},
  "platforms": {"linux": {"vulkan": {
    "command": "/opt/lemonade/bin/llama-server",
    "args": ["-m", "{checkpoint:main}", "--port", "{port}", "-c", "{ctx_size}"],
    "stop_command": "kill", "stop_command_args": ["-9", "{pid}"],
    "env": {"GGML_VK_VISIBLE_DEVICES": "{custom:vk_device:-0}"}
  }}}
})MANIFEST";

const char* kVariantOf = R"MANIFEST({
  "recipe": "llamacpp-rocm-nightly",
  "display_name": "llama.cpp ROCm Nightly",
  "api_contract_version": "1",
  "variant_of": "llamacpp",
  "capabilities": ["chat_completion", "completion", "embeddings"],
  "source": "https://example.invalid/llama.tgz",
  "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "platforms": {"linux": {"rocm": {
    "binary": "llama-server",
    "argv_extra": ["--gpu-layers", "{custom:gpu_layers:-0}"],
    "reserved_args": ["--port", "-m"]
  }}}
})MANIFEST";

json parse_or_die(const char* text) { return json::parse(text); }

bool parses(const char* text) {
    BackendManifest manifest;
    std::string error;
    return parse_backend_manifest(parse_or_die(text), manifest, error);
}

std::string parse_error_of(const char* text) {
    BackendManifest manifest;
    std::string error;
    parse_backend_manifest(parse_or_die(text), manifest, error);
    return error;
}

bool rejects_with(const char* text, const std::string& needle) {
    BackendManifest manifest;
    std::string error;
    if (parse_backend_manifest(parse_or_die(text), manifest, error)) return false;
    return error.find(needle) != std::string::npos;
}

void test_capability_registry() {
    check("known capability recognized", is_capability("chat_completion"));
    check("unknown capability rejected", !is_capability("telepathy"));
    check("audio_generation label mapping", capability_mode_label("audio_generation") == "audio-generation");
    check("model_3d label mapping", capability_mode_label("model_3d") == "3d");
    check("streaming_transcription is variant_of only",
          capability_info("streaming_transcription")->variant_of_only);
    check("plumbing capability has no mode", capability_mode_label("tokenize").empty());
    auto modes = deployment_modes_for_capabilities(
        {"chat_completion", "completion", "embeddings", "tokenize"});
    check("modes dedupe and skip plumbing",
          modes.size() == 2 && modes[0] == "chat" && modes[1] == "embeddings");
}

void test_token_vocabulary() {
    std::string error;
    check("fixed token accepted", validate_tokens_in_string("--port {port}", error));
    check("checkpoint token accepted", validate_tokens_in_string("{checkpoint:main}", error));
    check("custom default token accepted", validate_tokens_in_string("{custom:x:-0}", error));
    check("env token accepted", validate_tokens_in_string("{env:HOME}", error));
    check("unknown token rejected", !validate_tokens_in_string("{bogus}", error));
    check("empty token rejected", !validate_tokens_in_string("{}", error));
    check("unterminated token rejected", !validate_tokens_in_string("{port", error));
    check("nested token rejected", !validate_tokens_in_string("{a{b}}", error));
}

void test_parse_valid() {
    BackendManifest manifest;
    std::string error;
    bool ok = parse_backend_manifest(parse_or_die(kPassthrough), manifest, error);
    check("valid passthrough parses", ok);
    check("passthrough recipe captured", manifest.recipe == "llamacpp-vulkan-custom");
    check("passthrough platform captured", manifest.platforms.by_os["linux"].count("vulkan") == 1);

    BackendManifest variant;
    std::string variant_error;
    bool variant_ok = parse_backend_manifest(parse_or_die(kVariantOf), variant, variant_error);
    check("valid variant_of parses", variant_ok);
    check("variant_of provenance captured", variant.variant_of == "llamacpp" && !variant.sha256.empty());
    check("variant_of binary captured",
          variant.platforms.by_os["linux"]["rocm"].binary == "llama-server");
}

void test_parse_rejections() {
    check("unknown top-level field rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],"platforms":{"linux":{"cpu":
                            {"command":"x","args":[]}}},"bogus":1})", "unknown field"));
    check("unknown capability rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["telepathy"],"platforms":{"linux":{"cpu":
                            {"command":"x","args":[]}}}})", "unknown capability"));
    check("newer contract rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"2",
                            "capabilities":["completion"],"platforms":{"linux":{"cpu":
                            {"command":"x","args":[]}}}})", "unsupported api_contract_version"));
    check("extends+variant_of rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "extends":"base","variant_of":"llamacpp","capabilities":["completion"],
                            "platforms":{"linux":{"cpu":{"binary":"llama-server"}}}})",
                       "mutually exclusive"));
    check("source without variant_of rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],"source":"https://x/y.tgz",
                            "platforms":{"linux":{"cpu":{"command":"x","args":[]}}}})",
                       "only valid with 'variant_of'"));
    check("http source rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "variant_of":"llamacpp","source":"http://x/y.tgz",
                            "sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "capabilities":["completion"],
                            "platforms":{"linux":{"cpu":{"binary":"llama-server"}}}})",
                       "https://"));
    check("binary traversal rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "variant_of":"llamacpp",
                            "sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "capabilities":["completion"],
                            "platforms":{"linux":{"cpu":{"binary":"../evil"}}}})",
                       "bare executable"));
    check("requested_ports>1 rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],"requested_ports":2,
                            "platforms":{"linux":{"cpu":{"command":"x","args":[]}}}})",
                       "requested_ports"));
    check("missing required field rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1"})",
                       "missing required field"));
    check("unknown token rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],"platforms":{"linux":{"cpu":
                            {"command":"x","args":["{nope}"]}}}})", "unknown token"));
    check("passthrough binary rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],"platforms":{"linux":{"cpu":
                            {"binary":"llama-server"}}}})", "only valid with 'variant_of'"));
    check("enable args for undeclared capability rejected",
          rejects_with(R"({"recipe":"ok_recipe","display_name":"x","api_contract_version":"1",
                            "capabilities":["completion"],
                            "capability_enable_args":{"embeddings":["--e"]},
                            "platforms":{"linux":{"cpu":{"command":"x","args":[]}}}})",
                       "not a declared capability"));
}

void write_file(const fs::path& path, const std::string& content, int mode) {
    std::ofstream out(path);
    out << content;
    out.close();
#ifndef _WIN32
    ::chmod(path.c_str(), mode);
#else
    (void)mode;
#endif
}

std::string simple_manifest(const std::string& recipe, const std::string& display) {
    json doc = {
        {"recipe", recipe},
        {"display_name", display},
        {"api_contract_version", "1"},
        {"capabilities", json::array({"completion"})},
        {"platforms", {{"linux", {{"cpu", {{"command", "x"}, {"args", json::array()}}}}}}},
    };
    return doc.dump(2);
}

void test_extends_merge() {
#ifndef _WIN32
    std::string tpl = "/tmp/lemonade_ext_extends_XXXXXX";
    char* dir = mkdtemp(tpl.data());
    check("extends temp dir created", dir != nullptr);
    if (dir == nullptr) return;

    json base = {
        {"recipe", "base_ext"},
        {"display_name", "Base"},
        {"api_contract_version", "1"},
        {"capabilities", json::array({"completion"})},
        {"recipe_options", {{"threads", 4}, {"ctx_size", 2048}}},
        {"platforms", {{"linux", {{"cpu", {{"command", "x"}, {"args", json::array()}}}}}}},
    };
    json child = base;
    child["recipe"] = "child_ext";
    child["display_name"] = "Child";
    child["extends"] = "base_ext";
    child["recipe_options"] = {{"threads", 8}};

    write_file(std::string(dir) + "/base_ext.json", base.dump(2), 0600);
    write_file(std::string(dir) + "/child_ext.json", child.dump(2), 0600);

    DiscoveryPaths paths;
    paths.user_config.push_back(dir);
    ExternalRegistry::instance().refresh(paths);
    const BackendManifest* merged = ExternalRegistry::instance().manifest_for("child_ext");
    check("extends child discovered", merged != nullptr);
    if (merged != nullptr) {
        check("extends inherits base option", merged->recipe_options.value("ctx_size", 0) == 2048);
        check("extends child overrides base", merged->recipe_options.value("threads", 0) == 8);
    }

    // A missing base drops the child and records why.
    json orphan = child;
    orphan["recipe"] = "orphan_ext";
    orphan["extends"] = "does_not_exist";
    write_file(std::string(dir) + "/orphan_ext.json", orphan.dump(2), 0600);
    ExternalRegistry::instance().refresh(paths);
    check("orphan extends dropped",
          ExternalRegistry::instance().manifest_for("orphan_ext") == nullptr);

    fs::remove_all(dir);
#endif
}

void test_permission_checks() {
#ifndef _WIN32
    std::string template_path = "/tmp/lemonade_ext_reg_XXXXXX";
    char* dir = mkdtemp(template_path.data());
    check("temp dir created", dir != nullptr);
    if (dir == nullptr) return;

    std::string secure = std::string(dir) + "/secure.json";
    write_file(secure, simple_manifest("secure_recipe", "Secure"), 0600);
    std::string reason;
    check("0600 descriptor trusted", descriptor_path_is_trusted(secure, false, reason));

    std::string insecure = std::string(dir) + "/insecure.json";
    write_file(insecure, simple_manifest("insecure_recipe", "Insecure"), 0666);
    check("0666 descriptor rejected", !descriptor_path_is_trusted(insecure, false, reason));

    std::string link = std::string(dir) + "/link.json";
    fs::create_symlink(secure, link);
    check("symlinked descriptor rejected", !descriptor_path_is_trusted(link, false, reason));

    DiscoveryPaths paths;
    paths.user_config.push_back(dir);
    ExternalRegistry::instance().refresh(paths);
    check("registry discovers trusted descriptor",
          ExternalRegistry::instance().manifest_for("secure_recipe") != nullptr);
    check("registry does not discover world-writable descriptor",
          ExternalRegistry::instance().manifest_for("insecure_recipe") == nullptr);
    check("registry records a rejection reason",
          !ExternalRegistry::instance().rejected().empty());

    fs::remove_all(dir);
#endif
}

void test_token_engine() {
    TokenSources sources;
    sources.fixed["port"] = "8080";
    sources.fixed["checkpoint:main"] = "/models/x.gguf";
    sources.custom_option = [](const std::string& name, std::string& value) {
        if (name == "threads") { value = "8"; return true; }
        if (name == "evil") { value = "--oops"; return true; }
        return false;
    };
    sources.env = [](const std::string& name, std::string& value) {
        if (name == "HF_HOME") { value = "/hf"; return true; }
        return false;
    };

    std::string out;
    std::string error;
    check("resolve fixed token", resolve_template("--port {port}", sources, out, error) && out == "--port 8080");
    check("resolve checkpoint token", resolve_template("{checkpoint:main}", sources, out, error) && out == "/models/x.gguf");
    check("resolve custom token", resolve_template("{custom:threads}", sources, out, error) && out == "8");
    check("resolve custom default", resolve_template("{custom:missing:-4}", sources, out, error) && out == "4");
    check("unresolved custom errors", !resolve_template("{custom:missing}", sources, out, error));
    check("env allowlisted resolves", resolve_template("{env:HF_HOME}", sources, out, error) && out == "/hf");
    check("env secret-shaped rejected", !resolve_template("{env:LEMONADE_API_KEY}", sources, out, error));
    check("env unset default resolves",
          resolve_template("{env:SSL_CERT_FILE:-/etc/ssl/cert.pem}", sources, out, error) &&
              out == "/etc/ssl/cert.pem");
    check("negative default allowed",
          resolve_template("{custom:missing:--1}", sources, out, error) && out == "-1");
    check("leading-dash token rejected", !resolve_template("{custom:evil}", sources, out, error));

    TokenSources args;
    args.custom_args = {"--foo", "bar"};
    args.reserved_args = {"--port"};
    std::vector<std::string> argv;
    check("custom_args expands to multiple",
          resolve_args({"--x", "{custom_args}"}, args, argv, error) && argv.size() == 3);
    args.custom_args = {"--port", "1"};
    check("reserved custom arg rejected", !resolve_args({"{custom_args}"}, args, argv, error));
    check("is_negative_number", is_negative_number("-12") && is_negative_number("-1.5") &&
                                    !is_negative_number("-x"));
}

void test_discovery_priority_and_reserved() {
#ifndef _WIN32
    std::string tpl_cfg = "/tmp/lemonade_ext_cfg_XXXXXX";
    std::string tpl_cache = "/tmp/lemonade_ext_cache_XXXXXX";
    char* cfg = mkdtemp(tpl_cfg.data());
    char* cache = mkdtemp(tpl_cache.data());
    check("discovery temp dirs created", cfg != nullptr && cache != nullptr);
    if (cfg == nullptr || cache == nullptr) return;

    write_file(std::string(cfg) + "/dup.json", simple_manifest("dup_recipe", "From Config"), 0600);
    write_file(std::string(cache) + "/dup.json", simple_manifest("dup_recipe", "From Cache"), 0600);
    write_file(std::string(cache) + "/reserved.json", simple_manifest("builtin_recipe", "Reserved"), 0600);
    write_file(std::string(cache) + "/fresh.json", simple_manifest("fresh_recipe", "Fresh"), 0600);

    DiscoveryPaths paths;
    paths.user_config.push_back(cfg);
    paths.user_cache.push_back(cache);

    auto is_reserved = [](const std::string& recipe) { return recipe == "builtin_recipe"; };
    ExternalRegistry::instance().refresh(paths, is_reserved);

    const BackendManifest* dup = ExternalRegistry::instance().manifest_for("dup_recipe");
    check("higher-priority path wins duplicate", dup != nullptr && dup->display_name == "From Config");
    check("reserved recipe rejected",
          ExternalRegistry::instance().manifest_for("builtin_recipe") == nullptr);
    check("distinct recipe discovered",
          ExternalRegistry::instance().manifest_for("fresh_recipe") != nullptr);

    fs::remove_all(cfg);
    fs::remove_all(cache);
#endif
}

}  // namespace

int main() {
    std::printf("=== external backend manifest + registry tests ===\n");
    test_capability_registry();
    test_token_vocabulary();
    test_parse_valid();
    test_parse_rejections();
    test_token_engine();
    test_extends_merge();
    test_permission_checks();
    test_discovery_priority_and_reserved();
    std::printf("=== %d failure(s) ===\n", failures);
    return failures == 0 ? 0 : 1;
}
