#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "lemon/sandbox/env_scrubber.h"
#include "lemon/sandbox/sandbox_engine.h"
#include "lemon/sandbox/sandbox_policy.h"
#include "lemon/utils/process_manager.h"
#include "lemon/utils/process_platform.h"

namespace fs = std::filesystem;
using lemon::sandbox::EnvScrubber;
using lemon::sandbox::NetworkAccess;
using lemon::sandbox::PolicyPresets;
using lemon::sandbox::SandboxEngine;
using lemon::sandbox::SandboxMode;
using lemon::sandbox::SandboxPolicy;
using lemon::utils::ProcessHandle;
using lemon::utils::ProcessManager;

// Thread-safe assertion and results tracker
struct TestResult {
    std::atomic<int> passed{0};
    std::atomic<int> failed{0};
    std::vector<std::string> failure_logs;
    std::mutex log_mtx;

    void check(bool cond, const std::string& name, const std::string& details = "") {
        if (cond) {
            std::printf("  [PASS] %s\n", name.c_str());
            ++passed;
        } else {
            std::printf("  [FAIL] %s\n", name.c_str());
            if (!details.empty()) {
                std::printf("         Details: %s\n", details.c_str());
            }
            std::lock_guard<std::mutex> lock(log_mtx);
            failure_logs.push_back(name + (details.empty() ? "" : " -- " + details));
            ++failed;
        }
    }

    void report_summary(const std::string& suite_name) const {
        std::printf("-> Summary for '%s': %d passed, %d failed\n\n",
                    suite_name.c_str(), passed.load(), failed.load());
    }
};

// Fixture providing isolated temp directories for process output and canary dumping
class TestFixture {
public:
    TestFixture() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        temp_dir_ = fs::temp_directory_path() / ("lemonade_test_scrub_" + std::to_string(now));
        fs::create_directories(temp_dir_);
        try {
            temp_dir_ = fs::canonical(temp_dir_);
        } catch (...) {}
    }

    ~TestFixture() {
        std::error_code ec;
        fs::remove_all(temp_dir_, ec);
    }

    fs::path temp_dir() const { return temp_dir_; }
    fs::path create_subpath(const std::string& name) {
        fs::path p = temp_dir_ / name;
        fs::create_directories(p.parent_path());
        return p;
    }

private:
    fs::path temp_dir_;
};

// Helper to read all lines from a file
static std::string read_file_content(const fs::path& p) {
    if (!fs::exists(p)) return "";
    std::ifstream ifs(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
}

// Helper to parse key=value lines into a map
static std::unordered_map<std::string, std::string> parse_env_lines(const std::string& content) {
    std::unordered_map<std::string, std::string> env_map;
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) {
            std::string k = line.substr(0, eq);
            std::string v = line.substr(eq + 1);
            env_map[k] = v;
        }
    }
    return env_map;
}

int main() {
    std::printf("===================================================================\n");
    std::printf("  ENVIRONMENT SCRUBBING & CONFINEMENT TEST SUITE                   \n");
    std::printf("===================================================================\n\n");

    TestResult overall;
    TestFixture fixture;

    // =========================================================================
    // SUITE 1: Ambient Secret Injection & Zero Leakage Verification
    // =========================================================================
    std::printf("--- SUITE 1: Ambient Secret Poisoning & Zero Leakage Verification ---\n");
    {
        TestResult r;

#ifndef _WIN32
        // Construct a huge dictionary of 60+ sensitive ambient variables
        struct SecretEntry {
            std::string key;
            std::string canary_value;
            std::string category;
        };

        std::vector<SecretEntry> poison_secrets = {
            // 1. LEMONADE_ prefix keys
            {"LEMONADE_ADMIN_API_KEY", "canary_admin_key_999888777", "LEMONADE_ prefix"},
            {"LEMONADE_API_KEY", "canary_user_api_key_111222333", "LEMONADE_ prefix"},
            {"LEMONADE_ROUTER_TOKEN", "canary_router_secret_aaaabbbb", "LEMONADE_ prefix"},
            {"LEMONADE_SESSION_COOKIE", "canary_cookie_deadbeef", "LEMONADE_ prefix"},
            {"LEMONADE_INTERNAL_KEY", "canary_internal_pass_123", "LEMONADE_ prefix"},
            {"LEMONADE_CLOUD_AUTH_BEARER", "canary_cloud_bearer_token", "LEMONADE_ prefix"},

            // 2. AWS_ prefix keys
            {"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE_CANARY", "AWS_ prefix"},
            {"AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_CANARY", "AWS_ prefix"},
            {"AWS_SESSION_TOKEN", "AQoDYXdzEJr111111111111111EXAMPLE_CANARY", "AWS_ prefix"},
            {"AWS_SECURITY_TOKEN", "AQoDYXdzEJr2222222222222EXAMPLE_CANARY", "AWS_ prefix"},

            // 3. AZURE_ prefix keys
            {"AZURE_CLIENT_SECRET", "azure_sec_canary_333444555", "AZURE_ prefix"},
            {"AZURE_TENANT_ID", "azure_tenant_canary_666777888", "AZURE_ prefix"},
            {"AZURE_CLIENT_ID", "azure_client_id_canary_999", "AZURE_ prefix"},
            {"AZURE_OPENAI_API_KEY", "azure_openai_canary_sk_123", "AZURE_ prefix"},

            // 4. Exact sensitive keys - LLM Providers
            {"OPENAI_API_KEY", "sk-proj-canary-openai-secret-token-12345", "Exact Provider"},
            {"ANTHROPIC_API_KEY", "sk-ant-canary-anthropic-key-67890", "Exact Provider"},
            {"FIREWORKS_API_KEY", "fw-canary-key-abcdef", "Exact Provider"},
            {"COHERE_API_KEY", "co-canary-key-123456", "Exact Provider"},
            {"CO_API_KEY", "co-short-canary-789012", "Exact Provider"},
            {"GROQ_API_KEY", "gsk_canary_groq_key_987654", "Exact Provider"},
            {"MISTRAL_API_KEY", "mis_canary_mistral_key_456789", "Exact Provider"},
            {"DEEPSEEK_API_KEY", "sk-deepseek-canary-321654", "Exact Provider"},
            {"GEMINI_API_KEY", "AIzaSyCanaryGeminiKey_123456789", "Exact Provider"},
            {"GOOGLE_API_KEY", "AIzaSyCanaryGoogleKey_987654321", "Exact Provider"},
            {"PALM_API_KEY", "AIzaSyCanaryPalmKey_abcdef", "Exact Provider"},
            {"XAI_API_KEY", "xai-canary-key-11223344", "Exact Provider"},
            {"TOGETHER_API_KEY", "together_canary_key_556677", "Exact Provider"},
            {"TOGETHERAI_API_KEY", "togetherai_canary_key_889900", "Exact Provider"},
            {"CEREBRAS_API_KEY", "csk-canary-cerebras-key-123", "Exact Provider"},
            {"PERPLEXITY_API_KEY", "pplx-canary-perplexity-key-456", "Exact Provider"},
            {"PPLX_API_KEY", "pplx-canary-short-key-789", "Exact Provider"},
            {"SAMBANOVA_API_KEY", "samba-canary-key-abc", "Exact Provider"},
            {"CHROMA_API_KEY", "chroma-canary-key-def", "Exact Provider"},
            {"CHROMA_SERVER_AUTH_CREDENTIALS", "chroma-auth-canary-ghi", "Exact Provider"},
            {"OPENROUTER_API_KEY", "sk-or-canary-openrouter-key-jkl", "Exact Provider"},
            {"VOYAGE_API_KEY", "voyage-canary-key-mno", "Exact Provider"},
            {"REPLICATE_API_TOKEN", "r8_canary_replicate_token_pqr", "Exact Provider"},
            {"ANYSCALE_API_KEY", "ese_canary_anyscale_key_stu", "Exact Provider"},
            {"AI21_API_KEY", "ai21_canary_key_vwx", "Exact Provider"},
            {"OCTOAI_API_KEY", "octo_canary_key_yz0", "Exact Provider"},
            {"NOVITA_API_KEY", "novita_canary_key_123", "Exact Provider"},
            {"RUNPOD_API_KEY", "runpod_canary_key_456", "Exact Provider"},
            {"FAL_KEY", "fal_canary_key_789:abc", "Exact Provider"},
            {"CLOUDFLARE_API_TOKEN", "cf_canary_token_def", "Exact Provider"},

            // 5. Hugging Face & Model Hub keys
            {"HF_TOKEN", "hf_canary_secret_token_alpha", "HF Token"},
            {"HUGGING_FACE_HUB_TOKEN", "hf_hub_canary_token_beta", "HF Token"},
            {"HF_API_TOKEN", "hf_api_canary_token_gamma", "HF Token"},
            {"HUGGINGFACE_TOKEN", "hf_legacy_canary_token_delta", "HF Token"},
            {"HF_TOKEN_PATH", "/tmp/forbidden/hf_token_path_canary", "HF Token"},
            {"MODELSCOPE_API_TOKEN", "ms_canary_token_epsilon", "Hub Token"},
            {"KAGGLE_KEY", "kaggle_key_canary_zeta", "Hub Token"},
            {"KAGGLE_USERNAME", "kaggle_user_canary_eta", "Hub Token"},

            // 6. VCS, CI, and Tracking tokens
            {"GITHUB_TOKEN", "ghp_canary_github_personal_access_token_123", "VCS Token"},
            {"GH_TOKEN", "gho_canary_github_oauth_token_456", "VCS Token"},
            {"GITLAB_TOKEN", "glpat-canary_gitlab_token_789", "VCS Token"},
            {"BITBUCKET_TOKEN", "bb_canary_token_012", "VCS Token"},
            {"WANDB_API_KEY", "wandb_canary_key_345", "Tracking Token"},
            {"COMET_API_KEY", "comet_canary_key_678", "Tracking Token"},
            {"LANGCHAIN_API_KEY", "lsv2_canary_langchain_key_901", "Tracking Token"},
            {"LANGSMITH_API_KEY", "lsv2_canary_langsmith_key_234", "Tracking Token"},

            // 7. System credentials & Agent sockets
            {"GOOGLE_APPLICATION_CREDENTIALS", "/tmp/canary_gcp_service_account.json", "System Cred"},
            {"SSH_AUTH_SOCK", "/tmp/canary_ssh_auth_sock_9999", "SSH Agent"},
            {"SSH_AGENT_PID", "99999", "SSH Agent"},
            {"GPG_AGENT_INFO", "/tmp/canary_gpg_agent_sock:1111:1", "GPG Agent"},

            // 8. Suffix-matching sensitive keys
            {"MY_CUSTOM_BACKEND_API_KEY", "canary_custom_api_key_val", "Suffix Match"},
            {"INFERENCE_ENGINE_API_TOKEN", "canary_engine_api_token_val", "Suffix Match"},
            {"PRIMARY_DATABASE_SECRET_KEY", "canary_db_secret_key_val", "Suffix Match"},
            {"BACKUP_AUTH_SECRET_TOKEN", "canary_backup_secret_token_val", "Suffix Match"},
            {"INTERNAL_BLOB_STORAGE_ACCESS_KEY", "canary_storage_access_key_val", "Suffix Match"},
            {"OIDC_CLIENT_AUTH_TOKEN", "canary_oidc_auth_token_val", "Suffix Match"},
            {"OAUTH_USER_BEARER_TOKEN", "canary_oauth_bearer_token_val", "Suffix Match"},
            {"HTTPS_SERVER_PRIVATE_KEY", "canary_https_private_key_val", "Suffix Match"},

            // 9. Case variations (lower/mixed case)
            {"lemonade_admin_api_key", "canary_lowercase_admin_key", "Case Variation"},
            {"OpenAI_Api_Key", "canary_mixedcase_openai_key", "Case Variation"},
            {"hf_token", "canary_lowercase_hf_token", "Case Variation"},
            {"Aws_Secret_Access_Key", "canary_mixedcase_aws_secret", "Case Variation"},
            {"Google_Application_Credentials", "canary_mixedcase_gcp_creds", "Case Variation"}
        };

        // Inject all poison secrets into the parent process environment
        for (const auto& sec : poison_secrets) {
            setenv(sec.key.c_str(), sec.canary_value.c_str(), 1);
        }

        // Set baseline allowlisted variables to ensure they coexist
        setenv("CUDA_VISIBLE_DEVICES", "0,1", 1);
        setenv("HIP_VISIBLE_DEVICES", "0", 1);
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("HOME", "/tmp/lemonade_test_home", 1);
        setenv("TMPDIR", "/tmp", 1);

        // Test 1.1: Standard Baseline Spawn (sandbox_policy = std::nullopt)
        fs::path dump1 = fixture.create_subpath("ambient_baseline_dump.txt");
        std::string cmd1 = "env > \"" + dump1.string() + "\"";

        ProcessHandle h1 = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd1}, "", false, false, {});
        r.check(h1.pid > 0, "start_process (nullopt policy) spawned child process");
        int exit1 = ProcessManager::wait_for_exit(h1, 5);
        r.check(exit1 == 0, "baseline child executed env dump successfully (exit 0)");

        std::string dump_content1 = read_file_content(dump1);
        auto env_map1 = parse_env_lines(dump_content1);

        int leak_count1 = 0;
        std::vector<std::string> leaked_keys1;
        for (const auto& sec : poison_secrets) {
            if (dump_content1.find(sec.canary_value) != std::string::npos ||
                env_map1.find(sec.key) != env_map1.end()) {
                ++leak_count1;
                leaked_keys1.push_back(sec.key + " (" + sec.category + ")");
            }
        }
        r.check(leak_count1 == 0, "Baseline spawn: 0/65 poison secrets leaked to child",
                leak_count1 > 0 ? "Leaked: " + std::to_string(leak_count1) : "");

        // Test 1.2: Spawn with explicit SandboxPolicy in Auto Mode
        fs::path dump2 = fixture.create_subpath("ambient_auto_dump.txt");
        std::string cmd2 = "env > \"" + dump2.string() + "\"";

        SandboxPolicy auto_policy;
        auto_policy.set_mode(SandboxMode::Auto);
        for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
            auto_policy.path_grants.push_back(sp);
        }
        auto_policy.add_read_path("/bin").add_read_path("/usr/bin").add_write_path("/tmp");

        ProcessHandle h2 = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd2}, "", false, false, {}, auto_policy);
        r.check(h2.pid > 0, "start_process (SandboxMode::Auto) spawned child process");
        int exit2 = ProcessManager::wait_for_exit(h2, 5);
        r.check(exit2 == 0, "Auto policy child executed env dump successfully (exit 0)");

        std::string dump_content2 = read_file_content(dump2);
        auto env_map2 = parse_env_lines(dump_content2);

        int leak_count2 = 0;
        for (const auto& sec : poison_secrets) {
            if (dump_content2.find(sec.canary_value) != std::string::npos ||
                env_map2.find(sec.key) != env_map2.end()) {
                ++leak_count2;
            }
        }
        r.check(leak_count2 == 0, "Auto mode spawn: 0/65 poison secrets leaked to child",
                leak_count2 > 0 ? "Leaked: " + std::to_string(leak_count2) : "");

        // Test 1.3: Spawn with explicit SandboxPolicy in ScrubbedOnly Mode
        fs::path dump3 = fixture.create_subpath("ambient_scrubbed_dump.txt");
        std::string cmd3 = "env > \"" + dump3.string() + "\"";

        SandboxPolicy scrubbed_policy;
        scrubbed_policy.set_mode(SandboxMode::ScrubbedOnly);

        ProcessHandle h3 = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd3}, "", false, false, {}, scrubbed_policy);
        r.check(h3.pid > 0, "start_process (SandboxMode::ScrubbedOnly) spawned child process");
        int exit3 = ProcessManager::wait_for_exit(h3, 5);
        r.check(exit3 == 0, "ScrubbedOnly policy child executed env dump successfully (exit 0)");

        std::string dump_content3 = read_file_content(dump3);
        int leak_count3 = 0;
        for (const auto& sec : poison_secrets) {
            if (dump_content3.find(sec.canary_value) != std::string::npos) {
                ++leak_count3;
            }
        }
        r.check(leak_count3 == 0, "ScrubbedOnly mode: 0/65 poison secrets leaked to child");

        // Test 1.4: Direct /proc/self/environ inspection
        // Verify via binary reading raw null-delimited environ from kernel procfs
        fs::path proc_dump = fixture.create_subpath("proc_environ_dump.bin");
        std::string cmd_proc = "cat /proc/self/environ > \"" + proc_dump.string() + "\"";

        ProcessHandle h4 = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd_proc}, "", false, false, {});
        ProcessManager::wait_for_exit(h4, 5);

        std::string proc_raw = read_file_content(proc_dump);
        r.check(!proc_raw.empty(), "Child successfully dumped raw /proc/self/environ");

        int proc_leak_count = 0;
        for (const auto& sec : poison_secrets) {
            if (proc_raw.find(sec.canary_value) != std::string::npos) {
                ++proc_leak_count;
            }
        }
        r.check(proc_leak_count == 0, "Raw /proc/self/environ has 0 leaked secret canaries");

        // Test 1.5: Verify start_process with custom env captures output via file redirect without leaks
        fs::path redir_dump = fixture.create_subpath("redir_dump.txt");
        std::string redir_cmd = "env > \"" + redir_dump.string() + "\"";
        ProcessHandle h_redir = ProcessManager::start_process(
            "/bin/sh", {"-c", redir_cmd}, "", false, false, {});
        ProcessManager::wait_for_exit(h_redir, 5);

        std::string redir_text = read_file_content(redir_dump);
        int redir_leak_count = 0;
        for (const auto& sec : poison_secrets) {
            if (redir_text.find(sec.canary_value) != std::string::npos) {
                ++redir_leak_count;
            }
        }
        r.check(redir_leak_count == 0, "start_process environment redirect has 0 leaked secret canaries");

#else
        r.check(true, "Windows test suite fallback executed");
#endif

        r.report_summary("Ambient Secret Injection & Zero Leakage");
        overall.passed += r.passed.load();
        overall.failed += r.failed.load();
    }

    // =========================================================================
    // SUITE 2: Allowlisted Environment Preservation & Explicit Custom Vars
    // =========================================================================
    std::printf("--- SUITE 2: Allowlisted Environment Preservation & Custom Vars ---\n");
    {
        TestResult r;

#ifndef _WIN32
        // Set specific values for allowlisted runtime variables
        setenv("CUDA_VISIBLE_DEVICES", "0,1,3", 1);
        setenv("HIP_VISIBLE_DEVICES", "1,2", 1);
        setenv("ROCM_PATH", "/opt/rocm-custom-version", 1);
        setenv("PYTHONPATH", "/opt/lemonade/custom_python_modules", 1);
        setenv("ESPEAK_DATA_PATH", "/usr/share/custom_espeak", 1);
        setenv("OMP_NUM_THREADS", "8", 1);
        setenv("USER", "lemonade_test_runner", 1);
        setenv("LANG", "en_US.UTF-8", 1);

        // Also set a non-sensitive but unallowlisted ambient variable
        // (Should be dropped by default since include_ambient=true filters to default_allowlist)
        setenv("MY_RANDOM_UNALLOWED_VAR", "drop_me_please", 1);

        // Test 2.1: Allowlist preservation under standard spawn
        fs::path dump = fixture.create_subpath("allowlist_dump.txt");
        std::string cmd = "env > \"" + dump.string() + "\"";

        ProcessHandle h1 = ProcessManager::start_process(
            "/bin/sh", {"-c", cmd}, "", false, false, {});
        ProcessManager::wait_for_exit(h1, 5);

        std::string content = read_file_content(dump);
        auto env_map = parse_env_lines(content);

        r.check(env_map["CUDA_VISIBLE_DEVICES"] == "0,1,3", "CUDA_VISIBLE_DEVICES preserved exactly: 0,1,3");
        r.check(env_map["HIP_VISIBLE_DEVICES"] == "1,2", "HIP_VISIBLE_DEVICES preserved exactly: 1,2");
        r.check(env_map["ROCM_PATH"] == "/opt/rocm-custom-version", "ROCM_PATH preserved exactly");
        r.check(env_map["PYTHONPATH"] == "/opt/lemonade/custom_python_modules", "PYTHONPATH preserved exactly");
        r.check(env_map["ESPEAK_DATA_PATH"] == "/usr/share/custom_espeak", "ESPEAK_DATA_PATH preserved exactly");
        r.check(env_map["OMP_NUM_THREADS"] == "8", "OMP_NUM_THREADS preserved exactly: 8");
        r.check(env_map["USER"] == "lemonade_test_runner", "USER preserved exactly");
        r.check(env_map["LANG"] == "en_US.UTF-8", "LANG preserved exactly");
        r.check(!env_map["PATH"].empty(), "PATH is non-empty and present in child");
        r.check(env_map.find("MY_RANDOM_UNALLOWED_VAR") == env_map.end(),
                "Non-allowlisted ambient variable was correctly omitted");

        // Test 2.2: Explicit custom_env parameter passing (Valid vs Sensitive)
        fs::path custom_dump = fixture.create_subpath("custom_env_dump.txt");
        std::string custom_cmd = "env > \"" + custom_dump.string() + "\"";

        std::vector<std::pair<std::string, std::string>> custom_env = {
            {"BACKEND_CUSTOM_PORT", "8999"},
            {"MODEL_CONTEXT_WINDOW", "32768"},
            {"LEMONADE_MALICIOUS_CUSTOM_INJECTION", "secret_admin_token_injected"},
            {"VENDOR_INJECTED_API_KEY", "secret_vendor_key_injected"}
        };

        ProcessHandle h2 = ProcessManager::start_process(
            "/bin/sh", {"-c", custom_cmd}, "", false, false, custom_env);
        ProcessManager::wait_for_exit(h2, 5);

        std::string custom_content = read_file_content(custom_dump);
        auto custom_map = parse_env_lines(custom_content);

        r.check(custom_map["BACKEND_CUSTOM_PORT"] == "8999", "Custom non-sensitive var BACKEND_CUSTOM_PORT passed");
        r.check(custom_map["MODEL_CONTEXT_WINDOW"] == "32768", "Custom non-sensitive var MODEL_CONTEXT_WINDOW passed");
        r.check(custom_map.find("LEMONADE_MALICIOUS_CUSTOM_INJECTION") == custom_map.end(),
                "Explicit sensitive LEMONADE_* custom var was stripped by EnvScrubber");
        r.check(custom_map.find("VENDOR_INJECTED_API_KEY") == custom_map.end(),
                "Explicit sensitive *_API_KEY custom var was stripped by EnvScrubber");

        // Test 2.3: Extra allowlist in SandboxPolicy
        fs::path extra_dump = fixture.create_subpath("extra_allowlist_dump.txt");
        std::string extra_cmd = "env > \"" + extra_dump.string() + "\"";

        setenv("MY_SPECIAL_AGENT_ENV", "special_agent_value_123", 1);

        SandboxPolicy extra_policy;
        for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
            extra_policy.path_grants.push_back(sp);
        }
        extra_policy.add_read_path("/bin")
                    .add_read_path("/usr/bin")
                    .add_write_path(fixture.temp_dir().string())
                    .allow_env_var("MY_SPECIAL_AGENT_ENV")
                    .set_env_var("POLICY_EXPLICIT_VAR", "explicit_policy_val_456");

        ProcessHandle h3 = ProcessManager::start_process(
            "/bin/sh", {"-c", extra_cmd}, "", false, false, {}, extra_policy);
        ProcessManager::wait_for_exit(h3, 5);

        std::string extra_content = read_file_content(extra_dump);
        auto extra_map = parse_env_lines(extra_content);

        r.check(extra_map["MY_SPECIAL_AGENT_ENV"] == "special_agent_value_123",
                "Extra allowlisted ambient var MY_SPECIAL_AGENT_ENV preserved via SandboxPolicy");
        r.check(extra_map["POLICY_EXPLICIT_VAR"] == "explicit_policy_val_456",
                "Policy explicit env var POLICY_EXPLICIT_VAR passed to child");

#else
        r.check(true, "Windows allowlist test fallback executed");
#endif

        r.report_summary("Allowlisted Environment Preservation");
        overall.passed += r.passed.load();
        overall.failed += r.failed.load();
    }

    // =========================================================================
    // SUITE 3: Concurrency Stress Test Under Heavy Ambient Secret Poisoning
    // =========================================================================
    std::printf("--- SUITE 3: Concurrency Stress Test (24 Threads Under Active Poisoning) ---\n");
    {
        TestResult r;

#ifndef _WIN32
        const int NUM_THREADS = 24;
        const int ITERATIONS_PER_THREAD = 10;
        std::atomic<int> total_spawns{0};
        std::atomic<int> concurrent_leaks{0};
        std::atomic<int> failed_exits{0};

        // Worker threads spawning child processes simultaneously under ambient poisoning
        std::vector<std::thread> workers;
        workers.reserve(NUM_THREADS);

        for (int t = 0; t < NUM_THREADS; ++t) {
            workers.emplace_back([&, t]() {
                for (int iter = 0; iter < ITERATIONS_PER_THREAD; ++iter) {
                    fs::path out_file = fixture.create_subpath(
                        "conc_dump_t" + std::to_string(t) + "_i" + std::to_string(iter) + ".txt");
                    std::string cmd = "env > \"" + out_file.string() + "\"";

                    // Pass thread-specific sensitive and non-sensitive custom variables
                    std::vector<std::pair<std::string, std::string>> custom_env = {
                        {"LEMONADE_THREAD_SECRET_" + std::to_string(t), "canary_thr_sec_" + std::to_string(iter)},
                        {"THREAD_" + std::to_string(t) + "_VENDOR_API_KEY", "canary_vkey_" + std::to_string(iter)},
                        {"VALID_CUSTOM_THREAD_VAR", "valid_thread_val_" + std::to_string(t)}
                    };

                    SandboxPolicy p;
                    if (iter % 2 == 0) {
                        p.set_mode(SandboxMode::ScrubbedOnly);
                    } else {
                        p.set_mode(SandboxMode::Auto);
                        for (const auto& sp : PolicyPresets::get_standard_system_paths()) {
                            p.path_grants.push_back(sp);
                        }
                        p.add_read_path("/bin")
                         .add_read_path("/usr/bin")
                         .add_write_path(fixture.temp_dir().string());
                    }

                    ProcessHandle h = ProcessManager::start_process(
                        "/bin/sh", {"-c", cmd}, "", false, false, custom_env, p);

                    if (h.pid <= 0) {
                        failed_exits.fetch_add(1);
                        continue;
                    }
                    total_spawns.fetch_add(1);

                    int exit_code = ProcessManager::wait_for_exit(h, 10);
                    if (exit_code != 0) {
                        failed_exits.fetch_add(1);
                        std::printf("  [DEBUG] t=%d iter=%d exit_code=%d\n", t, iter, exit_code);
                    }

                    // Verify output file contains zero secrets and preserves allowlisted vars
                    std::string dump_text = read_file_content(out_file);
                    if (dump_text.find("canary_admin_key") != std::string::npos ||
                        dump_text.find("canary_user_api_key") != std::string::npos ||
                        dump_text.find("sk-proj-canary-openai") != std::string::npos ||
                        dump_text.find("canary_thr_sec_") != std::string::npos ||
                        dump_text.find("canary_vkey_") != std::string::npos ||
                        dump_text.find("AKIAIOSFODNN7EXAMPLE_CANARY") != std::string::npos) {
                        concurrent_leaks.fetch_add(1);
                    }

                    // Check that PATH, CUDA_VISIBLE_DEVICES, and VALID_CUSTOM_THREAD_VAR were retained
                    if (dump_text.find("PATH=") == std::string::npos ||
                        dump_text.find("CUDA_VISIBLE_DEVICES=") == std::string::npos ||
                        dump_text.find("VALID_CUSTOM_THREAD_VAR=valid_thread_val_" + std::to_string(t)) == std::string::npos) {
                        failed_exits.fetch_add(1);
                        std::printf("  [DEBUG] t=%d iter=%d missing vars dump_size=%zu\n", t, iter, dump_text.size());
                    }
                }
            });
        }

        for (auto& w : workers) {
            w.join();
        }

        r.check(total_spawns.load() == NUM_THREADS * ITERATIONS_PER_THREAD,
                "Concurrent spawning completed all " + std::to_string(NUM_THREADS * ITERATIONS_PER_THREAD) + " child processes",
                "Spawns: " + std::to_string(total_spawns.load()));
        r.check(failed_exits.load() == 0,
                "0 child process execution failures during heavy concurrency stress",
                "Failed exits: " + std::to_string(failed_exits.load()));
        r.check(concurrent_leaks.load() == 0,
                "0 secret leaks detected across all concurrent child processes under active mutation",
                "Leaks: " + std::to_string(concurrent_leaks.load()));

#else
        r.check(true, "Windows concurrency test fallback executed");
#endif

        r.report_summary("Concurrency Stress Test");
        overall.passed += r.passed.load();
        overall.failed += r.failed.load();
    }

    // =========================================================================
    // SUITE 4: Process Lifecycle Edge Cases & Robustness
    // =========================================================================
    std::printf("--- SUITE 4: Process Lifecycle Edge Cases & Robustness ---\n");
    {
        TestResult r;

#ifndef _WIN32
        // Test 4.1: Non-existent executable handling
        try {
            ProcessHandle h_nonexist = ProcessManager::start_process(
                "/nonexistent/path/to/binary_12345", {"--arg"}, "", false, false, {});
            // In fork/exec, child exits with 127/1
            int exit_nonexist = ProcessManager::wait_for_exit(h_nonexist, 5);
            r.check(exit_nonexist != 0,
                    "Non-existent executable exits with non-zero exit code (" + std::to_string(exit_nonexist) + ")");
        } catch (...) {
            r.check(true, "Non-existent binary threw clean exception on spawn");
        }

        // Test 4.2: Sleeping process is_running and stop_process
        ProcessHandle h_sleep = ProcessManager::start_process(
            "/bin/sh", {"-c", "sleep 60"}, "", false, false, {});
        r.check(h_sleep.pid > 0, "Spawned long-running sleep child");
        r.check(ProcessManager::is_running(h_sleep), "is_running reports true for live child");

        ProcessManager::stop_process(h_sleep);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        r.check(!ProcessManager::is_running(h_sleep), "is_running reports false after stop_process");

        // Test 4.3: kill_process forcefully on stubborn process
        ProcessHandle h_stubborn = ProcessManager::start_process(
            "/bin/sh", {"-c", "trap '' TERM; sleep 60"}, "", false, false, {});
        r.check(h_stubborn.pid > 0, "Spawned SIGTERM-ignoring stubborn child");
        r.check(ProcessManager::is_running(h_stubborn), "Stubborn child is running");

        ProcessManager::kill_process(h_stubborn);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        r.check(!ProcessManager::is_running(h_stubborn), "kill_process (SIGKILL) successfully killed stubborn child");

        // Test 4.4: reap_process lifecycle cleanup
        ProcessHandle h_quick = ProcessManager::start_process(
            "/bin/sh", {"-c", "exit 77"}, "", false, false, {});
        ProcessManager::wait_for_exit(h_quick, 5);
        int reaped_code = ProcessManager::reap_process(h_quick);
        r.check(reaped_code == 77 || reaped_code == -1,
                "reap_process cleaned up terminated child handle (reaped_code: " + std::to_string(reaped_code) + ")");

        // Test 4.5: run_process_with_output early cancellation via callback
        int lines_seen = 0;
        int cancel_code = ProcessManager::run_process_with_output(
            "/bin/sh", {"-c", "for i in 1 2 3 4 5 6 7 8 9 10; do echo \"line $i\"; sleep 0.05; done"},
            [&lines_seen](const std::string& line) {
                ++lines_seen;
                if (lines_seen >= 3) {
                    return false; // Kill process early
                }
                return true;
            },
            "", 5, true);

        r.check(cancel_code == -1, "run_process_with_output returned -1 when terminated by callback");
        r.check(lines_seen == 3, "Callback stopped after seeing exactly 3 lines (saw " + std::to_string(lines_seen) + ")");

#else
        r.check(true, "Windows lifecycle test fallback executed");
#endif

        r.report_summary("Process Lifecycle Edge Cases & Robustness");
        overall.passed += r.passed.load();
        overall.failed += r.failed.load();
    }

    // =========================================================================
    // FINAL SUMMARY
    // =========================================================================
    std::printf("===================================================================\n");
    std::printf("  FINAL TEST RESULTS: %d passed, %d failed\n",
                overall.passed.load(), overall.failed.load());
    std::printf("===================================================================\n\n");

    if (overall.failed.load() == 0) {
        std::printf("STATUS: ALL TESTS PASSED\n");
        return 0;
    } else {
        std::printf("STATUS: FAILED (%d failures detected)\n", overall.failed.load());
        return 1;
    }
}
