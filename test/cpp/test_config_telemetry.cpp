#include <algorithm>
#include <cassert>
#include <cstdio>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <lemon/runtime_config.h>

#include "test_config_helpers.h"

using json = nlohmann::json;
using lemon::RuntimeConfig;
using test_helpers::check;
using test_helpers::parse_cli_args;

int main() {
    std::puts("=== RUNNING RUNTIME CONFIG & TELEMETRY TESTS ===");

    json base_cfg = {
        {"config_version", 2},
        {"port", 13305},
        {"host", "localhost"},
        {"telemetry", {
            {"enabled", false},
            {"hide_inputs", false},
            {"hide_outputs", false},
            {"hide_thinking", false},
            {"max_queue_capacity", 1000},
            {"otlp", {
                {"endpoint", "http://localhost:4318/v1/traces"},
                {"protocol", "http/protobuf"},
                {"semantics", {"openinference", "otel_genai"}},
                {"headers", json::object()},
                {"max_retries", 0},
                {"retry_backoff_base_s", 5.0},
                {"send_batch_size", 100},
                {"batch_timeout_s", 1.0}
            }}
        }}
    };

    RuntimeConfig config(base_cfg);

    // 1. Test recursive merge: toggling telemetry should preserve existing otlp.* settings
    json toggle_off = {
        {"telemetry", {
            {"enabled", false}
        }}
    };
    config.set(toggle_off);
    json snapshot = config.snapshot();
    check(snapshot["telemetry"]["enabled"] == false, "telemetry toggled off");
    check(snapshot["telemetry"]["otlp"]["endpoint"] == "http://localhost:4318/v1/traces", "otlp.endpoint preserved on toggle off");
    check(snapshot["telemetry"]["otlp"]["semantics"] == json::array({"openinference", "otel_genai"}), "otlp.semantics preserved on toggle off");

    json toggle_on = {
        {"telemetry", {
            {"enabled", true}
        }}
    };
    config.set(toggle_on);
    snapshot = config.snapshot();
    check(snapshot["telemetry"]["enabled"] == true, "telemetry toggled on");
    check(snapshot["telemetry"]["otlp"]["endpoint"] == "http://localhost:4318/v1/traces", "otlp.endpoint preserved on toggle on");
    check(snapshot["telemetry"]["otlp"]["semantics"] == json::array({"openinference", "otel_genai"}), "otlp.semantics preserved on toggle on");

    // 2. Test validation: rejecting unknown telemetry / OTLP subkeys
    bool threw_unknown_telemetry = false;
    try {
        json invalid_telemetry = {
            {"telemetry", {
                {"unknown_field", true}
            }}
        };
        config.set(invalid_telemetry);
    } catch (const std::invalid_argument& e) {
        threw_unknown_telemetry = true;
        std::printf("Expected exception caught: %s\n", e.what());
    }
    check(threw_unknown_telemetry, "rejects unknown telemetry subkey");

    bool threw_unknown_otlp = false;
    try {
        json invalid_otlp = {
            {"telemetry", {
                {"otlp", {
                    {"unknown_otlp_field", "val"}
                }}
            }}
        };
        config.set(invalid_otlp);
    } catch (const std::invalid_argument& e) {
        threw_unknown_otlp = true;
        std::printf("Expected exception caught: %s\n", e.what());
    }
    check(threw_unknown_otlp, "rejects unknown telemetry.otlp subkey");

    // 3. Test max_attribute_length and max_queue_bytes defaults and validation
    check(config.telemetry_max_attribute_length() == 0, "telemetry_max_attribute_length defaults to 0");
    check(config.telemetry_max_queue_bytes() == 134217728, "telemetry_max_queue_bytes defaults to 134217728 (128MB)");

    bool threw_invalid_max_attr_len = false;
    try {
        json invalid_max_attr = {
            {"telemetry", {
                {"max_attribute_length", -1}
            }}
        };
        config.set(invalid_max_attr);
    } catch (const std::invalid_argument& e) {
        threw_invalid_max_attr_len = true;
        std::printf("Expected exception caught: %s\n", e.what());
    }
    check(threw_invalid_max_attr_len, "rejects negative telemetry.max_attribute_length");

    bool threw_invalid_max_queue_bytes = false;
    try {
        json invalid_max_bytes = {
            {"telemetry", {
                {"max_queue_bytes", -1}
            }}
        };
        config.set(invalid_max_bytes);
    } catch (const std::invalid_argument& e) {
        threw_invalid_max_queue_bytes = true;
        std::printf("Expected exception caught: %s\n", e.what());
    }
    check(threw_invalid_max_queue_bytes, "rejects negative telemetry.max_queue_bytes");

    json valid_max_attr = {
        {"telemetry", {
            {"max_attribute_length", 8192},
            {"max_queue_bytes", 268435456}
        }}
    };
    config.set(valid_max_attr);
    check(config.telemetry_max_attribute_length() == 8192, "updates max_attribute_length to 8192");
    check(config.telemetry_max_queue_bytes() == 268435456, "updates max_queue_bytes to 268435456 (256MB)");

    json reset_max_attr = {
        {"telemetry", {
            {"max_attribute_length", 0},
            {"max_queue_bytes", 134217728}
        }}
    };
    config.set(reset_max_attr);
    check(config.telemetry_max_attribute_length() == 0, "resets max_attribute_length to 0");
    check(config.telemetry_max_queue_bytes() == 134217728, "resets max_queue_bytes to 134217728");

    // 4. Test CLI dotted key config path parsing logic
    std::vector<std::string> cli_args = {
        "telemetry.otlp.endpoint=http://127.0.0.1:5555/v1/traces",
        "telemetry.otlp.protocol=http/json",
        "telemetry.otlp.semantics=[\"openinference\"]",
        "telemetry.otlp.headers={\"Authorization\":\"Bearer test-key\"}",
        "port=9090"
    };
    json cli_updates = parse_cli_args(cli_args);
    check(cli_updates["port"] == 9090, "CLI parses top-level key");
    check(cli_updates["telemetry"]["otlp"]["endpoint"] == "http://127.0.0.1:5555/v1/traces", "CLI parses 3-level dotted path endpoint");
    check(cli_updates["telemetry"]["otlp"]["protocol"] == "http/json", "CLI parses 3-level dotted path protocol");
    check(cli_updates["telemetry"]["otlp"]["semantics"].is_array(), "CLI parses JSON array for semantics");
    check(cli_updates["telemetry"]["otlp"]["semantics"][0] == "openinference", "CLI parsed array value matches");
    check(cli_updates["telemetry"]["otlp"]["headers"].is_object(), "CLI parses JSON object for headers");
    check(cli_updates["telemetry"]["otlp"]["headers"]["Authorization"] == "Bearer test-key", "CLI parsed object field matches");

    // 5. Test safe max_bytes conversion logic on 64-bit platforms
    auto compute_max_bytes = [](int64_t max_queue_bytes) -> size_t {
        size_t max_bytes = 0;
        if (max_queue_bytes > 0) {
            if (static_cast<uint64_t>(max_queue_bytes) > std::numeric_limits<size_t>::max()) {
                max_bytes = std::numeric_limits<size_t>::max();
            } else {
                max_bytes = static_cast<size_t>(max_queue_bytes);
            }
        }
        return max_bytes;
    };

    check(compute_max_bytes(0) == 0, "max_bytes conversion: 0 -> 0 (unlimited)");
    check(compute_max_bytes(-1) == 0, "max_bytes conversion: negative -> 0");
    check(compute_max_bytes(134217728) == 134217728, "max_bytes conversion: 128MB exact value preserved on 64-bit");
    check(compute_max_bytes(268435456) == 268435456, "max_bytes conversion: 256MB exact value preserved");

    // 6. Test iterator-safe removal and byte eviction deque simulation
    struct SimulatedTask {
        std::string id;
        std::string endpoint;
        size_t approx_bytes;
    };
    std::deque<SimulatedTask> sim_queue;
    size_t sim_current_bytes = 0;
    size_t sim_max_bytes = 1000;
    size_t sim_max_capacity = 10;
    size_t sim_dropped = 0;

    auto sim_remove_task_at = [&](std::deque<SimulatedTask>::iterator it, std::vector<std::string>& batch) {
        batch.push_back(it->id);
        if (sim_current_bytes >= it->approx_bytes) {
            sim_current_bytes -= it->approx_bytes;
        } else {
            sim_current_bytes = 0;
        }
        return sim_queue.erase(it);
    };

    auto sim_push = [&](const std::string& id, const std::string& ep, size_t bytes) {
        if (sim_max_bytes > 0 && bytes > sim_max_bytes) {
            sim_dropped++;
            return;
        }
        while (!sim_queue.empty() && ((sim_max_bytes > 0 && sim_current_bytes + bytes > sim_max_bytes) || sim_queue.size() >= sim_max_capacity)) {
            sim_dropped++;
            if (sim_current_bytes >= sim_queue.front().approx_bytes) {
                sim_current_bytes -= sim_queue.front().approx_bytes;
            } else {
                sim_current_bytes = 0;
            }
            sim_queue.pop_front();
        }
        sim_current_bytes += bytes;
        sim_queue.push_back({id, ep, bytes});
    };

    sim_push("oversized", "ep1", 1500);
    check(sim_queue.empty() && sim_dropped == 1, "simulated queue: oversized span dropped immediately");

    sim_push("t1", "ep1", 400);
    sim_push("t2", "ep1", 400);
    check(sim_queue.size() == 2 && sim_current_bytes == 800 && sim_dropped == 1, "simulated queue: accumulated 800 bytes");

    sim_push("t3", "ep1", 400);
    check(sim_queue.size() == 2 && sim_queue.front().id == "t2" && sim_current_bytes == 800 && sim_dropped == 2, "simulated queue: FIFO evicted t1 on byte limit");

    std::vector<std::string> collected_batch;
    auto it = sim_queue.begin();
    while (it != sim_queue.end()) {
        if (it->endpoint == "ep1") {
            it = sim_remove_task_at(it, collected_batch);
        } else {
            ++it;
        }
    }
    check(collected_batch.size() == 2 && sim_queue.empty() && sim_current_bytes == 0, "simulated queue: iterator-safe batch extraction emptied queue and reset bytes");

    return test_helpers::report_results("C++ config/telemetry");
}
