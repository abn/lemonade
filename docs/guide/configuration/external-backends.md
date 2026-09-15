# External Backends

Lemonade normally runs inference engines from its own bundled and downloaded backend builds. An **external backend** lets you run an out-of-tree engine instead. You drop a JSON **manifest** into a discovery directory, `lemond` discovers it at runtime, launches the engine as a subprocess, health-probes it, and proxies its fixed Lemonade routes onto it. No C++ rebuild is required, so you can track a fork, a nightly, a container image, or an internal build on your own schedule.

There are two manifest shapes:

| Shape | Execution Comes From | Use It For |
|-------|----------------------|------------|
| **Passthrough** | The manifest's own `command` and `args` | A binary you install and manage yourself. |
| **`variant_of`** | A built-in backend's argv construction, against a pinned binary the CLI downloads | A drop-in fork of a built-in engine. `llamacpp` is the first built-in that exposes this. |

> **Security:** an external backend runs as an unsandboxed subprocess with the same privileges as `lemond`. Only install manifests you trust. See [Process confinement](#process-confinement) for what is and is not enforced.

- [Discovery](#discovery)
- [Capabilities](#capabilities)
- [A manifest example](#a-manifest-example)
- [Launch tokens](#launch-tokens)
- [The platform matrix](#the-platform-matrix)
- [`variant_of`: pinned binaries](#variant_of-pinned-binaries)
- [CLI install and uninstall](#cli-install-and-uninstall)
- [Use an external recipe with a model](#use-an-external-recipe-with-a-model)
- [Troubleshooting](#troubleshooting)
- [Process confinement](#process-confinement)
- [Known limitations](#known-limitations)

## Discovery

`lemond` scans these directories in priority order. The first trusted descriptor that claims a recipe wins, so a manifest in a higher-priority directory shadows the same recipe lower down. A recipe that collides with a built-in is rejected rather than shadowed.

| Priority | Platform | Directory |
|----------|----------|-----------|
| 1 | Linux / macOS | `$XDG_CONFIG_HOME/lemonade/backends`, or `~/.config/lemonade/backends` |
| 1 | Windows | `%APPDATA%\Lemonade\backends` |
| 2 | Linux / macOS | `$XDG_CACHE_HOME/lemonade/backends`, or `~/.cache/lemonade/backends` |
| 2 | Windows | `%USERPROFILE%\.cache\lemonade\backends` |
| 3 | Linux | `/usr/share/lemonade-server/backends`, `/usr/local/share/lemonade-server/backends`, `/etc/lemonade/backends` |
| 3 | macOS | `/Library/Application Support/Lemonade/backends` |
| 3 | Windows | `%ProgramData%\Lemonade\backends` |

A descriptor is only trusted when all of the following hold:

- It is a regular `.json` file. Symlinked descriptors are rejected.
- On POSIX, it is not group or world writable (`mode & 0022 == 0`).
- On POSIX, it is owned by your user for a user path, or by root (UID 0) for a system path.
- No ancestor directory owned by another user is group or world writable without the sticky bit.
- On Windows, the owner is your user or Administrators (LocalSystem for a system path), and the DACL grants no write access to `Everyone` or `Users`.

`lemond` scans the discovery directories when it first needs an external recipe, and `/system-info` enumerates them on first use. Once an external backend has been created, a background watcher re-scans every 2 seconds, so manifest edits are picked up without a restart.

## Capabilities

A manifest declares the capabilities the engine serves. Each capability maps to one deployment mode and one or more fixed Lemonade routes. A manifest can never open a route: an operation outside its declared set is answered with the standard `unsupported_operation` envelope. `responses` is the one exception today; see the notes below.

| Manifest Capability | Mode Label | Routes |
|---------------------|-----------|--------|
| `chat_completion` | `chat` | `POST /v1/chat/completions` |
| `completion` | `chat` | `POST /v1/completions` |
| `responses` | `chat` | `POST /v1/responses` |
| `embeddings` | `embeddings` | `POST /v1/embeddings` |
| `reranking` | `reranking` | `POST /v1/rerank` |
| `transcription` | `transcription` | `POST /v1/audio/transcriptions` |
| `tts` | `tts` | `POST /v1/audio/speech` |
| `classification` | `classification` | `POST /v1/classify` |
| `image` | `image` | `POST /v1/images/generations`, `/v1/images/edits`, `/v1/images/variations` |
| `audio_generation` | `audio-generation` | `POST /v1/audio/generations` |
| `model_3d` | `3d` | `POST /v1/3d/generations` |
| `slots` | (plumbing, no mode) | `GET /v1/slots`, `POST /v1/slots/{id}` |
| `tokenize` | (plumbing, no mode) | `POST /v1/tokenize` |
| `streaming_transcription` | `transcription` | Realtime WebSocket |

The names above use the canonical `/v1` form. Every route is also served under `/api/v0/`, `/api/v1/`, and `/v0/`, per the quad-prefix registration rule.

Notes:

- `slots` and `tokenize` are **plumbing**: they do not describe a deployment mode and do not count toward which mode a model loads in.
- `streaming_transcription` is **`variant_of` only**. A passthrough manifest cannot declare it.
- `image` covers generations, edits, and variations. Image **upscale** (`POST /v1/images/upscale`) is not part of this capability: Lemonade dispatches it directly to the `sd-cpp` or `thenoise` recipe, so an external backend cannot serve it.
- `responses` is declared for completeness. The router does not currently gate `POST /v1/responses`, so declaring it is advisory: declare it when the engine serves the route.

## A manifest example

The following annotated manifest is based on the shipped [`llamacpp_vulkan_custom.json`](../../examples/external_backends/llamacpp_vulkan_custom.json). It launches a user-installed Vulkan `llama-server` directly.

> The `//` comments below are annotation only. The manifest parser rejects JSON comments, so remove them from a real file.

```jsonc
{
  // Stable recipe id. Must match ^[a-z0-9][a-z0-9_-]{1,63}$ and must not
  // collide with a built-in recipe.
  "recipe": "llamacpp-vulkan-custom",
  "display_name": "llama.cpp Server (Vulkan Custom)",

  // Manifest contract major. This build supports "1" only.
  "api_contract_version": "1",

  // The routes this engine serves. At least one, no duplicates.
  "capabilities": ["chat_completion", "completion"],

  // Accelerator sharing: standard, exclusive_npu, coexist_by_type, unmetered.
  "slot_policy": "standard",

  // How lemond confirms the engine is up after launch. Defaults:
  // type=http, endpoint=/health, expected_status=200, timeout_seconds=90,
  // poll_interval_ms=100. type may be http, tcp, or process.
  "health_probe": {
    "type": "http",
    "endpoint": "/health",
    "expected_status": 200,
    "timeout_seconds": 60,
    "poll_interval_ms": 200
  },

  // Host OS -> accelerator -> launch spec. At least one OS and one
  // accelerator are required.
  "platforms": {
    "linux": {
      "vulkan": {
        "command": "/opt/lemonade/bin/llamacpp/vulkan/llama-server",
        "args": [
          "-m", "{checkpoint:main}",
          "--host", "{host}",
          "--port", "{port}",
          "-c", "{ctx_size}",
          "-t", "{threads}"
        ],
        // Optional argv run before launch (to clear a stale process) and on
        // unload. {pid} is available to the stop command after launch.
        "stop_command": "kill",
        "stop_command_args": ["-9", "{pid}"],
        // Optional environment for the subprocess. Keys are literal; values
        // are templates.
        "env": {
          "GGML_VK_VISIBLE_DEVICES": "{custom:vk_device:-0}"
        }
      }
    }
  }
}
```

Field summary:

| Field | Required | Notes |
|-------|----------|-------|
| `recipe` | yes | Stable id, `^[a-z0-9][a-z0-9_-]{1,63}$`. Colliding with a built-in is rejected. |
| `display_name` | yes | Shown by `/system-info` and `lemonade backends --all`. |
| `api_contract_version` | yes | Must be `"1"`. A newer major is rejected with a clear message, never partially honored. |
| `capabilities` | yes | Non-empty, unique, from the table above. |
| `platforms` | yes | Non-empty OS map, each with a non-empty accelerator map. |
| `slot_policy` | no | `standard` (default), `exclusive_npu`, `coexist_by_type`, `unmetered`. |
| `health_probe` | no | How readiness is confirmed. See the annotated defaults. |
| `default_accelerator` | no | Which accelerator block to use when the request names no device. |
| `endpoints` | no | Per-capability remap of a nonstandard engine-side path onto the fixed route. Values are engine paths, not Lemonade routes. |
| `reserved_args` | no | Flags a user's `{custom_args}` must not supply. |
| `source`, `sha256`, `version_policy` | `variant_of` only | Pinned binary provenance. See [`variant_of`](#variant_of-pinned-binaries). |
| `extensions` | no | Open bag for experimental keys. It is the only forward-compatible seam within major 1. |
| `extends`, `recipe_options`, `capability_enable_args`, `custom_options`, `requested_ports`, `model_management`, `downsize_endpoint` | no | Additional declarative fields. See [Known limitations](#known-limitations). |

Unknown fields, unknown capability names, and unknown tokens are rejected at discovery. The only open objects are `recipe_options` and `extensions`.

## Launch tokens

`command`, `args`, `working_dir`, `stop_command`, `stop_command_args`, `argv_extra`, and each `env` value are templates. Text inside `{...}` is a token. Unknown tokens and malformed `custom:`/`env:` specs are rejected when the manifest is parsed, so a token error is a discovery failure, not a launch failure.

A token that resolves to a value beginning with `-` is rejected unless the value is a well-formed negative number (for example `-1` or `-1.5`). This prevents a model option from injecting extra argv flags.

### Runtime

| Token | Value |
|-------|-------|
| `{port}` | The loopback port `lemond` chose for this load. |
| `{host}` | `127.0.0.1`. |
| `{pid}` | The child process id. Available to the stop command after launch. |
| `{log_level}` | The server's log level. |
| `{recipe}` | The manifest's recipe id. |
| `{model_name}` | The loaded model name. |

### Checkpoints and paths

| Token | Value |
|-------|-------|
| `{checkpoint:NAME}` | Absolute resolved path for checkpoint `NAME` (for example `main`, `mmproj`, `vae`). |
| `{checkpoint_relative:NAME}` | The same path relative to the Hugging Face cache when it is inside it, else the bare filename. |
| `{resolved_path}` | Absolute path of the `main` checkpoint. |
| `{model_relative_path}` | `main` relative to the Hugging Face cache. |
| `{model_dir}` | Directory containing the `main` checkpoint. |
| `{exe_dir}` | Directory containing the passthrough `command`. |
| `{hf_cache}` | The Hugging Face cache root. |
| `{cache_dir}` | The Lemonade cache root. |

### Hardware and devices

| Token | Source |
|-------|--------|
| `{rocm_arch}` | Detected ROCm architecture. |
| `{cuda_arch}` | Detected CUDA architecture. |
| `{target_device}` | The `target_device` recipe option, else `gpu_id`, else `0`. |
| `{hip_visible_devices}` | `hip_visible_devices`, else `gpu_id`, else `0`. |
| `{cuda_visible_devices}` | `cuda_visible_devices`, else `gpu_id`, else `0`. |
| `{rocr_visible_devices}` | `rocr_visible_devices`, else `gpu_id`, else `0`. |
| `{ggml_vk_visible_devices}` | `ggml_vk_visible_devices`, else `gpu_id`, else `0`. |
| `{ze_affinity_mask}` | `ze_affinity_mask`, else `gpu_id`, else `0`. |

### Recipe options

| Token | Default |
|-------|---------|
| `{ctx_size}` | `2048` |
| `{batch_size}` | `512` |
| `{ubatch_size}` | `512` |
| `{threads}` | `4` |
| `{cache_type_k}` | `f16` |
| `{cache_type_v}` | `f16` |

### Custom options and argv

| Token | Value |
|-------|-------|
| `{custom:NAME}` | The model's recipe option `NAME`. |
| `{custom:NAME:-DEFAULT}` | The option when set, otherwise `DEFAULT`. |
| `{custom_args}` | The model's `args` recipe option, split into one or more argv entries. |

Every entry supplied through `{custom_args}` is checked against the manifest's `reserved_args` (and the selected block's `reserved_args`). A match on the exact flag, or on a leading `<flag>=`, is rejected. A manifest should list the flags it constructs itself so a model option cannot override them.

### Environment

| Token | Value |
|-------|-------|
| `{env:NAME}` | An allowlisted environment variable. |
| `{env:NAME:-DEFAULT}` | The variable when set, otherwise `DEFAULT`. |

`{env:NAME}` is default-deny. v1 allows only `HF_HOME`, `HF_HUB_CACHE`, `TRANSFORMERS_CACHE`, `SSL_CERT_FILE`, and `SSL_CERT_DIR`. Any `LEMONADE_*` name, and any name containing `API_KEY`, `TOKEN`, `SECRET`, `PASS`, or `AUTH`, is rejected. Proxy variables are excluded because their values may embed credentials that would land in argv.

The subprocess still inherits `lemond`'s ambient environment. `{env:...}` controls what a template may read, not what the child receives.

## The platform matrix

`platforms` keys by host OS (`linux`, `darwin`, `windows`) and then by accelerator (`cpu`, `gpu`, `rocm`, `cuda`, `vulkan`, `metal`, `oneapi`, `npu`, `tpu`). Each accelerator block is one of:

- **Passthrough:** `command` plus `args`.
- **`variant_of`:** `binary` (a bare executable name inside the downloaded artifact; no path separators or traversal). Do not mix `command`/`args` with `binary`.

Both shapes accept the optional `working_dir`, `stop_command`, `stop_command_args`, `env`, `argv_extra`, and `reserved_args`.

When a load request names no device, `lemond` picks an accelerator in this order:

1. The requested `device` recipe option, if the manifest has a block with that exact key.
2. `default_accelerator`, if the manifest declares one and the block exists.
3. Runtime detection: `metal` on macOS, otherwise `cuda` when a CUDA architecture is detected, then `rocm` when a ROCm architecture is detected, then `vulkan`, `gpu`, and `cpu`.
4. The first accelerator key in the block, as a last resort.

If the manifest has no block for the host OS, the load fails with a clear error.

## `variant_of`: pinned binaries

A `variant_of` manifest reuses a built-in backend's argv construction against your own binary. Today only `llamacpp` exposes a launch plan, so `variant_of` is `"llamacpp"` for every current use.

The manifest adds binary provenance at the top level and a `binary` in each platform block:

```jsonc
{
  "recipe": "llamacpp-rocm-nightly",
  "display_name": "llama.cpp ROCm Nightly (community fork)",
  "api_contract_version": "1",
  "variant_of": "llamacpp",
  "capabilities": ["chat_completion", "completion", "embeddings"],

  // https:// only. The CLI fetches this; lemond never downloads executables.
  "source": "https://example.invalid/llamacpp-rocm/nightly/llama-server-linux-rocm.tar.gz",

  // pinned (default) requires sha256. roll_forward is an explicit opt-out for
  // an artifact that moves.
  "version_policy": "pinned",
  "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",

  "platforms": {
    "linux": {
      "rocm": {
        "binary": "llama-server",
        "argv_extra": ["--gpu-layers", "{custom:gpu_layers:-0}"],
        "reserved_args": ["--port", "--host", "-m"]
      }
    }
  }
}
```

At load time `lemond` asks the built-in backend for its launch plan (executable, argv, working directory, environment), substitutes the external recipe's installed binary, appends `argv_extra`, and launches it. `source` is limited to `https://`, and `sha256` must be `sha256:` followed by 64 lowercase hex characters. `source`, `sha256`, and `version_policy` are only valid with `variant_of`.

The download happens in the CLI, never in `lemond`:

- `install-external` fetches `source`, verifies `sha256` unless the policy is `roll_forward`, extracts the archive (or places a bare binary), marks it executable, and installs it under `<cache>/external/<recipe>/` (`<cache>` is the Lemonade cache directory, for example `~/.cache/lemonade` on Linux).
- `lemond` launches `<cache>/external/<recipe>/<binary>`. If it is missing, the load fails and you run `install-external` first.

## CLI install and uninstall

```bash
lemonade backends install-external <recipe> [--yes]
lemonade backends uninstall-external <recipe> [--yes]
```

Before doing anything, both commands print the manifest's provenance (display name, `variant_of`, `source`, `sha256`, `version_policy`, and capabilities) and this disclosure:

```text
WARNING: this backend runs as an external subprocess. No process
         sandbox is enforced by this RFC; run only manifests you trust.
```

`--yes` skips the interactive confirmation. On a non-interactive terminal without `--yes`, the command refuses rather than assuming consent.

- **install-external** downloads and verifies a `variant_of` binary. For a passthrough manifest that declares no `source`, there is nothing to download; the command records consent and provenance and tells you the binary is user-provided.
- **uninstall-external** removes the manifest and the install directory. It refuses to remove a system descriptor (one found under a system discovery path); remove those with your package manager.

To see discovered external recipes:

```bash
lemonade backends --all
```

External recipes also appear in `GET /v1/system-info` with `"is_external": true`.

## Use an external recipe with a model

Register a model against the recipe in `user_models.json`. The recipe name must match the manifest. This example registers a local GGUF against the Vulkan manifest above:

```json
{
  "My-Vulkan-Model": {
    "source": "local_path",
    "checkpoints": {
      "main": "/absolute/path/to/model.gguf"
    },
    "recipe": "llamacpp-vulkan-custom",
    "size": 4.0
  }
}
```

Then load it and send a request to a route the manifest declares:

```bash
curl -s http://localhost:8000/api/v1/load \
  -H 'Content-Type: application/json' \
  -d '{"model_name": "user.My-Vulkan-Model"}'

curl -s http://localhost:8000/api/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "user.My-Vulkan-Model", "messages": [{"role": "user", "content": "Hello"}]}'
```

Per-model tuning goes in `recipe_options.json` under the full `user.*` name. See [Add a Custom Model](./custom-models.md) for the full registration reference.

## Troubleshooting

| Symptom | Likely Cause |
|---------|--------------|
| Recipe missing from `lemonade backends --all` | The descriptor is not trusted (symlink, group/world writable, wrong owner), invalid JSON, an unknown field/capability/token, or it collides with a built-in or a higher-priority manifest. Validate against the schema and check file mode and ownership. |
| Load fails with `no external manifest registered` | The recipe in `user_models.json` does not match any discovered manifest. |
| Load fails with `binary is not installed` | A `variant_of` binary is missing. Run `lemonade backends install-external <recipe>`. |
| `health probe failed` | The engine never answered the probe within `timeout_seconds`. Check the engine's own logs, the `command`/`args`, and the port. |
| `unsupported_operation` on a route | The manifest does not declare that capability. Add it if the engine serves it. |
| Unknown token at discovery | A `{...}` name is not in the token vocabulary. |
| `recipe option ... has no value` at load | A `{custom:NAME}` token has no value and no `:-DEFAULT`. |
| `environment variable ... is not resolvable` | An `{env:NAME}` name is not on the v1 allowlist or is secret-shaped. |
| `file is group or world writable` | `chmod` the descriptor so group and others cannot write to it (for example `chmod 600`). |
| `unsupported api_contract_version` | The manifest declares a major this build does not support. |

## Process confinement

Process confinement is explicitly **out of scope** for external backends. This feature does not provide filesystem confinement, does not scrub the child's ambient environment, and has no sandbox grant block. An external backend runs as a subprocess with `lemond`'s own privileges, so a manifest can run any command the `lemond` user can run.

Those protections belong to a companion sandbox RFC. Treat every manifest as trusted code.

## Known limitations

- Custom option values: `{custom:NAME}` and `{custom_args}` are read from the model's recipe options. The recipe-option allowlist for an external recipe is currently limited, so a custom token without a `:-DEFAULT` may not resolve from `recipe_options.json` in this version. Supply a default, or set the option explicitly where the recipe exposes it.
- `capability_enable_args`, `requested_ports` (beyond validating it equals 1), `model_management`, `downsize_endpoint`, `extends`, and the manifest's own `recipe_options` are parsed and validated but are not yet consumed at runtime.
- `GET /system-info` lists `custom_options` so they can be displayed, but does not apply their defaults.
