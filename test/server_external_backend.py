#!/usr/bin/env python3
"""Live integration test for RFC01 external backend manifests.

Runs a real ``lemond`` with an isolated config/cache, drops a manifest for a
tiny fake OpenAI-compatible engine, registers a model against that recipe, and
exercises discovery, load, proxying, capability gating, and teardown.

Run:  ./.venv/bin/python test/server_external_backend.py
      LEMONADE_TEST_PORT=13357 ./.venv/bin/python test/server_external_backend.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LEMOND_BINARY = os.environ.get(
    "LEMOND_BINARY", os.path.join(REPO_ROOT, "build", "lemond")
)
PORT = int(os.environ.get("LEMONADE_TEST_PORT", "13357"))
BASE = f"http://127.0.0.1:{PORT}/api/v1"

FAKE_ENGINE = """\
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        if self.path.startswith("/v1/chat/completions"):
            self._send(200, {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 0,
                "model": "fake-external",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "pong"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            })
        else:
            self._send(404, {"error": "not found"})


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
"""


def request(method, path, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode()
            return response.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as error:
        body = error.read().decode()
        return error.code, (json.loads(body) if body else {})


class ExternalBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "/" not in LEMOND_BINARY and shutil.which(LEMOND_BINARY) is None:
            raise unittest.SkipTest(f"lemond binary not found: {LEMOND_BINARY}")
        if "/" in LEMOND_BINARY and not os.path.exists(LEMOND_BINARY):
            raise unittest.SkipTest(f"lemond binary not found at {LEMOND_BINARY}")

        cls.workdir = tempfile.mkdtemp(prefix="lemonade_external_it_")
        cls.cache_dir = os.path.join(cls.workdir, "cache")
        cls.config_dir = os.path.join(cls.workdir, "config")
        cls.xdg_config = os.path.join(cls.workdir, "xdg-config")
        cls.hf_home = os.path.join(cls.workdir, "hf")
        backends_dir = os.path.join(cls.xdg_config, "lemonade", "backends")
        for directory in (cls.cache_dir, cls.config_dir, backends_dir, cls.hf_home):
            os.makedirs(directory, exist_ok=True)

        cls.engine_path = os.path.join(cls.workdir, "fake_engine.py")
        with open(cls.engine_path, "w", encoding="utf-8") as handle:
            handle.write(FAKE_ENGINE)

        model_path = os.path.join(cls.workdir, "model.gguf")
        with open(model_path, "w", encoding="utf-8") as handle:
            handle.write("dummy")

        manifest = {
            "recipe": "fake-external",
            "display_name": "Fake External Engine",
            "api_contract_version": "1",
            "capabilities": ["chat_completion", "completion"],
            "health_probe": {
                "type": "http",
                "endpoint": "/health",
                "expected_status": 200,
                "timeout_seconds": 30,
                "poll_interval_ms": 100,
            },
            "platforms": {
                "linux": {
                    "cpu": {
                        "command": sys.executable,
                        "args": [cls.engine_path, "{port}"],
                        "env": {"PYTHONUNBUFFERED": "1"},
                        "stop_command": "kill",
                        "stop_command_args": ["-9", "{pid}"],
                    }
                }
            },
        }
        manifest_path = os.path.join(backends_dir, "fake-external.json")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)
        os.chmod(manifest_path, 0o600)

        user_models = {
            "user.fake-external-model": {
                "checkpoint": model_path,
                "checkpoints": {"main": model_path},
                "source": "local_path",
                "recipe": "fake-external",
                "recipe_options": {},
            }
        }
        with open(
            os.path.join(cls.config_dir, "user_models.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(user_models, handle, indent=2)

        env = os.environ.copy()
        env.pop("LEMONADE_API_KEY", None)
        env.pop("LEMONADE_ADMIN_API_KEY", None)
        env["XDG_CONFIG_HOME"] = cls.xdg_config
        env["HF_HOME"] = cls.hf_home
        cls.server = subprocess.Popen(
            [LEMOND_BINARY, cls.cache_dir, cls.config_dir, "--port", str(PORT)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                status, _ = request("GET", "/health", timeout=2)
                if status == 200:
                    break
            except Exception:
                time.sleep(0.5)
        else:
            cls.server.terminate()
            raise RuntimeError("lemond did not become healthy")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None) is not None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
        if getattr(cls, "workdir", None):
            shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_01_manifest_discovered_in_system_info(self):
        status, info = request("GET", "/system-info")
        self.assertEqual(status, 200)
        recipes = info.get("recipes", {})
        self.assertIn("fake-external", recipes)
        self.assertEqual(
            recipes["fake-external"].get("display_name"), "Fake External Engine"
        )
        self.assertTrue(recipes["fake-external"].get("is_external"))

    def test_02_model_listed(self):
        status, models = request("GET", "/models?show_all=true")
        self.assertEqual(status, 200)
        ids = [m.get("id") for m in models.get("data", [])]
        self.assertIn("user.fake-external-model", ids)

    def test_03_load_chat_and_gate(self):
        status, _ = request(
            "POST", "/load", {"model_name": "user.fake-external-model"}, timeout=90
        )
        self.assertEqual(status, 200, "load should succeed")

        status, chat = request(
            "POST",
            "/chat/completions",
            {
                "model": "user.fake-external-model",
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(chat["choices"][0]["message"]["content"], "pong")

        status, error = request(
            "POST", "/embeddings", {"model": "user.fake-external-model", "input": "x"}
        )
        self.assertNotEqual(status, 200, "undeclared capability must be rejected")
        self.assertEqual(error.get("error", {}).get("type"), "unsupported_operation")

    def test_04_unload_cleans_up_subprocess(self):
        request("POST", "/unload", {})
        deadline = time.time() + 10
        while time.time() < deadline:
            result = subprocess.run(
                ["pgrep", "-f", self.engine_path], capture_output=True, text=True
            )
            if result.returncode != 0:
                break
            time.sleep(0.5)
        result = subprocess.run(
            ["pgrep", "-f", self.engine_path], capture_output=True, text=True
        )
        self.assertNotEqual(
            result.returncode, 0, "fake engine subprocess must be gone after unload"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
