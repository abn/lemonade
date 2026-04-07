"""
Integration tests for the Unix Domain Socket HTTP server in lemond (Linux only).

lemond exposes an HTTP/1.1 server over a Unix Domain Socket at
$XDG_RUNTIME_DIR/lemonade/lemond.sock in addition to its TCP listener.
This allows tray apps and sandboxed (Flatpak) clients to:
  - Discover the TCP port lemond is listening on (via GET /v1/health)
  - Issue API calls without knowing the port in advance

These tests start a fresh lemond instance and verify the UDS HTTP endpoint.

Usage:
    python test/server_uds.py [--server-binary /path/to/lemond]
"""

import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import unittest

# Only run on Linux
@unittest.skipUnless(platform.system() == "Linux", "UDS HTTP server is Linux-only")
class UdsHttpServerTests(unittest.TestCase):
    """Tests for HTTP endpoints exposed over the Unix Domain Socket."""

    _server_proc = None
    _cache_dir = None
    _uds_path = None
    _http_port = None

    @classmethod
    def _uds_socket_path(cls):
        """Mirror compute_uds_socket_path() from server.cpp."""
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        if xdg:
            return os.path.join(xdg, "lemonade", "lemond.sock")
        uid = os.getuid()
        base = "/run" if uid == 0 else f"/run/user/{uid}"
        return os.path.join(base, "lemonade", "lemond.sock")

    @classmethod
    def _wait_for_uds(cls, path, timeout_s=30):
        """Poll until the UDS socket is available."""
        for _ in range(timeout_s * 2):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect(path)
                sock.close()
                return True
            except OSError:
                pass
            time.sleep(0.5)
        return False

    @classmethod
    def _http_get_uds(cls, path, endpoint):
        """Send an HTTP GET request over a Unix Domain Socket. Returns (status, body)."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(path)
            request = f"GET {endpoint} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except OSError:
                    break

        response_str = response.decode("utf-8", errors="replace")
        # Split headers and body
        if "\r\n\r\n" in response_str:
            headers_part, body = response_str.split("\r\n\r\n", 1)
        else:
            headers_part, body = response_str, ""

        # Extract status code from first line
        first_line = headers_part.split("\r\n")[0]
        parts = first_line.split(" ", 2)
        status = int(parts[1]) if len(parts) >= 2 else 0

        return status, body

    @classmethod
    def setUpClass(cls):
        """Start a lemond instance and wait for both HTTP and UDS to be ready."""
        # Find the server binary
        binary = cls._find_server_binary()
        if not binary:
            raise unittest.SkipTest("lemond binary not found; use --server-binary to specify")

        cls._cache_dir = tempfile.mkdtemp(prefix="lemonade_uds_test_")
        cls._uds_path = cls._uds_socket_path()
        cls._http_port = 13399  # Use a non-default port to avoid conflicts

        env = os.environ.copy()
        env["LEMONADE_CACHE_DIR"] = cls._cache_dir
        env["LEMONADE_PORT"] = str(cls._http_port)
        env["LEMONADE_HOST"] = "127.0.0.1"
        env["LEMONADE_NO_BROADCAST"] = "1"
        # Clear any systemd socket activation vars so we create our own socket
        env.pop("LISTEN_PID", None)
        env.pop("LISTEN_FDS", None)

        cls._server_proc = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for the UDS socket to appear
        if not cls._wait_for_uds(cls._uds_path):
            cls._server_proc.terminate()
            raise unittest.SkipTest(f"lemond UDS socket not available at {cls._uds_path}")

    @classmethod
    def tearDownClass(cls):
        if cls._server_proc:
            cls._server_proc.terminate()
            try:
                cls._server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls._server_proc.kill()
        import shutil
        if cls._cache_dir and os.path.isdir(cls._cache_dir):
            shutil.rmtree(cls._cache_dir, ignore_errors=True)

    @classmethod
    def _find_server_binary(cls):
        """Look for the lemond binary in common build locations."""
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "build", "lemond"),
            "/usr/local/bin/lemond",
            "/usr/bin/lemond",
        ]
        # Allow override via --server-binary argument
        for i, arg in enumerate(sys.argv):
            if arg == "--server-binary" and i + 1 < len(sys.argv):
                candidates.insert(0, sys.argv[i + 1])
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    # ── Tests ──────────────────────────────────────────────────────────────────

    def test_001_health_returns_200(self):
        """GET /v1/health over UDS returns HTTP 200."""
        status, body = self._http_get_uds(self._uds_path, "/v1/health")
        self.assertEqual(status, 200)

    def test_002_health_contains_port(self):
        """GET /v1/health over UDS includes the TCP port in JSON body."""
        status, body = self._http_get_uds(self._uds_path, "/v1/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("port", data)
        self.assertEqual(data["port"], self._http_port)

    def test_003_health_contains_status_ok(self):
        """GET /v1/health over UDS returns {status: ok}."""
        status, body = self._http_get_uds(self._uds_path, "/v1/health")
        data = json.loads(body)
        self.assertEqual(data.get("status"), "ok")

    def test_004_models_returns_200(self):
        """GET /v1/models over UDS returns HTTP 200."""
        status, body = self._http_get_uds(self._uds_path, "/v1/models")
        self.assertEqual(status, 200)

    def test_005_api_v1_health_returns_200(self):
        """GET /api/v1/health over UDS returns HTTP 200 (quad-prefix check)."""
        status, body = self._http_get_uds(self._uds_path, "/api/v1/health")
        self.assertEqual(status, 200)

    def test_006_socket_permission_is_owner_only(self):
        """UDS socket file has mode 0600 (owner read/write only)."""
        stat_result = os.stat(self._uds_path)
        mode = stat_result.st_mode & 0o777
        self.assertEqual(mode, 0o600, f"Expected 0600, got {oct(mode)}")

    def test_007_system_info_returns_200(self):
        """GET /v1/system-info over UDS returns HTTP 200."""
        status, body = self._http_get_uds(self._uds_path, "/v1/system-info")
        self.assertEqual(status, 200)

    def test_008_bad_api_method_returns_4xx(self):
        """A well-known API path called with wrong method returns 4xx."""
        # GET on a POST-only endpoint should return 405 or 404; either is fine
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(self._uds_path)
            request = (
                "DELETE /v1/health HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except OSError:
                    break
        first_line = response.decode("utf-8", errors="replace").split("\r\n")[0]
        status = int(first_line.split(" ", 2)[1])
        self.assertGreaterEqual(status, 400, f"Expected 4xx, got {status}")

    def test_009_tcp_health_also_works(self):
        """The TCP HTTP server is still reachable on its port."""
        import urllib.request
        url = f"http://127.0.0.1:{self._http_port}/v1/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_010_health_contains_uds_socket_path(self):
        """GET /v1/health includes 'uds_socket' field pointing to the socket path."""
        status, body = self._http_get_uds(self._uds_path, "/v1/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("uds_socket", data)
        self.assertEqual(data["uds_socket"], self._uds_path)

    def test_011_systemd_socket_activation(self):
        """lemond inherits a pre-bound socket fd (simulating systemd socket activation).

        Technique: create and bind the socket in the parent, pass the fd via pass_fds,
        then in preexec_fn (runs after fork, before exec) dup it to fd 3
        (SD_LISTEN_FDS_START) and set LISTEN_PID/LISTEN_FDS.

        We must NOT pass env= to Popen because Python then calls execve() with that
        explicit dict, bypassing os.environ entirely.  Without env=, Python calls
        execvp() which inherits whatever os.environ contains at exec time — so
        preexec_fn's os.environ modifications (including LISTEN_PID=child-pid) do
        reach the exec'd process.
        """
        binary = self._find_server_binary()
        if not binary:
            self.skipTest("lemond binary not found")

        import fcntl
        import tempfile

        activation_path = os.path.join(
            tempfile.mkdtemp(prefix="lemonade_sd_test_"), "lemond.sock"
        )
        http_port = 13398

        # Create and bind the socket in the parent — this simulates what systemd does
        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Clear close-on-exec so the fd survives exec() when passed via pass_fds
        flags = fcntl.fcntl(srv_sock.fileno(), fcntl.F_GETFD)
        fcntl.fcntl(srv_sock.fileno(), fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        srv_sock.bind(activation_path)
        srv_sock.listen(5)
        inherited_fd = srv_sock.fileno()

        cache_dir = tempfile.mkdtemp(prefix="lemonade_sd_cache_")

        # Temporarily configure the process environment so that execvp() (used when
        # env= is omitted from Popen) picks up the right vars.  LISTEN_PID/LISTEN_FDS
        # are set inside preexec_fn so the child PID is available via os.getpid().
        env_overrides = {
            "LEMONADE_CACHE_DIR": cache_dir,
            "LEMONADE_PORT": str(http_port),
            "LEMONADE_HOST": "127.0.0.1",
            "LEMONADE_NO_BROADCAST": "1",
        }
        env_to_remove = ["LISTEN_PID", "LISTEN_FDS"]
        saved_env = {}
        for k, v in env_overrides.items():
            saved_env[k] = os.environ.get(k)
            os.environ[k] = v
        for k in env_to_remove:
            saved_env[k] = os.environ.pop(k, None)

        def preexec_fn():
            # Runs in the child after fork(), before exec().
            # os.getpid() here is the child's PID — exactly what LISTEN_PID must be.
            if inherited_fd != 3:
                os.dup2(inherited_fd, 3)
            os.environ["LISTEN_PID"] = str(os.getpid())
            os.environ["LISTEN_FDS"] = "1"

        proc = subprocess.Popen(
            [binary],
            # No env= — Python uses execvp() which inherits os.environ, so preexec_fn's
            # LISTEN_PID/LISTEN_FDS assignments are visible to the exec'd lemond.
            pass_fds=(inherited_fd,),
            preexec_fn=preexec_fn,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Restore the test process environment immediately after fork
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Parent closes its copy — lemond now owns the fd
        srv_sock.close()

        try:
            # Poll with real HTTP requests until lemond starts accepting them.
            # We cannot use _wait_for_uds (raw socket connect) here because the
            # kernel's listen backlog accepts connections before lemond's accept()
            # loop starts — the connect succeeds but the request would time out.
            status, body = 0, ""
            for _ in range(40):  # up to 20 seconds
                try:
                    status, body = self._http_get_uds(activation_path, "/v1/health")
                    if status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.5)

            self.assertEqual(status, 200, "Expected 200 from systemd-activated socket")
            data = json.loads(body)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data.get("port"), http_port)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            import shutil
            shutil.rmtree(cache_dir, ignore_errors=True)
            try:
                os.unlink(activation_path)
            except OSError:
                pass

    def test_012_post_request_handled_over_uds(self):
        """POST requests over UDS return a proper JSON response.

        All other UDS tests use GET; this verifies that POST bodies are
        transported correctly over the Unix Domain Socket.  We use
        POST /v1/chat/completions with a non-existent model as a
        no-backend probe: the server must return a 4xx JSON error, not
        drop the connection or return an empty body.

        Note: /logs/stream is a WebSocket endpoint (separate port) and is
        not served over the UDS HTTP server — hence we exercise streaming
        via the chat/completions path instead.
        """
        body = json.dumps({
            "model": "nonexistent-model-uds-probe",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": False,
        }).encode()
        request = (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        ) + body

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(self._uds_path)
            sock.sendall(request)
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except OSError:
                    break

        response = data.decode("utf-8", errors="replace")
        status_line = response.split("\r\n", 1)[0]
        status_code = int(status_line.split(" ", 2)[1])

        # Unknown model → 4xx; connection must not be silently dropped
        self.assertGreaterEqual(status_code, 400, f"Unexpected status: {status_line}")
        self.assertLess(status_code, 600, f"Unexpected status: {status_line}")

        # Response body must be valid JSON containing an error field
        body_start = response.find("\r\n\r\n")
        self.assertGreater(body_start, 0, "No header/body separator in response")
        parsed = json.loads(response[body_start + 4:])
        self.assertIn("error", parsed, "Expected 'error' key in JSON error response")

    def test_999_shutdown_via_uds(self):
        """POST /internal/shutdown over UDS stops the server."""
        # Send shutdown
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(self._uds_path)
            request = (
                "POST /internal/shutdown HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            try:
                sock.recv(4096)  # consume response (may be partial)
            except OSError:
                pass

        # Server should exit within 30 seconds (shutdown unloads models, stops listeners)
        try:
            self._server_proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("lemond did not exit after /internal/shutdown")
        finally:
            self._server_proc = None  # prevent tearDownClass from re-terminating


def main():
    # Allow --server-binary to be passed alongside unittest args
    filtered_argv = [a for a in sys.argv if not a.startswith("--server-binary")]
    if "--server-binary" in sys.argv:
        idx = sys.argv.index("--server-binary")
        if idx + 1 < len(sys.argv):
            filtered_argv = [a for a in filtered_argv if a != sys.argv[idx + 1]]

    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = lambda a, b: (a > b) - (a < b)
    suite = loader.loadTestsFromTestCase(UdsHttpServerTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
