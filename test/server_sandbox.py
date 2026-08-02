#!/usr/bin/env python3
import json
import os
import sys
import unittest
import requests

from utils.server_base import ServerTestBase, run_server_tests
from utils.test_models import PORT


class TestServerSandbox(ServerTestBase):
    def test_sandbox_status_quad_prefixes(self):
        host_url = f"http://localhost:{PORT}"
        prefixes = ["/api/v0", "/api/v1", "/v0", "/v1"]
        for prefix in prefixes:
            url = f"{host_url}{prefix}/system/sandbox"
            resp = requests.get(url, timeout=5)
            self.assertEqual(
                resp.status_code,
                200,
                f"Expected 200 from {prefix}/system/sandbox, got {resp.status_code}",
            )
            data = resp.json()
            self.assertIn("active", data)
            self.assertIn("available", data)
            self.assertIn("nono_path", data)
            self.assertIn("policy", data)

            policy = data["policy"]
            self.assertIn("enabled", policy)
            self.assertIn("engine", policy)
            self.assertIn("block_outbound_network", policy)
            self.assertIn("allow_gpu_devices", policy)

    def test_system_sandbox_hyphen_route(self):
        host_url = f"http://localhost:{PORT}"
        prefixes = ["/api/v0", "/api/v1", "/v0", "/v1"]
        for prefix in prefixes:
            url = f"{host_url}{prefix}/system-sandbox"
            resp = requests.get(url, timeout=5)
            self.assertEqual(
                resp.status_code,
                200,
                f"Expected 200 from {prefix}/system-sandbox, got {resp.status_code}",
            )

    def test_sandbox_policy_defaults(self):
        host_url = f"http://localhost:{PORT}"
        url = f"{host_url}/v1/system/sandbox"
        resp = requests.get(url, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        policy = data["policy"]
        self.assertEqual(policy["engine"], "nono")
        self.assertTrue(policy["block_outbound_network"])
        self.assertTrue(policy["allow_gpu_devices"])


if __name__ == "__main__":
    run_server_tests(TestServerSandbox, "SANDBOX TESTS")
