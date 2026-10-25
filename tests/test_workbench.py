import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from siem.analysis.static import analyze_file  # noqa: E402
from siem.api.server import create_server, parse_named_api_keys  # noqa: E402
from siem.intel.virustotal import HashReputation  # noqa: E402

# Imports an injection API and stores a firewall registry path as UTF-16, like real Windows malware.
SAMPLE = b"MZ" + b"\x00" * 64 + b"WriteProcessMemory\x00CreateRemoteThread\x00\x00\x00" + "SOFTWARE\\WindowsFirewall".encode("utf-16-le")


class CapabilityAnalysisTests(unittest.TestCase):
    def test_capabilities_and_wide_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.exe"
            path.write_bytes(SAMPLE)
            analysis = analyze_file(path)
        self.assertEqual(analysis.capabilities["process-injection"], ["writeprocessmemory", "createremotethread"])
        self.assertIn("security-tampering", analysis.capabilities)
        self.assertIn("SOFTWARE\\WindowsFirewall", analysis.strings)
        self.assertEqual(analysis.classification, "suspicious")


class WorkbenchApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self._environment = mock.patch.dict(os.environ)
        self._environment.start()
        for name in ("VIRUSTOTAL_API_KEY", "OPENAI_API_KEY"):
            os.environ.pop(name, None)
        keys = parse_named_api_keys("alice:analyst-key=analyst,noc:viewer-key=viewer,root:admin-key=admin")
        try:
            self.server = create_server("127.0.0.1", 0, self.root / "siem.db", api_keys=keys)
        except PermissionError:
            self.skipTest("environment does not permit local listening sockets")
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        self._environment.stop()
        self._directory.cleanup()

    def _call(self, path: str, key: str, method: str = "GET", body: dict | None = None) -> dict:
        request = Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                          headers={"X-API-Key": key, "Content-Type": "application/json"})
        with urlopen(request) as response:
            return json.loads(response.read())

    def _status(self, *args) -> int:
        with self.assertRaises(HTTPError) as caught:
            self._call(*args)
        caught.exception.close()
        return caught.exception.code

    def _analyze(self, key: str = "analyst-key") -> dict:
        body = {"filename": "C:\\Users\\bob\\invoice.exe", "content_base64": base64.b64encode(SAMPLE).decode()}
        return self._call("/analyze", key, "POST", body)["analysis"]

    def test_upload_is_analyzed_stored_inert_and_alerted(self) -> None:
        analysis = self._analyze()
        self.assertEqual(analysis["filename"], "invoice.exe")
        self.assertEqual(analysis["classification"], "suspicious")
        self.assertEqual(analysis["analyst"], "alice")
        sample = self.root / "samples" / f"{analysis['sha256']}.sample"
        self.assertEqual(sample.stat().st_mode & 0o777, 0o600)
        alerts = self._call("/alerts?rule=file.suspicious", "viewer-key")["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("process-injection", alerts[0]["reason"])
        self.assertEqual(self._call("/analyses", "viewer-key")["analyses"][0]["sha256"], analysis["sha256"])
        self.assertIn("Capability `process-injection`", self._call(f"/report?sha256={analysis['sha256']}", "viewer-key")["markdown"])

    def test_roles_and_bad_uploads(self) -> None:
        self.assertEqual(self._status("/analyze", "viewer-key", "POST", {"filename": "a", "content_base64": "QQ=="}), 403)
        self.assertEqual(self._status("/analyze", "analyst-key", "POST", {"filename": "a", "content_base64": "not base64!"}), 400)
        self.assertEqual(self._status("/analyze", "analyst-key", "POST", {"filename": "a", "content_base64": ""}), 400)
        sha256 = self._analyze()["sha256"]
        self.assertEqual(self._status(f"/analyses/{sha256}/quarantine", "analyst-key", "POST", {}), 403)
        self.assertEqual(self._status(f"/analyses/{'0' * 64}/quarantine", "admin-key", "POST", {}), 400)

    def test_admin_quarantine_moves_the_sample(self) -> None:
        sha256 = self._analyze()["sha256"]
        record = self._call(f"/analyses/{sha256}/quarantine", "admin-key", "POST", {})["analysis"]
        self.assertTrue(record["quarantined"])
        self.assertEqual(record["quarantined_by"], "root")
        self.assertFalse((self.root / "samples" / f"{sha256}.sample").exists())
        self.assertEqual(len(list((self.root / "quarantine").glob("*.quarantined"))), 1)
        self.assertEqual(self._call("/events?text=quarantined", "viewer-key")["count"], 1)

    def test_indicator_match_on_scan_and_upload(self) -> None:
        sha256 = self._analyze()["sha256"]
        self._call("/iocs", "analyst-key", "POST", {"kind": "sha256", "value": sha256, "source": "abuse.ch", "confidence": 90})
        self.assertEqual(self._call("/iocs", "viewer-key")["indicators"][0]["source"], "abuse.ch")
        self.assertEqual(self._call("/iocs/scan", "analyst-key", "POST", {})["new_alerts"], 1)
        self.assertEqual(self._analyze()["ioc"]["confidence"], 90)
        self.assertEqual(self._status("/iocs", "analyst-key", "POST", {"kind": "bogus", "value": "x"}), 400)

    def test_optional_integrations_report_when_unconfigured(self) -> None:
        sha256 = self._analyze()["sha256"]
        self.assertEqual(self._call("/capabilities", "viewer-key"), {"ai": False, "virustotal": False})
        self.assertEqual(self._status(f"/analyses/{sha256}/virustotal", "analyst-key", "POST", {}), 503)
        self.assertEqual(self._status("/report/ai", "analyst-key", "POST", {}), 503)

    def test_virustotal_lookup_is_cached_and_alerts(self) -> None:
        sha256 = self._analyze()["sha256"]
        os.environ["VIRUSTOTAL_API_KEY"] = "test"
        reputation = HashReputation(sha256=sha256, found=True, malicious=40, total_engines=70, tags=("peexe",))
        with mock.patch("siem.api.workbench.lookup_hash", return_value=reputation) as lookup:
            result = self._call(f"/analyses/{sha256}/virustotal", "analyst-key", "POST", {})["virustotal"]
            self._call(f"/analyses/{sha256}/virustotal", "analyst-key", "POST", {})
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(result["malicious"], 40)
        self.assertEqual(self._call("/alerts?rule=intel.external-reputation", "viewer-key")["alerts"][0]["severity"], "critical")
        self.assertEqual(self._call("/analyses", "viewer-key")["analyses"][0]["virustotal"]["total_engines"], 70)


if __name__ == "__main__":
    unittest.main()
