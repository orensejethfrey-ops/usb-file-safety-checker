import json
import subprocess
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import defender_server


class DefenderServerTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), defender_server.RequestHandler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, payload=None, headers=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request_headers = {"Origin": self.origin}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        request = Request(
            self.origin + path,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=3) as response:
                body = response.read()
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass
                return response.status, body
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_serves_dashboard_from_local_origin(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Microsoft Defender drive scan", body)

    def test_rejects_non_local_origins(self):
        status, payload = self.request(
            "POST",
            "/api/scan",
            {"drive": "E:\\"},
            {"Origin": "https://example.com"},
        )
        self.assertEqual(status, 403)
        self.assertIn("local", payload["error"])

    def test_rejects_invalid_drive_values(self):
        status, payload = self.request("POST", "/api/scan", {"drive": "C:\\folder"})
        self.assertEqual(status, 400)
        self.assertIn("drive letter", payload["error"])

    @mock.patch("defender_server.scan_drive")
    def test_scans_only_a_validated_drive(self, scan_drive):
        scan_drive.return_value = {
            "status": "clean",
            "message": "Defender reported no detections in this scan.",
            "detectionCount": 0,
        }
        status, payload = self.request("POST", "/api/scan", {"drive": "E:\\"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "clean")
        scan_drive.assert_called_once_with("E:\\")

    def test_rejects_unknown_api_routes(self):
        status, _ = self.request("GET", "/api/other")
        self.assertEqual(status, 404)

    @mock.patch("defender_server.get_defender_status")
    def test_status_does_not_expose_local_scanner_paths(self, get_status):
        get_status.return_value = {
            "available": True,
            "scanCommand": r"C:\private\defender\MpCmdRun.exe",
            "drives": [{"path": "E:\\", "label": "Removable drive"}],
        }
        status, payload = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertNotIn("scanCommand", payload)
        self.assertNotIn("private", json.dumps(payload))

    @mock.patch("defender_server._read_scan_threats", return_value=[])
    @mock.patch("defender_server.subprocess.run")
    @mock.patch("defender_server.find_mpcmdrun", return_value=r"C:\Defender\MpCmdRun.exe")
    @mock.patch("defender_server.get_defender_status")
    @mock.patch("defender_server.get_local_drives")
    def test_defender_scan_disables_automatic_remediation(
        self,
        get_drives,
        get_status,
        find_command,
        run,
        read_threats,
    ):
        get_drives.return_value = [{"path": "E:\\", "label": "Removable drive"}]
        get_status.return_value = {"available": True}
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        result = defender_server.scan_drive("E:\\")

        self.assertEqual(result["status"], "clean")
        command = run.call_args.args[0]
        self.assertIn("-DisableRemediation", command)
        self.assertEqual(command[5], "E:\\")
        self.assertEqual(result["detectionCount"], 0)


if __name__ == "__main__":
    unittest.main()
