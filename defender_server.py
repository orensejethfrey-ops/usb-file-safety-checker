#!/usr/bin/env python3
"""Loopback-only bridge for running Microsoft Defender scans on a chosen drive."""

from __future__ import annotations

import ctypes
import glob
import json
import os
import re
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


HOST = "127.0.0.1"
PORT = 8765
ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "index.html"
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:").rstrip("\\/").upper()
SCAN_TIMEOUT_SECONDS = 2 * 60 * 60
POWERSHELL_TIMEOUT_SECONDS = 30
_scan_lock = threading.Lock()


class ScanError(Exception):
    """A Defender scan could not be completed or verified."""


def _run_powershell(command: str, timeout: int = POWERSHELL_TIMEOUT_SECONDS) -> str:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise ScanError("Windows Defender PowerShell commands failed.")
    return completed.stdout.strip()


def find_mpcmdrun() -> str:
    candidates = []
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    default_path = os.path.join(program_files, "Windows Defender", "MpCmdRun.exe")
    if os.path.isfile(default_path):
        candidates.append(default_path)

    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    candidates.extend(
        glob.glob(
            os.path.join(
                program_data,
                "Microsoft",
                "Windows Defender",
                "Platform",
                "*",
                "MpCmdRun.exe",
            )
        )
    )
    candidates = [path for path in candidates if os.path.isfile(path)]
    if not candidates:
        raise ScanError("Microsoft Defender's scan command could not be found.")
    return max(candidates, key=os.path.getmtime)


def get_local_drives() -> list[dict[str, str]]:
    if os.name != "nt":
        return []

    kernel32 = ctypes.windll.kernel32
    kernel32.GetLogicalDrives.restype = ctypes.c_uint32
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint32
    drive_mask = kernel32.GetLogicalDrives()
    drives = []
    for index in range(26):
        if not drive_mask & (1 << index):
            continue
        letter = chr(ord("A") + index)
        root = f"{letter}:\\"
        drive_type = kernel32.GetDriveTypeW(root)
        if drive_type not in (2, 3):
            continue
        drive_id = f"{letter}:"
        if drive_id.upper() == SYSTEM_DRIVE:
            continue
        drives.append({
            "path": root,
            "label": "Removable drive" if drive_type == 2 else "Fixed drive",
        })
    return drives


def get_defender_status() -> dict:
    if os.name != "nt":
        return {"available": False, "error": "The local scanner runs on Windows only."}

    try:
        mpcmdrun = find_mpcmdrun()
        command = (
            "$ErrorActionPreference='Stop'; "
            "$s=Get-MpComputerStatus -ErrorAction Stop; "
            "[pscustomobject]@{ "
            "antivirusEnabled=[bool]$s.AntivirusEnabled; "
            "serviceEnabled=[bool]$s.AMServiceEnabled; "
            "signatureUpdated=$s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') "
            "} | ConvertTo-Json -Compress"
        )
        status_text = _run_powershell(command)
        status = json.loads(status_text)
        if not status.get("antivirusEnabled") or not status.get("serviceEnabled"):
            return {
                "available": False,
                "error": "Microsoft Defender Antivirus is not active on this computer.",
                "drives": get_local_drives(),
            }
        return {
            "available": True,
            "engine": "Microsoft Defender",
            "signatureUpdated": status.get("signatureUpdated"),
            "drives": get_local_drives(),
            "remediation": "disabled",
            "scanCommand": mpcmdrun,
        }
    except (OSError, subprocess.TimeoutExpired, ScanError, ValueError, json.JSONDecodeError):
        return {
            "available": False,
            "error": "Could not verify Microsoft Defender. Check Windows Security and try again.",
            "drives": get_local_drives(),
        }


def _read_scan_threats(drive: str) -> list[dict]:
    import base64

    encoded_drive = base64.b64encode(drive.encode("utf-8")).decode("ascii")
    command = (
        "$ErrorActionPreference='Stop'; "
        "$drive=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + encoded_drive
        + "')); "
        "$matches=@(foreach($t in @(Get-MpThreat -ErrorAction Stop)){ "
        "$resources=@($t.Resources | ForEach-Object { "
        "$p=([string]$_ -replace '(?i)^file:','').TrimStart('_'); "
        "$p.StartsWith($drive,[StringComparison]::OrdinalIgnoreCase) "
        "}); "
        "if($resources -contains $true){ "
        "[pscustomobject]@{threatId=$t.ThreatID; "
        "threatName=$t.ThreatName; severity=$t.SeverityID; "
        "isActive=$t.IsActive} } "
        "}); "
        "ConvertTo-Json -InputObject $matches -Compress -Depth 4"
    )
    output = _run_powershell(command)
    if not output:
        return []
    decoded = json.loads(output)
    if isinstance(decoded, dict):
        return [decoded]
    if not isinstance(decoded, list):
        raise ScanError("Microsoft Defender returned an unreadable scan result.")
    return decoded


def scan_drive(drive: str) -> dict:
    if os.name != "nt":
        raise ScanError("The local scanner runs on Windows only.")

    available_drives = {item["path"].upper() for item in get_local_drives()}
    normalized_drive = drive.upper()
    if normalized_drive not in available_drives:
        raise ScanError("That drive is unavailable or cannot be scanned by this app.")
    if normalized_drive.rstrip("\\/") == SYSTEM_DRIVE:
        raise ScanError("Scanning the Windows system drive from this app is not allowed.")

    status = get_defender_status()
    if not status["available"]:
        raise ScanError(status["error"])

    command_path = find_mpcmdrun()
    try:
        completed = subprocess.run(
            [
                command_path,
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                drive,
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ScanError(
            "The Defender scan timed out. Check Windows Security for its current status."
        ) from error
    except OSError as error:
        raise ScanError("Microsoft Defender could not start the drive scan.") from error

    try:
        detections = _read_scan_threats(drive)
    except (OSError, subprocess.TimeoutExpired, ScanError, ValueError, json.JSONDecodeError) as error:
        if completed.returncode != 0:
            raise ScanError("Microsoft Defender reported that the scan did not complete.") from error
        return {
            "status": "unverified",
            "message": (
                "Defender finished the scan, but its detection history could not be checked. "
                "Review Windows Security before using files on this drive."
            ),
            "detectionCount": None,
        }

    if detections:
        message = (
            f"Defender reports {len(detections)} threat"
            f"{'' if len(detections) == 1 else 's'} associated with this drive."
        )
        if completed.returncode != 0:
            message += " The scan did not complete."
        return {
            "status": "detected",
            "message": message,
            "detectionCount": len(detections),
            "detections": detections,
            "remediation": "disabled",
        }

    if completed.returncode != 0:
        raise ScanError("Microsoft Defender reported that the scan did not complete.")

    return {
        "status": "clean",
        "message": "Defender reported no detections in this scan.",
        "detectionCount": 0,
        "remediation": "disabled",
    }


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "USBDefenderLocal/1.0"

    def log_message(self, format_string: str, *args: object) -> None:
        # Do not log request details or local drive information.
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _is_local_request(self) -> bool:
        expected_host = f"{HOST}:{self.server.server_port}"
        if self.headers.get("Host", "").lower() != expected_host.lower():
            return False
        origin = self.headers.get("Origin")
        expected_origin = f"http://{expected_host}"
        return origin is None or origin == expected_origin

    def do_GET(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Only the local app can access this scanner."})
            return

        route = urlsplit(self.path).path
        if route == "/":
            try:
                body = PAGE.read_bytes()
            except OSError:
                self._json(500, {"error": "The local app page could not be read."})
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        if route == "/api/status":
            status = get_defender_status()
            status.pop("scanCommand", None)
            self._json(200 if status["available"] else 503, status)
            return
        self._json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Only the local app can access this scanner."})
            return
        if urlsplit(self.path).path != "/api/scan":
            self._json(404, {"error": "Not found."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
            self._json(415, {"error": "Send the selected USB drive as JSON."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json(400, {"error": "A valid request length is required."})
            return
        if content_length <= 0 or content_length > 4096:
            self._json(413, {"error": "The scan request is invalid or too large."})
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "The scan request is not valid JSON."})
            return
        if not isinstance(payload, dict) or set(payload) != {"drive"}:
            self._json(400, {"error": "Choose one available drive to scan."})
            return
        drive = payload["drive"]
        if not isinstance(drive, str) or not re.fullmatch(r"[A-Za-z]:\\", drive):
            self._json(400, {"error": "Choose a valid drive letter."})
            return
        if not _scan_lock.acquire(blocking=False):
            self._json(409, {"error": "A drive scan is already running."})
            return
        try:
            result = scan_drive(drive)
            self._json(200, result)
        except ScanError as error:
            self._json(500, {"error": str(error)})
        finally:
            _scan_lock.release()


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    if os.name != "nt":
        print("This companion app requires Windows and Microsoft Defender.", file=sys.stderr)
        return 1
    if not PAGE.is_file():
        print("index.html is missing from this folder.", file=sys.stderr)
        return 1

    server = LocalServer((HOST, PORT), RequestHandler)
    url = f"http://{HOST}:{PORT}/"
    print("USB File Safety Checker local companion is running.")
    print(f"Open {url} in your browser.")
    print("Only this PC can connect. Press Ctrl+C here to stop the scanner.")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping the local scanner.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
