#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
admin_panel.py — TUI-админ-панель к серверу messenger-server.

Не лезет в БД напрямую. Подключается по штатному бинарному протоколу
от имени admin-аккаунта и пользуется командами:
    USER_LIST, USER_BLOCK, USER_UNBLOCK, CERT_REVOKE,
    LOG_QUERY, ADMIN_STATS.

Раскладка:
    ┌── Stats ──────────────────────────────────────────────┐
    │  users  online  blocked  events/24h  CRL              │
    ├── Users (live) ──────────────┬── Event Log (live) ────┤
    │ id  name      role  online   │  HH:MM:SS uid  type    │
    │  …                           │  …                     │
    └──────────────────────────────┴────────────────────────┘
                  [B]lock [U]nblock [R]evoke [Q]uit

Запуск:
    pip install rich cryptography
    python3 admin_panel.py --host 127.0.0.1 --port 9000 \\
                           --user admin --password adminpass

Hotkeys работают только при запуске в обычном TTY (не в pipe).
В режиме без TTY панель просто живёт в read-only — обновляется,
но не принимает ввод (можно использовать как «монитор» рядом с сервером).
"""

import argparse
import binascii
import json
import os
import socket
import struct
import sys
import threading
import time
import zlib
from datetime import datetime
from queue import Queue, Empty
from typing import Any, Optional

# ── rich ─────────────────────────────────────────────────────
try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
except ImportError:
    sys.stderr.write("[!] Нужен пакет rich:  pip install rich\n")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write("[!] Нужен пакет cryptography:  pip install cryptography\n")
    sys.exit(1)


# ── протокол (1:1 с protocol.h) ──────────────────────────────
MAGIC = 0xABCD
PROTO_VERSION = 1
HEADER_SIZE = 14
CHECKSUM_SIZE = 4

CMD = {
    "AUTH_REQ":         0x01, "AUTH_RESP":        0x02,
    "REG_REQ":          0x03, "REG_RESP":         0x04,
    "MSG_DELIVER":      0x11, "MSG_ACK":          0x12,
    "PING":             0x30, "PONG":             0x31,
    "USER_BLOCK":       0x40, "USER_UNBLOCK":     0x41,
    "CERT_REVOKE":      0x42,
    "USER_LIST":        0x73, "USER_LIST_RESP":   0x74,
    "LOG_QUERY":        0x80, "LOG_RESP":         0x81,
    "ADMIN_STATS":      0x82, "ADMIN_STATS_RESP": 0x83,
    "ERR":              0xFF,
}
CMD_NAME = {v: k for k, v in CMD.items()}

FLAG_COMPRESSED = 0x0001
FLAG_ENCRYPTED  = 0x0002


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def build_packet(cmd: int, request_id: int, payload: bytes, flags: int = 0) -> bytes:
    total_len = HEADER_SIZE + len(payload) + CHECKSUM_SIZE
    header = struct.pack("!HI B B I H", MAGIC, total_len, PROTO_VERSION, cmd, request_id, flags)
    data = header + payload
    return data + struct.pack("!I", crc32(data))


def parse_packet(data: bytes) -> Optional[dict]:
    if len(data) < HEADER_SIZE + CHECKSUM_SIZE:
        return None
    magic, total_len, ver, cmd, req_id, flags = struct.unpack_from("!HI B B I H", data)
    if magic != MAGIC or ver != PROTO_VERSION or total_len != len(data):
        return None
    payload = data[HEADER_SIZE:total_len - CHECKSUM_SIZE]
    stored = struct.unpack_from("!I", data, total_len - CHECKSUM_SIZE)[0]
    if stored != crc32(data[:total_len - CHECKSUM_SIZE]):
        return None
    return {"cmd": cmd, "request_id": req_id, "flags": flags, "payload": payload}


def aes_gcm_decrypt(payload: bytes, key: bytes) -> bytes:
    """Совместимо с серверным форматом (IV(12) + ciphertext + tag(16))."""
    if not key or len(payload) < 28:
        return payload
    iv = payload[:12]
    rest = payload[12:]
    aes = AESGCM(key)
    try:
        return aes.decrypt(iv, rest, None)
    except Exception:
        # Альтернативный порядок: IV + tag + ciphertext
        try:
            tag = rest[:16]; ct = rest[16:]
            return aes.decrypt(iv, ct + tag, None)
        except Exception as e:
            raise RuntimeError(f"AES-GCM decrypt failed: {e}")


def maybe_decompress(data: bytes) -> bytes:
    if len(data) > 4:
        try:
            return zlib.decompress(data[4:])  # 4-байтный prefix size
        except zlib.error:
            pass
    try:
        return zlib.decompress(data)
    except zlib.error:
        return data


# ── Клиентская часть для admin ───────────────────────────────
class AdminClient:
    """Тонкий клиент: запросы request/response через очередь ожиданий."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.session_key: Optional[bytes] = None
        self.user_id: Optional[int] = None
        self.req = 0
        self._buf = b""
        self._lock = threading.Lock()
        self._waiters: dict[int, Queue] = {}
        self._running = False
        self._reader: Optional[threading.Thread] = None
        # Колбэки на серверные пуши (логи), пока не используются — но место есть
        self.on_disconnect = None

    # --- low-level ---
    def _next_id(self) -> int:
        self.req += 1
        return self.req

    def _send(self, cmd: int, payload_dict: Any, rid: Optional[int] = None) -> int:
        if rid is None:
            rid = self._next_id()
        body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8") if payload_dict is not None else b""
        with self._lock:
            self.sock.sendall(build_packet(cmd, rid, body))
        return rid

    def _decode_payload(self, p: dict) -> Any:
        data = p["payload"]
        flags = p["flags"]
        if not data:
            return {}
        if flags & FLAG_ENCRYPTED:
            if not self.session_key:
                return {"_error": "no_key"}
            try:
                data = aes_gcm_decrypt(data, self.session_key)
            except Exception as e:
                return {"_error": f"decrypt: {e}"}
        if flags & FLAG_COMPRESSED:
            data = maybe_decompress(data)
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                return data

    # --- reader thread ---
    def _reader_loop(self):
        while self._running:
            try:
                if len(self._buf) >= HEADER_SIZE:
                    if struct.unpack_from("!H", self._buf, 0)[0] == MAGIC:
                        tl = struct.unpack_from("!I", self._buf, 2)[0]
                        if 0 < tl <= len(self._buf):
                            raw = self._buf[:tl]
                            self._buf = self._buf[tl:]
                            p = parse_packet(raw)
                            if p:
                                self._handle_packet(p)
                            continue
                chunk = self.sock.recv(8192)
                if not chunk:
                    self._running = False
                    if self.on_disconnect:
                        self.on_disconnect()
                    return
                self._buf += chunk
            except Exception:
                self._running = False
                if self.on_disconnect:
                    self.on_disconnect()
                return

    def _handle_packet(self, p: dict):
        cmd = p["cmd"]
        # Сервер шлёт нам PING -> отвечаем PONG, чтобы heartbeat не убил соединение
        if cmd == CMD["PING"]:
            try:
                with self._lock:
                    self.sock.sendall(build_packet(CMD["PONG"], p["request_id"], b""))
            except Exception:
                pass
            return
        # Прочее — это ответы на наши запросы
        rid = p["request_id"]
        q = self._waiters.pop(rid, None)
        if q is not None:
            q.put((cmd, self._decode_payload(p)))

    # --- public ---
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self._running = True
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def close(self):
        self._running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    def request(self, cmd: int, payload: Any, timeout: float = 5.0) -> tuple[int, Any]:
        rid = self._next_id()
        q: Queue = Queue(maxsize=1)
        self._waiters[rid] = q
        self._send(cmd, payload, rid=rid)
        try:
            return q.get(timeout=timeout)
        except Empty:
            self._waiters.pop(rid, None)
            raise TimeoutError(f"no response for cmd=0x{cmd:02x} (rid={rid})")

    def login(self, username: str, password: str) -> bool:
        cmd, resp = self.request(CMD["AUTH_REQ"],
                                 {"username": username, "password": password, "device": "admin-panel"})
        if cmd == CMD["AUTH_RESP"] and isinstance(resp, dict) and resp.get("success"):
            self.user_id = resp.get("user_id")
            sk = resp.get("session_key")
            if sk:
                self.session_key = bytes.fromhex(sk)
            return True
        return False

    # --- admin operations ---
    def get_stats(self) -> dict:
        _, r = self.request(CMD["ADMIN_STATS"], {})
        return r if isinstance(r, dict) else {}

    def list_users(self) -> list[dict]:
        _, r = self.request(CMD["USER_LIST"], {})
        if isinstance(r, dict):
            return r.get("users", [])
        return []

    def query_logs(self, limit: int = 50, user_id: Optional[int] = None,
                   type_filter: Optional[str] = None) -> list[dict]:
        payload = {"limit": limit}
        if user_id is not None:
            payload["user_id"] = user_id
        if type_filter:
            payload["type"] = type_filter
        _, r = self.request(CMD["LOG_QUERY"], payload)
        if isinstance(r, dict):
            return r.get("entries", [])
        return []

    def block(self, user_id: int) -> bool:
        _, r = self.request(CMD["USER_BLOCK"], {"user_id": user_id})
        return r == "blocked" or (isinstance(r, dict) and r.get("success", False))

    def unblock(self, user_id: int) -> bool:
        _, r = self.request(CMD["USER_UNBLOCK"], {"user_id": user_id})
        return r == "unblocked" or (isinstance(r, dict) and r.get("success", False))

    def revoke(self, username: str) -> bool:
        _, r = self.request(CMD["CERT_REVOKE"], {"username": username})
        return isinstance(r, dict) and r.get("success", False)


# ── TUI ──────────────────────────────────────────────────────
class AdminTUI:
    REFRESH_HZ = 2  # обновлений в секунду

    def __init__(self, client: AdminClient):
        self.client = client
        self.console = Console()
        self.users: list[dict] = []
        self.logs: list[dict] = []
        self.stats: dict = {}
        self.last_action: str = ""
        self.last_action_ok: Optional[bool] = None
        self.selected_idx: int = 0
        self._stop = threading.Event()
        self._data_lock = threading.Lock()

    # ── render ──
    def _stats_panel(self) -> Panel:
        s = self.stats
        # Цветной "Online" с процентами
        total = s.get("users_total", 0) or 1
        online = s.get("users_online", 0)
        blocked = s.get("users_blocked", 0)
        admins = s.get("users_admins", 0)
        events_24h = s.get("events_last_24h", 0)
        events_total = s.get("events_total", 0)
        crl = s.get("crl_size", 0)

        t = Table.grid(expand=True, padding=(0, 2))
        for _ in range(7):
            t.add_column(justify="center")
        t.add_row(
            "[bold]Users[/]",   "[bold]Online[/]", "[bold]Blocked[/]",
            "[bold]Admins[/]",  "[bold]Events 24h[/]", "[bold]Events total[/]",
            "[bold]CRL[/]",
        )
        t.add_row(
            f"[cyan]{s.get('users_total', '—')}[/]",
            f"[green]{online}[/]/{s.get('users_total', '—')}",
            f"[red]{blocked}[/]" if blocked else "[dim]0[/]",
            f"[magenta]{admins}[/]",
            f"[yellow]{events_24h}[/]",
            f"[dim]{events_total}[/]",
            f"[red]{crl}[/]" if crl else "[dim]0[/]",
        )
        return Panel(t, title="📊  Stats", border_style="cyan")

    def _users_panel(self) -> Panel:
        t = Table(expand=True, show_lines=False, header_style="bold")
        t.add_column("#", width=3, justify="right", style="dim")
        t.add_column("ID", width=4, justify="right")
        t.add_column("Username")
        t.add_column("Role", width=8)
        t.add_column("Status", width=10)
        t.add_column("Online", width=8, justify="center")

        for i, u in enumerate(self.users):
            pointer = "▶" if i == self.selected_idx else " "
            uid = u.get("id", "?")
            name = u.get("username", "?")
            role = u.get("role", "user")
            blocked = u.get("is_blocked", 0)
            online = u.get("online", False)

            status = "[red]BLOCKED[/]" if blocked else "[green]active[/]"
            online_s = "[green]●[/]" if online else "[dim]○[/]"
            role_s = f"[magenta]{role}[/]" if role == "admin" else role

            row_style = "on grey15" if i == self.selected_idx else ""
            t.add_row(pointer, str(uid), name, role_s, status, online_s, style=row_style)

        return Panel(t, title=f"👥  Users ({len(self.users)})", border_style="blue")

    def _logs_panel(self) -> Panel:
        t = Table(expand=True, show_lines=False, header_style="bold")
        t.add_column("Time", width=8, style="dim")
        t.add_column("UID", width=4, justify="right")
        t.add_column("Event", width=18)
        t.add_column("Details", overflow="fold")

        # logs приходят DESC по id - выводим как есть (свежие сверху)
        for e in self.logs[:30]:
            ts_full = e.get("created_at", "") or ""
            ts = ts_full[-8:] if len(ts_full) >= 8 else ts_full
            uid = e.get("user_id", 0) or 0
            uid_s = "[dim]sys[/]" if not uid else str(uid)
            etype = e.get("event_type", "") or ""
            details = e.get("details", "") or ""

            # Раскраска по типу события
            color = "white"
            if "auth_fail" in etype or "fail" in etype: color = "red"
            elif "auth_success" in etype or "registered" in etype: color = "green"
            elif "blocked" in etype or "revoked" in etype: color = "yellow"
            elif "message_sent" in etype: color = "cyan"
            elif "sync" in etype: color = "magenta"
            t.add_row(ts, uid_s, f"[{color}]{etype}[/]", details)

        return Panel(t, title=f"📜  Event log (last {len(self.logs)})", border_style="green")

    def _help_panel(self) -> Panel:
        if self.last_action_ok is True:
            status_text = f"[green]✓ {self.last_action}[/]"
        elif self.last_action_ok is False:
            status_text = f"[red]✗ {self.last_action}[/]"
        else:
            status_text = f"[dim]{self.last_action}[/]"

        line = Text.from_markup(
            "[bold]↑/↓[/] select   "
            "[bold cyan]B[/]lock   "
            "[bold green]U[/]nblock   "
            "[bold red]R[/]evoke cert   "
            "[bold]L[/]ogs refresh   "
            "[bold]Q[/]uit       "
            f"  {status_text}"
        )
        return Panel(Align.center(line), border_style="dim")

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="stats", size=4),
            Layout(name="body"),
            Layout(name="help", size=3),
        )
        layout["body"].split_row(
            Layout(name="users", ratio=1),
            Layout(name="logs", ratio=1),
        )
        layout["stats"].update(self._stats_panel())
        layout["users"].update(self._users_panel())
        layout["logs"].update(self._logs_panel())
        layout["help"].update(self._help_panel())
        return layout

    # ── data refresh ──
    def _refresh_loop(self):
        """Фон: раз в 2 сек тянем stats/users/logs с сервера."""
        while not self._stop.is_set():
            try:
                stats = self.client.get_stats()
                users = self.client.list_users()
                logs = self.client.query_logs(limit=80)
                with self._data_lock:
                    self.stats = stats
                    self.users = users
                    self.logs = logs
                    if self.selected_idx >= len(self.users):
                        self.selected_idx = max(0, len(self.users) - 1)
            except Exception as e:
                with self._data_lock:
                    self.last_action = f"refresh error: {e}"
                    self.last_action_ok = False
            self._stop.wait(2.0)

    # ── input ──
    def _selected_user(self) -> Optional[dict]:
        with self._data_lock:
            if 0 <= self.selected_idx < len(self.users):
                return dict(self.users[self.selected_idx])
        return None

    def _do_block(self):
        u = self._selected_user()
        if not u:
            return
        ok = self.client.block(int(u["id"]))
        self.last_action = f"block user {u['id']} ('{u['username']}')"
        self.last_action_ok = ok

    def _do_unblock(self):
        u = self._selected_user()
        if not u:
            return
        ok = self.client.unblock(int(u["id"]))
        self.last_action = f"unblock user {u['id']} ('{u['username']}')"
        self.last_action_ok = ok

    def _do_revoke(self):
        u = self._selected_user()
        if not u:
            return
        ok = self.client.revoke(str(u["username"]))
        self.last_action = f"revoke cert of '{u['username']}'"
        self.last_action_ok = ok

    def _input_loop_unix(self, live: Live):
        """Сырой ввод одиночных клавиш (UNIX termios). На Windows — заглушка."""
        if not sys.stdin.isatty():
            return  # без TTY работаем как монитор без ввода
        try:
            import termios, tty, select
        except ImportError:
            return

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not self._stop.is_set():
                r, _, _ = select.select([sys.stdin], [], [], 0.2)
                if not r:
                    continue
                ch = sys.stdin.read(1)
                if ch == "\x1b":  # ESC-последовательность для стрелок
                    rest = sys.stdin.read(2) if select.select([sys.stdin], [], [], 0.05)[0] else ""
                    if rest == "[A":
                        with self._data_lock:
                            self.selected_idx = max(0, self.selected_idx - 1)
                    elif rest == "[B":
                        with self._data_lock:
                            self.selected_idx = min(max(0, len(self.users) - 1), self.selected_idx + 1)
                elif ch in ("q", "Q"):
                    self._stop.set()
                    return
                elif ch in ("b", "B"):
                    self._do_block()
                elif ch in ("u", "U"):
                    self._do_unblock()
                elif ch in ("r", "R"):
                    self._do_revoke()
                elif ch in ("k", "K"):
                    with self._data_lock:
                        self.selected_idx = max(0, self.selected_idx - 1)
                elif ch in ("j", "J"):
                    with self._data_lock:
                        self.selected_idx = min(max(0, len(self.users) - 1), self.selected_idx + 1)
                elif ch in ("l", "L"):
                    self.last_action = "manual refresh"
                    self.last_action_ok = True
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    # ── main ──
    def run(self):
        # Стартовая загрузка, чтобы первый кадр был не пустой
        try:
            self.stats = self.client.get_stats()
            self.users = self.client.list_users()
            self.logs = self.client.query_logs(limit=80)
        except Exception as e:
            self.last_action = f"initial fetch failed: {e}"
            self.last_action_ok = False

        refresher = threading.Thread(target=self._refresh_loop, daemon=True)
        refresher.start()

        with Live(self.render(), console=self.console, refresh_per_second=self.REFRESH_HZ,
                  screen=True) as live:
            input_thread = threading.Thread(target=self._input_loop_unix, args=(live,), daemon=True)
            input_thread.start()
            try:
                while not self._stop.is_set():
                    live.update(self.render())
                    time.sleep(1.0 / self.REFRESH_HZ)
            except KeyboardInterrupt:
                pass
            finally:
                self._stop.set()


# ── entry point ──────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Admin TUI panel for messenger-server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--user", default="admin", help="имя админ-аккаунта")
    ap.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD", "adminpass"),
                    help="пароль (по умолчанию ADMIN_PASSWORD из env или 'adminpass')")
    args = ap.parse_args()

    console = Console()
    console.print(f"[cyan]→ connecting to {args.host}:{args.port}…[/]")
    client = AdminClient(args.host, args.port)
    try:
        client.connect()
    except Exception as e:
        console.print(f"[red]connect failed:[/] {e}")
        return 1

    console.print(f"[cyan]→ login as[/] '{args.user}' …")
    try:
        ok = client.login(args.user, args.password)
    except Exception as e:
        console.print(f"[red]login error:[/] {e}")
        client.close()
        return 1

    if not ok:
        console.print("[red]login failed — wrong credentials or user is not 'admin'[/]")
        client.close()
        return 1

    # Sanity-check: убедимся, что у нас права админа (стучимся в admin-only)
    try:
        s = client.get_stats()
        if "_error" in s or not s:
            console.print("[red]server denied admin operation — your account is probably not 'admin'[/]")
            client.close()
            return 1
    except Exception as e:
        console.print(f"[red]admin check failed:[/] {e}")
        client.close()
        return 1

    console.print(f"[green]✓ admin session established (user_id={client.user_id})[/]")
    time.sleep(0.5)

    tui = AdminTUI(client)
    try:
        tui.run()
    finally:
        client.close()
        console.print("[dim]bye[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())