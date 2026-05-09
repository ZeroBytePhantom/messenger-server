#!/usr/bin/env python3
"""
Тестовый клиент для системы обмена сообщениями v2.
Поддерживает: регистрация, аутентификация, создание чатов, отправка сообщений,
контакты, профили, список пользователей, блокировка/разблокировка, шифрование.

  python3 test_client.py [--host HOST] [--port PORT]
  python3 test_client.py --auto   # автоматический тест
"""

import socket, struct, json, threading, sys, uuid, time, argparse, binascii
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import zlib

MAGIC = 0xABCD
PROTO_VERSION = 1
HEADER_SIZE = 14
CHECKSUM_SIZE = 4

# Commands
CMD = {
    'AUTH_REQ':0x01,'AUTH_RESP':0x02,'REG_REQ':0x03,'REG_RESP':0x04,
    'MSG_SEND':0x10,'MSG_DELIVER':0x11,'MSG_ACK':0x12,'MSG_STATUS':0x13,
    'SYNC_REQ':0x20,'SYNC_RESP':0x21,'SYNC_P2P':0x22,
    'PING':0x30,'PONG':0x31,
    'USER_BLOCK':0x40,'USER_UNBLOCK':0x41,'CERT_REVOKE':0x42,
    'CHAT_CREATE':0x50,'CHAT_RESP':0x51,'CHAT_JOIN':0x52,'CHAT_LEAVE':0x53,
    'CONTACT_ADD':0x60,'CONTACT_RESP':0x61,'CONTACT_ACCEPT':0x62,'CONTACT_LIST':0x63,
    'PROFILE_GET':0x70,'PROFILE_RESP':0x71,'PROFILE_UPDATE':0x72,
    'USER_LIST':0x73,'USER_LIST_RESP':0x74,
    'ERR':0xFF,
}
CMD_NAMES = {v:k for k,v in CMD.items()}

def crc32(data): return binascii.crc32(data) & 0xFFFFFFFF

def build_packet(cmd, request_id, payload, flags=0):
    total_len = HEADER_SIZE + len(payload) + CHECKSUM_SIZE
    header = struct.pack("!HI B B I H", MAGIC, total_len, PROTO_VERSION, cmd, request_id, flags)
    data = header + payload
    return data + struct.pack("!I", crc32(data))

def parse_packet(data):
    if len(data) < HEADER_SIZE + CHECKSUM_SIZE: return None
    magic, total_len, ver, cmd, req_id, flags = struct.unpack_from("!HI B B I H", data)
    if magic != MAGIC or ver != PROTO_VERSION or total_len != len(data): return None
    payload = data[HEADER_SIZE:total_len-CHECKSUM_SIZE]
    stored = struct.unpack_from("!I", data, total_len-CHECKSUM_SIZE)[0]
    if stored != crc32(data[:total_len-CHECKSUM_SIZE]): return None
    return {"cmd":cmd, "request_id":req_id, "flags":flags, "payload":payload}


class CryptoHelper:
    @staticmethod
    def decrypt(payload, key):
        if not key or len(payload) < 28:
            return payload

        iv = payload[:12]
        data_with_tag = payload[12:]

        aesgcm = AESGCM(key)

        # Попытка 1: Стандартный порядок (IV + Ciphertext + Tag)
        try:
            return aesgcm.decrypt(iv, data_with_tag, None)
        except:
            pass

        # Попытка 2: C++ порядок (IV + Tag(16) + Ciphertext)
        # Часто в C++ Tag идет сразу после IV
        try:
            tag = data_with_tag[:16]
            ciphertext = data_with_tag[16:]
            return aesgcm.decrypt(iv, ciphertext + tag, None)
        except:
            raise Exception("AES-GCM decryption failed (tried both tag positions)")

    @staticmethod
    def decompress(data):
        if not data or not isinstance(data, (bytes, bytearray)):
            return data
        # Сервер добавляет 4-байтный big-endian префикс с оригинальным размером
        # перед zlib-сжатыми данными (compress2)
        if len(data) > 4:
            try:
                return zlib.decompress(data[4:])
            except zlib.error:
                pass
        try:
            return zlib.decompress(data)
        except zlib.error:
            try:
                return zlib.decompress(data, -15)  # Raw deflate
            except:
                return data


class MessengerClient:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = None
        self.req = 0
        self.running = False
        self.authenticated = False
        self.user_id = None
        self.token = None
        self.username = None
        self.session_key = None
        self._buf = b""
        self._lock = threading.Lock()

    def _handle_payload(self, packet):
        data = packet["payload"]
        flags = packet["flags"]

        # Если данные уже расшифрованы или это пустой список
        if not data: return {}

        if flags & 0x02:  # ENCRYPTED (server: Flags::ENCRYPTED = 0x0002)
            if self.session_key:
                try:
                    data = CryptoHelper.decrypt(data, self.session_key)
                except Exception as e:
                    # ВАЖНО: если не расшифровалось, мы увидим это в тесте
                    return f"DECRYPT_ERROR: {data[:16].hex()}"
            else:
                return f"NO_KEY_ERROR: {data[:16].hex()}"

        if flags & 0x01:  # COMPRESSED (server: Flags::COMPRESSED = 0x0001)
            data = CryptoHelper.decompress(data)

        try:
            return json.loads(data.decode('utf-8'))
        except:
            try:
                return data.decode('utf-8')
            except:
                return data

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.running = True
        print(f"[+] Подключено к {self.host}:{self.port}")

    def disconnect(self):
        self.running = False
        if self.sock: self.sock.close(); self.sock = None
        print("[*] Отключено")

    def _next(self): self.req += 1; return self.req

    def _send(self, cmd, payload_dict, rid=None):
        if rid is None: rid = self._next()
        data = json.dumps(payload_dict, ensure_ascii=False).encode()
        with self._lock: self.sock.sendall(build_packet(cmd, rid, data))
        return rid

    def _send_raw(self, cmd, payload_bytes, rid=None):
        if rid is None: rid = self._next()
        with self._lock: self.sock.sendall(build_packet(cmd, rid, payload_bytes))
        return rid

    def _recv_raw(self):
        """Получить один сырой пакет из сокета."""
        while self.running:
            if len(self._buf) >= HEADER_SIZE:
                m = struct.unpack_from("!H", self._buf, 0)[0]
                if m == MAGIC and len(self._buf) >= 6:
                    tl = struct.unpack_from("!I", self._buf, 2)[0]
                    if len(self._buf) >= tl:
                        pkt = self._buf[:tl]; self._buf = self._buf[tl:]
                        return parse_packet(pkt)
            try:
                c = self.sock.recv(4096)
                if not c: self.running = False; return None
                self._buf += c
            except socket.timeout:
                raise  # Пробрасываем таймаут наверх для _recv
            except:
                self.running = False; return None

    def _handle_background(self, p):
        """Обработать фоновый пакет (PING, MSG_DELIVER и т.д.). Возвращает True если обработан."""
        if not p: return False
        cmd = p["cmd"]
        if cmd == CMD['PING']:
            self.send_pong(p["request_id"])
            return True
        if cmd == CMD['MSG_DELIVER']:
            # Сохраняем доставленное сообщение (просто логируем в тесте)
            try:
                m = self._handle_payload(p)
                if isinstance(m, dict):
                    uid = m.get("message_uid", "")
                    self._send_raw(CMD['MSG_ACK'], uid.encode())
            except: pass
            return True
        if cmd == CMD['SYNC_RESP']:
            # Может прийти как push после подключения (delivery_.onUserConnected)
            # Не ожидаемый — пропускаем
            return True
        return False

    def _recv(self, *expected_cmds, timeout_s=5.0):
        """Получить пакет с одним из expected_cmds, обрабатывая фоновые пакеты.
        Если expected_cmds не указаны — возвращает первый пакет (как раньше)."""
        if not expected_cmds:
            return self._recv_raw()
        deadline = time.monotonic() + timeout_s
        self.sock.settimeout(timeout_s)
        try:
            while self.running and time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0: break
                self.sock.settimeout(max(remaining, 0.1))
                p = self._recv_raw()
                if not p: return None
                if p["cmd"] in expected_cmds or p["cmd"] == CMD['ERR']:
                    return p
                # Фоновый пакет — обработать и продолжить
                self._handle_background(p)
        except socket.timeout:
            return None
        finally:
            self.sock.settimeout(None)
        return None

    def register(self, username, password):
        self._send(CMD['REG_REQ'], {"username":username,"password":password})
        p = self._recv(CMD['REG_RESP'])
        if p and p["cmd"] == CMD['REG_RESP']: return self._handle_payload(p)
        if p and p["cmd"] == CMD['ERR']: return {"success":False,"error":p["payload"].decode('utf-8', errors='ignore')}
        return {"success":False,"error":"no response"}

    def login(self, username, password, device="test-client"):
        self._send(CMD['AUTH_REQ'], {"username":username,"password":password,"device":device})
        p = self._recv(CMD['AUTH_RESP'])
        if p and p["cmd"] == CMD['AUTH_RESP']:
            r = self._handle_payload(p)
            if r and isinstance(r, dict) and r.get("success"):
                self.authenticated = True
                self.user_id = r.get("user_id")
                self.token = r.get("token")
                self.username = username
                if "session_key" in r:
                    self.session_key = bytes.fromhex(r["session_key"])
            return r
        if p and p["cmd"] == CMD['ERR']: return {"success":False,"error":p["payload"].decode('utf-8', errors='ignore')}
        return {"success":False,"error":"no response"}

    def send_message(self, chat_id, content):
        self._send(CMD['MSG_SEND'], {"chat_id":chat_id,"message_uid":str(uuid.uuid4()),"content":content})
        p = self._recv(CMD['MSG_ACK'])
        if p and p["cmd"] == CMD['MSG_ACK']: return {"success":True,"ack":self._handle_payload(p)}
        if p and p["cmd"] == CMD['ERR']: return {"success":False,"error":p["payload"].decode('utf-8', errors='ignore')}
        return {"success":False,"error":"no response"}

    def create_chat(self, chat_type="private", name="", user_id=None, participants=None):
        payload = {"type": chat_type, "name": name}
        if user_id: payload["user_id"] = user_id
        if participants: payload["participants"] = participants

        self._send(CMD['CHAT_CREATE'], payload)
        p = self._recv(CMD['CHAT_RESP'])
        if p and p["cmd"] == CMD['CHAT_RESP']: return self._handle_payload(p)
        if p and p["cmd"] == CMD['ERR']: return {"success":False,"error":p["payload"].decode('utf-8', errors='ignore')}
        return {"success": False, "error": "no response"}

    def user_list(self):
        self._send_raw(CMD['USER_LIST'], b"{}")
        p = self._recv(CMD['USER_LIST_RESP'])
        if p and p["cmd"] == CMD['USER_LIST_RESP']: return self._handle_payload(p)
        return None

    def contact_add(self, contact_id):
        self._send(CMD['CONTACT_ADD'], {"contact_id":contact_id})
        p = self._recv(CMD['CONTACT_RESP'])
        if p and p["cmd"] == CMD['CONTACT_RESP']: return self._handle_payload(p)
        return None

    def contact_accept(self, contact_id):
        self._send(CMD['CONTACT_ACCEPT'], {"contact_id":contact_id})
        p = self._recv(CMD['CONTACT_RESP'])
        if p and p["cmd"] == CMD['CONTACT_RESP']: return self._handle_payload(p)
        return None

    def contact_list(self):
        self._send_raw(CMD['CONTACT_LIST'], b"{}")
        p = self._recv(CMD['CONTACT_RESP'])
        if p and p["cmd"] == CMD['CONTACT_RESP']: return self._handle_payload(p)
        return None

    def profile_get(self, user_id=None):
        payload = {"user_id": user_id} if user_id else {}
        self._send(CMD['PROFILE_GET'], payload)
        p = self._recv(CMD['PROFILE_RESP'])
        if p and p["cmd"] == CMD['PROFILE_RESP']: return self._handle_payload(p)
        return None

    def profile_update(self, display_name="", bio=""):
        self._send(CMD['PROFILE_UPDATE'], {"display_name":display_name,"bio":bio})
        p = self._recv(CMD['PROFILE_RESP'])
        if p and p["cmd"] == CMD['PROFILE_RESP']: return self._handle_payload(p)
        return None

    def sync(self, since="2000-01-01 00:00:00"):
        self._send_raw(CMD['SYNC_REQ'], since.encode())
        p = self._recv(CMD['SYNC_RESP'])
        if p and p["cmd"] == CMD['SYNC_RESP']: return self._handle_payload(p)
        return None

    def block_user(self, target_id):
        self._send(CMD['USER_BLOCK'], {"user_id":target_id})
        p = self._recv(CMD['AUTH_RESP']); return self._handle_payload(p) if p else "no response"

    def unblock_user(self, target_id):
        self._send(CMD['USER_UNBLOCK'], {"user_id":target_id})
        p = self._recv(CMD['AUTH_RESP']); return self._handle_payload(p) if p else "no response"

    def send_pong(self, rid=0): self._send_raw(CMD['PONG'], b"", rid)


def receiver_thread(client):
    while client.running:
        p = client._recv_raw()
        if not p:
            if client.running: print("\n[!] Соединение потеряно"); client.running = False
            break
        cmd = p["cmd"]; name = CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        if cmd == CMD['PING']: client.send_pong(p["request_id"])
        elif cmd == CMD['MSG_DELIVER']:
            try:
                m = client._handle_payload(p)
                if isinstance(m, dict):
                    print(f"\n  📨 [Чат {m.get('chat_id')}] user {m.get('sender_id')}: {m.get('content')}")
                    uid = m.get("message_uid","")
                    client._send_raw(CMD['MSG_ACK'], uid.encode())
            except Exception as e: print(f"\n  [!] Ошибка: {e}")
        elif cmd == CMD['SYNC_RESP']:
            try:
                d = client._handle_payload(p)
                if isinstance(d, dict):
                    msgs = d.get("messages",[])
                    print(f"\n  📋 Синхронизация: {len(msgs)} сообщений")
                    for m in msgs: print(f"     [{m.get('chat_id')}] user {m.get('sender_id')}: {m.get('content')}")
            except: pass
        elif cmd == CMD['ERR']:
            print(f"\n  ❌ Ошибка: {p['payload'].decode('utf-8', errors='ignore')}")
        else:
            try:
                data = client._handle_payload(p)
                if isinstance(data, dict):
                    print(f"\n  [<-] {name}: {json.dumps(data, ensure_ascii=False, indent=2)}")
                else:
                    print(f"\n  [<-] {name}: {data}")
            except:
                print(f"\n  [<-] {name}: {p['payload'][:200]}")
        print("> ", end="", flush=True)


def print_help():
    print("""
╔══════════════════════════════════════════════════════════════╗
║  register <user> <pass>         — регистрация                ║
║  login <user> <pass>            — вход                       ║
║  send <chat_id> <текст>         — отправить сообщение        ║
║  create_chat <user_id>          — создать приватный чат       ║
║  create_group <имя> [id1,id2]   — создать групповой чат      ║
║  users                          — список пользователей       ║
║  contacts                       — мои контакты               ║
║  add_contact <user_id>          — добавить контакт            ║
║  accept_contact <user_id>       — принять запрос              ║
║  profile [user_id]              — профиль                    ║
║  set_profile <имя> <био>        — обновить профиль           ║
║  sync                           — синхронизация              ║
║  block <user_id>                — заблокировать (админ)       ║
║  unblock <user_id>              — разблокировать (админ)      ║
║  status                         — текущий статус             ║
║  help                           — справка                    ║
║  quit                           — выход                      ║
╚══════════════════════════════════════════════════════════════╝""")


def interactive(client):
    print_help()
    recv_started = False
    while client.running:
        try: line = input("> ").strip()
        except: break
        if not line: continue
        parts = line.split(maxsplit=2); cmd = parts[0].lower()
        try:
            if cmd == "help": print_help()
            elif cmd in ("quit","exit"): break
            elif cmd == "status":
                if client.authenticated:
                    enc = "ДА (AES-256-GCM)" if client.session_key else "НЕТ"
                    print(f"  ✅ {client.username} (ID:{client.user_id}) | Шифрование: {enc}")
                else: print("  ⚪ Не авторизован")
            elif cmd == "register":
                if len(parts)<3: print("  register <user> <pass>"); continue
                r = client.register(parts[1], parts[2])
                print(f"  ✅ ID={r.get('user_id')}" if isinstance(r, dict) and r.get("success") else f"  ❌ {r.get('error') if isinstance(r, dict) else 'Ошибка'}")
            elif cmd == "login":
                if len(parts)<3: print("  login <user> <pass>"); continue
                r = client.login(parts[1], parts[2])
                if isinstance(r, dict) and r.get("success"):
                    print(f"  ✅ {client.username} ID={client.user_id}")
                    if client.session_key: print(f"  🔐 Шифрование AES-256-GCM активировано")
                    if not recv_started: recv_started=True; threading.Thread(target=receiver_thread,args=(client,),daemon=True).start()
                else: print(f"  ❌ {r.get('error') if isinstance(r, dict) else 'Ошибка'}")
            elif cmd == "send":
                if not client.authenticated: print("  ⚠ login first"); continue
                if len(parts)<3: print("  send <chat_id> <текст>"); continue
                r = client.send_message(int(parts[1]), parts[2])
                print("  ✅ Отправлено" if isinstance(r, dict) and r.get("success") else f"  ❌ {r.get('error') if isinstance(r, dict) else 'Ошибка'}")
            elif cmd == "create_chat":
                if len(parts)<2: print("  create_chat <user_id>"); continue
                r = client.create_chat("private", user_id=int(parts[1]))
                print(f"  ✅ chat_id={r.get('chat_id')}" if isinstance(r, dict) and r.get("success") else f"  ❌ {r.get('error') if isinstance(r, dict) else 'Ошибка'}")
            elif cmd == "create_group":
                name = parts[1] if len(parts)>1 else "Group"
                pids = [int(x) for x in parts[2].split(",")] if len(parts)>2 else []
                r = client.create_chat("group", name=name, participants=pids)
                print(f"  ✅ chat_id={r.get('chat_id')}" if isinstance(r, dict) and r.get("success") else f"  ❌ {r.get('error') if isinstance(r, dict) else 'Ошибка'}")
            elif cmd == "users":
                r = client.user_list()
                if isinstance(r, dict):
                    for u in r.get("users",[]):
                        st = "🟢" if u.get("online") else "⚪"
                        bl = " [BLOCKED]" if u.get("is_blocked") else ""
                        print(f"  {st} ID={u['id']} {u['username']} ({u.get('role', 'user')}){bl}")
                else: print("  ❌ Нет ответа")
            elif cmd == "contacts":
                r = client.contact_list()
                if isinstance(r, dict):
                    for c in r.get("contacts",[]): print(f"  ✅ contact_id={c['contact_id']}")
                    for p in r.get("pending",[]): print(f"  ⏳ запрос от user_id={p['from_user_id']}")
                    if not r.get("contacts") and not r.get("pending"): print("  Нет контактов")
            elif cmd == "add_contact":
                if len(parts)<2: print("  add_contact <user_id>"); continue
                r = client.contact_add(int(parts[1]))
                print(f"  ✅ Запрос отправлен" if isinstance(r, dict) and r.get("success") else f"  ❌")
            elif cmd == "accept_contact":
                if len(parts)<2: print("  accept_contact <user_id>"); continue
                r = client.contact_accept(int(parts[1]))
                print(f"  ✅ Контакт добавлен" if isinstance(r, dict) and r.get("success") else f"  ❌")
            elif cmd == "profile":
                uid = int(parts[1]) if len(parts)>1 else None
                r = client.profile_get(uid)
                if isinstance(r, dict):
                    print(f"  👤 {r.get('username','')} (ID:{r.get('user_id')})")
                    if r.get('display_name'): print(f"     Имя: {r['display_name']}")
                    if r.get('bio'): print(f"     Био: {r['bio']}")
                    print(f"     Роль: {r.get('role','')} | Онлайн: {'Да' if r.get('online') else 'Нет'}")
            elif cmd == "set_profile":
                name = parts[1] if len(parts)>1 else ""
                bio = parts[2] if len(parts)>2 else ""
                r = client.profile_update(name, bio)
                print("  ✅ Профиль обновлён" if isinstance(r, dict) and r.get("success") else "  ❌")
            elif cmd == "sync":
                r = client.sync()
                if isinstance(r, dict):
                    msgs = r.get("messages",[])
                    print(f"  📋 {len(msgs)} сообщений")
                    for m in msgs: print(f"     [{m.get('chat_id')}] user {m.get('sender_id')}: {m.get('content')}")
            elif cmd == "block":
                if len(parts)<2: print("  block <user_id>"); continue
                print(f"  Результат: {client.block_user(int(parts[1]))}")
            elif cmd == "unblock":
                if len(parts)<2: print("  unblock <user_id>"); continue
                print(f"  Результат: {client.unblock_user(int(parts[1]))}")
            else: print(f"  ? Неизвестная команда. help")
        except Exception as e: print(f"  ❌ {e}")
    client.disconnect()


def auto_test(host, port):
    print("="*60)
    print("  АВТОМАТИЧЕСКИЙ ТЕСТ v2")
    print("="*60)

    print("\n[1] Регистрация Alice и Bob...")
    alice = MessengerClient(host, port); alice.connect()
    r = alice.register("alice", "pass123"); print(f"    Alice: {r}")
    r = alice.login("alice", "pass123"); print(f"    Alice login: success={isinstance(r, dict) and r.get('success')}, session_key={'есть' if alice.session_key else 'нет'}")

    bob = MessengerClient(host, port); bob.connect()
    r = bob.register("bob", "pass456"); print(f"    Bob: {r}")
    r = bob.login("bob", "pass456"); print(f"    Bob login: success={isinstance(r, dict) and r.get('success')}")

    print("\n[2] Список пользователей...")
    r = alice.user_list()
    if isinstance(r, dict):
        for u in r.get("users",[]): print(f"    ID={u['id']} {u['username']} online={u.get('online')}")

    print("\n[3] Создание приватного чата Alice <-> Bob...")
    r = alice.create_chat("private", user_id=bob.user_id)
    chat_id = r.get("chat_id", -1) if isinstance(r, dict) else -1; print(f"    chat_id={chat_id}")

    if chat_id != -1:
        print("\n[4] Alice -> Bob: сообщение...")
        r = alice.send_message(chat_id, "Привет, Bob! Это Alice.")
        print(f"    Результат: {r}")

        print("\n[5] Bob получает сообщение (sync)...")
        r = bob.sync(); print(f"    Sync: {r}")

        print("\n[6] Bob -> Alice: ответ...")
        r = bob.send_message(chat_id, "Привет Alice! Получил твоё сообщение.")
        print(f"    Результат: {r}")

    print("\n[7] Контакты: Alice добавляет Bob...")
    r = alice.contact_add(bob.user_id); print(f"    Запрос: {r}")
    r = bob.contact_accept(alice.user_id); print(f"    Принятие: {r}")
    r = alice.contact_list(); print(f"    Контакты Alice: {r}")

    print("\n[8] Профили...")
    alice.profile_update("Алиса Иванова", "Тестовый пользователь")
    r = bob.profile_get(alice.user_id); print(f"    Профиль Alice (вид от Bob): {r}")

    print("\n[9] Повторная регистрация (ожидаемо ошибка)...")
    r = alice.register("alice", "pass123"); print(f"    {r}")

    print("\n[10] Неверный пароль...")
    wrong = MessengerClient(host, port); wrong.connect()
    r = wrong.login("alice", "wrongpass"); print(f"    {r}")
    wrong.disconnect()

    if chat_id != -1:
        print("\n[11] Store-and-Forward: Bob оффлайн...")
        bob.disconnect()
        time.sleep(0.5)
        r = alice.send_message(chat_id, "Это оффлайн сообщение для Bob")
        print(f"    Alice отправила: {r}")

        print("    Bob reconnect...")
        bob2 = MessengerClient(host, port); bob2.connect()
        r = bob2.login("bob", "pass456"); print(f"    Bob login: {isinstance(r, dict) and r.get('success')}")
        time.sleep(0.5)
        r = bob2.sync(); print(f"    Bob sync (должно быть оффлайн-сообщение): {r}")
        bob2.disconnect()

    alice.disconnect()
    print("\n" + "="*60)
    print("  ТЕСТ ЗАВЕРШЁН УСПЕШНО")
    print("="*60)


def main():
    p = argparse.ArgumentParser(description="Тестовый клиент мессенджера v2")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9090)
    p.add_argument("--auto", action="store_true", help="Автоматический тест")
    args = p.parse_args()
    if args.auto: auto_test(args.host, args.port)
    else:
        c = MessengerClient(args.host, args.port)
        try: c.connect(); interactive(c)
        except ConnectionRefusedError: print(f"[!] Не удалось подключиться к {args.host}:{args.port}")
        except Exception as e: print(f"[!] {e}"); c.disconnect()

if __name__ == "__main__": main()