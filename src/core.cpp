#include "core.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

using json = nlohmann::json;

namespace msg {

// ── Локальный хелпер для отладочного вывода в консоль ──────
// Используется для наглядной демонстрации работы сервера на защите.
// Формат: [HH:MM:SS.mmm][TAG] сообщение
namespace {
    std::string nowTs() {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto t  = system_clock::to_time_t(now);
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream os;
        os << std::put_time(&tm, "%H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return os.str();
    }

    inline void LOG(const std::string& tag, const std::string& msg) {
        std::cout << '[' << nowTs() << "][" << tag << "] " << msg << std::endl;
    }
    inline void WARN(const std::string& tag, const std::string& msg) {
        std::cerr << '[' << nowTs() << "][" << tag << "][WARN] " << msg << std::endl;
    }

    // Безопасное превью JSON-пейлоада для логов (обрезаем длинные значения)
    std::string previewPayload(const std::string& s, size_t maxLen = 120) {
        if (s.size() <= maxLen) return s;
        return s.substr(0, maxLen) + "...(+" + std::to_string(s.size() - maxLen) + "b)";
    }

    // Расшифровка имени команды для логов
    const char* cmdName(Cmd c) {
        switch (c) {
            case Cmd::AUTH_REQ:       return "AUTH_REQ";
            case Cmd::AUTH_RESP:      return "AUTH_RESP";
            case Cmd::REG_REQ:        return "REG_REQ";
            case Cmd::REG_RESP:       return "REG_RESP";
            case Cmd::MSG_SEND:       return "MSG_SEND";
            case Cmd::MSG_DELIVER:    return "MSG_DELIVER";
            case Cmd::MSG_ACK:        return "MSG_ACK";
            case Cmd::MSG_STATUS:     return "MSG_STATUS";
            case Cmd::SYNC_REQ:       return "SYNC_REQ";
            case Cmd::SYNC_RESP:      return "SYNC_RESP";
            case Cmd::SYNC_P2P:       return "SYNC_P2P";
            case Cmd::PING:           return "PING";
            case Cmd::PONG:           return "PONG";
            case Cmd::CHAT_CREATE:    return "CHAT_CREATE";
            case Cmd::CHAT_JOIN:      return "CHAT_JOIN";
            case Cmd::CHAT_LEAVE:     return "CHAT_LEAVE";
            case Cmd::CHAT_RESP:      return "CHAT_RESP";
            case Cmd::CONTACT_ADD:    return "CONTACT_ADD";
            case Cmd::CONTACT_ACCEPT: return "CONTACT_ACCEPT";
            case Cmd::CONTACT_LIST:   return "CONTACT_LIST";
            case Cmd::CONTACT_RESP:   return "CONTACT_RESP";
            case Cmd::PROFILE_GET:    return "PROFILE_GET";
            case Cmd::PROFILE_UPDATE: return "PROFILE_UPDATE";
            case Cmd::PROFILE_RESP:   return "PROFILE_RESP";
            case Cmd::USER_LIST:      return "USER_LIST";
            case Cmd::USER_LIST_RESP: return "USER_LIST_RESP";
            case Cmd::USER_BLOCK:     return "USER_BLOCK";
            case Cmd::USER_UNBLOCK:   return "USER_UNBLOCK";
            case Cmd::CERT_REVOKE:    return "CERT_REVOKE";
            case Cmd::ERR:            return "ERR";
            default:                  return "UNKNOWN";
        }
    }
} // namespace

// ── PayloadCodec ───────────────────────────────────────────
void PayloadCodec::setKey(const std::string& connId, const Bytes& key) {
    std::lock_guard lk(mu_); keys_[connId] = key;
    LOG("Codec", "session key set for conn=" + connId + " (" + std::to_string(key.size()) + " bytes)");
}
void PayloadCodec::removeKey(const std::string& connId) {
    std::lock_guard lk(mu_); keys_.erase(connId);
    LOG("Codec", "session key removed for conn=" + connId);
}
Bytes PayloadCodec::getKey(const std::string& connId) const {
    std::lock_guard lk(mu_);
    auto it = keys_.find(connId); return it != keys_.end() ? it->second : Bytes{};
}
bool PayloadCodec::hasKey(const std::string& connId) const {
    std::lock_guard lk(mu_); return keys_.count(connId) > 0;
}

Packet PayloadCodec::encode(Packet pkt, const std::string& connId, bool compress) {
    Bytes data = pkt.payload;
    uint16_t flags = pkt.flags;
    size_t origSize = data.size();

    // Compress first (before encryption)
    if (compress && data.size() > 64) {
        auto compressed = Compression::compress(data);
        if (!compressed.empty() && compressed.size() < data.size()) {
            LOG("Codec", std::string("compress ") + cmdName(pkt.type) +
                " " + std::to_string(data.size()) + "B -> " + std::to_string(compressed.size()) + "B");
            data = std::move(compressed);
            flags |= Flags::COMPRESSED;
        }
    }

    // Encrypt
    auto key = getKey(connId);
    if (!key.empty()) {
        auto encrypted = Crypto::encrypt(data, key);
        if (!encrypted.empty()) {
            LOG("Codec", std::string("encrypt ") + cmdName(pkt.type) +
                " conn=" + connId + " " + std::to_string(data.size()) + "B -> " + std::to_string(encrypted.size()) + "B");
            data = std::move(encrypted);
            flags |= Flags::ENCRYPTED;
        }
    } else {
        LOG("Codec", std::string("plain ") + cmdName(pkt.type) +
            " conn=" + connId + " (no session key, " + std::to_string(origSize) + "B)");
    }

    pkt.payload = std::move(data);
    pkt.flags = flags;
    return pkt;
}

Packet PayloadCodec::decode(Packet pkt, const std::string& connId) {
    Bytes data = pkt.payload;

    // Decrypt first
    if (pkt.flags & Flags::ENCRYPTED) {
        auto key = getKey(connId);
        if (!key.empty()) {
            auto decrypted = Crypto::decrypt(data, key);
            if (!decrypted.empty()) {
                LOG("Codec", std::string("decrypt ") + cmdName(pkt.type) +
                    " conn=" + connId + " " + std::to_string(data.size()) + "B -> " + std::to_string(decrypted.size()) + "B");
                data = std::move(decrypted);
                pkt.flags &= ~Flags::ENCRYPTED;
            } else {
                WARN("Codec", "decryption failed for conn=" + connId + " cmd=" + cmdName(pkt.type));
                return pkt; // return as-is, dispatch will see ENCRYPTED flag still set
            }
        } else {
            WARN("Codec", "no key for ENCRYPTED packet conn=" + connId);
        }
    }

    // Decompress
    if (pkt.flags & Flags::COMPRESSED) {
        auto decompressed = Compression::decompress(data);
        if (!decompressed.empty()) {
            LOG("Codec", std::string("decompress ") + cmdName(pkt.type) +
                " " + std::to_string(data.size()) + "B -> " + std::to_string(decompressed.size()) + "B");
            data = std::move(decompressed);
            pkt.flags &= ~Flags::COMPRESSED;
        }
    }

    pkt.payload = std::move(data);
    return pkt;
}

// ── SessionMgr ─────────────────────────────────────────────
void SessionMgr::registerOnline(UserId uid, const std::string& token, const std::string& connId) {
    std::lock_guard lk(mu_);
    user_conn_[uid] = connId; conn_user_[connId] = uid; user_token_[uid] = token;
    LOG("Session", "user " + std::to_string(uid) + " ONLINE on conn=" + connId +
        " (total online=" + std::to_string(user_conn_.size()) + ")");
}
void SessionMgr::registerOffline(UserId uid) {
    std::lock_guard lk(mu_);
    auto it = user_conn_.find(uid);
    if (it != user_conn_.end()) { conn_user_.erase(it->second); user_conn_.erase(it); }
    auto it2 = user_token_.find(uid);
    if (it2 != user_token_.end()) { repo_.deactivate(it2->second); user_token_.erase(it2); }
    LOG("Session", "user " + std::to_string(uid) + " OFFLINE");
}
void SessionMgr::removeByConn(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = conn_user_.find(connId);
    if (it != conn_user_.end()) {
        UserId uid = it->second; user_conn_.erase(uid); conn_user_.erase(it);
        auto it2 = user_token_.find(uid);
        if (it2 != user_token_.end()) { repo_.deactivate(it2->second); user_token_.erase(it2); }
        LOG("Session", "conn=" + connId + " dropped (user " + std::to_string(uid) + " OFFLINE)");
    } else {
        LOG("Session", "conn=" + connId + " dropped (no auth user)");
    }
}
bool SessionMgr::isOnline(UserId uid) const { std::lock_guard lk(mu_); return user_conn_.count(uid) > 0; }
std::optional<std::string> SessionMgr::getConnId(UserId uid) const {
    std::lock_guard lk(mu_);
    auto it = user_conn_.find(uid); return it != user_conn_.end() ? std::optional(it->second) : std::nullopt;
}
std::optional<UserId> SessionMgr::getUserByConn(const std::string& connId) const {
    std::lock_guard lk(mu_);
    auto it = conn_user_.find(connId); return it != conn_user_.end() ? std::optional(it->second) : std::nullopt;
}
void SessionMgr::refresh(const std::string& token) { repo_.updateActive(token); }

// ── CA ─────────────────────────────────────────────────────
bool CA::init(const std::string& key_path, const std::string& cert_path) {
    std::ifstream kf(key_path), cf(cert_path);
    if (kf.good() && cf.good()) return loadCredentials(key_path, cert_path);
    return generateCredentials(key_path, cert_path);
}

bool CA::generateCredentials(const std::string& kp, const std::string& cp) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    EVP_PKEY_CTX_free(ctx);

    X509* x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);
    X509_set_pubkey(x509, pkey);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char*)"MessengerCA", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    FILE* f = fopen(kp.c_str(), "wb");
    if (f) { PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr); fclose(f); }
    f = fopen(cp.c_str(), "wb");
    if (f) { PEM_write_X509(f, x509); fclose(f); }

    server_key_ = pkey; server_cert_ = x509;
    LOG("CA", "generated new server credentials (RSA-2048, self-signed, CN=MessengerCA)");
    return true;
}

bool CA::loadCredentials(const std::string& kp, const std::string& cp) {
    FILE* f = fopen(kp.c_str(), "r");
    if (!f) return false;
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr); fclose(f);
    f = fopen(cp.c_str(), "r");
    if (!f) { EVP_PKEY_free(pkey); return false; }
    X509* x509 = PEM_read_X509(f, nullptr, nullptr, nullptr); fclose(f);
    if (!pkey || !x509) { if (pkey) EVP_PKEY_free(pkey); if (x509) X509_free(x509); return false; }
    server_key_ = pkey; server_cert_ = x509;
    LOG("CA", "loaded server credentials from disk");
    return true;
}

std::pair<Bytes, Bytes> CA::generateKeyPair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx); EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey); EVP_PKEY_CTX_free(ctx);
    Bytes pub, priv;
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len > 0) { pub.resize(len); auto* p = pub.data(); i2d_PUBKEY(pkey, &p); }
    len = i2d_PrivateKey(pkey, nullptr);
    if (len > 0) { priv.resize(len); auto* p = priv.data(); i2d_PrivateKey(pkey, &p); }
    EVP_PKEY_free(pkey);
    return {pub, priv};
}

Bytes CA::signCert(const Bytes& pubkey, const std::string& username) {
    X509* x509 = X509_new(); X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char*)username.c_str(), -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name((X509*)server_cert_));
    const uint8_t* p = pubkey.data();
    EVP_PKEY* user_key = d2i_PUBKEY(nullptr, &p, pubkey.size());
    if (user_key) X509_set_pubkey(x509, user_key);
    X509_sign(x509, (EVP_PKEY*)server_key_, EVP_sha256());
    Bytes cert; int len = i2d_X509(x509, nullptr);
    if (len > 0) { cert.resize(len); auto* pp = cert.data(); i2d_X509(x509, &pp); }
    if (user_key) EVP_PKEY_free(user_key); X509_free(x509);
    LOG("CA", "signed certificate for '" + username + "' (" + std::to_string(cert.size()) + " bytes, valid 365d)");
    return cert;
}

bool CA::verifyCert(const Bytes& cert) {
    const uint8_t* p = cert.data();
    X509* x509 = d2i_X509(nullptr, &p, cert.size());
    if (!x509) return false;
    int ok = X509_verify(x509, (EVP_PKEY*)server_key_); X509_free(x509); return ok == 1;
}
void CA::revoke(const std::string& u) {
    std::lock_guard lk(mu_); revoked_.insert(u);
    LOG("CA", "certificate REVOKED for user '" + u + "' (CRL size=" + std::to_string(revoked_.size()) + ")");
}
bool CA::isRevoked(const std::string& u) const { std::lock_guard lk(mu_); return revoked_.count(u) > 0; }
std::vector<std::string> CA::getRevokedList() const { std::lock_guard lk(mu_); return {revoked_.begin(), revoked_.end()}; }

// ── AuthMgr ────────────────────────────────────────────────
std::string AuthMgr::genSalt() {
    uint8_t buf[16]; RAND_bytes(buf, 16);
    std::ostringstream ss; for (auto b : buf) ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return ss.str();
}
std::string AuthMgr::hashPw(const std::string& pw, const std::string& salt) {
    std::string input = pw + salt; uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t*)input.c_str(), input.size(), hash);
    std::ostringstream ss; for (auto b : hash) ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return ss.str();
}
std::string AuthMgr::genToken() {
    uint8_t buf[32]; RAND_bytes(buf, 32);
    std::ostringstream ss; for (auto b : buf) ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return ss.str();
}

AuthResult AuthMgr::registerUser(const std::string& username, const std::string& password) {
    AuthResult res;
    LOG("Auth", "REGISTER request for username='" + username + "'");
    if (users_.findByName(username)) {
        res.error = "user already exists";
        WARN("Auth", "registration rejected: '" + username + "' already exists");
        return res;
    }
    auto salt = genSalt(); auto hash = hashPw(password, salt);
    auto [pubkey, privkey] = ca_.generateKeyPair();
    auto cert = ca_.signCert(pubkey, username);
    auto id = users_.create(username, hash, salt, pubkey, cert);
    if (id < 0) {
        res.error = "db error";
        WARN("Auth", "registration FAILED for '" + username + "' (db error)");
        return res;
    }
    res.success = true; res.user_id = id; res.certificate = cert;
    log_.log(id, "user_registered", username);
    LOG("Auth", "user '" + username + "' registered with id=" + std::to_string(id) +
        " (cert " + std::to_string(cert.size()) + "B issued)");
    return res;
}

AuthResult AuthMgr::authenticate(const std::string& username, const std::string& password,
                                  const std::string& device) {
    AuthResult res;
    LOG("Auth", "AUTH request username='" + username + "' device='" + device + "'");
    auto user = users_.findByName(username);
    if (!user) {
        res.error = "not found";
        log_.logSystem("auth_fail", username);
        WARN("Auth", "auth failed: user '" + username + "' not found");
        return res;
    }
    if (user->is_blocked) {
        res.error = "blocked";
        log_.log(user->id, "auth_fail", "blocked");
        WARN("Auth", "auth failed: user '" + username + "' is BLOCKED");
        return res;
    }
    auto hash = hashPw(password, user->salt);
    if (hash != user->password_hash) {
        res.error = "wrong password";
        log_.log(user->id, "auth_fail", "bad password");
        WARN("Auth", "auth failed: wrong password for '" + username + "'");
        return res;
    }

    auto token = genToken();
    sessions_.create(user->id, token, device);

    // Generate session encryption key
    res.session_key = Crypto::generateSessionKey();

    res.success = true; res.user_id = user->id; res.token = token;
    res.certificate = user->certificate;
    log_.log(user->id, "auth_success", device);
    LOG("Auth", "user '" + username + "' (id=" + std::to_string(user->id) +
        ") authenticated, token=" + token.substr(0, 8) + "... session_key=" +
        std::to_string(res.session_key.size()) + "B");
    return res;
}

// ── MessageRouter ──────────────────────────────────────────
Result MessageRouter::handleMessage(UserId sender, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"]; std::string msg_uid = j["message_uid"]; std::string content = j["content"];
        LOG("MsgRouter", "MSG from user=" + std::to_string(sender) +
            " chat=" + std::to_string(chat_id) + " uid=" + msg_uid +
            " len=" + std::to_string(content.size()) + "B");
        if (!chats_.isParticipant(chat_id, sender)) {
            WARN("MsgRouter", "user " + std::to_string(sender) + " is NOT a participant of chat " + std::to_string(chat_id));
            return Result::fail("not a participant");
        }
        auto msg_id = msgs_.save(msg_uid, chat_id, sender, content);
        if (msg_id < 0) {
            WARN("MsgRouter", "save failed for uid=" + msg_uid);
            return Result::fail("save failed");
        }
        auto participants = chats_.getParticipants(chat_id);
        int delivered = 0, queued = 0;
        for (auto uid : participants) {
            if (uid == sender) continue;
            if (sessions_.isOnline(uid)) {
                auto deliver = makePacket(Cmd::MSG_DELIVER, pkt.request_id, pkt.payloadStr());
                if (send_) send_(*sessions_.getConnId(uid), deliver);
                msgs_.setStatus(msg_id, uid, "delivered");
                delivered++;
            } else {
                msgs_.enqueue(uid, msg_id);
                msgs_.setStatus(msg_id, uid, "sent");
                queued++;
            }
        }
        log_.log(sender, "message_sent", "chat=" + std::to_string(chat_id));
        LOG("MsgRouter", "message id=" + std::to_string(msg_id) +
            " delivered_online=" + std::to_string(delivered) +
            " queued_offline=" + std::to_string(queued));
        return Result::ok();
    } catch (const std::exception& e) {
        WARN("MsgRouter", std::string("parse error: ") + e.what());
        return Result::fail(std::string("parse error: ") + e.what());
    }
}

// ── DeliveryMgr ────────────────────────────────────────────
void DeliveryMgr::onUserConnected(UserId uid) {
    auto pending = msgs_.getPending(uid);
    auto connId = sessions_.getConnId(uid);
    if (!connId || pending.empty()) {
        if (connId) LOG("Delivery", "user " + std::to_string(uid) + " has no pending messages");
        return;
    }
    LOG("Delivery", "delivering " + std::to_string(pending.size()) +
        " queued message(s) to user " + std::to_string(uid));
    for (auto& sq : pending) {
        auto msg = msgs_.findById(sq.message_id);
        if (!msg) { msgs_.dequeue(sq.id); continue; }
        json j; j["message_uid"] = msg->uid; j["chat_id"] = msg->chat_id;
        j["sender_id"] = msg->sender_id; j["content"] = msg->content; j["created_at"] = msg->created_at;
        auto pkt = makePacket(Cmd::MSG_DELIVER, 0, j.dump());
        if (send_) send_(*connId, pkt);
        msgs_.dequeue(sq.id); msgs_.setStatus(sq.message_id, uid, "delivered");
    }
    log_.log(uid, "sync_completed", "pending=" + std::to_string(pending.size()));
    LOG("Delivery", "delivery complete for user " + std::to_string(uid));
}
void DeliveryMgr::onAck(UserId uid, const std::string& msgUid) {
    auto msg = msgs_.findByUid(msgUid);
    if (msg) {
        msgs_.setStatus(msg->id, uid, "delivered");
        LOG("Delivery", "ACK from user=" + std::to_string(uid) + " msg=" + msgUid);
    }
}
void DeliveryMgr::onRead(UserId uid, const std::string& msgUid) {
    auto msg = msgs_.findByUid(msgUid);
    if (msg) {
        msgs_.setStatus(msg->id, uid, "read");
        LOG("Delivery", "READ from user=" + std::to_string(uid) + " msg=" + msgUid);
    }
}

// ── P2PSyncMgr ─────────────────────────────────────────────
SyncResult P2PSyncMgr::handleP2PSync(UserId uid, const Packet& pkt) {
    SyncResult res;
    try {
        auto arr = json::parse(pkt.payloadStr());
        LOG("P2PSync", "P2P sync from user=" + std::to_string(uid) +
            " items=" + std::to_string(arr.size()));
        for (auto& item : arr) {
            std::string msg_uid = item["message_uid"]; ChatId chat_id = item["chat_id"];
            UserId sender_id = item["sender_id"]; std::string content = item["content"];
            std::string created_at = item.value("created_at", "");
            if (msgs_.exists(msg_uid)) { res.duplicates++; continue; }
            auto user = users_.findById(sender_id);
            if (!user || user->is_blocked) { res.errors++; continue; }
            if (!chats_.isParticipant(chat_id, sender_id)) { res.errors++; continue; }
            auto mid = msgs_.save(msg_uid, chat_id, sender_id, content, "p2p_sync", created_at);
            if (mid < 0) { res.errors++; continue; }
            res.accepted++;
            auto parts = chats_.getParticipants(chat_id);
            for (auto pid : parts) {
                if (pid == uid) continue;
                if (sessions_.isOnline(pid)) {
                    json dj; dj["message_uid"]=msg_uid; dj["chat_id"]=chat_id;
                    dj["sender_id"]=sender_id; dj["content"]=content;
                    if (send_) send_(*sessions_.getConnId(pid), makePacket(Cmd::MSG_DELIVER, 0, dj.dump()));
                } else { msgs_.enqueue(pid, mid); }
            }
        }
    } catch (...) { res.errors++; WARN("P2PSync", "exception during P2P sync processing"); }
    auto connId = sessions_.getConnId(uid);
    if (connId && send_) {
        json resp; resp["accepted"]=res.accepted; resp["duplicates"]=res.duplicates;
        resp["errors"]=res.errors; resp["crl"]=ca_.getRevokedList();
        send_(*connId, makePacket(Cmd::SYNC_RESP, pkt.request_id, resp.dump()));
    }
    log_.log(uid, "sync_completed", "accepted="+std::to_string(res.accepted));
    LOG("P2PSync", "user=" + std::to_string(uid) +
        " accepted=" + std::to_string(res.accepted) +
        " duplicates=" + std::to_string(res.duplicates) +
        " errors=" + std::to_string(res.errors));
    return res;
}

void P2PSyncMgr::handleFullSync(UserId uid, const Packet& pkt) {
    auto connId = sessions_.getConnId(uid); if (!connId) return;
    std::string since = pkt.payloadStr();
    LOG("P2PSync", "FULL sync request user=" + std::to_string(uid) +
        " since='" + (since.empty() ? "<all>" : since) + "'");
    auto chats = chats_.getChatsForUser(uid);
    json msgs_arr = json::array();
    for (auto& chat : chats) {
        auto messages = msgs_.getSince(chat.id, since);
        for (auto& m : messages) {
            json mj; mj["message_uid"]=m.uid; mj["chat_id"]=m.chat_id;
            mj["sender_id"]=m.sender_id; mj["content"]=m.content; mj["created_at"]=m.created_at;
            msgs_arr.push_back(std::move(mj));
        }
    }
    json resp; resp["messages"]=msgs_arr; resp["crl"]=ca_.getRevokedList();
    if (send_) send_(*connId, makePacket(Cmd::SYNC_RESP, pkt.request_id, resp.dump()));
    LOG("P2PSync", "FULL sync sent to user=" + std::to_string(uid) +
        " chats=" + std::to_string(chats.size()) +
        " messages=" + std::to_string(msgs_arr.size()) +
        " crl=" + std::to_string(ca_.getRevokedList().size()));
}

// ── HeartbeatMon (now sends PING) ──────────────────────────
void HeartbeatMon::start(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto& e = entries_[connId];
    e.ping_timer = std::make_shared<boost::asio::steady_timer>(io_);
    e.pong_timer = std::make_shared<boost::asio::steady_timer>(io_);
    LOG("Heartbeat", "started for conn=" + connId +
        " (interval=" + std::to_string(interval_) + "s timeout=" + std::to_string(timeout_) + "s)");
    schedulePing(connId);
}
void HeartbeatMon::stop(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = entries_.find(connId);
    if (it != entries_.end()) {
        it->second.ping_timer->cancel(); it->second.pong_timer->cancel(); entries_.erase(it);
        LOG("Heartbeat", "stopped for conn=" + connId);
    }
}
void HeartbeatMon::onPong(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = entries_.find(connId);
    if (it != entries_.end()) {
        it->second.waiting = false; it->second.pong_timer->cancel();
        LOG("Heartbeat", "PONG received from conn=" + connId);
        schedulePing(connId);
    }
}
void HeartbeatMon::stopAll() {
    std::lock_guard lk(mu_);
    LOG("Heartbeat", "stopping all (" + std::to_string(entries_.size()) + " entries)");
    for (auto& [id, e] : entries_) { e.ping_timer->cancel(); e.pong_timer->cancel(); }
    entries_.clear();
}

void HeartbeatMon::schedulePing(const std::string& connId) {
    auto it = entries_.find(connId); if (it == entries_.end()) return;
    it->second.ping_timer->expires_after(std::chrono::seconds(interval_));
    it->second.ping_timer->async_wait([this, connId](boost::system::error_code ec) {
        if (ec) return;
        // Send PING packet to client
        if (send_) send_(connId, makePacket(Cmd::PING, 0, ""));
        LOG("Heartbeat", "PING -> conn=" + connId);
        std::lock_guard lk(mu_);
        auto it = entries_.find(connId);
        if (it != entries_.end()) { it->second.waiting = true; schedulePongTimeout(connId); }
    });
}

void HeartbeatMon::schedulePongTimeout(const std::string& connId) {
    auto it = entries_.find(connId); if (it == entries_.end()) return;
    it->second.pong_timer->expires_after(std::chrono::seconds(timeout_));
    it->second.pong_timer->async_wait([this, connId](boost::system::error_code ec) {
        if (ec) return;
        std::lock_guard lk(mu_);
        auto it = entries_.find(connId);
        if (it != entries_.end() && it->second.waiting) {
            entries_.erase(it);
            WARN("Heartbeat", "PONG TIMEOUT for conn=" + connId + " - dropping connection");
            if (timeout_cb_) timeout_cb_(connId);
        }
    });
}

// ── Dispatcher ─────────────────────────────────────────────
Dispatcher::Dispatcher(AuthMgr& auth, SessionMgr& sessions, MessageRouter& router,
                       DeliveryMgr& delivery, P2PSyncMgr& sync, HeartbeatMon& heartbeat,
                       ConnectionManager& conns, UserRepo& users, ChatRepo& chats,
                       ContactRepo& contacts, ProfileRepo& profiles, CA& ca,
                       EventLog& log, PayloadCodec& codec)
    : auth_(auth), sessions_(sessions), router_(router), delivery_(delivery),
      sync_(sync), heartbeat_(heartbeat), conns_(conns), users_(users), chats_(chats),
      contacts_(contacts), profiles_(profiles), ca_(ca), log_(log), codec_(codec)
{
    auto sf = [this](const std::string& c, const Packet& p) { sendPacket(c, p); };
    router_.setSend(sf); delivery_.setSend(sf); sync_.setSend(sf); heartbeat_.setSend(sf);
}

void Dispatcher::sendPacket(const std::string& connId, const Packet& pkt) {
    auto encoded = codec_.encode(pkt, connId);
    conns_.send(connId, serialize(encoded));
}

void Dispatcher::dispatch(const std::string& connId, const Packet& raw_pkt) {
    // Decode (decrypt/decompress) the packet
    auto pkt = codec_.decode(raw_pkt, connId);

    LOG("Dispatch", std::string("<- ") + cmdName(pkt.type) +
        " conn=" + connId +
        " req=" + std::to_string(pkt.request_id) +
        " flags=0x" + [&]{ std::ostringstream os; os << std::hex << pkt.flags; return os.str(); }() +
        " payload=" + previewPayload(pkt.payloadStr()));

    // Helper: require auth
    auto requireAuth = [&]() -> std::optional<UserId> {
        auto uid = sessions_.getUserByConn(connId);
        if (!uid) {
            WARN("Dispatch", std::string("rejected ") + cmdName(pkt.type) +
                 " from conn=" + connId + " - not authenticated");
            sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "not authenticated"));
        }
        return uid;
    };

    switch (pkt.type) {
        case Cmd::AUTH_REQ:    handleAuth(connId, pkt); break;
        case Cmd::REG_REQ:     handleRegister(connId, pkt); break;
        case Cmd::MSG_SEND: {
            if (auto uid = requireAuth()) {
                auto res = router_.handleMessage(*uid, pkt);
                sendPacket(connId, makePacket(Cmd::MSG_ACK, pkt.request_id, res.success ? "ok" : res.error));
            } break;
        }
        case Cmd::MSG_ACK:    { auto uid = requireAuth(); if (uid) delivery_.onAck(*uid, pkt.payloadStr()); break; }
        case Cmd::MSG_STATUS: { auto uid = requireAuth(); if (uid) delivery_.onRead(*uid, pkt.payloadStr()); break; }
        case Cmd::SYNC_REQ:   { auto uid = requireAuth(); if (uid) sync_.handleFullSync(*uid, pkt); break; }
        case Cmd::SYNC_P2P:   { auto uid = requireAuth(); if (uid) sync_.handleP2PSync(*uid, pkt); break; }
        case Cmd::PONG:        heartbeat_.onPong(connId); break;
        // Chat management
        case Cmd::CHAT_CREATE: { auto uid = requireAuth(); if (uid) handleChatCreate(connId, *uid, pkt); break; }
        case Cmd::CHAT_JOIN:   { auto uid = requireAuth(); if (uid) handleChatJoin(connId, *uid, pkt); break; }
        case Cmd::CHAT_LEAVE:  { auto uid = requireAuth(); if (uid) handleChatLeave(connId, *uid, pkt); break; }
        // Contacts
        case Cmd::CONTACT_ADD:    { auto uid = requireAuth(); if (uid) handleContactAdd(connId, *uid, pkt); break; }
        case Cmd::CONTACT_ACCEPT: { auto uid = requireAuth(); if (uid) handleContactAccept(connId, *uid, pkt); break; }
        case Cmd::CONTACT_LIST:   { auto uid = requireAuth(); if (uid) handleContactList(connId, *uid, pkt); break; }
        // Profiles
        case Cmd::PROFILE_GET:    { auto uid = requireAuth(); if (uid) handleProfileGet(connId, *uid, pkt); break; }
        case Cmd::PROFILE_UPDATE: { auto uid = requireAuth(); if (uid) handleProfileUpdate(connId, *uid, pkt); break; }
        // User list
        case Cmd::USER_LIST:      { auto uid = requireAuth(); if (uid) handleUserList(connId, *uid, pkt); break; }
        // Admin
        case Cmd::USER_BLOCK:     { auto uid = requireAuth(); if (uid) handleUserBlock(connId, *uid, pkt); break; }
        case Cmd::USER_UNBLOCK:   { auto uid = requireAuth(); if (uid) handleUserUnblock(connId, *uid, pkt); break; }
        case Cmd::CERT_REVOKE:    { auto uid = requireAuth(); if (uid) handleCertRevoke(connId, *uid, pkt); break; }
        // Админ-панель
        case Cmd::LOG_QUERY:      { auto uid = requireAuth(); if (uid) handleLogQuery(connId, *uid, pkt); break; }
        case Cmd::ADMIN_STATS:    { auto uid = requireAuth(); if (uid) handleAdminStats(connId, *uid, pkt); break; }
        default:
            WARN("Dispatch", std::string("UNKNOWN cmd: 0x") +
                 [&]{ std::ostringstream os; os << std::hex << (int)pkt.type; return os.str(); }() +
                 " from conn=" + connId);
    }
}

void Dispatcher::handleAuth(const std::string& connId, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        auto res = auth_.authenticate(j["username"], j["password"], j.value("device", ""));
        json resp; resp["success"] = res.success;
        if (res.success) {
            resp["user_id"] = res.user_id; resp["token"] = res.token;
            // Send session key as hex for the client to use encryption
            std::ostringstream ks;
            for (auto b : res.session_key) ks << std::hex << std::setfill('0') << std::setw(2) << (int)b;
            resp["session_key"] = ks.str();

            sessions_.registerOnline(res.user_id, res.token, connId);
            codec_.setKey(connId, res.session_key);
            profiles_.updateLastOnline(res.user_id);
            heartbeat_.start(connId);
            // Send auth response BEFORE encrypted packets (key not set on client yet)
            conns_.send(connId, serialize(makePacket(Cmd::AUTH_RESP, pkt.request_id, resp.dump())));
            LOG("Dispatch", "-> AUTH_RESP conn=" + connId + " user=" + std::to_string(res.user_id) +
                " (sent unencrypted, contains session_key)");
            delivery_.onUserConnected(res.user_id);
            return; // already sent
        } else {
            resp["error"] = res.error;
        }
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, resp.dump()));
        LOG("Dispatch", "-> AUTH_RESP conn=" + connId + " success=false error='" + res.error + "'");
    } catch (const std::exception& e) {
        WARN("Dispatch", std::string("handleAuth exception: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleRegister(const std::string& connId, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        auto res = auth_.registerUser(j["username"], j["password"]);
        json resp; resp["success"] = res.success;
        if (res.success) resp["user_id"] = res.user_id;
        else resp["error"] = res.error;
        sendPacket(connId, makePacket(Cmd::REG_RESP, pkt.request_id, resp.dump()));
        LOG("Dispatch", std::string("-> REG_RESP conn=") + connId +
            " success=" + (res.success ? "true" : "false"));
    } catch (const std::exception& e) {
        WARN("Dispatch", std::string("handleRegister exception: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleChatCreate(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        std::string name = j.value("name", "");
        std::string type = j.value("type", "group");
        // For private chats, use getOrCreatePrivate
        if (type == "private" && j.contains("user_id")) {
            UserId other = j["user_id"];
            auto chat_id = chats_.getOrCreatePrivate(uid, other);
            json resp; resp["success"] = (chat_id >= 0); resp["chat_id"] = chat_id;
            sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
            LOG("Chat", "PRIVATE chat user=" + std::to_string(uid) +
                " <-> user=" + std::to_string(other) + " id=" + std::to_string(chat_id));
        } else {
            auto chat_id = chats_.create(name, type);
            if (chat_id >= 0) chats_.addParticipant(chat_id, uid, "owner");
            // Add other participants if specified
            int extra = 0;
            if (j.contains("participants")) {
                for (auto& pid : j["participants"]) {
                    chats_.addParticipant(chat_id, pid.get<UserId>(), "member"); extra++;
                }
            }
            json resp; resp["success"] = (chat_id >= 0); resp["chat_id"] = chat_id;
            sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
            log_.log(uid, "chat_created", "id=" + std::to_string(chat_id));
            LOG("Chat", "CREATED " + type + " chat id=" + std::to_string(chat_id) +
                " name='" + name + "' owner=" + std::to_string(uid) +
                " extra_members=" + std::to_string(extra));
        }
    } catch (const std::exception& e) {
        WARN("Chat", std::string("handleChatCreate: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleChatJoin(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"];
        chats_.addParticipant(chat_id, uid, "member");
        json resp; resp["success"] = true; resp["chat_id"] = chat_id;
        sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
        LOG("Chat", "user " + std::to_string(uid) + " JOINED chat " + std::to_string(chat_id));
    } catch (const std::exception& e) {
        WARN("Chat", std::string("handleChatJoin: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleChatLeave(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"];
        chats_.removeParticipant(chat_id, uid);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
        LOG("Chat", "user " + std::to_string(uid) + " LEFT chat " + std::to_string(chat_id));
    } catch (const std::exception& e) {
        WARN("Chat", std::string("handleChatLeave: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleContactAdd(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId contact_id = j["contact_id"];
        contacts_.addRequest(uid, contact_id);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
        log_.log(uid, "contact_request", "to=" + std::to_string(contact_id));
        LOG("Contact", "request from user=" + std::to_string(uid) +
            " to user=" + std::to_string(contact_id));
    } catch (const std::exception& e) {
        WARN("Contact", std::string("handleContactAdd: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleContactAccept(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId contact_id = j["contact_id"];
        contacts_.accept(uid, contact_id);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
        log_.log(uid, "contact_accepted", "from=" + std::to_string(contact_id));
        LOG("Contact", "user=" + std::to_string(uid) +
            " ACCEPTED contact from user=" + std::to_string(contact_id));
    } catch (const std::exception& e) {
        WARN("Contact", std::string("handleContactAccept: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleContactList(const std::string& connId, UserId uid, const Packet& pkt) {
    auto contacts = contacts_.getContacts(uid);
    auto pending = contacts_.getPending(uid);
    json resp; json arr = json::array(); json parr = json::array();
    for (auto& c : contacts) { json cj; cj["contact_id"]=c.contact_id; cj["status"]=c.status; arr.push_back(cj); }
    for (auto& p : pending) { json pj; pj["from_user_id"]=p.user_id; pj["status"]=p.status; parr.push_back(pj); }
    resp["contacts"] = arr; resp["pending"] = parr;
    sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
    LOG("Contact", "LIST for user=" + std::to_string(uid) +
        " contacts=" + std::to_string(contacts.size()) +
        " pending=" + std::to_string(pending.size()));
}

void Dispatcher::handleProfileGet(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId target = j.value("user_id", uid);
        auto prof = profiles_.get(target);
        auto user = users_.findById(target);
        json resp;
        if (user) {
            resp["user_id"] = user->id; resp["username"] = user->username; resp["role"] = user->role;
            if (prof) { resp["display_name"]=prof->display_name; resp["bio"]=prof->bio; resp["last_online"]=prof->last_online; }
            resp["online"] = sessions_.isOnline(target);
            LOG("Profile", "GET user=" + std::to_string(uid) +
                " target=" + std::to_string(target) + " ('" + user->username + "')");
        } else {
            resp["error"] = "not found";
            WARN("Profile", "GET target=" + std::to_string(target) + " - not found");
        }
        sendPacket(connId, makePacket(Cmd::PROFILE_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) {
        WARN("Profile", std::string("handleProfileGet: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleProfileUpdate(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        std::string dn = j.value("display_name", "");
        std::string bio = j.value("bio", "");
        profiles_.createOrUpdate(uid, dn, bio);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::PROFILE_RESP, pkt.request_id, resp.dump()));
        LOG("Profile", "UPDATE user=" + std::to_string(uid) +
            " display_name='" + dn + "' bio_len=" + std::to_string(bio.size()));
    } catch (const std::exception& e) {
        WARN("Profile", std::string("handleProfileUpdate: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleUserList(const std::string& connId, UserId uid, const Packet& pkt) {
    auto all = users_.listAll();
    json resp; json arr = json::array();
    int online = 0;
    for (auto& u : all) {
        bool isOnline = sessions_.isOnline(u.id);
        if (isOnline) online++;
        json uj; uj["id"]=u.id; uj["username"]=u.username; uj["role"]=u.role;
        uj["is_blocked"]=u.is_blocked; uj["online"]=isOnline;
        arr.push_back(uj);
    }
    resp["users"] = arr;
    sendPacket(connId, makePacket(Cmd::USER_LIST_RESP, pkt.request_id, resp.dump()));
    LOG("Dispatch", "-> USER_LIST_RESP conn=" + connId +
        " total=" + std::to_string(all.size()) +
        " online=" + std::to_string(online));
}

void Dispatcher::handleUserBlock(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") {
        WARN("Admin", "user " + std::to_string(uid) + " tried USER_BLOCK without admin rights");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return;
    }
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId target = j["user_id"];
        users_.setBlocked(target, true);
        log_.log(uid, "user_blocked", "target=" + std::to_string(target));
        LOG("Admin", "user " + std::to_string(target) + " BLOCKED by admin " + std::to_string(uid));
        // Disconnect blocked user if online
        auto targetConn = sessions_.getConnId(target);
        if (targetConn) {
            sendPacket(*targetConn, makePacket(Cmd::ERR, 0, "you have been blocked"));
            sessions_.removeByConn(*targetConn);
            conns_.removeConnection(*targetConn);
            LOG("Admin", "blocked user " + std::to_string(target) +
                " disconnected (conn=" + *targetConn + ")");
        }
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, "blocked"));
    } catch (...) {
        WARN("Admin", "handleUserBlock: bad request");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request"));
    }
}

void Dispatcher::handleUserUnblock(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") {
        WARN("Admin", "user " + std::to_string(uid) + " tried USER_UNBLOCK without admin rights");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return;
    }
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId target = j["user_id"];
        users_.setBlocked(target, false);
        log_.log(uid, "user_unblocked", "target=" + std::to_string(target));
        LOG("Admin", "user " + std::to_string(target) + " UNBLOCKED by admin " + std::to_string(uid));
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, "unblocked"));
    } catch (...) {
        WARN("Admin", "handleUserUnblock: bad request");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request"));
    }
}

void Dispatcher::handleCertRevoke(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") {
        WARN("Admin", "user " + std::to_string(uid) + " tried CERT_REVOKE without admin rights");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return;
    }
    try {
        auto j = json::parse(pkt.payloadStr());
        std::string username = j["username"];
        ca_.revoke(username);
        log_.log(uid, "cert_revoked", username);
        LOG("Admin", "cert REVOKED for '" + username + "' by admin " + std::to_string(uid));
        json resp; resp["success"] = true; resp["revoked"] = username; resp["crl"] = ca_.getRevokedList();
        sendPacket(connId, makePacket(Cmd::SYNC_RESP, pkt.request_id, resp.dump()));
    } catch (...) {
        WARN("Admin", "handleCertRevoke: bad request");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request"));
    }
}

void Dispatcher::handleLogQuery(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") {
        WARN("Admin", "user " + std::to_string(uid) + " tried LOG_QUERY without admin rights");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return;
    }
    try {
        // Все параметры опциональны
        int64_t user_filter = -1;
        std::string type_filter;
        int limit = 100;
        if (!pkt.payloadStr().empty()) {
            auto j = json::parse(pkt.payloadStr());
            if (j.contains("user_id") && !j["user_id"].is_null()) user_filter = j["user_id"].get<int64_t>();
            if (j.contains("type"))    type_filter = j["type"].get<std::string>();
            if (j.contains("limit"))   limit = j["limit"].get<int>();
        }
        auto entries = log_.query(user_filter, type_filter, limit);
        json arr = json::array();
        for (auto& e : entries) {
            json je;
            je["id"]         = e.id;
            je["user_id"]    = e.user_id;
            je["event_type"] = e.event_type;
            je["details"]    = e.details;
            je["created_at"] = e.created_at;
            arr.push_back(std::move(je));
        }
        json resp; resp["entries"] = arr;
        sendPacket(connId, makePacket(Cmd::LOG_RESP, pkt.request_id, resp.dump()));
        LOG("Admin", "LOG_QUERY by admin " + std::to_string(uid) +
            " filter_user=" + (user_filter < 0 ? "any" : std::to_string(user_filter)) +
            " filter_type='" + type_filter + "'" +
            " returned=" + std::to_string(entries.size()));
    } catch (const std::exception& e) {
        WARN("Admin", std::string("handleLogQuery: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

void Dispatcher::handleAdminStats(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") {
        WARN("Admin", "user " + std::to_string(uid) + " tried ADMIN_STATS without admin rights");
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return;
    }
    try {
        auto all = users_.listAll();
        size_t total = all.size();
        size_t blocked = 0;
        size_t admins = 0;
        for (auto& u : all) {
            if (u.is_blocked) blocked++;
            if (u.role == "admin") admins++;
        }
        // ISO-8601 за последние 24 часа
        auto now = std::chrono::system_clock::now() - std::chrono::hours(24);
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        std::ostringstream day_iso;
        day_iso << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

        json resp;
        resp["users_total"]       = total;
        resp["users_blocked"]     = blocked;
        resp["users_admins"]      = admins;
        resp["users_online"]      = sessions_.onlineCount();
        resp["events_total"]      = log_.countTotal();
        resp["events_last_24h"]   = log_.countSince(day_iso.str());
        resp["crl_size"]          = ca_.getRevokedList().size();
        sendPacket(connId, makePacket(Cmd::ADMIN_STATS_RESP, pkt.request_id, resp.dump()));
        LOG("Admin", "ADMIN_STATS by admin " + std::to_string(uid) +
            " (total=" + std::to_string(total) +
            " online=" + std::to_string(sessions_.onlineCount()) + ")");
    } catch (const std::exception& e) {
        WARN("Admin", std::string("handleAdminStats: ") + e.what());
        sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what()));
    }
}

} // namespace msg