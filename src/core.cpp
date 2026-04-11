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

// ── PayloadCodec ───────────────────────────────────────────
void PayloadCodec::setKey(const std::string& connId, const Bytes& key) {
    std::lock_guard lk(mu_); keys_[connId] = key;
}
void PayloadCodec::removeKey(const std::string& connId) {
    std::lock_guard lk(mu_); keys_.erase(connId);
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

    // Compress first (before encryption)
    if (compress && data.size() > 64) {
        auto compressed = Compression::compress(data);
        if (!compressed.empty() && compressed.size() < data.size()) {
            data = std::move(compressed);
            flags |= Flags::COMPRESSED;
        }
    }

    // Encrypt
    auto key = getKey(connId);
    if (!key.empty()) {
        auto encrypted = Crypto::encrypt(data, key);
        if (!encrypted.empty()) {
            data = std::move(encrypted);
            flags |= Flags::ENCRYPTED;
        }
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
                data = std::move(decrypted);
                pkt.flags &= ~Flags::ENCRYPTED;
            } else {
                std::cerr << "[Codec] Decryption failed for " << connId << std::endl;
                return pkt; // return as-is, dispatch will see ENCRYPTED flag still set
            }
        }
    }

    // Decompress
    if (pkt.flags & Flags::COMPRESSED) {
        auto decompressed = Compression::decompress(data);
        if (!decompressed.empty()) {
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
}
void SessionMgr::registerOffline(UserId uid) {
    std::lock_guard lk(mu_);
    auto it = user_conn_.find(uid);
    if (it != user_conn_.end()) { conn_user_.erase(it->second); user_conn_.erase(it); }
    auto it2 = user_token_.find(uid);
    if (it2 != user_token_.end()) { repo_.deactivate(it2->second); user_token_.erase(it2); }
}
void SessionMgr::removeByConn(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = conn_user_.find(connId);
    if (it != conn_user_.end()) {
        UserId uid = it->second; user_conn_.erase(uid); conn_user_.erase(it);
        auto it2 = user_token_.find(uid);
        if (it2 != user_token_.end()) { repo_.deactivate(it2->second); user_token_.erase(it2); }
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
    std::cout << "[CA] Generated new server credentials" << std::endl;
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
    std::cout << "[CA] Loaded server credentials" << std::endl;
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
    return cert;
}

bool CA::verifyCert(const Bytes& cert) {
    const uint8_t* p = cert.data();
    X509* x509 = d2i_X509(nullptr, &p, cert.size());
    if (!x509) return false;
    int ok = X509_verify(x509, (EVP_PKEY*)server_key_); X509_free(x509); return ok == 1;
}
void CA::revoke(const std::string& u) { std::lock_guard lk(mu_); revoked_.insert(u); }
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
    if (users_.findByName(username)) { res.error = "user already exists"; return res; }
    auto salt = genSalt(); auto hash = hashPw(password, salt);
    auto [pubkey, privkey] = ca_.generateKeyPair();
    auto cert = ca_.signCert(pubkey, username);
    auto id = users_.create(username, hash, salt, pubkey, cert);
    if (id < 0) { res.error = "db error"; return res; }
    res.success = true; res.user_id = id; res.certificate = cert;
    log_.log(id, "user_registered", username);
    return res;
}

AuthResult AuthMgr::authenticate(const std::string& username, const std::string& password,
                                  const std::string& device) {
    AuthResult res;
    auto user = users_.findByName(username);
    if (!user) { res.error = "not found"; log_.logSystem("auth_fail", username); return res; }
    if (user->is_blocked) { res.error = "blocked"; log_.log(user->id, "auth_fail", "blocked"); return res; }
    auto hash = hashPw(password, user->salt);
    if (hash != user->password_hash) { res.error = "wrong password"; log_.log(user->id, "auth_fail", "bad password"); return res; }

    auto token = genToken();
    sessions_.create(user->id, token, device);

    // Generate session encryption key
    res.session_key = Crypto::generateSessionKey();

    res.success = true; res.user_id = user->id; res.token = token;
    res.certificate = user->certificate;
    log_.log(user->id, "auth_success", device);
    return res;
}

// ── MessageRouter ──────────────────────────────────────────
Result MessageRouter::handleMessage(UserId sender, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"]; std::string msg_uid = j["message_uid"]; std::string content = j["content"];
        if (!chats_.isParticipant(chat_id, sender)) return Result::fail("not a participant");
        auto msg_id = msgs_.save(msg_uid, chat_id, sender, content);
        if (msg_id < 0) return Result::fail("save failed");
        auto participants = chats_.getParticipants(chat_id);
        for (auto uid : participants) {
            if (uid == sender) continue;
            if (sessions_.isOnline(uid)) {
                auto deliver = makePacket(Cmd::MSG_DELIVER, pkt.request_id, pkt.payloadStr());
                if (send_) send_(*sessions_.getConnId(uid), deliver);
                msgs_.setStatus(msg_id, uid, "delivered");
            } else {
                msgs_.enqueue(uid, msg_id);
                msgs_.setStatus(msg_id, uid, "sent");
            }
        }
        log_.log(sender, "message_sent", "chat=" + std::to_string(chat_id));
        return Result::ok();
    } catch (const std::exception& e) { return Result::fail(std::string("parse error: ") + e.what()); }
}

// ── DeliveryMgr ────────────────────────────────────────────
void DeliveryMgr::onUserConnected(UserId uid) {
    auto pending = msgs_.getPending(uid);
    auto connId = sessions_.getConnId(uid);
    if (!connId || pending.empty()) return;
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
}
void DeliveryMgr::onAck(UserId uid, const std::string& msgUid) {
    auto msg = msgs_.findByUid(msgUid); if (msg) msgs_.setStatus(msg->id, uid, "delivered");
}
void DeliveryMgr::onRead(UserId uid, const std::string& msgUid) {
    auto msg = msgs_.findByUid(msgUid); if (msg) msgs_.setStatus(msg->id, uid, "read");
}

// ── P2PSyncMgr ─────────────────────────────────────────────
SyncResult P2PSyncMgr::handleP2PSync(UserId uid, const Packet& pkt) {
    SyncResult res;
    try {
        auto arr = json::parse(pkt.payloadStr());
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
    } catch (...) { res.errors++; }
    auto connId = sessions_.getConnId(uid);
    if (connId && send_) {
        json resp; resp["accepted"]=res.accepted; resp["duplicates"]=res.duplicates;
        resp["errors"]=res.errors; resp["crl"]=ca_.getRevokedList();
        send_(*connId, makePacket(Cmd::SYNC_RESP, pkt.request_id, resp.dump()));
    }
    log_.log(uid, "sync_completed", "accepted="+std::to_string(res.accepted));
    return res;
}

void P2PSyncMgr::handleFullSync(UserId uid, const Packet& pkt) {
    auto connId = sessions_.getConnId(uid); if (!connId) return;
    std::string since = pkt.payloadStr();
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
}

// ── HeartbeatMon (now sends PING) ──────────────────────────
void HeartbeatMon::start(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto& e = entries_[connId];
    e.ping_timer = std::make_shared<boost::asio::steady_timer>(io_);
    e.pong_timer = std::make_shared<boost::asio::steady_timer>(io_);
    schedulePing(connId);
}
void HeartbeatMon::stop(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = entries_.find(connId);
    if (it != entries_.end()) { it->second.ping_timer->cancel(); it->second.pong_timer->cancel(); entries_.erase(it); }
}
void HeartbeatMon::onPong(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = entries_.find(connId);
    if (it != entries_.end()) { it->second.waiting = false; it->second.pong_timer->cancel(); schedulePing(connId); }
}
void HeartbeatMon::stopAll() {
    std::lock_guard lk(mu_);
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
        if (it != entries_.end() && it->second.waiting) { entries_.erase(it); if (timeout_cb_) timeout_cb_(connId); }
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

    // Helper: require auth
    auto requireAuth = [&]() -> std::optional<UserId> {
        auto uid = sessions_.getUserByConn(connId);
        if (!uid) sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "not authenticated"));
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
        default:
            std::cerr << "[Dispatcher] Unknown cmd: 0x" << std::hex << (int)pkt.type << std::dec << std::endl;
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
            delivery_.onUserConnected(res.user_id);
            return; // already sent
        } else {
            resp["error"] = res.error;
        }
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) {
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
    } catch (const std::exception& e) {
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
        } else {
            auto chat_id = chats_.create(name, type);
            if (chat_id >= 0) chats_.addParticipant(chat_id, uid, "owner");
            // Add other participants if specified
            if (j.contains("participants")) {
                for (auto& pid : j["participants"]) chats_.addParticipant(chat_id, pid.get<UserId>(), "member");
            }
            json resp; resp["success"] = (chat_id >= 0); resp["chat_id"] = chat_id;
            sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
            log_.log(uid, "chat_created", "id=" + std::to_string(chat_id));
        }
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleChatJoin(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"];
        chats_.addParticipant(chat_id, uid, "member");
        json resp; resp["success"] = true; resp["chat_id"] = chat_id;
        sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleChatLeave(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        ChatId chat_id = j["chat_id"];
        chats_.removeParticipant(chat_id, uid);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CHAT_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleContactAdd(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId contact_id = j["contact_id"];
        contacts_.addRequest(uid, contact_id);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
        log_.log(uid, "contact_request", "to=" + std::to_string(contact_id));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleContactAccept(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId contact_id = j["contact_id"];
        contacts_.accept(uid, contact_id);
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
        log_.log(uid, "contact_accepted", "from=" + std::to_string(contact_id));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleContactList(const std::string& connId, UserId uid, const Packet& pkt) {
    auto contacts = contacts_.getContacts(uid);
    auto pending = contacts_.getPending(uid);
    json resp; json arr = json::array(); json parr = json::array();
    for (auto& c : contacts) { json cj; cj["contact_id"]=c.contact_id; cj["status"]=c.status; arr.push_back(cj); }
    for (auto& p : pending) { json pj; pj["from_user_id"]=p.user_id; pj["status"]=p.status; parr.push_back(pj); }
    resp["contacts"] = arr; resp["pending"] = parr;
    sendPacket(connId, makePacket(Cmd::CONTACT_RESP, pkt.request_id, resp.dump()));
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
        } else { resp["error"] = "not found"; }
        sendPacket(connId, makePacket(Cmd::PROFILE_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleProfileUpdate(const std::string& connId, UserId uid, const Packet& pkt) {
    try {
        auto j = json::parse(pkt.payloadStr());
        profiles_.createOrUpdate(uid, j.value("display_name", ""), j.value("bio", ""));
        json resp; resp["success"] = true;
        sendPacket(connId, makePacket(Cmd::PROFILE_RESP, pkt.request_id, resp.dump()));
    } catch (const std::exception& e) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, e.what())); }
}

void Dispatcher::handleUserList(const std::string& connId, UserId uid, const Packet& pkt) {
    auto all = users_.listAll();
    json resp; json arr = json::array();
    for (auto& u : all) {
        json uj; uj["id"]=u.id; uj["username"]=u.username; uj["role"]=u.role;
        uj["is_blocked"]=u.is_blocked; uj["online"]=sessions_.isOnline(u.id);
        arr.push_back(uj);
    }
    resp["users"] = arr;
    sendPacket(connId, makePacket(Cmd::USER_LIST_RESP, pkt.request_id, resp.dump()));
}

void Dispatcher::handleUserBlock(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return; }
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId target = j["user_id"];
        users_.setBlocked(target, true);
        log_.log(uid, "user_blocked", "target=" + std::to_string(target));
        // Disconnect blocked user if online
        auto targetConn = sessions_.getConnId(target);
        if (targetConn) {
            sendPacket(*targetConn, makePacket(Cmd::ERR, 0, "you have been blocked"));
            sessions_.removeByConn(*targetConn);
            conns_.removeConnection(*targetConn);
        }
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, "blocked"));
    } catch (...) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request")); }
}

void Dispatcher::handleUserUnblock(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return; }
    try {
        auto j = json::parse(pkt.payloadStr());
        UserId target = j["user_id"];
        users_.setBlocked(target, false);
        log_.log(uid, "user_unblocked", "target=" + std::to_string(target));
        sendPacket(connId, makePacket(Cmd::AUTH_RESP, pkt.request_id, "unblocked"));
    } catch (...) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request")); }
}

void Dispatcher::handleCertRevoke(const std::string& connId, UserId uid, const Packet& pkt) {
    auto user = users_.findById(uid);
    if (!user || user->role != "admin") { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "denied")); return; }
    try {
        auto j = json::parse(pkt.payloadStr());
        std::string username = j["username"];
        ca_.revoke(username);
        log_.log(uid, "cert_revoked", username);
        json resp; resp["success"] = true; resp["revoked"] = username; resp["crl"] = ca_.getRevokedList();
        sendPacket(connId, makePacket(Cmd::SYNC_RESP, pkt.request_id, resp.dump()));
    } catch (...) { sendPacket(connId, makePacket(Cmd::ERR, pkt.request_id, "bad request")); }
}

} // namespace msg
