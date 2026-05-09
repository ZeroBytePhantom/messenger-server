#pragma once

#include "types.h"
#include "protocol.h"
#include "database.h"
#include "transport.h"
#include "crypto.h"
#include <boost/asio.hpp>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <set>
#include <functional>

namespace msg {

using SendFn = std::function<void(const std::string& connId, const Packet& pkt)>;

// ── Payload codec (encrypt + compress) ─────────────────────
class PayloadCodec {
public:
    // Store per-connection session keys
    void setKey(const std::string& connId, const Bytes& key);
    void removeKey(const std::string& connId);
    Bytes getKey(const std::string& connId) const;
    bool hasKey(const std::string& connId) const;

    // Encode: optionally compress, then encrypt; sets flags
    Packet encode(Packet pkt, const std::string& connId, bool compress = false);
    // Decode: decrypt if ENCRYPTED, decompress if COMPRESSED
    Packet decode(Packet pkt, const std::string& connId);

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, Bytes> keys_;
};

// ── Session manager ────────────────────────────────────────
class SessionMgr {
public:
    SessionMgr(SessionRepo& repo, EventLog& log) : repo_(repo), log_(log) {}
    void registerOnline(UserId uid, const std::string& token, const std::string& connId);
    void registerOffline(UserId uid);
    void removeByConn(const std::string& connId);
    bool isOnline(UserId uid) const;
    std::optional<std::string> getConnId(UserId uid) const;
    std::optional<UserId> getUserByConn(const std::string& connId) const;
    void refresh(const std::string& token);
    size_t onlineCount() const { std::lock_guard lk(mu_); return user_conn_.size(); }
private:
    SessionRepo& repo_;
    EventLog& log_;
    mutable std::mutex mu_;
    std::unordered_map<UserId, std::string> user_conn_;
    std::unordered_map<std::string, UserId> conn_user_;
    std::unordered_map<UserId, std::string> user_token_;
};

// ── Certificate authority ──────────────────────────────────
class CA {
public:
    bool init(const std::string& key_path, const std::string& cert_path);
    std::pair<Bytes, Bytes> generateKeyPair();
    Bytes signCert(const Bytes& pubkey, const std::string& username);
    bool verifyCert(const Bytes& cert);
    void revoke(const std::string& username);
    bool isRevoked(const std::string& username) const;
    std::vector<std::string> getRevokedList() const;
private:
    void* server_key_ = nullptr;
    void* server_cert_ = nullptr;
    mutable std::mutex mu_;
    std::set<std::string> revoked_;
    bool generateCredentials(const std::string& kp, const std::string& cp);
    bool loadCredentials(const std::string& kp, const std::string& cp);
};

// ── Auth manager ───────────────────────────────────────────
struct AuthResult {
    bool success = false;
    UserId user_id = -1;
    std::string token, error;
    Bytes certificate;
    Bytes session_key; // AES-256 key for this session
};

class AuthMgr {
public:
    AuthMgr(UserRepo& users, SessionRepo& sessions, EventLog& log, CA& ca)
        : users_(users), sessions_(sessions), log_(log), ca_(ca) {}
    AuthResult registerUser(const std::string& username, const std::string& password);
    AuthResult authenticate(const std::string& username, const std::string& password,
                            const std::string& device = "");
private:
    UserRepo& users_;
    SessionRepo& sessions_;
    EventLog& log_;
    CA& ca_;
    std::string genSalt();
    std::string hashPw(const std::string& pw, const std::string& salt);
    std::string genToken();
};

// ── Message router ─────────────────────────────────────────
class MessageRouter {
public:
    MessageRouter(MessageRepo& msgs, ChatRepo& chats, EventLog& log, SessionMgr& sessions)
        : msgs_(msgs), chats_(chats), log_(log), sessions_(sessions) {}
    void setSend(SendFn fn) { send_ = std::move(fn); }
    Result handleMessage(UserId sender, const Packet& pkt);
private:
    MessageRepo& msgs_; ChatRepo& chats_; EventLog& log_; SessionMgr& sessions_;
    SendFn send_;
};

// ── Delivery manager ───────────────────────────────────────
class DeliveryMgr {
public:
    DeliveryMgr(MessageRepo& msgs, EventLog& log, SessionMgr& sessions)
        : msgs_(msgs), log_(log), sessions_(sessions) {}
    void setSend(SendFn fn) { send_ = std::move(fn); }
    void onUserConnected(UserId uid);
    void onAck(UserId uid, const std::string& msgUid);
    void onRead(UserId uid, const std::string& msgUid);
private:
    MessageRepo& msgs_; EventLog& log_; SessionMgr& sessions_;
    SendFn send_;
};

// ── P2P sync manager ──────────────────────────────────────
struct SyncResult { int accepted = 0, duplicates = 0, errors = 0; };

class P2PSyncMgr {
public:
    P2PSyncMgr(MessageRepo& msgs, ChatRepo& chats, UserRepo& users,
               EventLog& log, SessionMgr& sessions, CA& ca)
        : msgs_(msgs), chats_(chats), users_(users), log_(log), sessions_(sessions), ca_(ca) {}
    void setSend(SendFn fn) { send_ = std::move(fn); }
    SyncResult handleP2PSync(UserId uid, const Packet& pkt);
    void handleFullSync(UserId uid, const Packet& pkt);
private:
    MessageRepo& msgs_; ChatRepo& chats_; UserRepo& users_;
    EventLog& log_; SessionMgr& sessions_; CA& ca_;
    SendFn send_;
};

// ── Heartbeat monitor (now sends PING packets) ─────────────
class HeartbeatMon {
public:
    using TimeoutCb = std::function<void(const std::string& connId)>;

    HeartbeatMon(boost::asio::io_context& io, int interval = 30, int timeout = 15)
        : io_(io), interval_(interval), timeout_(timeout) {}

    void onTimeout(TimeoutCb cb) { timeout_cb_ = std::move(cb); }
    void setSend(SendFn fn) { send_ = std::move(fn); }
    void start(const std::string& connId);
    void stop(const std::string& connId);
    void onPong(const std::string& connId);
    void stopAll();
private:
    boost::asio::io_context& io_;
    int interval_, timeout_;
    TimeoutCb timeout_cb_;
    SendFn send_;
    struct Entry {
        std::shared_ptr<boost::asio::steady_timer> ping_timer, pong_timer;
        bool waiting = false;
    };
    std::mutex mu_;
    std::unordered_map<std::string, Entry> entries_;
    void schedulePing(const std::string& connId);
    void schedulePongTimeout(const std::string& connId);
};

// ── Dispatcher (all commands) ──────────────────────────────
class Dispatcher {
public:
    Dispatcher(AuthMgr& auth, SessionMgr& sessions, MessageRouter& router,
               DeliveryMgr& delivery, P2PSyncMgr& sync, HeartbeatMon& heartbeat,
               ConnectionManager& conns, UserRepo& users, ChatRepo& chats,
               ContactRepo& contacts, ProfileRepo& profiles, CA& ca,
               EventLog& log, PayloadCodec& codec);

    void dispatch(const std::string& connId, const Packet& pkt);

private:
    AuthMgr& auth_; SessionMgr& sessions_; MessageRouter& router_;
    DeliveryMgr& delivery_; P2PSyncMgr& sync_; HeartbeatMon& heartbeat_;
    ConnectionManager& conns_; UserRepo& users_; ChatRepo& chats_;
    ContactRepo& contacts_; ProfileRepo& profiles_; CA& ca_;
    EventLog& log_; PayloadCodec& codec_;

    void sendPacket(const std::string& connId, const Packet& pkt);
    void handleAuth(const std::string& connId, const Packet& pkt);
    void handleRegister(const std::string& connId, const Packet& pkt);
    void handleChatCreate(const std::string& connId, UserId uid, const Packet& pkt);
    void handleChatJoin(const std::string& connId, UserId uid, const Packet& pkt);
    void handleChatLeave(const std::string& connId, UserId uid, const Packet& pkt);
    void handleContactAdd(const std::string& connId, UserId uid, const Packet& pkt);
    void handleContactAccept(const std::string& connId, UserId uid, const Packet& pkt);
    void handleContactList(const std::string& connId, UserId uid, const Packet& pkt);
    void handleProfileGet(const std::string& connId, UserId uid, const Packet& pkt);
    void handleProfileUpdate(const std::string& connId, UserId uid, const Packet& pkt);
    void handleUserList(const std::string& connId, UserId uid, const Packet& pkt);
    void handleUserBlock(const std::string& connId, UserId uid, const Packet& pkt);
    void handleUserUnblock(const std::string& connId, UserId uid, const Packet& pkt);
    void handleCertRevoke(const std::string& connId, UserId uid, const Packet& pkt);
    // Админ-панель
    void handleLogQuery(const std::string& connId, UserId uid, const Packet& pkt);
    void handleAdminStats(const std::string& connId, UserId uid, const Packet& pkt);
};

} // namespace msg