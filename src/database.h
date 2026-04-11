#pragma once

#include "types.h"
#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <mutex>

namespace msg {

using Row = std::unordered_map<std::string, std::string>;

class Database {
public:
    ~Database();
    bool open(const std::string& path);
    void close();
    bool exec(const std::string& sql);
    std::vector<Row> query(const std::string& sql);
    sqlite3* handle() { return db_; }
    std::string error() const;
private:
    sqlite3* db_ = nullptr;
};

// ── Data records ───────────────────────────────────────────
struct UserRec {
    UserId id = 0;
    std::string username, password_hash, salt, role, created_at;
    Bytes public_key, certificate;
    bool is_blocked = false;
};

struct SessionRec {
    int64_t id = 0; UserId user_id = 0;
    std::string token, device_info, created_at, last_active;
    bool is_active = false;
};

struct MessageRec {
    MessageId id = 0; std::string uid;
    ChatId chat_id = 0; UserId sender_id = 0;
    std::string content, origin, sync_status, created_at;
};

struct ChatRec {
    ChatId id = 0; std::string name, type, created_at;
};

struct SyncQueueRec {
    int64_t id = 0; UserId target_user_id = 0; MessageId message_id = 0;
    int retry_count = 0; std::string created_at;
};

struct ContactRec {
    int64_t id = 0; UserId user_id = 0; UserId contact_id = 0;
    std::string status, created_at;
};

struct ProfileRec {
    UserId user_id = 0;
    std::string display_name, bio, last_online;
};

// ── Users ──────────────────────────────────────────────────
class UserRepo {
public:
    explicit UserRepo(Database& db) : db_(db) {}
    UserId create(const std::string& username, const std::string& hash,
                  const std::string& salt, const Bytes& pubkey, const Bytes& cert);
    std::optional<UserRec> findByName(const std::string& username);
    std::optional<UserRec> findById(UserId id);
    bool setBlocked(UserId id, bool blocked);
    bool updateLastOnline(UserId id);
    std::vector<UserRec> listAll();
private:
    Database& db_;
};

// ── Sessions ───────────────────────────────────────────────
class SessionRepo {
public:
    explicit SessionRepo(Database& db) : db_(db) {}
    int64_t create(UserId uid, const std::string& token, const std::string& device);
    std::optional<SessionRec> findByToken(const std::string& token);
    bool updateActive(const std::string& token);
    bool deactivate(const std::string& token);
    int deactivateOld(int timeout_sec);
private:
    Database& db_;
};

// ── Messages ───────────────────────────────────────────────
class MessageRepo {
public:
    explicit MessageRepo(Database& db) : db_(db) {}
    MessageId save(const std::string& uid, ChatId chat, UserId sender,
                   const std::string& content, const std::string& origin = "server",
                   const std::string& created_at = "");
    bool exists(const std::string& uid);
    std::vector<MessageRec> getForChat(ChatId chat, int limit = 100);
    std::vector<MessageRec> getSince(ChatId chat, const std::string& since);
    std::optional<MessageRec> findByUid(const std::string& uid);
    std::optional<MessageRec> findById(MessageId id);
    bool setStatus(MessageId msg, UserId user, const std::string& status);
    bool enqueue(UserId target, MessageId msg);
    std::vector<SyncQueueRec> getPending(UserId target);
    bool dequeue(int64_t queueId);
    bool incRetry(int64_t queueId);
private:
    Database& db_;
};

// ── Chats ──────────────────────────────────────────────────
class ChatRepo {
public:
    explicit ChatRepo(Database& db) : db_(db) {}
    ChatId create(const std::string& name, const std::string& type);
    bool addParticipant(ChatId chat, UserId user, const std::string& role = "member");
    bool removeParticipant(ChatId chat, UserId user);
    bool isParticipant(ChatId chat, UserId user);
    std::vector<UserId> getParticipants(ChatId chat);
    std::vector<ChatRec> getChatsForUser(UserId user);
    ChatId getOrCreatePrivate(UserId u1, UserId u2);
private:
    Database& db_;
};

// ── Contacts ───────────────────────────────────────────────
class ContactRepo {
public:
    explicit ContactRepo(Database& db) : db_(db) {}
    bool addRequest(UserId from, UserId to);
    bool accept(UserId user_id, UserId contact_id);
    bool remove(UserId user_id, UserId contact_id);
    std::vector<ContactRec> getContacts(UserId user_id);
    std::vector<ContactRec> getPending(UserId user_id);
    std::string getStatus(UserId user_id, UserId contact_id);
private:
    Database& db_;
};

// ── Profiles ───────────────────────────────────────────────
class ProfileRepo {
public:
    explicit ProfileRepo(Database& db) : db_(db) {}
    bool createOrUpdate(UserId uid, const std::string& display_name, const std::string& bio);
    std::optional<ProfileRec> get(UserId uid);
    bool updateLastOnline(UserId uid);
private:
    Database& db_;
};

// ── Event log ──────────────────────────────────────────────
class EventLog {
public:
    explicit EventLog(Database& db) : db_(db) {}
    void log(UserId uid, const std::string& type, const std::string& details = "");
    void logSystem(const std::string& type, const std::string& details = "");
private:
    Database& db_;
};

} // namespace msg
