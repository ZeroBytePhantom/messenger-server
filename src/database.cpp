#include "database.h"
#include <iostream>
#include <sstream>

namespace msg {

// ── Database ───────────────────────────────────────────────
Database::~Database() { close(); }

bool Database::open(const std::string& path) {
    return sqlite3_open(path.c_str(), &db_) == SQLITE_OK;
}

void Database::close() {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

bool Database::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (err) { std::cerr << "[DB] " << err << std::endl; sqlite3_free(err); }
    return rc == SQLITE_OK;
}

std::vector<Row> Database::query(const std::string& sql) {
    std::vector<Row> rows;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return rows;
    int cols = sqlite3_column_count(stmt);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Row row;
        for (int i = 0; i < cols; i++) {
            const char* name = sqlite3_column_name(stmt, i);
            const char* val  = (const char*)sqlite3_column_text(stmt, i);
            row[name] = val ? val : "";
        }
        rows.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::string Database::error() const {
    return db_ ? sqlite3_errmsg(db_) : "not open";
}

// ── helper: read UserRec from statement ────────────────────
static std::optional<UserRec> readUserRow(sqlite3_stmt* stmt) {
    UserRec u;
    u.id = sqlite3_column_int64(stmt, 0);
    const char* txt = (const char*)sqlite3_column_text(stmt, 1);
    u.username = txt ? txt : "";
    txt = (const char*)sqlite3_column_text(stmt, 2);
    u.password_hash = txt ? txt : "";
    txt = (const char*)sqlite3_column_text(stmt, 3);
    u.salt = txt ? txt : "";
    auto pk = (const uint8_t*)sqlite3_column_blob(stmt, 4);
    int pk_len = sqlite3_column_bytes(stmt, 4);
    if (pk && pk_len > 0) u.public_key.assign(pk, pk + pk_len);
    auto ct = (const uint8_t*)sqlite3_column_blob(stmt, 5);
    int ct_len = sqlite3_column_bytes(stmt, 5);
    if (ct && ct_len > 0) u.certificate.assign(ct, ct + ct_len);
    txt = (const char*)sqlite3_column_text(stmt, 6);
    u.role = txt ? txt : "user";
    u.is_blocked = sqlite3_column_int(stmt, 7) != 0;
    txt = (const char*)sqlite3_column_text(stmt, 8);
    u.created_at = txt ? txt : "";
    return u;
}

// ── UserRepo ───────────────────────────────────────────────
UserId UserRepo::create(const std::string& username, const std::string& hash,
                        const std::string& salt, const Bytes& pubkey, const Bytes& cert) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Users(username,password_hash,salt,public_key,certificate) VALUES(?,?,?,?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, pubkey.data(), (int)pubkey.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, cert.data(), (int)cert.size(), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db_.handle()) : -1;
}

std::optional<UserRec> UserRepo::findByName(const std::string& username) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Users WHERE username=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    auto result = readUserRow(stmt);
    sqlite3_finalize(stmt);
    return result;
}

std::optional<UserRec> UserRepo::findById(UserId id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Users WHERE id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_int64(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    auto result = readUserRow(stmt);
    sqlite3_finalize(stmt);
    return result;
}

bool UserRepo::setBlocked(UserId id, bool blocked) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE Users SET is_blocked=? WHERE id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, blocked ? 1 : 0);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserRepo::updateLastOnline(UserId id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE Profiles SET last_online=CURRENT_TIMESTAMP WHERE user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<UserRec> UserRepo::listAll() {
    std::vector<UserRec> out;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Users ORDER BY id";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto u = readUserRow(stmt);
        if (u) out.push_back(std::move(*u));
    }
    sqlite3_finalize(stmt);
    return out;
}

// ── SessionRepo ────────────────────────────────────────────
int64_t SessionRepo::create(UserId uid, const std::string& token, const std::string& device) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Sessions(user_id,session_token,device_info) VALUES(?,?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, uid);
    sqlite3_bind_text(stmt, 2, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, device.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db_.handle()) : -1;
}

std::optional<SessionRec> SessionRepo::findByToken(const std::string& token) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Sessions WHERE session_token=? AND is_active=1";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    SessionRec s;
    s.id = sqlite3_column_int64(stmt, 0);
    s.user_id = sqlite3_column_int64(stmt, 1);
    const char* txt = (const char*)sqlite3_column_text(stmt, 2);
    s.token = txt ? txt : "";
    txt = (const char*)sqlite3_column_text(stmt, 3); s.device_info = txt ? txt : "";
    txt = (const char*)sqlite3_column_text(stmt, 4); s.created_at = txt ? txt : "";
    txt = (const char*)sqlite3_column_text(stmt, 5); s.last_active = txt ? txt : "";
    s.is_active = sqlite3_column_int(stmt, 6) != 0;
    sqlite3_finalize(stmt);
    return s;
}

bool SessionRepo::updateActive(const std::string& token) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE Sessions SET last_active=CURRENT_TIMESTAMP WHERE session_token=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool SessionRepo::deactivate(const std::string& token) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE Sessions SET is_active=0 WHERE session_token=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

int SessionRepo::deactivateOld(int timeout_sec) {
    std::string sql = "UPDATE Sessions SET is_active=0 WHERE is_active=1 AND "
                      "last_active < datetime('now', '-" + std::to_string(timeout_sec) + " seconds')";
    db_.exec(sql);
    return sqlite3_changes(db_.handle());
}

// ── MessageRepo ────────────────────────────────────────────
MessageId MessageRepo::save(const std::string& uid, ChatId chat, UserId sender,
                            const std::string& content, const std::string& origin,
                            const std::string& created_at) {
    sqlite3_stmt* stmt = nullptr;
    std::string sql;
    if (created_at.empty())
        sql = "INSERT INTO Messages(message_uid,chat_id,sender_id,content,origin) VALUES(?,?,?,?,?)";
    else
        sql = "INSERT INTO Messages(message_uid,chat_id,sender_id,content,origin,created_at) VALUES(?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, chat);
    sqlite3_bind_int64(stmt, 3, sender);
    sqlite3_bind_text(stmt, 4, content.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, origin.c_str(), -1, SQLITE_TRANSIENT);
    if (!created_at.empty())
        sqlite3_bind_text(stmt, 6, created_at.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db_.handle()) : -1;
}

bool MessageRepo::exists(const std::string& uid) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT 1 FROM Messages WHERE message_uid=? LIMIT 1";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt); return found;
}

static MessageRec readMsgFromStmt(sqlite3_stmt* stmt) {
    MessageRec m;
    int cols = sqlite3_column_count(stmt);
    Row row;
    for (int i = 0; i < cols; i++) {
        const char* name = sqlite3_column_name(stmt, i);
        const char* val  = (const char*)sqlite3_column_text(stmt, i);
        row[name] = val ? val : "";
    }
    m.id = std::stoll(row["id"]); m.uid = row["message_uid"];
    m.chat_id = std::stoll(row["chat_id"]); m.sender_id = std::stoll(row["sender_id"]);
    m.content = row["content"]; m.origin = row["origin"];
    m.sync_status = row["sync_status"]; m.created_at = row["created_at"];
    return m;
}

std::vector<MessageRec> MessageRepo::getForChat(ChatId chat, int limit) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Messages WHERE chat_id=? ORDER BY created_at DESC LIMIT ?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, chat); sqlite3_bind_int(stmt, 2, limit);
    std::vector<MessageRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(readMsgFromStmt(stmt));
    sqlite3_finalize(stmt); return out;
}

std::vector<MessageRec> MessageRepo::getSince(ChatId chat, const std::string& since) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Messages WHERE chat_id=? AND created_at>? ORDER BY created_at";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, chat);
    sqlite3_bind_text(stmt, 2, since.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<MessageRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(readMsgFromStmt(stmt));
    sqlite3_finalize(stmt); return out;
}

std::optional<MessageRec> MessageRepo::findByUid(const std::string& uid) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Messages WHERE message_uid=? LIMIT 1";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    auto m = readMsgFromStmt(stmt); sqlite3_finalize(stmt); return m;
}

std::optional<MessageRec> MessageRepo::findById(MessageId id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT * FROM Messages WHERE id=? LIMIT 1";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_int64(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    auto m = readMsgFromStmt(stmt); sqlite3_finalize(stmt); return m;
}

bool MessageRepo::setStatus(MessageId msg, UserId user, const std::string& status) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO Message_Statuses(message_id,user_id,status,updated_at) "
                      "VALUES(?,?,?,CURRENT_TIMESTAMP)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, msg); sqlite3_bind_int64(stmt, 2, user);
    sqlite3_bind_text(stmt, 3, status.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool MessageRepo::enqueue(UserId target, MessageId msg) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Sync_Queue(target_user_id,message_id) VALUES(?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, target); sqlite3_bind_int64(stmt, 2, msg);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

std::vector<SyncQueueRec> MessageRepo::getPending(UserId target) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id,target_user_id,message_id,retry_count,created_at "
                      "FROM Sync_Queue WHERE target_user_id=? ORDER BY created_at";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, target);
    std::vector<SyncQueueRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SyncQueueRec s;
        s.id = sqlite3_column_int64(stmt, 0); s.target_user_id = sqlite3_column_int64(stmt, 1);
        s.message_id = sqlite3_column_int64(stmt, 2); s.retry_count = sqlite3_column_int(stmt, 3);
        const char* txt = (const char*)sqlite3_column_text(stmt, 4);
        s.created_at = txt ? txt : "";
        out.push_back(std::move(s));
    }
    sqlite3_finalize(stmt); return out;
}

bool MessageRepo::dequeue(int64_t queueId) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM Sync_Queue WHERE id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, queueId);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool MessageRepo::incRetry(int64_t queueId) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE Sync_Queue SET retry_count=retry_count+1 WHERE id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, queueId);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

// ── ChatRepo ───────────────────────────────────────────────
ChatId ChatRepo::create(const std::string& name, const std::string& type) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Chats(name,type) VALUES(?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db_.handle()) : -1;
}

bool ChatRepo::addParticipant(ChatId chat, UserId user, const std::string& role) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR IGNORE INTO Chat_Participants(chat_id,user_id,role) VALUES(?,?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, chat); sqlite3_bind_int64(stmt, 2, user);
    sqlite3_bind_text(stmt, 3, role.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool ChatRepo::removeParticipant(ChatId chat, UserId user) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM Chat_Participants WHERE chat_id=? AND user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, chat); sqlite3_bind_int64(stmt, 2, user);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool ChatRepo::isParticipant(ChatId chat, UserId user) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT 1 FROM Chat_Participants WHERE chat_id=? AND user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, chat); sqlite3_bind_int64(stmt, 2, user);
    bool f = (sqlite3_step(stmt) == SQLITE_ROW); sqlite3_finalize(stmt); return f;
}

std::vector<UserId> ChatRepo::getParticipants(ChatId chat) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT user_id FROM Chat_Participants WHERE chat_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, chat);
    std::vector<UserId> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt); return out;
}

std::vector<ChatRec> ChatRepo::getChatsForUser(UserId user) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT c.id,c.name,c.type,c.created_at FROM Chats c "
                      "JOIN Chat_Participants cp ON c.id=cp.chat_id WHERE cp.user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, user);
    std::vector<ChatRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ChatRec c; c.id = sqlite3_column_int64(stmt, 0);
        const char* t = (const char*)sqlite3_column_text(stmt, 1); c.name = t?t:"";
        t = (const char*)sqlite3_column_text(stmt, 2); c.type = t?t:"";
        t = (const char*)sqlite3_column_text(stmt, 3); c.created_at = t?t:"";
        out.push_back(std::move(c));
    }
    sqlite3_finalize(stmt); return out;
}

ChatId ChatRepo::getOrCreatePrivate(UserId u1, UserId u2) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT cp1.chat_id FROM Chat_Participants cp1 "
                      "JOIN Chat_Participants cp2 ON cp1.chat_id=cp2.chat_id "
                      "JOIN Chats c ON c.id=cp1.chat_id "
                      "WHERE c.type='private' AND cp1.user_id=? AND cp2.user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, u1); sqlite3_bind_int64(stmt, 2, u2);
    ChatId existing = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) existing = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    if (existing >= 0) return existing;
    ChatId id = create("", "private");
    if (id < 0) return -1;
    addParticipant(id, u1, "member"); addParticipant(id, u2, "member");
    return id;
}

// ── ContactRepo ────────────────────────────────────────────
bool ContactRepo::addRequest(UserId from, UserId to) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR IGNORE INTO Contacts(user_id,contact_id,status) VALUES(?,?,'pending')";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, from); sqlite3_bind_int64(stmt, 2, to);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

bool ContactRepo::accept(UserId user_id, UserId contact_id) {
    sqlite3_stmt* stmt = nullptr;
    // Update existing pending request
    const char* sql = "UPDATE Contacts SET status='confirmed' WHERE user_id=? AND contact_id=? AND status='pending'";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, contact_id); sqlite3_bind_int64(stmt, 2, user_id);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return false;
    // Add reverse direction
    sqlite3_stmt* stmt2 = nullptr;
    const char* sql2 = "INSERT OR IGNORE INTO Contacts(user_id,contact_id,status) VALUES(?,?,'confirmed')";
    if (sqlite3_prepare_v2(db_.handle(), sql2, -1, &stmt2, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt2, 1, user_id); sqlite3_bind_int64(stmt2, 2, contact_id);
    rc = sqlite3_step(stmt2); sqlite3_finalize(stmt2); return rc == SQLITE_DONE;
}

bool ContactRepo::remove(UserId user_id, UserId contact_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM Contacts WHERE (user_id=? AND contact_id=?) OR (user_id=? AND contact_id=?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, user_id); sqlite3_bind_int64(stmt, 2, contact_id);
    sqlite3_bind_int64(stmt, 3, contact_id); sqlite3_bind_int64(stmt, 4, user_id);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

std::vector<ContactRec> ContactRepo::getContacts(UserId user_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id,user_id,contact_id,status,created_at FROM Contacts "
                      "WHERE user_id=? AND status='confirmed'";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, user_id);
    std::vector<ContactRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ContactRec c; c.id = sqlite3_column_int64(stmt, 0);
        c.user_id = sqlite3_column_int64(stmt, 1); c.contact_id = sqlite3_column_int64(stmt, 2);
        const char* t = (const char*)sqlite3_column_text(stmt, 3); c.status = t?t:"";
        t = (const char*)sqlite3_column_text(stmt, 4); c.created_at = t?t:"";
        out.push_back(std::move(c));
    }
    sqlite3_finalize(stmt); return out;
}

std::vector<ContactRec> ContactRepo::getPending(UserId user_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id,user_id,contact_id,status,created_at FROM Contacts "
                      "WHERE contact_id=? AND status='pending'";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    sqlite3_bind_int64(stmt, 1, user_id);
    std::vector<ContactRec> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ContactRec c; c.id = sqlite3_column_int64(stmt, 0);
        c.user_id = sqlite3_column_int64(stmt, 1); c.contact_id = sqlite3_column_int64(stmt, 2);
        const char* t = (const char*)sqlite3_column_text(stmt, 3); c.status = t?t:"";
        t = (const char*)sqlite3_column_text(stmt, 4); c.created_at = t?t:"";
        out.push_back(std::move(c));
    }
    sqlite3_finalize(stmt); return out;
}

std::string ContactRepo::getStatus(UserId user_id, UserId contact_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT status FROM Contacts WHERE user_id=? AND contact_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return "";
    sqlite3_bind_int64(stmt, 1, user_id); sqlite3_bind_int64(stmt, 2, contact_id);
    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* t = (const char*)sqlite3_column_text(stmt, 0); result = t?t:"";
    }
    sqlite3_finalize(stmt); return result;
}

// ── ProfileRepo ────────────────────────────────────────────
bool ProfileRepo::createOrUpdate(UserId uid, const std::string& display_name, const std::string& bio) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Profiles(user_id,display_name,bio) VALUES(?,?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name, bio=excluded.bio";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, uid);
    sqlite3_bind_text(stmt, 2, display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, bio.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

std::optional<ProfileRec> ProfileRepo::get(UserId uid) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT user_id,display_name,bio,last_online FROM Profiles WHERE user_id=?";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_int64(stmt, 1, uid);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    ProfileRec p; p.user_id = sqlite3_column_int64(stmt, 0);
    const char* t = (const char*)sqlite3_column_text(stmt, 1); p.display_name = t?t:"";
    t = (const char*)sqlite3_column_text(stmt, 2); p.bio = t?t:"";
    t = (const char*)sqlite3_column_text(stmt, 3); p.last_online = t?t:"";
    sqlite3_finalize(stmt); return p;
}

bool ProfileRepo::updateLastOnline(UserId uid) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Profiles(user_id,last_online) VALUES(?,CURRENT_TIMESTAMP) "
                      "ON CONFLICT(user_id) DO UPDATE SET last_online=CURRENT_TIMESTAMP";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, uid);
    int rc = sqlite3_step(stmt); sqlite3_finalize(stmt); return rc == SQLITE_DONE;
}

// ── EventLog ───────────────────────────────────────────────
void EventLog::log(UserId uid, const std::string& type, const std::string& details) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Event_Log(user_id,event_type,details) VALUES(?,?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, uid);
    sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, details.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
}

void EventLog::logSystem(const std::string& type, const std::string& details) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO Event_Log(event_type,details) VALUES(?,?)";
    if (sqlite3_prepare_v2(db_.handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_text(stmt, 1, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, details.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
}

} // namespace msg
