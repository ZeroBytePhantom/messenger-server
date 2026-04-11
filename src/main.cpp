#include "core.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <csignal>
#include <thread>

using json = nlohmann::json;

namespace msg {

class Server {
public:
    explicit Server(const std::string& config_path) : config_path_(config_path), signals_(io_, SIGINT, SIGTERM) {}

    bool init() {
        if (!loadConfig()) return false;
        if (!initDB()) return false;
        if (!initCA()) return false;
        initComponents();
        return true;
    }

    void run() {
        signals_.async_wait([this](boost::system::error_code, int) { stop(); });
        transport_->start(io_);
        auto n = std::max(1u, std::thread::hardware_concurrency());
        std::vector<std::thread> threads;
        for (unsigned i = 0; i < n; i++) threads.emplace_back([this]() { io_.run(); });
        std::cout << "[Server] Running (" << n << " threads, port " << port_ << ")" << std::endl;
        for (auto& t : threads) t.join();
    }

    void stop() {
        std::cout << "[Server] Stopping..." << std::endl;
        heartbeat_->stopAll(); transport_->stop(); io_.stop();
    }

private:
    std::string config_path_;
    boost::asio::io_context io_;
    boost::asio::signal_set signals_;
    uint16_t port_ = 9090;
    std::string db_path_ = "messenger.db", ca_key_ = "server_key.pem", ca_cert_ = "server_cert.pem";
    int hb_interval_ = 30, hb_timeout_ = 15;

    std::unique_ptr<Database> db_;
    std::unique_ptr<UserRepo> users_;
    std::unique_ptr<SessionRepo> sessions_;
    std::unique_ptr<MessageRepo> messages_;
    std::unique_ptr<ChatRepo> chats_;
    std::unique_ptr<ContactRepo> contacts_;
    std::unique_ptr<ProfileRepo> profiles_;
    std::unique_ptr<EventLog> events_;
    std::unique_ptr<CA> ca_;
    std::unique_ptr<AuthMgr> auth_;
    std::unique_ptr<SessionMgr> session_mgr_;
    std::unique_ptr<MessageRouter> router_;
    std::unique_ptr<DeliveryMgr> delivery_;
    std::unique_ptr<P2PSyncMgr> sync_;
    std::unique_ptr<HeartbeatMon> heartbeat_;
    std::unique_ptr<ConnectionManager> conns_;
    std::unique_ptr<TcpTransport> transport_;
    std::unique_ptr<Dispatcher> dispatcher_;
    std::unique_ptr<PayloadCodec> codec_;

    bool loadConfig() {
        std::ifstream f(config_path_);
        if (!f.is_open()) { std::cout << "[Server] No config file, using defaults" << std::endl; return true; }
        try {
            auto j = json::parse(f);
            port_ = j.value("port", 9090);
            db_path_ = j.value("database", "messenger.db");
            ca_key_ = j.value("ca_key", "server_key.pem");
            ca_cert_ = j.value("ca_cert", "server_cert.pem");
            hb_interval_ = j.value("heartbeat_interval", 30);
            hb_timeout_ = j.value("heartbeat_timeout", 15);
        } catch (const std::exception& e) { std::cerr << "[Server] Config error: " << e.what() << std::endl; return false; }
        return true;
    }

    bool initDB() {
        db_ = std::make_unique<Database>();
        if (!db_->open(db_path_)) { std::cerr << "[Server] DB failed: " << db_->error() << std::endl; return false; }
        std::ifstream f("db/init.sql");
        if (f.is_open()) {
            std::string sql((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            db_->exec(sql);
            std::cout << "[Server] Database schema initialized" << std::endl;
        } else { std::cerr << "[Server] Warning: db/init.sql not found" << std::endl; }
        users_    = std::make_unique<UserRepo>(*db_);
        sessions_ = std::make_unique<SessionRepo>(*db_);
        messages_ = std::make_unique<MessageRepo>(*db_);
        chats_    = std::make_unique<ChatRepo>(*db_);
        contacts_ = std::make_unique<ContactRepo>(*db_);
        profiles_ = std::make_unique<ProfileRepo>(*db_);
        events_   = std::make_unique<EventLog>(*db_);
        std::cout << "[Server] Database ready" << std::endl;
        return true;
    }

    bool initCA() {
        ca_ = std::make_unique<CA>();
        if (!ca_->init(ca_key_, ca_cert_)) { std::cerr << "[Server] CA init failed" << std::endl; return false; }
        return true;
    }

    void initComponents() {
        codec_       = std::make_unique<PayloadCodec>();
        auth_        = std::make_unique<AuthMgr>(*users_, *sessions_, *events_, *ca_);
        session_mgr_ = std::make_unique<SessionMgr>(*sessions_, *events_);
        router_      = std::make_unique<MessageRouter>(*messages_, *chats_, *events_, *session_mgr_);
        delivery_    = std::make_unique<DeliveryMgr>(*messages_, *events_, *session_mgr_);
        sync_        = std::make_unique<P2PSyncMgr>(*messages_, *chats_, *users_, *events_, *session_mgr_, *ca_);
        heartbeat_   = std::make_unique<HeartbeatMon>(io_, hb_interval_, hb_timeout_);
        conns_       = std::make_unique<ConnectionManager>();
        transport_   = std::make_unique<TcpTransport>(port_);

        dispatcher_ = std::make_unique<Dispatcher>(
            *auth_, *session_mgr_, *router_, *delivery_, *sync_, *heartbeat_,
            *conns_, *users_, *chats_, *contacts_, *profiles_, *ca_, *events_, *codec_);

        transport_->onAccept([this](IConnection::Ptr conn) { conns_->addConnection(conn); });

        conns_->setPacketHandler([this](const std::string& connId, Packet pkt) {
            dispatcher_->dispatch(connId, std::move(pkt));
        });

        heartbeat_->onTimeout([this](const std::string& connId) {
            std::cout << "[Heartbeat] Timeout: " << connId << std::endl;
            session_mgr_->removeByConn(connId);
            codec_->removeKey(connId);
            conns_->removeConnection(connId);
        });

        std::cout << "[Server] Components initialized" << std::endl;
    }
};

} // namespace msg

int main(int argc, char* argv[]) {
    std::string config = "config.json";
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--config" && i + 1 < argc) config = argv[++i];
    }
    std::cout << "=== Messenger Server v1.0 ===" << std::endl;
    msg::Server server(config);
    if (!server.init()) return 1;
    server.run();
    return 0;
}
