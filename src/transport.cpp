#include "transport.h"
#include <iostream>

namespace msg {

// ── TcpConnection ──────────────────────────────────────────
TcpConnection::TcpConnection(boost::asio::ip::tcp::socket sock)
    : sock_(std::move(sock))
{
    try {
        auto ep = sock_.remote_endpoint();
        remote_id_ = ep.address().to_string() + ":" + std::to_string(ep.port());
    } catch (...) {
        remote_id_ = "unknown";
    }
}

void TcpConnection::asyncRead(uint8_t* buf, size_t max, ReadCb cb) {
    sock_.async_read_some(boost::asio::buffer(buf, max),
        [cb](boost::system::error_code ec, size_t n) {
            cb(nullptr, n, ec);
        });
}

void TcpConnection::asyncWrite(const uint8_t* data, size_t len, WriteCb cb) {
    boost::asio::async_write(sock_, boost::asio::buffer(data, len),
        [cb](boost::system::error_code ec, size_t) { cb(ec); });
}

void TcpConnection::close() {
    boost::system::error_code ec;
    sock_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    sock_.close(ec);
}

bool TcpConnection::isOpen() const { return sock_.is_open(); }
std::string TcpConnection::remoteId() const { return remote_id_; }

// ── TcpTransport ───────────────────────────────────────────
TcpTransport::TcpTransport(uint16_t port) : port_(port) {}

void TcpTransport::start(boost::asio::io_context& io) {
    acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(
        io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port_));
    std::cout << "[TCP] Listening on port " << port_ << std::endl;
    doAccept();
}

void TcpTransport::stop() {
    if (acceptor_ && acceptor_->is_open()) {
        acceptor_->close();
    }
}

void TcpTransport::doAccept() {
    acceptor_->async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket sock) {
        if (!ec) {
            auto conn = std::make_shared<TcpConnection>(std::move(sock));
            std::cout << "[TCP] New connection: " << conn->remoteId() << std::endl;
            if (accept_cb_) accept_cb_(conn);
        }
        if (acceptor_->is_open()) doAccept();
    });
}

// ── ConnectionManager ──────────────────────────────────────
void ConnectionManager::addConnection(IConnection::Ptr conn) {
    auto entry = std::make_shared<Entry>();
    entry->conn = conn;

    std::string id = conn->remoteId();

    entry->parser.onPacket([this, id](Packet pkt) {
        if (handler_) handler_(id, std::move(pkt));
    });
    entry->parser.onError([id](ErrCode code, const std::string& msg) {
        std::cerr << "[" << id << "] Parse error: " << msg << std::endl;
    });

    {
        std::lock_guard lk(mu_);
        conns_[id] = entry;
    }

    startRead(entry);
}

void ConnectionManager::removeConnection(const std::string& connId) {
    std::lock_guard lk(mu_);
    auto it = conns_.find(connId);
    if (it != conns_.end()) {
        it->second->conn->close();
        conns_.erase(it);
    }
}

void ConnectionManager::send(const std::string& connId, const Bytes& data) {
    std::shared_ptr<Entry> entry;
    {
        std::lock_guard lk(mu_);
        auto it = conns_.find(connId);
        if (it == conns_.end()) return;
        entry = it->second;
    }
    auto buf = std::make_shared<Bytes>(data);
    entry->conn->asyncWrite(buf->data(), buf->size(), [buf, connId](boost::system::error_code ec) {
        if (ec) std::cerr << "[" << connId << "] Write error: " << ec.message() << std::endl;
    });
}

void ConnectionManager::broadcast(const Bytes& data) {
    std::lock_guard lk(mu_);
    for (auto& [id, entry] : conns_) {
        auto buf = std::make_shared<Bytes>(data);
        entry->conn->asyncWrite(buf->data(), buf->size(), [buf](boost::system::error_code) {});
    }
}

bool ConnectionManager::has(const std::string& connId) const {
    std::lock_guard lk(mu_);
    return conns_.count(connId) > 0;
}

size_t ConnectionManager::count() const {
    std::lock_guard lk(mu_);
    return conns_.size();
}

void ConnectionManager::startRead(std::shared_ptr<Entry> entry) {
    auto conn = entry->conn;
    auto id = conn->remoteId();
    conn->asyncRead(entry->read_buf.data(), entry->read_buf.size(),
        [this, entry, id](const uint8_t*, size_t n, boost::system::error_code ec) {
            if (ec) {
                std::cout << "[" << id << "] Disconnected: " << ec.message() << std::endl;
                removeConnection(id);
                return;
            }
            entry->parser.feed(entry->read_buf.data(), n);
            startRead(entry);
        });
}

} // namespace msg
