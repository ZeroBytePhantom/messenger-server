#pragma once

#include "types.h"
#include "protocol.h"
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <array>

namespace msg {

// ── Abstract connection ────────────────────────────────────
class IConnection : public std::enable_shared_from_this<IConnection> {
public:
    using Ptr = std::shared_ptr<IConnection>;
    using ReadCb  = std::function<void(const uint8_t*, size_t, boost::system::error_code)>;
    using WriteCb = std::function<void(boost::system::error_code)>;

    virtual ~IConnection() = default;
    virtual void asyncRead(uint8_t* buf, size_t max, ReadCb cb) = 0;
    virtual void asyncWrite(const uint8_t* data, size_t len, WriteCb cb) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;
    virtual std::string remoteId() const = 0;
};

// ── Abstract transport ─────────────────────────────────────
class ITransport {
public:
    using AcceptCb = std::function<void(IConnection::Ptr)>;
    virtual ~ITransport() = default;
    virtual void start(boost::asio::io_context& io) = 0;
    virtual void stop() = 0;
    void onAccept(AcceptCb cb) { accept_cb_ = std::move(cb); }
protected:
    AcceptCb accept_cb_;
};

// ── TCP implementation ─────────────────────────────────────
class TcpConnection : public IConnection {
public:
    explicit TcpConnection(boost::asio::ip::tcp::socket sock);
    void asyncRead(uint8_t* buf, size_t max, ReadCb cb) override;
    void asyncWrite(const uint8_t* data, size_t len, WriteCb cb) override;
    void close() override;
    bool isOpen() const override;
    std::string remoteId() const override;
private:
    boost::asio::ip::tcp::socket sock_;
    std::string remote_id_;
};

class TcpTransport : public ITransport {
public:
    explicit TcpTransport(uint16_t port);
    void start(boost::asio::io_context& io) override;
    void stop() override;
private:
    uint16_t port_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    void doAccept();
};

// ── Bluetooth implementation (RFCOMM via BlueZ) ────────────
#if HAS_BLUETOOTH

#include <boost/asio/posix/stream_descriptor.hpp>

class BtConnection : public IConnection {
public:
    BtConnection(boost::asio::io_context& io, int fd, const std::string& addr);
    ~BtConnection() override;
    void asyncRead(uint8_t* buf, size_t max, ReadCb cb) override;
    void asyncWrite(const uint8_t* data, size_t len, WriteCb cb) override;
    void close() override;
    bool isOpen() const override;
    std::string remoteId() const override;
private:
    boost::asio::posix::stream_descriptor sd_;
    std::string remote_addr_;
    int raw_fd_;
};

class BtTransport : public ITransport {
public:
    explicit BtTransport(uint8_t channel = 1);
    ~BtTransport() override;
    void start(boost::asio::io_context& io) override;
    void stop() override;
private:
    uint8_t channel_;
    int listen_fd_ = -1;
    boost::asio::io_context* io_ = nullptr;
    std::unique_ptr<boost::asio::posix::stream_descriptor> listen_sd_;
    void doAccept();
};

#endif // HAS_BLUETOOTH

// ── Connection manager ─────────────────────────────────────
class ConnectionManager {
public:
    using PacketHandler = std::function<void(const std::string& connId, Packet pkt)>;

    void setPacketHandler(PacketHandler h) { handler_ = std::move(h); }
    void addConnection(IConnection::Ptr conn);
    void removeConnection(const std::string& connId);
    void send(const std::string& connId, const Bytes& data);
    void broadcast(const Bytes& data);
    bool has(const std::string& connId) const;
    size_t count() const;

private:
    struct Entry {
        IConnection::Ptr conn;
        StreamParser parser;
        std::array<uint8_t, 4096> read_buf;
    };

    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<Entry>> conns_;
    PacketHandler handler_;

    void startRead(std::shared_ptr<Entry> entry);
};

} // namespace msg