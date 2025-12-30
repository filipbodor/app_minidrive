#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include "minidrive/protocol.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/crypto.hpp"

namespace minidrive {

class Connection {
public:
    Connection(asio::io_context& io_context)
        : socket_(io_context), resolver_(io_context) {}

    bool connect(const std::string& host, uint16_t port) {
        try {
            auto endpoints = resolver_.resolve(host, std::to_string(port));
            asio::connect(socket_, endpoints);
            return true;
        } catch (...) {
            return false;
        }
    }

    void disconnect() {
        std::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    bool is_connected() const {
        return socket_.is_open();
    }

    bool send_message(const Message& msg) {
        try {
            auto buf = frame_message(msg.to_json());
            asio::write(socket_, asio::buffer(buf));
            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<Response> receive_response() {
        try {
            uint8_t len_buf[4];
            asio::read(socket_, asio::buffer(len_buf, 4));
            uint32_t len = parse_length(len_buf);
            
            if (len > MAX_MESSAGE_SIZE) return std::nullopt;
            
            std::vector<uint8_t> msg_buf(len);
            asio::read(socket_, asio::buffer(msg_buf));
            
            std::string json_str(msg_buf.begin(), msg_buf.end());
            auto j = nlohmann::json::parse(json_str);
            return Response::from_json(j);
        } catch (...) {
            return std::nullopt;
        }
    }

    Response send_command(const std::string& cmd, const nlohmann::json& args = {}) {
        Message msg{cmd, args};
        if (!send_message(msg)) {
            return Response::error(ErrorCode::CONNECTION_LOST);
        }
        auto resp = receive_response();
        if (!resp) {
            return Response::error(ErrorCode::CONNECTION_LOST);
        }
        return *resp;
    }

    bool send_raw(const uint8_t* data, size_t len) {
        try {
            asio::write(socket_, asio::buffer(data, len));
            return true;
        } catch (...) {
            return false;
        }
    }

    size_t receive_raw(uint8_t* data, size_t len) {
        try {
            return asio::read(socket_, asio::buffer(data, len));
        } catch (...) {
            return 0;
        }
    }

    asio::ip::tcp::socket& socket() { return socket_; }

private:
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
};

}
