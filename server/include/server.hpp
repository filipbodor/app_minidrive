#pragma once

#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <asio.hpp>
#include "session.hpp"
#include "user_store.hpp"
#include "session_manager.hpp"
#include "transfer_manager.hpp"

namespace minidrive {

class Server {
public:
    Server(uint16_t port, const std::filesystem::path& root)
        : acceptor_(io_context_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
          root_(root), users_(root), transfers_(root) {
        std::filesystem::create_directories(root);
    }

    void run() {
        start_accept();
        
        size_t thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) thread_count = 2;
        
        std::vector<std::thread> threads;
        for (size_t i = 0; i < thread_count; ++i) {
            threads.emplace_back([this] { io_context_.run(); });
        }
        
        for (auto& t : threads) {
            t.join();
        }
    }

    void stop() {
        io_context_.stop();
        users_.save();
        transfers_.save();
    }

    asio::io_context& get_io_context() { return io_context_; }

private:
    void start_accept() {
        acceptor_.async_accept(
            [this](std::error_code ec, asio::ip::tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(
                        std::move(socket), users_, sessions_, transfers_, root_
                    )->start();
                }
                start_accept();
            });
    }

    asio::io_context io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::filesystem::path root_;
    UserStore users_;
    SessionManager sessions_;
    TransferManager transfers_;
};

}
