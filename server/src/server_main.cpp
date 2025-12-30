#include <iostream>
#include <string>
#include <cstdint>
#include <csignal>
#include <filesystem>
#include <atomic>

#include "minidrive/version.hpp"
#include "minidrive/crypto.hpp"
#include "server.hpp"

namespace {
    std::atomic<bool> g_running{true};
    minidrive::Server* g_server = nullptr;
}

void signal_handler(int) {
    g_running = false;
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char* argv[]) {
    uint16_t port = 9000;
    std::filesystem::path root = "./data/server_root";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        }
    }

    if (!minidrive::crypto_init()) {
        std::cerr << "Failed to initialize crypto" << std::endl;
        return 1;
    }

    std::signal(SIGTERM, signal_handler);
    std::signal(SIGINT, signal_handler);

    std::cout << "MiniDrive Server v" << minidrive::version() << std::endl;
    std::cout << "Port: " << port << std::endl;
    std::cout << "Root: " << std::filesystem::absolute(root) << std::endl;

    try {
        minidrive::Server server(port, root);
        g_server = &server;
        std::cout << "Server started. Press Ctrl+C to stop." << std::endl;
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Server stopped." << std::endl;
    return 0;
}
