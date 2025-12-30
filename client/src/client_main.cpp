#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <asio.hpp>

#include "minidrive/version.hpp"
#include "minidrive/crypto.hpp"
#include "cli_parser.hpp"
#include "connection.hpp"
#include "shell.hpp"

namespace {
    std::atomic<bool> g_running{true};
    minidrive::Shell* g_shell = nullptr;
}

void signal_handler(int) {
    g_running = false;
    if (g_shell) {
        g_shell->stop();
    }
}

std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string password;
    std::getline(std::cin, password);
    return password;
}

int main(int argc, char* argv[]) {
    auto config = minidrive::parse_args(argc, argv);
    if (!config) {
        std::cerr << "Usage: " << argv[0] << " [username@]<host>:<port> [--log <file>]" << std::endl;
        return 1;
    }

    if (!minidrive::crypto_init()) {
        std::cerr << "Failed to initialize crypto" << std::endl;
        return 1;
    }

    std::signal(SIGINT, signal_handler);

    std::cout << "MiniDrive Client v" << minidrive::version() << std::endl;
    
    if (config->public_mode) {
        std::cout << "[warning] operating in public mode - files are visible to everyone" << std::endl;
    }

    minidrive::Logger logger(config->log_file);
    asio::io_context io_context;
    minidrive::Connection conn(io_context);

    std::cout << "Connecting to " << config->host << ":" << config->port << "..." << std::endl;
    
    if (!conn.connect(config->host, config->port)) {
        std::cerr << "ERROR: " << static_cast<int>(minidrive::ErrorCode::CONNECTION_LOST) << std::endl;
        std::cerr << "Failed to connect to server" << std::endl;
        return 2;
    }

    if (config->public_mode) {
        auto resp = conn.send_command("PUBLIC");
        if (resp.status != "OK") {
            std::cerr << "ERROR: " << static_cast<int>(resp.code) << std::endl;
            std::cerr << resp.message << std::endl;
            return 2;
        }
    } else {
        auto auth_resp = conn.send_command("AUTH", {
            {"username", config->username},
            {"password", ""}
        });
        
        if (auth_resp.code == minidrive::ErrorCode::USER_NOT_FOUND) {
            std::cout << "User " << config->username << " not found. Register? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            
            if (answer == "y" || answer == "Y") {
                std::string password = read_password("Password: ");
                auto reg_resp = conn.send_command("REGISTER", {
                    {"username", config->username},
                    {"password", password}
                });
                
                if (reg_resp.status == "OK") {
                    std::cout << "User registered successfully. Please reconnect." << std::endl;
                } else {
                    std::cerr << "ERROR: " << static_cast<int>(reg_resp.code) << std::endl;
                    std::cerr << reg_resp.message << std::endl;
                }
                return 0;
            }
            return 1;
        }
        
        std::string password = read_password("Password: ");
        auth_resp = conn.send_command("AUTH", {
            {"username", config->username},
            {"password", password}
        });
        
        if (auth_resp.status != "OK") {
            std::cerr << "ERROR: " << static_cast<int>(auth_resp.code) << std::endl;
            std::cerr << auth_resp.message << std::endl;
            return 2;
        }
        
        std::cout << "Logged as " << config->username << std::endl;
        
        auto resume_resp = conn.send_command("GET_RESUMABLE");
        if (resume_resp.status == "OK" && resume_resp.data.value("has_transfer", false)) {
            std::cout << "Incomplete upload/downloads detected, resume? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            
            if (answer == "y" || answer == "Y") {
                std::string path = resume_resp.data.value("remote_path", "");
                std::cout << "UPLOAD " << path << std::endl;
            }
        }
    }

    minidrive::Shell shell(conn, *config, logger);
    g_shell = &shell;
    shell.run();

    conn.disconnect();
    std::cout << "Goodbye!" << std::endl;
    return 0;
}
