#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <iostream>
#include <fstream>

namespace minidrive {

struct ClientConfig {
    std::string host;
    uint16_t port = 9000;
    std::string username;
    std::string log_file;
    bool public_mode = false;
};

inline std::optional<ClientConfig> parse_args(int argc, char* argv[]) {
    if (argc < 2) {
        return std::nullopt;
    }

    ClientConfig config;
    std::string endpoint = argv[1];
    
    size_t at_pos = endpoint.find('@');
    if (at_pos != std::string::npos) {
        config.username = endpoint.substr(0, at_pos);
        endpoint = endpoint.substr(at_pos + 1);
    } else {
        config.public_mode = true;
    }
    
    size_t colon_pos = endpoint.rfind(':');
    if (colon_pos == std::string::npos) {
        return std::nullopt;
    }
    
    config.host = endpoint.substr(0, colon_pos);
    std::string port_str = endpoint.substr(colon_pos + 1);
    
    try {
        config.port = static_cast<uint16_t>(std::stoi(port_str));
    } catch (...) {
        return std::nullopt;
    }
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--log" && i + 1 < argc) {
            config.log_file = argv[++i];
        }
    }
    
    return config;
}

class Logger {
public:
    explicit Logger(const std::string& file = "") {
        if (!file.empty()) {
            file_.open(file, std::ios::app);
        }
    }

    void log(const std::string& msg) {
        if (file_.is_open()) {
            file_ << msg << std::endl;
        }
    }

    void log_command(const std::string& cmd) {
        log("[CMD] " + cmd);
    }

    void log_response(const std::string& status, const std::string& msg) {
        log("[RSP] " + status + ": " + msg);
    }

private:
    std::ofstream file_;
};

}
