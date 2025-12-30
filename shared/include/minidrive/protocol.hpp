#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "error_codes.hpp"

namespace minidrive {

constexpr size_t CHUNK_SIZE = 65536;
constexpr size_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024;
constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024 * 1024;

struct Message {
    std::string cmd;
    nlohmann::json args;
    
    nlohmann::json to_json() const {
        return {{"cmd", cmd}, {"args", args}};
    }
    
    static Message from_json(const nlohmann::json& j) {
        Message m;
        m.cmd = j.value("cmd", "");
        m.args = j.value("args", nlohmann::json::object());
        return m;
    }
};

struct Response {
    std::string status;
    ErrorCode code;
    std::string message;
    nlohmann::json data;
    
    nlohmann::json to_json() const {
        return {
            {"status", status},
            {"code", static_cast<int32_t>(code)},
            {"message", message},
            {"data", data}
        };
    }
    
    static Response from_json(const nlohmann::json& j) {
        Response r;
        r.status = j.value("status", "ERROR");
        r.code = static_cast<ErrorCode>(j.value("code", 1));
        r.message = j.value("message", "");
        r.data = j.value("data", nlohmann::json::object());
        return r;
    }
    
    static Response ok(const nlohmann::json& data = {}) {
        return {"OK", ErrorCode::OK, "", data};
    }
    
    static Response error(ErrorCode code, const std::string& msg = "") {
        return {"ERROR", code, msg.empty() ? error_message(code) : msg, {}};
    }
};

struct FileEntry {
    std::string name;
    bool is_directory;
    uint64_t size;
    std::string hash;
    int64_t mtime;
    
    nlohmann::json to_json() const {
        return {
            {"name", name},
            {"is_directory", is_directory},
            {"size", size},
            {"hash", hash},
            {"mtime", mtime}
        };
    }
    
    static FileEntry from_json(const nlohmann::json& j) {
        FileEntry e;
        e.name = j.value("name", "");
        e.is_directory = j.value("is_directory", false);
        e.size = j.value("size", 0ULL);
        e.hash = j.value("hash", "");
        e.mtime = j.value("mtime", 0LL);
        return e;
    }
};

struct ChunkHeader {
    uint64_t offset;
    uint32_t size;
    std::string hash;
    bool is_last;
    
    nlohmann::json to_json() const {
        return {
            {"offset", offset},
            {"size", size},
            {"hash", hash},
            {"is_last", is_last}
        };
    }
    
    static ChunkHeader from_json(const nlohmann::json& j) {
        ChunkHeader h;
        h.offset = j.value("offset", 0ULL);
        h.size = j.value("size", 0U);
        h.hash = j.value("hash", "");
        h.is_last = j.value("is_last", false);
        return h;
    }
};

inline std::vector<uint8_t> frame_message(const nlohmann::json& j) {
    std::string s = j.dump();
    uint32_t len = static_cast<uint32_t>(s.size());
    std::vector<uint8_t> buf(4 + s.size());
    buf[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(len & 0xFF);
    std::memcpy(buf.data() + 4, s.data(), s.size());
    return buf;
}

inline uint32_t parse_length(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

}
