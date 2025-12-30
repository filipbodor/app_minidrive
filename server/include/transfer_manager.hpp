#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>

namespace minidrive {

struct TransferInfo {
    std::string username;
    std::string remote_path;
    std::string local_hash;
    uint64_t total_size;
    uint64_t bytes_received;
    std::chrono::system_clock::time_point last_update;
    bool is_upload;
};

class TransferManager {
public:
    explicit TransferManager(const std::filesystem::path& root) : root_(root) {
        transfers_file_ = root_ / ".transfers.json";
        load();
    }

    std::string start_upload(const std::string& username, const std::string& remote_path,
                             const std::string& hash, uint64_t size) {
        std::lock_guard lock(mutex_);
        std::string id = username + ":" + remote_path;
        TransferInfo info{username, remote_path, hash, size, 0,
                          std::chrono::system_clock::now(), true};
        transfers_[id] = info;
        save();
        return id;
    }

    bool update_progress(const std::string& id, uint64_t bytes) {
        std::lock_guard lock(mutex_);
        auto it = transfers_.find(id);
        if (it == transfers_.end()) return false;
        it->second.bytes_received = bytes;
        it->second.last_update = std::chrono::system_clock::now();
        save();
        return true;
    }

    void complete(const std::string& id) {
        std::lock_guard lock(mutex_);
        transfers_.erase(id);
        save();
    }

    std::optional<TransferInfo> get(const std::string& id) {
        std::lock_guard lock(mutex_);
        auto it = transfers_.find(id);
        if (it == transfers_.end()) return std::nullopt;
        return it->second;
    }

    std::optional<TransferInfo> find_resumable(const std::string& username) {
        std::lock_guard lock(mutex_);
        for (const auto& [id, info] : transfers_) {
            if (info.username == username) return info;
        }
        return std::nullopt;
    }

    void cleanup_stale(std::chrono::seconds timeout = std::chrono::seconds(3600)) {
        std::lock_guard lock(mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto it = transfers_.begin(); it != transfers_.end();) {
            if (now - it->second.last_update > timeout) {
                auto part_file = root_ / it->second.username / (it->second.remote_path + ".part");
                std::filesystem::remove(part_file);
                it = transfers_.erase(it);
            } else {
                ++it;
            }
        }
        save();
    }

    void save() {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& [id, info] : transfers_) {
            j.push_back({
                {"id", id},
                {"username", info.username},
                {"remote_path", info.remote_path},
                {"local_hash", info.local_hash},
                {"total_size", info.total_size},
                {"bytes_received", info.bytes_received},
                {"is_upload", info.is_upload}
            });
        }
        std::ofstream f(transfers_file_);
        if (f) f << j.dump(2);
    }

private:
    void load() {
        if (!std::filesystem::exists(transfers_file_)) return;
        std::ifstream f(transfers_file_);
        if (!f) return;
        nlohmann::json j;
        f >> j;
        for (const auto& item : j) {
            TransferInfo info;
            info.username = item.value("username", "");
            info.remote_path = item.value("remote_path", "");
            info.local_hash = item.value("local_hash", "");
            info.total_size = item.value("total_size", 0ULL);
            info.bytes_received = item.value("bytes_received", 0ULL);
            info.is_upload = item.value("is_upload", true);
            info.last_update = std::chrono::system_clock::now();
            transfers_[item.value("id", "")] = info;
        }
    }

    std::filesystem::path root_;
    std::filesystem::path transfers_file_;
    std::unordered_map<std::string, TransferInfo> transfers_;
    std::mutex mutex_;
};

}
