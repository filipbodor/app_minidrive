#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "minidrive/crypto.hpp"

namespace minidrive {

class UserStore {
public:
    explicit UserStore(const std::filesystem::path& root) : root_(root) {
        users_file_ = root_ / "users.json";
        load();
    }

    bool exists(const std::string& username) {
        std::lock_guard lock(mutex_);
        return users_.contains(username);
    }

    bool authenticate(const std::string& username, const std::string& password) {
        std::lock_guard lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        return verify_password(it->second, password);
    }

    bool register_user(const std::string& username, const std::string& password) {
        std::lock_guard lock(mutex_);
        if (users_.contains(username)) return false;
        
        std::string hash = hash_password(password);
        if (hash.empty()) return false;
        
        users_[username] = hash;
        
        auto user_dir = root_ / username;
        std::filesystem::create_directories(user_dir);
        
        save();
        return true;
    }

    std::filesystem::path user_root(const std::string& username) {
        if (username.empty()) {
            auto pub = root_ / "public";
            std::filesystem::create_directories(pub);
            return pub;
        }
        return root_ / username;
    }

    void save() {
        nlohmann::json j = users_;
        std::ofstream f(users_file_);
        if (f) f << j.dump(2);
    }

private:
    void load() {
        if (!std::filesystem::exists(users_file_)) {
            std::filesystem::create_directories(root_);
            std::filesystem::create_directories(root_ / "public");
            return;
        }
        std::ifstream f(users_file_);
        if (f) {
            nlohmann::json j;
            f >> j;
            users_ = j.get<std::unordered_map<std::string, std::string>>();
        }
    }

    std::filesystem::path root_;
    std::filesystem::path users_file_;
    std::unordered_map<std::string, std::string> users_;
    std::mutex mutex_;
};

}
