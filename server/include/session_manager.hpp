#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

namespace minidrive {

class SessionManager {
public:
    bool try_acquire(const std::string& username, bool allow_multiple = false) {
        std::lock_guard lock(mutex_);
        if (username == "__public__") {
            public_count_++;
            return true;
        }
        if (!allow_multiple && sessions_.contains(username)) {
            return false;
        }
        sessions_[username]++;
        return true;
    }

    void release(const std::string& username) {
        std::lock_guard lock(mutex_);
        if (username == "__public__") {
            if (public_count_ > 0) public_count_--;
            return;
        }
        auto it = sessions_.find(username);
        if (it != sessions_.end()) {
            if (--it->second == 0) {
                sessions_.erase(it);
            }
        }
    }

    bool has_session(const std::string& username) {
        std::lock_guard lock(mutex_);
        if (username == "__public__") return public_count_ > 0;
        return sessions_.contains(username);
    }

private:
    std::unordered_map<std::string, int> sessions_;
    int public_count_ = 0;
    std::mutex mutex_;
};

}
