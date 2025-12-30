#pragma once

#include <string>
#include <filesystem>
#include <optional>

namespace minidrive {

inline std::optional<std::filesystem::path> safe_path(
    const std::filesystem::path& root,
    const std::filesystem::path& user_path) {
    
    std::filesystem::path combined;
    if (user_path.is_absolute()) {
        combined = root / user_path.relative_path();
    } else {
        combined = root / user_path;
    }
    
    std::filesystem::path normalized = combined.lexically_normal();
    
    auto root_str = root.lexically_normal().string();
    auto norm_str = normalized.string();
    
    if (norm_str.find(root_str) != 0) {
        return std::nullopt;
    }
    
    return normalized;
}

inline std::optional<std::filesystem::path> safe_resolve(
    const std::filesystem::path& root,
    const std::filesystem::path& current,
    const std::filesystem::path& user_path) {
    
    std::filesystem::path base;
    if (user_path.is_absolute()) {
        base = root / user_path.relative_path();
    } else {
        base = current / user_path;
    }
    
    return safe_path(root, std::filesystem::relative(base, root));
}

inline std::string relative_to_root(
    const std::filesystem::path& root,
    const std::filesystem::path& path) {
    return std::filesystem::relative(path, root).string();
}

inline bool is_valid_filename(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    if (name.find('/') != std::string::npos) return false;
    if (name.find('\0') != std::string::npos) return false;
    return true;
}

}
