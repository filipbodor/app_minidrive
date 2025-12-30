#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sodium.h>
#include "connection.hpp"
#include "cli_parser.hpp"
#include "minidrive/protocol.hpp"
#include "minidrive/crypto.hpp"

namespace minidrive {

class Shell {
public:
    Shell(Connection& conn, const ClientConfig& config, Logger& logger)
        : conn_(conn), config_(config), logger_(logger) {}

    void run() {
        std::string line;
        while (running_) {
            std::cout << "> " << std::flush;
            if (!std::getline(std::cin, line)) {
                break;
            }
            
            if (line.empty()) continue;
            
            logger_.log_command(line);
            process_command(line);
        }
    }

    void stop() {
        running_ = false;
    }

private:
    std::vector<std::string> split(const std::string& s) {
        std::vector<std::string> tokens;
        std::istringstream iss(s);
        std::string token;
        bool in_quotes = false;
        std::string current;
        
        for (char c : s) {
            if (c == '"') {
                in_quotes = !in_quotes;
            } else if (c == ' ' && !in_quotes) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        if (!current.empty()) {
            tokens.push_back(current);
        }
        return tokens;
    }

    void process_command(const std::string& line) {
        auto tokens = split(line);
        if (tokens.empty()) return;
        
        std::string cmd = tokens[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);
        
        if (cmd == "HELP") {
            print_help();
        } else if (cmd == "EXIT" || cmd == "QUIT") {
            conn_.send_command("QUIT");
            running_ = false;
        } else if (cmd == "LIST" || cmd == "LS") {
            handle_list(tokens);
        } else if (cmd == "CD") {
            handle_cd(tokens);
        } else if (cmd == "PWD") {
            handle_pwd();
        } else if (cmd == "MKDIR") {
            handle_mkdir(tokens);
        } else if (cmd == "RMDIR") {
            handle_rmdir(tokens);
        } else if (cmd == "DELETE" || cmd == "RM") {
            handle_delete(tokens);
        } else if (cmd == "MOVE" || cmd == "MV") {
            handle_move(tokens);
        } else if (cmd == "COPY" || cmd == "CP") {
            handle_copy(tokens);
        } else if (cmd == "UPLOAD") {
            handle_upload(tokens);
        } else if (cmd == "DOWNLOAD") {
            handle_download(tokens);
        } else if (cmd == "SYNC") {
            handle_sync(tokens);
        } else {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_COMMAND) << std::endl;
            std::cout << "Unknown command: " << cmd << std::endl;
        }
    }

    void print_help() {
        std::cout << "OK" << std::endl;
        std::cout << "Available commands:" << std::endl;
        std::cout << "  HELP                    - Show this help" << std::endl;
        std::cout << "  EXIT                    - Close connection and exit" << std::endl;
        std::cout << "  LIST [path]             - List files in directory" << std::endl;
        std::cout << "  CD <path>               - Change directory" << std::endl;
        std::cout << "  PWD                     - Print working directory" << std::endl;
        std::cout << "  MKDIR <path>            - Create directory" << std::endl;
        std::cout << "  RMDIR <path>            - Remove directory (recursive)" << std::endl;
        std::cout << "  DELETE <path>           - Delete file" << std::endl;
        std::cout << "  MOVE <src> <dst>        - Move/rename file or folder" << std::endl;
        std::cout << "  COPY <src> <dst>        - Copy file or folder" << std::endl;
        std::cout << "  UPLOAD <local> [remote] - Upload file to server" << std::endl;
        std::cout << "  DOWNLOAD <remote> [local] - Download file from server" << std::endl;
        std::cout << "  SYNC <local> <remote>   - Sync local directory to server" << std::endl;
    }

    void print_response(const Response& resp) {
        logger_.log_response(resp.status, resp.message);
        if (resp.status == "OK") {
            std::cout << "OK" << std::endl;
        } else {
            std::cout << "ERROR: " << static_cast<int>(resp.code) << std::endl;
            std::cout << resp.message << std::endl;
        }
    }

    void handle_list(const std::vector<std::string>& tokens) {
        std::string path = tokens.size() > 1 ? tokens[1] : ".";
        auto resp = conn_.send_command("LIST", {{"path", path}});
        
        if (resp.status != "OK") {
            print_response(resp);
            return;
        }
        
        std::cout << "OK" << std::endl;
        auto entries = resp.data.value("entries", nlohmann::json::array());
        for (const auto& e : entries) {
            auto entry = FileEntry::from_json(e);
            if (entry.is_directory) {
                std::cout << "[DIR]  " << entry.name << "/" << std::endl;
            } else {
                std::cout << "[FILE] " << entry.name << " (" << entry.size << " bytes)" << std::endl;
            }
        }
    }

    void handle_cd(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: CD <path>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("CD", {{"path", tokens[1]}});
        print_response(resp);
        if (resp.status == "OK") {
            std::cout << "Changed to: " << resp.data.value("path", "") << std::endl;
        }
    }

    void handle_pwd() {
        auto resp = conn_.send_command("PWD");
        print_response(resp);
        if (resp.status == "OK") {
            std::cout << resp.data.value("path", "/") << std::endl;
        }
    }

    void handle_mkdir(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: MKDIR <path>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("MKDIR", {{"path", tokens[1]}});
        print_response(resp);
    }

    void handle_rmdir(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: RMDIR <path>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("RMDIR", {{"path", tokens[1]}});
        print_response(resp);
    }

    void handle_delete(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: DELETE <path>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("DELETE", {{"path", tokens[1]}});
        print_response(resp);
    }

    void handle_move(const std::vector<std::string>& tokens) {
        if (tokens.size() < 3) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: MOVE <src> <dst>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("MOVE", {{"src", tokens[1]}, {"dst", tokens[2]}});
        print_response(resp);
    }

    void handle_copy(const std::vector<std::string>& tokens) {
        if (tokens.size() < 3) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: COPY <src> <dst>" << std::endl;
            return;
        }
        auto resp = conn_.send_command("COPY", {{"src", tokens[1]}, {"dst", tokens[2]}});
        print_response(resp);
    }

    void handle_upload(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: UPLOAD <local_path> [remote_path]" << std::endl;
            return;
        }
        
        std::filesystem::path local_path = tokens[1];
        std::string remote_path = tokens.size() > 2 ? tokens[2] : local_path.filename().string();
        
        if (!std::filesystem::exists(local_path)) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::FILE_NOT_FOUND) << std::endl;
            std::cout << "Local file not found: " << local_path << std::endl;
            return;
        }
        
        if (std::filesystem::is_directory(local_path)) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Cannot upload directory. Use SYNC instead." << std::endl;
            return;
        }
        
        uint64_t file_size = std::filesystem::file_size(local_path);
        std::string file_hash = hash_file(local_path);
        
        auto start_resp = conn_.send_command("UPLOAD_START", {
            {"path", remote_path},
            {"size", file_size},
            {"hash", file_hash}
        });
        
        if (start_resp.status != "OK") {
            print_response(start_resp);
            return;
        }
        
        std::ifstream file(local_path, std::ios::binary);
        if (!file) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::IO_ERROR) << std::endl;
            std::cout << "Cannot open local file" << std::endl;
            return;
        }
        
        std::vector<char> buffer(CHUNK_SIZE);
        uint64_t offset = 0;
        
        while (file.read(buffer.data(), static_cast<std::streamsize>(CHUNK_SIZE)) || file.gcount() > 0) {
            size_t bytes_read = static_cast<size_t>(file.gcount());
            
            std::string encoded;
            encoded.resize(sodium_base64_encoded_len(bytes_read, sodium_base64_VARIANT_ORIGINAL));
            sodium_bin2base64(encoded.data(), encoded.size(),
                              reinterpret_cast<unsigned char*>(buffer.data()), bytes_read,
                              sodium_base64_VARIANT_ORIGINAL);
            while (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
            
            auto chunk_resp = conn_.send_command("UPLOAD_CHUNK", {
                {"data", encoded},
                {"offset", offset}
            });
            
            if (chunk_resp.status != "OK") {
                print_response(chunk_resp);
                return;
            }
            
            offset += bytes_read;
            
            int percent = static_cast<int>((offset * 100) / file_size);
            std::cout << "\rUploading: " << percent << "%" << std::flush;
        }
        
        std::cout << std::endl;
        
        auto end_resp = conn_.send_command("UPLOAD_END");
        print_response(end_resp);
    }

    void handle_download(const std::vector<std::string>& tokens) {
        if (tokens.size() < 2) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: DOWNLOAD <remote_path> [local_path]" << std::endl;
            return;
        }
        
        std::string remote_path = tokens[1];
        std::filesystem::path local_path;
        if (tokens.size() > 2) {
            local_path = tokens[2];
        } else {
            local_path = std::filesystem::path(remote_path).filename();
        }
        
        if (std::filesystem::exists(local_path)) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::FILE_EXISTS) << std::endl;
            std::cout << "Local file already exists: " << local_path << std::endl;
            return;
        }
        
        auto start_resp = conn_.send_command("DOWNLOAD_START", {{"path", remote_path}});
        
        if (start_resp.status != "OK") {
            print_response(start_resp);
            return;
        }
        
        uint64_t file_size = start_resp.data.value("size", 0ULL);
        std::string expected_hash = start_resp.data.value("hash", "");
        
        std::ofstream file(local_path, std::ios::binary);
        if (!file) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::IO_ERROR) << std::endl;
            std::cout << "Cannot create local file" << std::endl;
            return;
        }
        
        uint64_t received = 0;
        
        while (received < file_size) {
            auto chunk_resp = conn_.send_command("DOWNLOAD_CHUNK", {
                {"offset", received},
                {"chunk_size", CHUNK_SIZE}
            });
            
            if (chunk_resp.status != "OK") {
                file.close();
                std::filesystem::remove(local_path);
                print_response(chunk_resp);
                return;
            }
            
            std::string data_b64 = chunk_resp.data.value("data", "");
            std::string data;
            data.resize(data_b64.size());
            size_t decoded_len;
            sodium_base642bin(reinterpret_cast<unsigned char*>(data.data()), data.size(),
                              data_b64.c_str(), data_b64.size(), nullptr, &decoded_len,
                              nullptr, sodium_base64_VARIANT_ORIGINAL);
            data.resize(decoded_len);
            
            file.write(data.data(), static_cast<std::streamsize>(data.size()));
            received += decoded_len;
            
            int percent = static_cast<int>((received * 100) / file_size);
            std::cout << "\rDownloading: " << percent << "%" << std::flush;
            
            if (chunk_resp.data.value("is_last", false)) break;
        }
        
        std::cout << std::endl;
        file.close();
        
        std::string actual_hash = hash_file(local_path);
        if (!expected_hash.empty() && actual_hash != expected_hash) {
            std::filesystem::remove(local_path);
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::HASH_MISMATCH) << std::endl;
            std::cout << "Downloaded file hash mismatch" << std::endl;
            return;
        }
        
        std::cout << "OK" << std::endl;
        std::cout << "Downloaded: " << local_path << std::endl;
    }

    void handle_sync(const std::vector<std::string>& tokens) {
        if (tokens.size() < 3) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::INVALID_ARGS) << std::endl;
            std::cout << "Usage: SYNC <local_dir> <remote_dir>" << std::endl;
            return;
        }
        
        std::filesystem::path local_dir = tokens[1];
        std::string remote_dir = tokens[2];
        
        if (!std::filesystem::exists(local_dir) || !std::filesystem::is_directory(local_dir)) {
            std::cout << "ERROR: " << static_cast<int>(ErrorCode::DIR_NOT_FOUND) << std::endl;
            std::cout << "Local directory not found: " << local_dir << std::endl;
            return;
        }
        
        auto mkdir_resp = conn_.send_command("MKDIR", {{"path", remote_dir}});
        
        auto hashes_resp = conn_.send_command("GET_HASHES", {{"path", remote_dir}});
        if (hashes_resp.status != "OK") {
            print_response(hashes_resp);
            return;
        }
        
        auto remote_files = hashes_resp.data.value("files", nlohmann::json::object());
        
        std::unordered_map<std::string, std::string> local_files;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(local_dir)) {
            if (entry.is_regular_file()) {
                std::string rel = std::filesystem::relative(entry.path(), local_dir).string();
                local_files[rel] = hash_file(entry.path());
            }
        }
        
        int uploaded = 0, skipped = 0, deleted = 0;
        
        for (const auto& [rel_path, hash] : local_files) {
            std::string remote_path = remote_dir + "/" + rel_path;
            auto it = remote_files.find(rel_path);
            
            if (it != remote_files.end() && it.value() == hash) {
                skipped++;
                continue;
            }
            
            if (it != remote_files.end()) {
                conn_.send_command("DELETE", {{"path", remote_path}});
            }
            
            std::filesystem::path local_path = local_dir / rel_path;
            uint64_t file_size = std::filesystem::file_size(local_path);
            std::string file_hash = hash;
            
            auto parent = std::filesystem::path(remote_path).parent_path().string();
            if (!parent.empty() && parent != ".") {
                conn_.send_command("MKDIR", {{"path", parent}});
            }
            
            auto start_resp = conn_.send_command("UPLOAD_START", {
                {"path", remote_path},
                {"size", file_size},
                {"hash", file_hash}
            });
            
            if (start_resp.status != "OK") {
                std::cout << "Failed to upload: " << rel_path << std::endl;
                continue;
            }
            
            std::ifstream file(local_path, std::ios::binary);
            std::vector<char> buffer(CHUNK_SIZE);
            uint64_t offset = 0;
            
            while (file.read(buffer.data(), static_cast<std::streamsize>(CHUNK_SIZE)) || file.gcount() > 0) {
                size_t bytes_read = static_cast<size_t>(file.gcount());
                
                std::string encoded;
                encoded.resize(sodium_base64_encoded_len(bytes_read, sodium_base64_VARIANT_ORIGINAL));
                sodium_bin2base64(encoded.data(), encoded.size(),
                                  reinterpret_cast<unsigned char*>(buffer.data()), bytes_read,
                                  sodium_base64_VARIANT_ORIGINAL);
                while (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
                
                conn_.send_command("UPLOAD_CHUNK", {{"data", encoded}, {"offset", offset}});
                offset += bytes_read;
            }
            
            conn_.send_command("UPLOAD_END");
            uploaded++;
            std::cout << "Uploaded: " << rel_path << std::endl;
        }
        
        for (auto& [rel_path, hash] : remote_files.items()) {
            if (local_files.find(rel_path) == local_files.end()) {
                std::string remote_path = remote_dir + "/" + rel_path;
                conn_.send_command("DELETE", {{"path", remote_path}});
                deleted++;
                std::cout << "Deleted: " << rel_path << std::endl;
            }
        }
        
        std::cout << "OK" << std::endl;
        std::cout << "Sync complete: " << uploaded << " uploaded, " 
                  << skipped << " skipped, " << deleted << " deleted" << std::endl;
    }

    Connection& conn_;
    ClientConfig config_;
    Logger& logger_;
    bool running_ = true;
};

}
