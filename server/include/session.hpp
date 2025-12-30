#pragma once

#include <memory>
#include <string>
#include <filesystem>
#include <functional>
#include <vector>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include "minidrive/protocol.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/path_utils.hpp"
#include "minidrive/crypto.hpp"
#include "user_store.hpp"
#include "session_manager.hpp"
#include "transfer_manager.hpp"

namespace minidrive {

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ip::tcp::socket socket, UserStore& users,
            SessionManager& sessions, TransferManager& transfers,
            const std::filesystem::path& root)
        : socket_(std::move(socket)), users_(users), sessions_(sessions),
          transfers_(transfers), server_root_(root) {}

    ~Session() {
        if (!username_.empty()) {
            sessions_.release(session_key());
        }
    }

    void start() {
        read_message();
    }

private:
    std::string session_key() {
        return username_.empty() ? "__public__" : username_;
    }

    void read_message() {
        auto self = shared_from_this();
        length_buf_.resize(4);
        asio::async_read(socket_, asio::buffer(length_buf_),
            [this, self](std::error_code ec, size_t) {
                if (ec) return;
                uint32_t len = parse_length(length_buf_.data());
                if (len > MAX_MESSAGE_SIZE) return;
                message_buf_.resize(len);
                asio::async_read(socket_, asio::buffer(message_buf_),
                    [this, self](std::error_code ec2, size_t) {
                        if (ec2) return;
                        handle_message();
                    });
            });
    }

    void handle_message() {
        try {
            std::string json_str(message_buf_.begin(), message_buf_.end());
            auto j = nlohmann::json::parse(json_str);
            auto msg = Message::from_json(j);
            auto response = process_command(msg);
            send_response(response);
        } catch (...) {
            send_response(Response::error(ErrorCode::INVALID_COMMAND));
        }
    }

    Response process_command(const Message& msg) {
        if (msg.cmd == "AUTH") return handle_auth(msg.args);
        if (msg.cmd == "REGISTER") return handle_register(msg.args);
        if (msg.cmd == "PUBLIC") return handle_public(msg.args);
        
        if (!authenticated_ && !is_public_) {
            return Response::error(ErrorCode::AUTH_REQUIRED);
        }

        if (msg.cmd == "LIST") return handle_list(msg.args);
        if (msg.cmd == "CD") return handle_cd(msg.args);
        if (msg.cmd == "MKDIR") return handle_mkdir(msg.args);
        if (msg.cmd == "RMDIR") return handle_rmdir(msg.args);
        if (msg.cmd == "DELETE") return handle_delete(msg.args);
        if (msg.cmd == "MOVE") return handle_move(msg.args);
        if (msg.cmd == "COPY") return handle_copy(msg.args);
        if (msg.cmd == "UPLOAD_START") return handle_upload_start(msg.args);
        if (msg.cmd == "UPLOAD_CHUNK") return handle_upload_chunk(msg.args);
        if (msg.cmd == "UPLOAD_END") return handle_upload_end(msg.args);
        if (msg.cmd == "DOWNLOAD_START") return handle_download_start(msg.args);
        if (msg.cmd == "DOWNLOAD_CHUNK") return handle_download_chunk(msg.args);
        if (msg.cmd == "GET_HASHES") return handle_get_hashes(msg.args);
        if (msg.cmd == "GET_RESUMABLE") return handle_get_resumable(msg.args);
        if (msg.cmd == "RESUME_UPLOAD") return handle_resume_upload(msg.args);
        if (msg.cmd == "PWD") return handle_pwd(msg.args);
        if (msg.cmd == "QUIT") return handle_quit(msg.args);

        return Response::error(ErrorCode::INVALID_COMMAND);
    }

    Response handle_auth(const nlohmann::json& args) {
        std::string user = args.value("username", "");
        std::string pass = args.value("password", "");
        
        if (!users_.exists(user)) {
            return Response::error(ErrorCode::USER_NOT_FOUND);
        }
        
        if (!users_.authenticate(user, pass)) {
            return Response::error(ErrorCode::AUTH_FAILED);
        }
        
        if (!sessions_.try_acquire(user)) {
            return Response::error(ErrorCode::SESSION_EXISTS);
        }
        
        username_ = user;
        authenticated_ = true;
        user_root_ = users_.user_root(user);
        current_dir_ = user_root_;
        std::filesystem::create_directories(user_root_);
        
        return Response::ok({{"username", username_}});
    }

    Response handle_register(const nlohmann::json& args) {
        std::string user = args.value("username", "");
        std::string pass = args.value("password", "");
        
        if (user.empty() || pass.empty()) {
            return Response::error(ErrorCode::INVALID_ARGS);
        }
        
        if (users_.exists(user)) {
            return Response::error(ErrorCode::USER_EXISTS);
        }
        
        if (!users_.register_user(user, pass)) {
            return Response::error(ErrorCode::SERVER_ERROR);
        }
        
        return Response::ok({{"username", user}});
    }

    Response handle_public(const nlohmann::json&) {
        if (!sessions_.try_acquire("__public__")) {
            return Response::error(ErrorCode::SESSION_EXISTS);
        }
        
        is_public_ = true;
        user_root_ = users_.user_root("");
        current_dir_ = user_root_;
        std::filesystem::create_directories(user_root_);
        
        return Response::ok();
    }

    Response handle_list(const nlohmann::json& args) {
        std::string path = args.value("path", ".");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::DIR_NOT_FOUND);
        }
        
        nlohmann::json entries = nlohmann::json::array();
        for (const auto& entry : std::filesystem::directory_iterator(*resolved)) {
            FileEntry fe;
            fe.name = entry.path().filename().string();
            fe.is_directory = entry.is_directory();
            if (!fe.is_directory && entry.is_regular_file()) {
                fe.size = entry.file_size();
                auto ftime = entry.last_write_time();
                fe.mtime = std::chrono::duration_cast<std::chrono::seconds>(
                    ftime.time_since_epoch()).count();
            }
            entries.push_back(fe.to_json());
        }
        
        return Response::ok({{"entries", entries}});
    }

    Response handle_cd(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved) || !std::filesystem::is_directory(*resolved)) {
            return Response::error(ErrorCode::DIR_NOT_FOUND);
        }
        
        current_dir_ = *resolved;
        return Response::ok({{"path", relative_to_root(user_root_, current_dir_)}});
    }

    Response handle_pwd(const nlohmann::json&) {
        std::string rel = relative_to_root(user_root_, current_dir_);
        if (rel.empty() || rel == ".") rel = "/";
        return Response::ok({{"path", rel}});
    }

    Response handle_mkdir(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::DIR_EXISTS);
        }
        
        std::error_code ec;
        std::filesystem::create_directories(*resolved, ec);
        if (ec) {
            return Response::error(ErrorCode::IO_ERROR, ec.message());
        }
        
        return Response::ok();
    }

    Response handle_rmdir(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::DIR_NOT_FOUND);
        }
        
        if (!std::filesystem::is_directory(*resolved)) {
            return Response::error(ErrorCode::DIR_NOT_FOUND, "Not a directory");
        }
        
        std::error_code ec;
        std::filesystem::remove_all(*resolved, ec);
        if (ec) {
            return Response::error(ErrorCode::IO_ERROR, ec.message());
        }
        
        return Response::ok();
    }

    Response handle_delete(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }
        
        if (std::filesystem::is_directory(*resolved)) {
            return Response::error(ErrorCode::INVALID_ARGS, "Use RMDIR for directories");
        }
        
        std::error_code ec;
        std::filesystem::remove(*resolved, ec);
        if (ec) {
            return Response::error(ErrorCode::IO_ERROR, ec.message());
        }
        
        return Response::ok();
    }

    Response handle_move(const nlohmann::json& args) {
        std::string src = args.value("src", "");
        std::string dst = args.value("dst", "");
        
        auto src_resolved = safe_resolve(user_root_, current_dir_, src);
        auto dst_resolved = safe_resolve(user_root_, current_dir_, dst);
        
        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }
        
        if (std::filesystem::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_EXISTS);
        }
        
        std::error_code ec;
        std::filesystem::rename(*src_resolved, *dst_resolved, ec);
        if (ec) {
            return Response::error(ErrorCode::IO_ERROR, ec.message());
        }
        
        return Response::ok();
    }

    Response handle_copy(const nlohmann::json& args) {
        std::string src = args.value("src", "");
        std::string dst = args.value("dst", "");
        
        auto src_resolved = safe_resolve(user_root_, current_dir_, src);
        auto dst_resolved = safe_resolve(user_root_, current_dir_, dst);
        
        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }
        
        if (std::filesystem::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_EXISTS);
        }
        
        std::error_code ec;
        std::filesystem::copy(*src_resolved, *dst_resolved,
                              std::filesystem::copy_options::recursive, ec);
        if (ec) {
            return Response::error(ErrorCode::IO_ERROR, ec.message());
        }
        
        return Response::ok();
    }

    Response handle_upload_start(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        uint64_t size = args.value("size", 0ULL);
        std::string hash = args.value("hash", "");
        
        if (size > MAX_FILE_SIZE) {
            return Response::error(ErrorCode::FILE_TOO_LARGE);
        }
        
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_EXISTS);
        }
        
        auto parent = resolved->parent_path();
        if (!std::filesystem::exists(parent)) {
            std::filesystem::create_directories(parent);
        }
        
        upload_path_ = *resolved;
        upload_part_path_ = upload_path_.string() + ".part";
        upload_size_ = size;
        upload_hash_ = hash;
        upload_received_ = 0;
        
        upload_file_.open(upload_part_path_, std::ios::binary | std::ios::trunc);
        if (!upload_file_) {
            return Response::error(ErrorCode::IO_ERROR, "Cannot create file");
        }
        
        if (authenticated_) {
            upload_transfer_id_ = transfers_.start_upload(
                username_, relative_to_root(user_root_, upload_path_), hash, size);
        }
        
        return Response::ok({{"transfer_id", upload_transfer_id_}});
    }

    Response handle_upload_chunk(const nlohmann::json& args) {
        if (!upload_file_.is_open()) {
            return Response::error(ErrorCode::TRANSFER_NOT_FOUND);
        }
        
        std::string data_b64 = args.value("data", "");
        uint64_t offset = args.value("offset", 0ULL);
        
        std::string data;
        data.resize(data_b64.size());
        size_t decoded_len;
        if (sodium_base642bin(reinterpret_cast<unsigned char*>(data.data()), data.size(),
                              data_b64.c_str(), data_b64.size(), nullptr, &decoded_len,
                              nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
            return Response::error(ErrorCode::INVALID_ARGS, "Invalid base64");
        }
        data.resize(decoded_len);
        
        upload_file_.seekp(static_cast<std::streamoff>(offset));
        upload_file_.write(data.data(), static_cast<std::streamsize>(data.size()));
        upload_received_ = offset + data.size();
        
        if (!upload_transfer_id_.empty()) {
            transfers_.update_progress(upload_transfer_id_, upload_received_);
        }
        
        return Response::ok({{"received", upload_received_}});
    }

    Response handle_upload_end(const nlohmann::json&) {
        if (!upload_file_.is_open()) {
            return Response::error(ErrorCode::TRANSFER_NOT_FOUND);
        }
        
        upload_file_.close();
        
        std::string file_hash = hash_file(upload_part_path_);
        if (!upload_hash_.empty() && file_hash != upload_hash_) {
            std::filesystem::remove(upload_part_path_);
            if (!upload_transfer_id_.empty()) {
                transfers_.complete(upload_transfer_id_);
            }
            return Response::error(ErrorCode::HASH_MISMATCH);
        }
        
        std::filesystem::rename(upload_part_path_, upload_path_);
        
        if (!upload_transfer_id_.empty()) {
            transfers_.complete(upload_transfer_id_);
        }
        
        upload_transfer_id_.clear();
        return Response::ok({{"hash", file_hash}});
    }

    Response handle_download_start(const nlohmann::json& args) {
        std::string path = args.value("path", "");
        uint64_t offset = args.value("offset", 0ULL);
        
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }
        
        if (std::filesystem::is_directory(*resolved)) {
            return Response::error(ErrorCode::INVALID_ARGS, "Cannot download directory");
        }
        
        download_path_ = *resolved;
        download_size_ = std::filesystem::file_size(*resolved);
        download_offset_ = offset;
        download_hash_ = hash_file(*resolved);
        
        return Response::ok({
            {"size", download_size_},
            {"hash", download_hash_},
            {"offset", download_offset_}
        });
    }

    Response handle_download_chunk(const nlohmann::json& args) {
        uint64_t offset = args.value("offset", download_offset_);
        size_t chunk_size = args.value("chunk_size", CHUNK_SIZE);
        
        std::ifstream file(download_path_, std::ios::binary);
        if (!file) {
            return Response::error(ErrorCode::IO_ERROR, "Cannot open file");
        }
        
        file.seekg(static_cast<std::streamoff>(offset));
        std::vector<char> buffer(chunk_size);
        file.read(buffer.data(), static_cast<std::streamsize>(chunk_size));
        auto bytes_read = file.gcount();
        
        std::string encoded;
        encoded.resize(sodium_base64_encoded_len(static_cast<size_t>(bytes_read),
                                                  sodium_base64_VARIANT_ORIGINAL));
        sodium_bin2base64(encoded.data(), encoded.size(),
                          reinterpret_cast<unsigned char*>(buffer.data()),
                          static_cast<size_t>(bytes_read),
                          sodium_base64_VARIANT_ORIGINAL);
        while (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
        
        download_offset_ = offset + static_cast<uint64_t>(bytes_read);
        bool is_last = download_offset_ >= download_size_;
        
        return Response::ok({
            {"data", encoded},
            {"offset", offset},
            {"size", bytes_read},
            {"is_last", is_last}
        });
    }

    Response handle_get_hashes(const nlohmann::json& args) {
        std::string path = args.value("path", ".");
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        if (!std::filesystem::exists(*resolved)) {
            return Response::error(ErrorCode::DIR_NOT_FOUND);
        }
        
        nlohmann::json files = nlohmann::json::object();
        collect_hashes(*resolved, user_root_, files);
        
        return Response::ok({{"files", files}});
    }

    void collect_hashes(const std::filesystem::path& dir,
                        const std::filesystem::path& base,
                        nlohmann::json& files) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                std::string rel = std::filesystem::relative(entry.path(), base).string();
                files[rel] = hash_file(entry.path());
            }
        }
    }

    Response handle_get_resumable(const nlohmann::json&) {
        if (!authenticated_) {
            return Response::ok({{"has_transfer", false}});
        }
        
        auto info = transfers_.find_resumable(username_);
        if (!info) {
            return Response::ok({{"has_transfer", false}});
        }
        
        return Response::ok({
            {"has_transfer", true},
            {"remote_path", info->remote_path},
            {"bytes_received", info->bytes_received},
            {"total_size", info->total_size},
            {"hash", info->local_hash}
        });
    }

    Response handle_resume_upload(const nlohmann::json& args) {
        if (!authenticated_) {
            return Response::error(ErrorCode::AUTH_REQUIRED);
        }
        
        std::string path = args.value("path", "");
        auto info = transfers_.find_resumable(username_);
        
        if (!info || info->remote_path != path) {
            return Response::error(ErrorCode::TRANSFER_NOT_FOUND);
        }
        
        auto resolved = safe_resolve(user_root_, current_dir_, path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL);
        }
        
        upload_path_ = *resolved;
        upload_part_path_ = upload_path_.string() + ".part";
        upload_size_ = info->total_size;
        upload_hash_ = info->local_hash;
        upload_received_ = info->bytes_received;
        upload_transfer_id_ = username_ + ":" + path;
        
        upload_file_.open(upload_part_path_, std::ios::binary | std::ios::app);
        if (!upload_file_) {
            return Response::error(ErrorCode::IO_ERROR, "Cannot open file");
        }
        
        return Response::ok({
            {"offset", upload_received_},
            {"transfer_id", upload_transfer_id_}
        });
    }

    Response handle_quit(const nlohmann::json&) {
        return Response::ok();
    }

    void send_response(const Response& response) {
        auto self = shared_from_this();
        auto buf = std::make_shared<std::vector<uint8_t>>(
            frame_message(response.to_json()));
        asio::async_write(socket_, asio::buffer(*buf),
            [this, self, buf, quit = response.code == ErrorCode::OK && 
                                      message_buf_.size() >= 4](std::error_code ec, size_t) {
                if (!ec) {
                    read_message();
                }
            });
    }

    asio::ip::tcp::socket socket_;
    UserStore& users_;
    SessionManager& sessions_;
    TransferManager& transfers_;
    std::filesystem::path server_root_;
    
    std::string username_;
    bool authenticated_ = false;
    bool is_public_ = false;
    std::filesystem::path user_root_;
    std::filesystem::path current_dir_;
    
    std::vector<uint8_t> length_buf_;
    std::vector<uint8_t> message_buf_;
    
    std::filesystem::path upload_path_;
    std::filesystem::path upload_part_path_;
    std::ofstream upload_file_;
    uint64_t upload_size_ = 0;
    uint64_t upload_received_ = 0;
    std::string upload_hash_;
    std::string upload_transfer_id_;
    
    std::filesystem::path download_path_;
    uint64_t download_size_ = 0;
    uint64_t download_offset_ = 0;
    std::string download_hash_;
};

}
