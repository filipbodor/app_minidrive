#pragma once

#include <cstdint>
#include <string>

namespace minidrive {

enum class ErrorCode : int32_t {
    OK = 0,
    UNKNOWN_ERROR = 1,
    INVALID_COMMAND = 10,
    INVALID_ARGS = 11,
    AUTH_REQUIRED = 20,
    AUTH_FAILED = 21,
    USER_NOT_FOUND = 22,
    USER_EXISTS = 23,
    SESSION_EXISTS = 24,
    FILE_NOT_FOUND = 30,
    FILE_EXISTS = 31,
    DIR_NOT_FOUND = 32,
    DIR_EXISTS = 33,
    DIR_NOT_EMPTY = 34,
    PATH_TRAVERSAL = 35,
    PERMISSION_DENIED = 36,
    IO_ERROR = 37,
    TRANSFER_IN_PROGRESS = 40,
    TRANSFER_NOT_FOUND = 41,
    TRANSFER_FAILED = 42,
    HASH_MISMATCH = 43,
    FILE_TOO_LARGE = 44,
    CONNECTION_LOST = 50,
    SERVER_ERROR = 60
};

inline std::string error_message(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "Success";
        case ErrorCode::UNKNOWN_ERROR: return "Unknown error";
        case ErrorCode::INVALID_COMMAND: return "Invalid command";
        case ErrorCode::INVALID_ARGS: return "Invalid arguments";
        case ErrorCode::AUTH_REQUIRED: return "Authentication required";
        case ErrorCode::AUTH_FAILED: return "Authentication failed";
        case ErrorCode::USER_NOT_FOUND: return "User not found";
        case ErrorCode::USER_EXISTS: return "User already exists";
        case ErrorCode::SESSION_EXISTS: return "Session already exists for this user";
        case ErrorCode::FILE_NOT_FOUND: return "File not found";
        case ErrorCode::FILE_EXISTS: return "File already exists";
        case ErrorCode::DIR_NOT_FOUND: return "Directory not found";
        case ErrorCode::DIR_EXISTS: return "Directory already exists";
        case ErrorCode::DIR_NOT_EMPTY: return "Directory not empty";
        case ErrorCode::PATH_TRAVERSAL: return "Path traversal not allowed";
        case ErrorCode::PERMISSION_DENIED: return "Permission denied";
        case ErrorCode::IO_ERROR: return "I/O error";
        case ErrorCode::TRANSFER_IN_PROGRESS: return "Transfer already in progress";
        case ErrorCode::TRANSFER_NOT_FOUND: return "Transfer not found";
        case ErrorCode::TRANSFER_FAILED: return "Transfer failed";
        case ErrorCode::HASH_MISMATCH: return "Hash mismatch";
        case ErrorCode::FILE_TOO_LARGE: return "File too large";
        case ErrorCode::CONNECTION_LOST: return "Connection lost";
        case ErrorCode::SERVER_ERROR: return "Server error";
    }
    return "Unknown error";
}

}
