# MiniDrive Protocol

## Control Channel

All control messages are JSON documents encoded as UTF-8 with 32-bit length prefix (network byte order).

### Request Format
```json
{ "cmd": "COMMAND_NAME", "args": { ... } }
```

### Response Format
```json
{ "status": "OK|ERROR", "code": 0, "message": "", "data": { ... } }
```

## Commands

### Authentication

| Command | Args | Description |
|---------|------|-------------|
| `PUBLIC` | - | Enter public mode |
| `AUTH` | `username`, `password` | Authenticate user |
| `REGISTER` | `username`, `password` | Register new user |

### File Operations

| Command | Args | Description |
|---------|------|-------------|
| `LIST` | `path` | List directory contents |
| `CD` | `path` | Change directory |
| `PWD` | - | Print working directory |
| `MKDIR` | `path` | Create directory |
| `RMDIR` | `path` | Remove directory (recursive) |
| `DELETE` | `path` | Delete file |
| `MOVE` | `src`, `dst` | Move/rename file or folder |
| `COPY` | `src`, `dst` | Copy file or folder |

### File Transfer

| Command | Args | Description |
|---------|------|-------------|
| `UPLOAD_START` | `path`, `size`, `hash` | Start upload |
| `UPLOAD_CHUNK` | `data` (base64), `offset` | Send chunk |
| `UPLOAD_END` | - | Finish upload |
| `DOWNLOAD_START` | `path`, `offset` | Start download |
| `DOWNLOAD_CHUNK` | `offset`, `chunk_size` | Get chunk |

### Sync & Resume

| Command | Args | Description |
|---------|------|-------------|
| `GET_HASHES` | `path` | Get file hashes for sync |
| `GET_RESUMABLE` | - | Check for resumable transfers |
| `RESUME_UPLOAD` | `path` | Resume interrupted upload |

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 10 | INVALID_COMMAND | Unknown command |
| 11 | INVALID_ARGS | Invalid arguments |
| 20 | AUTH_REQUIRED | Authentication required |
| 21 | AUTH_FAILED | Wrong password |
| 22 | USER_NOT_FOUND | User does not exist |
| 23 | USER_EXISTS | User already registered |
| 24 | SESSION_EXISTS | Session limit reached |
| 30 | FILE_NOT_FOUND | File not found |
| 31 | FILE_EXISTS | File already exists |
| 32 | DIR_NOT_FOUND | Directory not found |
| 33 | DIR_EXISTS | Directory exists |
| 35 | PATH_TRAVERSAL | Path traversal blocked |
| 36 | PERMISSION_DENIED | Permission denied |
| 37 | IO_ERROR | I/O error |
| 43 | HASH_MISMATCH | Hash verification failed |
| 44 | FILE_TOO_LARGE | File exceeds 4GB limit |
| 50 | CONNECTION_LOST | Connection lost |

## Data Channel

File uploads/downloads use base64 encoding in JSON with 64KB chunks.

### Chunk Format
```json
{
  "data": "base64_encoded_data",
  "offset": 0,
  "size": 65536,
  "is_last": false
}
