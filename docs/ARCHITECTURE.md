```mermaid
sequenceDiagram
    participant Client
    participant ChatServer
    participant AuthLoop as handle_new_connection
    Client->>ChatServer: TCP connect
    ChatServer->>AuthLoop: spawn thread, ssl.wrap_socket()
    AuthLoop->>Client: (chờ dòng đầu tiên)
    alt PING
        Client->>AuthLoop: PING
        AuthLoop->>Client: PONG
    else LOGIN/REGISTER
        Client->>AuthLoop: LOGIN user pass
        AuthLoop->>AuthLoop: authentication.login()
        AuthLoop->>ClientRegistry: registry.add(session)
        AuthLoop->>Client: OK Connected as ...
        AuthLoop->>AuthLoop: spawn handle_messages thread
    end
```

```mermaid
stateDiagram-v2
    [*] --> Clean
    Clean --> Clean: LOGIN_FAILED (< MAX_LOGIN_ATTEMPTS trong LOGIN_WINDOW)
    Clean --> Blocked: LOGIN_FAILED thứ N trong window
    Blocked --> Clean: hết BLOCK_DURATION
```

## Threading

- 1 thread `_accept_loop` chấp nhận kết nối, spawn 1 thread `handle_new_connection` mỗi client.
- Sau khi login, mỗi client có thêm 1 thread `handle_messages` đọc tin nhắn liên tục.
- State dùng chung được bảo vệ bởi:
  - `ClientRegistry._lock` — bảo vệ `_sessions`, `_by_name`, `_client_ips`, `_ip_counts`.
  - `ClientRegistry._send_lock` — serialize ghi socket khi nhiều thread broadcast cùng lúc.
  - `SlidingWindowLimiter._lock` — bảo vệ state rate-limit (login/register/message flood).

> Lưu ý: `server_side/handlers/lock.py` (`state_lock`, `ip_lock`) là code cũ không còn được dùng — nên xoá trong 1 PR dọn dẹp riêng.

