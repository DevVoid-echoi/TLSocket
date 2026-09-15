import threading

"""Lock to ensure only 1 thread can access at a time"""
state_lock = threading.Lock()
ip_lock = threading.Lock()

# Bảo vệ việc ghi vào socket client: nhiều thread (broadcast, kick, phản hồi
# lệnh cá nhân) có thể cùng lúc gửi tới cùng 1 client. ssl.SSLSocket.sendall()
# không an toàn khi 2 thread ghi đồng thời - TLS record có thể bị chồng/xen
# kẽ và làm hỏng cả phiên (quan sát được: "[SSL: BAD_LENGTH] bad length").
#
# KNOWN GAP (ghi nhận 2026-09-15, chưa vá): hiện chỉ broadcast() và tin nhắn
# "You were kicked!" trong kick_user() (client_handler.py) được bọc lock này.
# Các client.send()/sendall() trực tiếp khác vẫn CHƯA được bọc, về lý thuyết
# vẫn có thể race với 1 broadcast() đang chạy song song nhắm cùng client:
#   - server.py: các phản hồi OK/ERR lúc REGISTER/LOGIN, các dòng
#     "New commands unlocked" trong server_console_input
#   - client_handler.py: phản hồi PERMISSION_DENIED/ERR cho KICK/BAN/UNBAN/SET,
#     khối "New commands unlocked" khi đổi role qua lệnh SET
# Để dành xử lý triệt để sau (gộp cùng giai đoạn hardening bảo mật).
send_lock = threading.Lock()
