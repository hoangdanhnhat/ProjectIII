# Đây là ý tưởng thực hiện đề tài của tôi:

- Tên đề tài: Hệ thống tự động thu thập bằng chứng số phục vụ DFIR/CA
- Phạm vi: Thu thập trên cả các hệ thống Windows, Linux
- Chức năng: Có khả năng thu thập các bằng chứng số quan trọng để phục vụ công tác điều tra (DFIR/CA) trong từng kịch bản cụ thể (e.g webshell, process injection, malicious service,...)
- Kiến trúc hệ thống: tôi muốn hệ thống được thiết kế như sau
  - một máy chủ trung tâm dùng để điều phối việc thu thập artifacts trên các máy thuộc scope theo dõi
  - trên các máy chủ nằm trong scope theo dõi, sẽ cài đặt một dịch vụ/ daemon. Daemon này luôn listen lệnh từ máy trung tâm. Dịch vụ này có khả năng xác định được vai trò của máy chủ (e.g. File Server, Web Server, máy client,...) từ đó xác định được có cần thu thập artifact trên các máy đó / thu thập artifact ở đâu tùy theo từng mục đích thu thập. Ví dụ: mục đích thu thập là xác định xem có webshell bất thường được tạo bởi attacker hay không, sau khi nhận lệnh từ máy chủ trung tâm, nếu daemon xác định máy là webserver, nó sẽ thu thập các file bất thường trong đường dẫn upload của webserver (ví dụ các file .aspx, .php, etc...)

- Công nghệ sử dụng: tôi muốn bản final sử dụng các stack có performance cao (Rust, Go), tuy nhiên có thể sử dụng các stack dễ hơn trong các bản prototype

- Trước tiên hãy thiết kế cho hệ thống linux trước, mở rộng sang hệ thống windows sau
