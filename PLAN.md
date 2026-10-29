# Kế hoạch triển khai hệ thống thu thập bằng chứng số DFIR/CA

## 1. Mục tiêu và phạm vi

Xây dựng hệ thống gồm **máy chủ điều phối** và **agent/daemon trên máy thuộc phạm vi quản lý**. Người điều tra tạo yêu cầu thu thập theo kịch bản; agent nhận yêu cầu, xác định vai trò máy, thu thập artifacts phù hợp và chuyển bằng chứng về máy chủ kèm thông tin kiểm chứng. Ưu tiên Linux; thiết kế giao thức và định dạng dữ liệu đủ độc lập nền tảng để bổ sung Windows sau.

**MVP:** điều tra nghi vấn webshell trên Linux (Nginx/Apache). Thu thập file đáng chú ý từ những đường dẫn đã được cấu hình/khám phá và metadata, log liên quan. Hệ thống *thu thập* dữ liệu phục vụ phân tích, không kết luận chắc chắn file là độc hại chỉ dựa vào phần mở rộng.

**Ngoài phạm vi MVP:** xử lý memory dump/process injection, phân tích malware tự động, phản ứng/xóa file, triển khai Windows và thu thập mọi loại artifact trên toàn hệ thống.

## 2. Kiến trúc đề xuất

```text
Điều tra viên → API/CLI máy chủ → hàng đợi tác vụ + kho metadata
                                ↓              ↑
                       agent Linux ←→ API nhận tác vụ / tải bằng chứng
                                ↓
                   bộ nhận diện vai trò + bộ thu thập theo kịch bản
```

- **Máy chủ:** xác thực người dùng và agent, quản lý danh sách máy được phép, tạo tác vụ theo host/scope, phân phối tác vụ, lưu trạng thái và metadata, nhận artifacts, tạo gói xuất phục vụ điều tra. MVP có thể dùng một dịch vụ Go, PostgreSQL và kho file cục bộ có cấu trúc; giao diện CLI/API là đủ.
- **Agent Linux:** chạy dưới systemd, chủ động kết nối về máy chủ bằng HTTPS (long-poll hoặc polling có backoff) để không phải mở cổng inbound trên các máy được theo dõi. Agent thực thi *chỉ* các loại tác vụ đã định nghĩa và đã được cấp quyền; không nhận shell command tùy ý.
- **Nhận diện vai trò:** kiểm tra dấu hiệu Nginx/Apache (dịch vụ/process, cấu hình site, document root) rồi gắn nhãn `web_server` kèm nguồn chứng minh. Cho phép cấu hình override/đường dẫn web root và upload; không suy đoán một đường dẫn upload chung cho mọi site. Khi không xác định được đường dẫn, báo `needs_configuration`, không tự quét toàn bộ filesystem.
- **Kịch bản thu thập:** module theo `scenario_id` và phiên bản. Bộ lập kế hoạch kết hợp vai trò host, mục tiêu và cấu hình để sinh danh sách nguồn dữ liệu. Agent báo lý do bỏ qua nếu host không phù hợp; điều tra viên vẫn có thể chọn host cụ thể trong phạm vi được phép.
- **Bảo quản bằng chứng:** dữ liệu gốc ở dạng byte; với mỗi file lưu hash SHA-256, kích thước, đường dẫn gốc, thời gian hệ thống, metadata/stat, thời gian thu thập UTC, host ID, job ID, kết quả/ lỗi và phiên bản collector. Ghi audit log cho tạo tác vụ, thu thập, tải về và truy cập; xác minh hash khi nhận và khi xuất. Ghi rõ dữ liệu có thể thay đổi trong lúc thu thập (live response); không tuyên bố tính toàn vẹn tuyệt đối của nguồn đang chạy.
- **Bảo mật:** TLS hai chiều hoặc token agent cấp riêng kết hợp TLS và quy trình xoay/thu hồi; RBAC cho API; giới hạn host, đường dẫn và loại tác vụ theo policy; giới hạn kích thước, băng thông và thời gian; chống đọc vượt phạm vi (symlink/path traversal), mã hóa kho bằng chứng và kiểm soát truy cập. Xác định yêu cầu quyền truy cập tối thiểu của agent cho từng nguồn; quyền cao hơn chỉ cấp khi kịch bản thật sự cần.

## 3. Hợp đồng dữ liệu tối thiểu

- `Host`: `host_id`, OS, hostname, vai trò và bằng chứng nhận diện, cấu hình đường dẫn được cho phép.
- `Job`: `job_id`, người tạo, `scenario_id`/version, host đích, tham số được kiểm tra, thời gian tạo/hạn, trạng thái.
- `Artifact`: `artifact_id`, `job_id`, `host_id`, loại, đường dẫn nguồn, metadata, SHA-256, kích thước, thời điểm thu thập, vị trí lưu, trạng thái/lỗi.
- Trạng thái tác vụ: `queued → running → completed | partial | failed | cancelled`; gửi lại an toàn theo `job_id`/`artifact_id` và ghi nhận từng artifact lỗi mà không mất toàn bộ tác vụ.

## 4. Các giai đoạn triển khai

| Giai đoạn | Công việc chính | Điều kiện hoàn thành |
| --- | --- | --- |
| 0. Khảo sát và thiết kế | Chốt môi trường thử nghiệm, nguồn artifact cho từng kịch bản, quyền truy cập, threat model, schema dữ liệu/API và cách lưu bằng chứng. | Có sơ đồ luồng, danh sách đường dẫn/cấu hình thử nghiệm và tiêu chí kiểm thử. |
| 1. Khung Linux | Máy chủ đăng ký agent; agent systemd kết nối outbound, heartbeat, nhận tác vụ, cập nhật trạng thái; xác thực và audit cơ bản. | Tạo và theo dõi tác vụ trên ít nhất 2 VM Linux; agent không thực thi lệnh tùy ý. |
| 2. MVP webshell | Phát hiện vai trò web server; đọc cấu hình web root/upload; lọc file đáng chú ý (phần mở rộng, file mới/sửa gần đây, vị trí bất thường); thu thập file, metadata và log web trong khoảng thời gian yêu cầu. | Trên lab Apache/Nginx có file mẫu, tìm và tải đúng artifacts; máy không phải web server được bỏ qua có lý do; báo lỗi rõ khi thiếu cấu hình. |
| 3. Độ tin cậy & bảo toàn | Hash và xác minh tải lên, manifest, giới hạn dung lượng, retry/idempotency, bảo vệ đường dẫn, audit, xuất bộ bằng chứng. | Hash khớp ở nguồn/đích, chịu được ngắt kết nối, xuất gói có thể kiểm chứng và truy nguyên người thao tác. |
| 4. Thêm kịch bản Linux | Dịch vụ độc hại: systemd unit/drop-in, trạng thái service, binary được tham chiếu, journal; process injection: chỉ khảo sát nguồn dữ liệu process/memory và quyền cần thiết, triển khai sau khi được phê duyệt phạm vi. | Mỗi kịch bản có fixture, manifest và kiểm thử riêng; không mở rộng quyền của MVP một cách mặc định. |
| 5. Mở rộng Windows | Tách collector theo OS; thêm Windows Service, phát hiện vai trò IIS/file server, đường dẫn cấu hình, Event Logs, services và artifacts phù hợp theo kịch bản. | Cùng API/manifest/job model hoạt động trên máy Windows thử nghiệm, kèm test chéo nền tảng. |

## 5. Stack và kiểm thử

- **Đề xuất triển khai:** Go cho server và agent Linux để có một codebase/stack đơn giản, cross-compile và dễ phân phối binary; PostgreSQL lưu metadata, filesystem có phân quyền cho artifact MVP. Khi có dữ liệu benchmark mới cân nhắc chuyển thành phần cần tối ưu sang Rust. Prototype nhanh có thể dùng Python để kiểm chứng collector, nhưng không thay đổi giao thức/manifest đã thống nhất.
- **Lab:** tối thiểu một server điều phối, một VM web server (Apache hoặc Nginx) và một VM không phải web server; dữ liệu giả lập, không sử dụng webshell thật trên môi trường production. Sau đó bổ sung VM Windows.
- **Kiểm thử:** unit cho nhận diện vai trò, lọc đường dẫn và schema; integration cho vòng đời tác vụ, retry và đối chiếu hash; end-to-end cho webshell fixture, mất kết nối, file thay đổi khi đọc, file lớn, symlink và agent không đủ quyền.
- **Chỉ số đánh giá:** tỷ lệ thu thập thành công trên bộ fixture, độ đầy đủ metadata, tỷ lệ kiểm chứng hash thành công, thời gian từ lúc tạo job đến lúc nhận artifact, CPU/RAM/băng thông của agent và số lần thu thập nhầm trên host không phù hợp.

## 6. Quyết định cần chốt trước khi lập trình

1. Danh sách hệ điều hành/distro và web server thực tế; cách xác định upload directories cho từng site.
2. Quy mô host, lượng bằng chứng ước tính, thời hạn lưu trữ và yêu cầu bảo vệ dữ liệu nhạy cảm.
3. Có được phép đọc nội dung file/log hay chỉ metadata, mức quyền cho agent, và quy trình phê duyệt tác vụ.
4. Định nghĩa `CA` trong bối cảnh đề tài và yêu cầu pháp lý/chain of custody cụ thể của đơn vị đánh giá.

## Trả lời cho câu hỏi 6.

1. Hiện tại tạo prototype trên Ubuntu, webserver chạy apache2, upload directories mặc định
2. Prototype trên 1 host, chưa cần bảo vệ dữ liệu, lưu dữ liệu như bình thường
3. Đọc nội dụng thoải mái, agent quyền cao
4. CA giống như DFIR cũng được, chain of custody tiêu chuẩn
