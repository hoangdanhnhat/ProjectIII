# DFIR/CA evidence collector — Linux lab prototype

Prototype gồm server điều phối và agent Linux viết bằng Go. Phạm vi hiện tại: **một host Ubuntu/Apache2**, kịch bản `webshell.v1`. Agent kiểm tra file cấu hình web server (Apache trên Linux, IIS trên Windows), đọc **đường dẫn upload cấu hình tường minh** (mặc định `/var/www/html/uploads` trên Linux, không có mặc định trên Windows) và gửi các file có phần mở rộng script (`.php`, `.phtml`, `.phar`, `.cgi`, `.pl`, `.py`, `.sh`, `.jsp`, `.aspx`). Nếu job có `since`, agent thu thập thêm file mới sửa đổi kể từ thời điểm đó. Agent thu thập snapshot `access.log` và `error.log` nếu truy cập được. Kết quả là **dữ liệu để điều tra**, không phải khẳng định webshell đã được phát hiện.

## Chạy thử trên một máy

Yêu cầu: Go >= 1.24, Ubuntu có Apache2. Chỉ dùng dữ liệu lab được phép thu thập. Apache **không có upload directory mặc định**: ví dụ dưới đây tạo `/var/www/html/uploads` cho lab; nếu ứng dụng dùng chỗ khác, thay `-uploads` bằng đường dẫn thật. Không cần cài PostgreSQL trong bản prototype một host.

```bash
go test ./...
go build -o bin/dfir-server ./cmd/dfir-server
go build -o bin/dfir-agent ./cmd/dfir-agent
sudo install -d -m 0750 /var/www/html/uploads
printf 'DFIR lab fixture — not executable PHP\n' | sudo tee /var/www/html/uploads/fixture.php >/dev/null
```

Trong **terminal 1**, đặt hai token **khác nhau, ngẫu nhiên**, rồi chạy server. Trong **terminal 2**, chạy agent với cùng agent token (trong thực tế không ghi token vào history hoặc repo; dùng environment file bảo vệ quyền đọc):

```bash
# terminal 1
export DFIR_OPERATOR_TOKEN="$(openssl rand -hex 32)"
export DFIR_AGENT_TOKEN="$(openssl rand -hex 32)"
./bin/dfir-server -data ./data -host-id lab-ubuntu

# terminal 2: thay <agent-token> bằng giá trị DFIR_AGENT_TOKEN của terminal 1
sudo env DFIR_AGENT_TOKEN='<agent-token>' ./bin/dfir-agent \
  -server http://127.0.0.1:8080 -host-id lab-ubuntu \
  -uploads /var/www/html/uploads

# terminal 3: thay <operator-token> bằng giá trị DFIR_OPERATOR_TOKEN của terminal 1
curl -sS -X POST http://127.0.0.1:8080/v1/jobs \
  -H 'Authorization: Bearer <operator-token>' -H 'Content-Type: application/json' \
  -d '{"host_id":"lab-ubuntu","scenario":"webshell.v1"}'
```

Lấy `id` từ response; kiểm tra kết quả và danh sách artifact:

```bash
curl -sS http://127.0.0.1:8080/v1/jobs/<job-id> \
  -H 'Authorization: Bearer <operator-token>'
curl -sS http://127.0.0.1:8080/v1/jobs/<job-id>/artifacts/<artifact-id> \
  -H 'Authorization: Bearer <operator-token>' -o evidence.bin
sha256sum evidence.bin  # so với sha256 trong job JSON
```

Nếu không dùng thư mục lab dưới document root hoặc muốn chạy test không cần Apache thật, có thể trỏ `-uploads` và `-web-config` tới fixture nằm trong thư mục thử nghiệm. `-web-logs ''` để bỏ qua log khi thử nghiệm. Không đưa fixture chứa mã độc vào web root có thể truy cập từ ngoài.

## Lab Docker (không cần cài Apache trên máy) / Docker lab (no Apache on the host)

**EN** — Run the lab in Docker: by default only the `dfir-server` container (plain HTTP for now, TLS deferred); the collector agent runs on a Windows host and polls outbound (see `deploy/docker/README.md` §4). The monitored Linux `web` container is opt-in via `make lab-up-web`. Evidence lands in `./data/`.

```bash
make lab-init                          # once: random tokens in .env (gitignored)
make lab-up                            # build + start the server only
make lab-job SCENARIO=netstat.v1       # run a job against the Windows agent
# optional full lab with the monitored Linux web host:
make lab-up-web && make lab-traffic && make lab-job
```

Console: `http://localhost:8080/`. Port conflicts: set `DFIR_CONSOLE_PORT`/`WEB_PORT` in `.env`. Full lab setup guide (Vietnamese): `deploy/docker/README.md`. Teardown: `make lab-down`; full reset: `make lab-clean`.

**VN** — Lab chạy trong Docker: mặc định chỉ có container `dfir-server` (HTTP thường, TLS để sau); agent thu thập chạy trên máy Windows và chỉ kết nối đi ra (xem `deploy/docker/README.md` mục 4). Container `web` Linux bị theo dõi là tùy chọn qua `make lab-up-web`. Bằng chứng nằm trong `./data/`. Các lệnh như trên; hướng dẫn dựng lab đầy đủ tại `deploy/docker/README.md`.

## Web console

Mở `http://127.0.0.1:8080/` (hoặc URL của server) và đăng nhập bằng `DFIR_OPERATOR_TOKEN`:

- Xem danh sách collection, trạng thái, thời lượng và số artifact; tự động cập nhật mỗi 5 giây.
- Tạo job mới (`host_id`, `webshell.v1`, tùy chọn `since`), mở chi tiết job và tải bằng chứng kèm SHA-256.
- Token chỉ được giữ trong `sessionStorage` của tab hiện tại; mọi lời gọi API vẫn dùng Bearer token. Giao diện không có build step và được nhúng trong binary server bằng `go:embed`, nên chỉ cần build lại server sau khi sửa asset.
- Console dùng thêm hai endpoint chỉ dành cho operator: `GET /v1/jobs` (danh sách, mới nhất trước) và `GET /v1/meta` (host/scenario được phép).

## Windows agent

Cùng một chương trình `cmd/dfir-agent` build được cho cả Linux và Windows; không có agent Windows riêng.

```powershell
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o bin\dfir-agent.exe .\cmd\dfir-agent
$env:DFIR_AGENT_TOKEN = '<agent-token>'
.\bin\dfir-agent.exe -server http://dfir.example:8080 -host-id win-lab `
  -uploads 'C:\inetpub\wwwroot\uploads' `
  -web-config 'C:\Windows\System32\inetsrv\config\applicationHost.config' `
  -web-logs 'C:\inetpub\logs\LogFiles\W3SVC*\*.log'
```

- `-uploads` **không có mặc định trên Windows** (IIS không có thư mục upload chuẩn). Nếu bỏ trống, job trả `needs_configuration` thay vì quét ổ đĩa.
- `-web-logs` nhận danh sách path hoặc glob pattern, cách nhau bằng dấu phẩy; tối đa 4 file mới nhất được gửi (server giới hạn 260 artifact/job = 256 upload + 4 log). Log IIS dùng kind `iis_log`, log Apache dùng `apache_log`. Server phải được build lại để chấp nhận `iis_log`; nếu chưa thể cập nhật server, chạy agent với `-web-logs ''` để chỉ thu thập file (nếu không, upload log bị 400 và job sẽ được thử lại mãi).
- `-apache-config` / `-apache-logs` vẫn được chấp nhận như alias của `-web-config` / `-web-logs`.
- Symlink, junction và reparse point bị từ chối ở mọi thành phần đường dẫn. Trên Windows agent dùng `os.Root` + `Lstat` từng thành phần; khác với `O_NOFOLLOW` trên Linux, cặp kiểm tra/mở không nguyên tử nên một thay thế cùng volume trong khe thời gian race chưa được chặn tuyệt đối.
- Cài đặt service và câu hỏi có cần server riêng cho Windows: xem `deploy/windows.md` (TLS sẽ bổ sung sau; lab hiện chạy HTTP).

## Luồng và định dạng

1. Operator tạo job trên `POST /v1/jobs` bằng token riêng; server chỉ nhận host ID đã cấu hình và kịch bản `webshell.v1` (tùy chọn `since` theo RFC3339, ví dụ `2026-10-24T00:00:00Z`).
2. Agent polling outbound qua `GET /v1/agent/jobs/next`, báo `skipped` nếu thiếu cấu hình web server, `needs_configuration` nếu chưa có thư mục upload, không tự quét toàn bộ host.
3. Agent đọc file từ đường dẫn được chỉ định (không theo symlink), so sánh metadata trước/sau khi đọc, tính SHA-256 của đúng byte gửi đi, rồi tải bằng chứng và metadata lên server. Server kiểm tra kích thước/hash, lưu `data/artifacts/<job-id>/<artifact-id>` và manifest `data/jobs/<job-id>.json`.
4. Agent gửi kết quả `completed`, `partial` hoặc `failed` và lý do. Job đang `running` có thể được agent thử lại sau khi khởi động lại; upload trùng ID/hash được xử lý idempotent. `data/audit.jsonl` ghi sự kiện tạo job, xem job, nhận artifact, hoàn thành và tải về. API download kiểm chứng hash trước khi trả byte.

Giới hạn lab: tối đa 10 MiB/file, 256 file từ upload directory/job (vượt giới hạn được ghi nhận là lỗi `partial`) và 4 log mới nhất/job (log cũ hơn bị bỏ và ghi chú trong `reason`, không tính là lỗi); các file quá 10 MiB được ghi nhận là lỗi `partial`. Log được chụp toàn bộ nếu <= 10 MiB; **chưa có cắt log theo `since`**. Dữ liệu trong hệ thống đang chạy có thể thay đổi trước/sau khi thu thập; manifest mô tả snapshot đã nhận, không chứng minh trạng thái nguồn ở thời điểm trước đó.

## Bảo mật và giới hạn chưa triển khai

- Lab hiện chạy **HTTP không TLS** (giai đoạn phát triển): token Bearer và bằng chứng truyền dạng rõ trên mạng. Chỉ dùng trong mạng lab tin cậy; không mở cổng ra Internet. Hai binary vẫn hỗ trợ TLS (`-tls-cert`/`-tls-key` ở server, `-tls-ca` ở agent) để bật lại sau mà không cần sửa code. Không đặt token trong mã nguồn, tài liệu cấu hình được commit, hay URL.
- Server có một operator token và một agent token, **chưa có RBAC/nhiều người dùng, đăng ký/thu hồi danh tính agent, mã hóa at rest, chứng thư client, xác thực riêng từng điều tra viên, hay chữ ký bất biến cho manifest/audit log**. Dùng máy lab cô lập; chưa phù hợp làm quy trình chain of custody pháp lý hoàn chỉnh.
- Agent chạy quyền cao để đọc log như đã chọn cho lab. Không gửi shell command từ server; server không thể chỉ định đường dẫn thu thập qua job. Agent bỏ qua symlink (và junction/reparse point trên Windows); chưa tự khám phá vị trí upload, chưa hỗ trợ Nginx. Windows hiện chỉ hỗ trợ thu thập file IIS + log; chưa có Event Log, systemd/Windows service hay process injection.
- Các mẫu trong `deploy/` chỉ là template cho cùng host (systemd cho Linux, `windows.md` cho Windows); cần cài binary, tạo user `dfir-server`, đặt file token tại `/etc/dfir-server.env` và `/etc/dfir-agent.env` với quyền `0600`, chỉnh endpoint/đường dẫn (và bật lại TLS khi cần) cho môi trường thực tế. Không tự động cài đặt lên máy người dùng.
