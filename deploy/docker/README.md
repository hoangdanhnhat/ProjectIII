# Hướng dẫn dựng lab Docker

Tài liệu này dựng lab DFIR collector với cấu hình mặc định như sau: server điều
phối chạy trong Docker trên máy Linux, và agent chạy trên máy Windows riêng
(chỉ kết nối đi ra). Lab hiện chạy HTTP thường (TLS để sau), token tự sinh,
bằng chứng nằm trong `./data/` trên máy Linux.

Máy web Linux bị theo dõi (container `web`) là **tùy chọn** — bật bằng
`make lab-up-web` khi cần; nó dùng chung host ID với agent Windows nên chỉ nên
chạy khi không có agent Windows nào đang polling (chi tiết mục 5). Hỗ trợ thu
thập trên Linux sẽ được bổ sung ở giai đoạn sau.

## Thành phần

```text
máy Linux (bạn)                                mạng Docker
---------------------------------------         ------------------------------------------
browser/curl ── http://localhost:8080 ────────▶ dfir-server    HTTP 0.0.0.0:8080, -host-id lab-ubuntu
                                                    ▲
                                                    │ http://dfir-server:8080 (tùy chọn, profile "web")
                                                    │ polling đi ra mỗi 5 giây
curl http://localhost:8081 ─── "tấn công viên" ─▶ web   Ubuntu 24.04 + Apache2 + dfir-agent (TÙY CHỌN)

máy Windows (agent mặc định)
dfir-agent.exe ── http://<ip-linux>:8080 ─────▶ dfir-server (chỉ kết nối đi ra, không mở cổng)
```

Các kịch bản (scenario) binary hiện hỗ trợ:

| Scenario | Chạy trên | Thu thập gì |
| --- | --- | --- |
| `webshell.v1` | container `web` Linux — cần `make lab-up-web` (và Windows có IIS) | file trong thư mục upload + các log web mới nhất |
| `netstat.v1` | Windows | bảng kết nối TCP/UDP kèm tiến trình sở hữu (JSON) |
| `eventlog.v1` | Windows | các kênh event log dạng JSON có phiên bản schema |

## Yêu cầu

- Máy Linux: Docker kèm compose v2, `openssl`, tùy chọn `make`
- Máy Windows: Windows 10/11 64-bit, PowerShell chạy quyền Administrator
- Hai máy cùng một mạng tin cậy (đường truyền là HTTP thường, không mã hóa)

## 1. Khởi động lab

```bash
make lab-init      # sinh .env với token operator + agent ngẫu nhiên (chạy lại an toàn)
make lab-up        # build và khởi động SERVER (mặc định: agent Windows là bên thu thập)
```

Không có `make`? Tương đương bằng tay:

```bash
./deploy/docker/gen-env.sh
docker compose up -d --build
```

- Console: `http://localhost:8080/` — đăng nhập bằng `DFIR_OPERATOR_TOKEN` trong `.env`.
- Nạp token vào shell: `set -a; . ./.env; set +a`.
- Cổng bị chiếm: đặt `DFIR_CONSOLE_PORT` / `WEB_PORT` trong `.env` rồi `make lab-up` lại.

**Bật thêm máy web Linux bị theo dõi** (chỉ khi không dùng agent Windows):

```bash
make lab-up-web    # = docker compose --profile web up -d --build (server + web)
```

## 2. Tạo job và kiểm tra

Với agent Windows (mặc định):

```bash
make lab-job SCENARIO=netstat.v1     # bảng kết nối TCP/UDP của máy Windows
make lab-job SCENARIO=eventlog.v1    # event log các kênh System, Application
```

Mong đợi: `status: completed` với artifact `netstat_snapshot` / `event_log`.

Với máy web Linux (đã `make lab-up-web`):

```bash
make lab-traffic                    # 5 request tới fixture -> dòng access.log thật
make lab-job                        # webshell.v1 mặc định; mong đợi 3 artifact
```

Thử thu thập theo `since`: tạo file mới trong uploads rồi chạy job với mốc thời gian:

```bash
docker compose exec web sh -c 'echo lab note > /var/www/html/uploads/notes.txt'
make lab-job SINCE=2026-10-27T00:00:00Z
```

## 3. Kiểm tra bằng chứng

```bash
make lab-status     # liệt kê job, mới nhất trước

# tải một artifact và đối chiếu hash
set -a; . ./.env; set +a
curl -sS -H "Authorization: Bearer $DFIR_OPERATOR_TOKEN" \
  http://localhost:8080/v1/jobs/<job-id>/artifacts/<artifact-id> -o evidence.bin
sha256sum evidence.bin   # phải khớp "sha256" trong job JSON
```

Bằng chứng trên máy: `data/artifacts/<job-id>/`, `data/jobs/<job-id>.json`,
`data/audit.jsonl` — do root sở hữu nên dùng `sudo` hoặc API/console.

## 4. Thêm agent Windows

Quy trình đã được kiểm chứng (PowerShell **quyền Administrator** trên máy Windows).

### 4a. Đưa binary sang Windows

Build trên Linux (Go trên máy chủ đã cũ; dùng container Go 1.24 — bước `chown`
giữ quyền sở hữu file cho bạn vì container chạy root):

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.24 sh -c \
  "go build -trimpath -o /src/bin/dfir-agent-windows.exe ./cmd/dfir-agent && chown $(id -u):$(id -g) /src/bin/dfir-agent-windows.exe"
```

Copy `bin/dfir-agent-windows.exe` tới `C:\dfir\dfir-agent.exe` (SMB, RDP, scp),
hoặc tạm thời phân phát qua LAN:

```bash
# Linux: mở server tải file (dừng bằng Ctrl-C hoặc pkill sau khi xong)
mkdir -p /tmp/opencode/agent-download
cp bin/dfir-agent-windows.exe /tmp/opencode/agent-download/dfir-agent.exe
python3 -m http.server 8000 --bind 0.0.0.0 --directory /tmp/opencode/agent-download
sha256sum /tmp/opencode/agent-download/dfir-agent.exe   # ghi lại hash này
```

```powershell
# Windows: tải về và xác nhận đây là bản build hiện tại
curl.exe -o C:\dfir\dfir-agent.exe http://<ip-linux>:8000/dfir-agent.exe
Get-FileHash C:\dfir\dfir-agent.exe -Algorithm SHA256   # phải khớp hash phía trên
```

> **Cú bẫy đã gặp:** bản binary cũ (trước thời kỳ HTTP) in ra
> `HTTP allowed only on loopback; use HTTPS for remote hosts` rồi thoát ngay.
> Thông báo đó nghĩa là bản trên Windows đã lỗi thời — tải lại bản mới. Nếu
> hash khớp thì thông báo đó không thể xuất hiện.

### 4b. Chạy agent

```powershell
$env:DFIR_AGENT_TOKEN = '<DFIR_AGENT_TOKEN trong .env>'

C:\dfir\dfir-agent.exe `
  -server http://<ip-linux>:8080 `
  -host-id lab-ubuntu `
  -interval 5s
```

Các cờ tùy chọn:

- `-eventlog-channels 'System,Application,Security'` (mặc định `System,Application`;
  kênh `Security` cần phiên chạy quyền Administrator)
- `-uploads 'C:\inetpub\wwwroot\uploads'` (chỉ dành cho `webshell.v1`; thiếu cờ này
  kịch bản đó trả `needs_configuration`, các kịch bản khác vẫn chạy bình thường)
- `-web-config` / `-web-logs` nếu IIS nằm ở đường dẫn không mặc định

Agent im lặng khi rảnh (không có job = `204`, không in gì). Agent không mở cổng
nào cho kết nối vào.

### 4c. Kiểm tra từ phía Linux

```bash
make lab-job SCENARIO=netstat.v1
```

Mong đợi: `completed` với một artifact `netstat_snapshot` (thấy tên tiến trình
Windows như `System`, `svchost.exe`). Sau đó thử `make lab-job SCENARIO=eventlog.v1`
— mong đợi một artifact `event_log` cho mỗi kênh.

### 4d. Cài thành service (chạy lâu dài)

```powershell
nssm install dfir-agent "C:\dfir\dfir-agent.exe"
nssm set dfir-agent AppParameters "-server http://<ip-linux>:8080 -host-id lab-ubuntu -eventlog-channels System,Application,Security"
nssm set dfir-agent AppEnvironmentExtra "DFIR_AGENT_TOKEN=<agent-token>"
nssm set dfir-agent AppStdout "C:\dfir\agent.log"
nssm set dfir-agent AppStderr "C:\dfir\agent.err.log"
nssm set dfir-agent Start SERVICE_AUTO_START
nssm start dfir-agent
```

Token phải nằm trong môi trường của service, tuyệt đối không đưa vào dòng lệnh
(đối số lệnh hiện rõ trong danh sách tiến trình).

## 5. Quan trọng: một host ID, hai agent

Server chỉ cấp quyền đúng **một** `-host-id` (`lab-ubuntu`) với một agent token.
Vì vậy mặc định chỉ **một** agent nên polling — agent Windows. Nếu bật thêm
container `web` (`make lab-up-web`), **bất kỳ agent nào cũng có thể nhận bất kỳ
job nào**: job `netstat.v1` rơi vào agent Linux sẽ trả `skipped` với lý do
`scenario netstat.v1 is not implemented on linux`, và ngược versa.

- Dùng agent Windows: **không** bật profile web. Nếu web đang chạy, dừng nó:

  ```bash
  docker compose stop web     # dừng agent Linux, server vẫn chạy
  docker compose start web    # bật lại khi cần
  ```

- Cần hai agent cùng lúc: chạy thêm một instance server riêng cho máy Windows
  (hàng đợi và thư mục bằng chứng tách biệt, không cần sửa code):

  ```bash
  set -a; . ./.env; set +a
  ./bin/dfir-server-linux -listen 0.0.0.0:8082 -data ./data-windows -host-id win-lab
  ```

  Khi đó trỏ agent Windows tới `http://<ip-linux>:8082 -host-id win-lab`, và mở
  `http://<ip-linux>:8082/` trên trình duyệt cho console của instance này. Build
  binary server native cũng bằng container Go:

  ```bash
  docker run --rm -v "$PWD:/src" -w /src golang:1.24 sh -c \
    "go build -trimpath -o /src/bin/dfir-server-linux ./cmd/dfir-server && chown $(id -u):$(id -g) /src/bin/dfir-server-linux"
  ```

## Tệp

| Tệp | Công dụng |
| --- | --- |
| `Dockerfile` | build nhiều giai đoạn: `builder` (golang:1.24, chạy `go test`) → hai target `server` và `web` |
| `compose.yaml` | service `dfir-server` (mặc định) và `web` (profile tùy chọn), cổng, volume, token từ `.env` |
| `deploy/docker/gen-env.sh` | sinh `.env` với token operator/agent ngẫu nhiên, chạy lại an toàn |
| `deploy/docker/gen-certs.sh` | giữ cho giai đoạn HTTPS sau; **hiện lab không dùng** |
| `deploy/docker/entrypoint-web.sh` | khởi động Apache, tạo fixture, chạy agent (chỉ trong container web) |
| `Makefile` | các lệnh `lab-*` |
| `.env` | token (tự sinh, đã gitignore) |
| `data/` | bằng chứng, manifest job, `audit.jsonl` (đã gitignore) |

## Các lệnh make

| Lệnh | Công dụng |
| --- | --- |
| `lab-init` | sinh token trong `.env` khi chưa có (chạy lại an toàn) |
| `lab-up` | build + khởi động **server** (mặc định) |
| `lab-up-web` | build + khởi động server **và** máy web Linux (profile `web`) |
| `lab-down` / `lab-clean` | dừng / dừng và xóa `data/`, `.env` (giữ hoặc reset) |
| `lab-logs` | xem log các container đang chạy |
| `lab-traffic` | 5 request tới fixture (cần `make lab-up-web`) |
| `lab-job` | tạo job theo `SCENARIO=` (mặc định `webshell.v1`, ví dụ `SCENARIO=netstat.v1`) và chờ kết quả; tùy chọn `SINCE=RFC3339` |
| `lab-status` | liệt kê job |

## Xử lý sự cố

- **Job trả `skipped` kèm `scenario ... is not implemented on linux`** — container
  `web` đang chạy và đã giành job của agent Windows. Dừng nó:
  `docker compose stop web`, rồi tạo job lại.
- **Cổng bị chiếm** — đặt `DFIR_CONSOLE_PORT=18080` và/hoặc `WEB_PORT=18081`
  trong `.env` rồi `make lab-up` lại.
- **Job kẹt ở `queued`** — không có agent nào polling host ID đó. Xem cửa sổ
  agent trên máy của nó; trên Windows chạy `Test-NetConnection <ip-linux> -Port 8080`.
- **Agent in `HTTP allowed only on loopback`** — binary cũ trước thời kỳ HTTP
  trên máy đó; copy bản build hiện tại và đối chiếu SHA-256 (mục 4a).
- **Agent ghi `poll: HTTP 401`** — token không khớp `DFIR_AGENT_TOKEN` của server (`.env`).
- **Agent ghi `poll: HTTP 400 unsupported host`** — `-host-id` khác với của server (`lab-ubuntu`).
- **`webshell.v1` trả `needs_configuration` trên Windows** — thiếu `-uploads`
  hoặc đường dẫn không phải thư mục tồn tại (IIS không có thư mục upload mặc định).
- **`webshell.v1` trả `skipped` trên Windows** — đúng như thiết kế khi không có
  IIS: collector kiểm tra `applicationHost.config` để xác định máy là web server.
- **`eventlog.v1` trả `partial` kèm access denied** — chạy quyền Administrator
  để đọc kênh `Security`.
- **Cảnh báo HTTP** — server ghi warning khi không bật TLS; đây là chế độ lab
  hiện tại. Chỉ dùng lab trong mạng tin cậy.
- **Reset toàn bộ** — `make lab-clean`.

## Giới hạn

Chỉ dành cho lab: HTTP thường, không mã hóa đường truyền (TLS để sau), container
chạy root, token nằm trong `.env`. Mỗi instance server chỉ cấp quyền đúng một
host ID (mục 5). Mỗi artifact tối đa 10 MiB, tối đa 260 artifact/job. Trên
Windows hiện có `netstat.v1` và `eventlog.v1` (và `webshell.v1` với IIS);
`services.v1`/`autoruns.v1` và hỗ trợ thu thập trên Linux đang được lên kế hoạch.
