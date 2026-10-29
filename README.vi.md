# Lantern - theo dõi bề mặt tấn công

Công cụ quản lý tài sản (tên miền, IP) và phát hiện điểm phơi nhiễm: subdomain, cấu hình web, cổng nguy hiểm.
Backend Python (FastAPI + SQLite), giao diện là các trang HTML tĩnh, có đăng ký (xác thực email bằng OTP) / đăng nhập bằng tên đăng nhập, nhiều người dùng.

> Chỉ quét tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản. Quét hệ thống người khác có thể vi phạm pháp luật.

## Cách 1: chạy trực tiếp (khuyên dùng khi phát triển)

### Bước 1. Cài Python 3.10+ và nmap
- Windows: cài Python từ python.org (tick "Add to PATH"), cài nmap từ nmap.org
- macOS: `brew install python nmap`
- Ubuntu/Debian: `sudo apt install python3 python3-venv nmap`

### Bước 2. (Tùy chọn) cài subfinder để tìm subdomain
Cần Go: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
Hoặc tải bản build sẵn ở trang releases của projectdiscovery/subfinder rồi bỏ vào PATH.
Không cài cũng chạy được, nhưng chỉ kiểm tra tên miền gốc.

### Bước 3. Cài thư viện
```
cd lantern
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Bước 4. Tạo file cấu hình
```
cp .env.example .env               # Windows: copy .env.example .env
```
Không còn API key. Đăng nhập bằng tài khoản tạo ở trang đăng ký.

**Gửi email OTP:** điền nhóm biến `LANTERN_SMTP_*` trong `.env` (ví dụ Gmail dùng "Mật khẩu ứng dụng").
Nếu để trống `LANTERN_SMTP_HOST`, server chạy chế độ phát triển: không gửi email thật mà in mã OTP ra terminal.

### Bước 5. Chạy
```
uvicorn app.main:app --reload
```
Mở http://127.0.0.1:8000 và đăng nhập bằng tài khoản admin được tạo ở lần chạy đầu (xem mục **Đăng nhập lần đầu** bên dưới).

**Nâng cấp từ bản cũ (dùng API key):** `lantern.db` cũ được tự động nâng cấp khi khởi động, không mất dữ liệu.
Các tài sản đã có sẽ thuộc về **tài khoản đầu tiên đăng ký**, nên hãy tự đăng ký tài khoản đó trước khi mời người khác.
Tài khoản đã tồn tại (đăng ký bằng email trước đây) được tự gán `username` lấy từ phần trước dấu `@` của email; đăng nhập bằng username đó.
Biến `LANTERN_API_KEY` trong `.env` không còn được dùng, có thể xóa.

## Đăng nhập lần đầu
Ở lần khởi động đầu tiên (database chưa có tài khoản nào), Lantern tự tạo tài khoản **admin** với **mật khẩu ngẫu nhiên riêng cho từng bản cài**. Mật khẩu không nằm cố định trong mã nguồn nên mỗi người tải về sẽ có một mật khẩu khác nhau.

1. Chạy server, xem trong terminal sẽ có khung thông báo `Tên đăng nhập: admin` và `Mật khẩu: <16 ký tự ngẫu nhiên>`.
2. Thông tin này cũng được lưu trong file `initial-admin-password.txt` cạnh file database (thư mục `data/` nếu dùng Docker, còn lại là thư mục dự án). Với Docker có thể xem bằng `docker compose logs lantern`.
3. Vào http://127.0.0.1:8000, đăng nhập bằng `admin` và mật khẩu đó.
4. Lantern **bắt buộc đặt mật khẩu mới** ngay lần đầu, chưa đổi thì chưa dùng được chức năng nào khác. Đổi xong file `initial-admin-password.txt` tự bị xóa.
5. Nên vào **Quản lý tài khoản** đổi email của admin thành email thật để nhận được thư quên mật khẩu (mặc định là `admin@lantern.local`).

Người dùng khác tự đăng ký ở `/register`, hoặc admin tạo cho họ. Bất cứ lúc nào cũng đổi được mật khẩu bằng nút **Đổi mật khẩu** ở cuối cột menu bên trái.

Muốn tự chọn tài khoản admin: đặt `LANTERN_ADMIN_USERNAME` và `LANTERN_ADMIN_PASSWORD` trong `.env` trước lần chạy đầu (nhớ xóa dòng mật khẩu sau đó). Khi đó không có mật khẩu ngẫu nhiên nào được tạo.

## Chạy ngầm để lịch quét tự động luôn hoạt động (Windows)
Lịch quét nằm trong chính server Lantern, nên chỉ chạy khi server đang chạy. Để không phải tự mở phần mềm:

1. Bấm đúp **`install-background.bat`** (chạy một lần). Script đăng ký Lantern tự khởi động mỗi khi bạn đăng nhập Windows, chạy ẩn (không có cửa sổ), tự chạy lại nếu bị tắt, rồi tạo shortcut **Lantern** trên Desktop.
2. Từ đó mở shortcut đó (hoặc http://127.0.0.1:8000) lúc nào cũng thấy sẵn kết quả của các lần quét tự động.
3. Gỡ bằng **`uninstall-background.bat`** (không xóa dữ liệu). Log nằm ở `lantern.log`.

Lưu ý: máy phải đang bật (không sleep/hibernate) thì mới quét đúng giờ; nếu lỡ giờ hẹn, Lantern tự quét bù ngay khi chạy lại. Nếu đang chạy bằng lệnh `uvicorn` thì tắt cửa sổ đó trước khi cài. Chạy thử ở chế độ có log trên màn hình: `.venv\Scripts\python serve.py`.
Trên VPS/Docker thì dùng `restart: unless-stopped` (đã có sẵn trong compose.yaml), không cần các script này.

## Cách 2: Docker
```
cp .env.example .env
docker compose up -d --build
```
Dữ liệu nằm trong thư mục `data/`. Dockerfile chưa được kiểm thử trong môi trường tạo ra nó, nếu lỗi ở bước build subfinder thì dùng Cách 1.

## Đưa lên server (VPS)
1. Chạy bằng Docker hoặc systemd, chỉ lắng nghe 127.0.0.1.
2. Đặt Caddy hoặc Nginx phía trước để có HTTPS (Caddy tự cấp chứng chỉ):
   ```
   lantern.tenmiencuaban.com {
       reverse_proxy 127.0.0.1:8000
   }
   ```
3. Đặt `LANTERN_SECURE_COOKIE=1` trong `.env` khi chạy qua HTTPS.
4. Cân nhắc giới hạn IP truy cập ở firewall. Ai cũng tự đăng ký được, nếu không muốn mở đăng ký công khai thì chặn `/register` ở reverse proxy sau khi đã tạo xong các tài khoản cần thiết.

## Luồng đăng ký
1. `/register`: nhập họ tên, tên đăng nhập, email, mật khẩu. Server **chưa tạo tài khoản**, chỉ lưu đăng ký ở trạng thái chờ và gửi mã OTP 6 số tới email.
2. `/verify`: nhập OTP. Đúng thì tạo tài khoản, hiện thông báo "Đăng ký thành công" rồi chuyển về `/login` (ô tên đăng nhập điền sẵn) để người dùng tự đăng nhập.
3. Mã OTP hết hạn sau 10 phút, nhập sai 5 lần thì khóa mã (phải xin mã mới), gửi lại cách nhau 60 giây, tối đa 5 lần gửi cho mỗi lần đăng ký.
   Mỗi IP bị giới hạn 8 yêu cầu gửi mã / 15 phút để tránh bị lợi dụng spam email.

## Giao diện, quét, lịch quét và báo cáo
- Menu nằm ở cột bên trái: Tổng quan, Tài sản, Subdomain, Quét cổng, CVE, Phát hiện, Lịch sử quét, Lịch quét, Giám sát, Báo cáo, (Quản lý tài khoản cho admin) và **Cài đặt** ở cuối.
- **Quét:** mỗi tài sản (mục Tài sản và Tổng quan) có nút **Quét** riêng. Đang quét hiện vòng xoay "Đang quét…", quét xong hiện dấu **✓** (kèm nút "Quét lại"), thất bại hiện dấu **!** (kèm "Thử lại"). Trang tự cập nhật, không cần tải lại.
- **Thêm nhiều tài sản và nhóm:** ô thêm tài sản nhận nhiều mục một lần (mỗi dòng một IP / tên miền / dải IP, hoặc cách nhau bằng dấu phẩy; tối đa 200 mục). Nhập **tên nhóm** để gộp chúng vào một nhóm; không nhập tên mà thêm từ 2 mục trở lên thì tự tạo nhóm "Nhóm dd/mm hh:mm". Nhập tên nhóm đã có thì thêm vào nhóm đó, và IP bạn đã thêm lẻ trước đó cũng được chuyển vào nhóm. Thêm đúng 1 mục và không đặt tên nhóm thì là tài sản lẻ như cũ.
  Nhóm hiện thành một khối có thể thu gọn, với nút **Quét cả nhóm**: server quét **lần lượt từng mục một** (xong cái này mới tới cái kế tiếp), mục chưa tới lượt hiện "Chờ quét…", nhóm hiện tiến độ "Đang quét 2/5" rồi thành dấu ✓ khi xong hết. Vẫn quét riêng từng mục được. "Gỡ nhóm" chỉ gỡ nhóm, giữ lại tài sản; nhóm tự biến mất khi xóa hết tài sản trong đó. Báo cáo chọn được theo nhóm. Dải IP (CIDR) vẫn là một tài sản, không tự tách thành từng IP. Lịch quét tự động vẫn đặt riêng cho từng tài sản.
- **Lịch quét:** mục *Lịch quét* cho chọn từng tài sản: tần suất (Tắt, 1 giờ, 6 giờ, 12 giờ, hằng ngày, hằng tuần), **giờ:phút chạy** và, với lịch hằng tuần, **thứ trong tuần**. Hằng ngày/hằng tuần chạy đúng giờ:phút đã chọn. Với 1/6/12 giờ, giờ:phút là mốc đầu tiên trong ngày và các lần sau lặp theo chu kỳ (vd mỗi 6 giờ từ 08:30 → 08:30, 14:30, 20:30, 02:30). Giờ được tính theo múi giờ của trình duyệt lúc bạn đặt lịch (lưu kèm trong DB), không phụ thuộc múi giờ server/Docker. Server kiểm tra mỗi 30 giây nên giờ chạy thực tế có thể trễ tối đa ~30 giây. Lần quét đầu tiên diễn ra ở mốc giờ kế tiếp sau khi đặt lịch. Lần quét tự động có nhãn "Tự động" trong Lịch sử quét. Nếu tài sản đang được quét thì lịch hoãn 1 phút rồi thử lại.
  **Chỉ chạy 1 worker uvicorn** (mặc định), nếu chạy nhiều worker thì mỗi worker sẽ tự lập lịch một lần. Server tắt thì lịch không chạy; bật lại, các lịch đã quá giờ sẽ quét ngay.
- **Báo cáo:** mục *Báo cáo* chọn phạm vi (tất cả hoặc một tài sản), định dạng và có/không gồm phát hiện đã xử lý:
  HTML (xem, in hoặc "In / Lưu PDF" bằng trình duyệt), CSV (UTF-8 có BOM, mở bằng Excel; ô bắt đầu bằng `= + - @` được chống chèn công thức), JSON.

## Cài đặt (mục "Cài đặt" ở cuối menu)
Mỗi người dùng tự tùy chỉnh, thay đổi áp dụng ngay và được lưu trong **trình duyệt** (localStorage, khóa `lantern-settings`), không cần bấm Lưu:
- **Giao diện:** chủ đề Sáng / Tối / Theo hệ thống, màu nhấn (xanh ngọc, xanh dương, tím, cam, hồng), mật độ hiển thị (thoải mái / gọn), cỡ chữ (nhỏ / vừa / lớn), giảm chuyển động (mặc định theo hệ điều hành).
- **Ngôn ngữ và định dạng:** Tiếng Việt / English, định dạng giờ (theo ngôn ngữ / 24 giờ / 12 giờ).
- **Hành vi:** trang mở đầu, chu kỳ tự làm mới dữ liệu (tắt, 15 giây, 30 giây, 1 phút, 5 phút), mặc định hiện phát hiện đã xử lý, hỏi xác nhận trước khi xóa / gỡ nhóm / xử lý hàng loạt.
- **Thông báo:** bật/tắt chấm đỏ ở mục Giám sát.
- Nút **Đặt lại mặc định** đưa mọi tùy chọn về ban đầu.

Lưu ý: cài đặt gắn với trình duyệt chứ chưa gắn với tài khoản (đổi trình duyệt/thiết bị thì cài đặt khác). Chủ đề, màu nhấn và cỡ chữ cũng áp dụng cho các trang đăng nhập/đăng ký/quên mật khẩu. Ngôn ngữ hiện chỉ áp dụng cho giao diện chính; thông báo lỗi từ máy chủ và file báo cáo xuất ra vẫn bằng tiếng Việt. Muốn thêm ngôn ngữ mới thì thêm một bảng chuỗi vào `static/i18n.js`.

## Phân quyền và quản lý tài khoản
- Có 2 role: **admin** và **user**. Mọi người dùng thấy thẻ `User: ... · Role: ...` ở cuối cột menu bên trái.
- Admin dùng được mọi tính năng như user, cộng thêm mục **Quản lý tài khoản** (cuối cột menu bên trái): xem danh sách, thêm, sửa (họ tên, email, tên đăng nhập, role, đặt lại mật khẩu), xóa.
  Xóa luôn hiện hộp thoại xác nhận "Bạn có chắc muốn xóa tài khoản này không?" và cho biết sẽ mất bao nhiêu tài sản.
- Quy tắc an toàn (kiểm tra ở server): không tự xóa mình, không tự đổi role của mình, không xóa/hạ quyền admin cuối cùng. Đổi mật khẩu của người khác sẽ đăng xuất họ khỏi các thiết bị khác.
- Xóa tài khoản sẽ xóa kèm tài sản, phát hiện, lịch sử quét và phiên đăng nhập của tài khoản đó.
- Cách có tài khoản admin:
  1. Hệ thống mới tự tạo tài khoản `admin` với mật khẩu ngẫu nhiên (xem mục *Đăng nhập lần đầu*).
  2. DB cũ: tài khoản **tạo sớm nhất** được tự nâng thành admin khi nâng cấp.
  3. Hoặc đặt `LANTERN_ADMIN_USERNAME` + `LANTERN_ADMIN_PASSWORD` trong `.env` (xem `.env.example`) để tạo/nâng quyền khi khởi động.
- Mỗi người (kể cả admin) hiện chỉ thấy tài sản, phát hiện, lần quét của chính mình.

## Quên mật khẩu
1. `/forgot` (link "Quên mật khẩu?" ở trang đăng nhập): nhập email, server gửi OTP 6 số nếu email có tài khoản.
2. `/reset`: nhập OTP + mật khẩu mới. Đúng thì đổi mật khẩu, **đăng xuất mọi thiết bị**, mở khóa đăng nhập (nếu đang bị khóa vì sai nhiều lần) rồi chuyển về `/login`.
- Email chưa đăng ký sẽ nhận lỗi "Tài khoản này không tồn tại" (HTTP 404) và không có mail nào được gửi. Đổi lại, người ngoài có thể dò xem một email đã đăng ký hay chưa; lượt thử vẫn bị tính vào giới hạn 8 yêu cầu / IP / 15 phút để hạn chế dò hàng loạt.
- Cùng giới hạn như đăng ký: OTP 10 phút, sai 5 lần thì khóa mã, gửi lại cách nhau 60 giây, tối đa 5 lần, 8 yêu cầu / IP / 15 phút. Mã chỉ dùng một lần.

## Bảo mật đăng nhập
- Mật khẩu băm bằng scrypt có salt riêng, không lưu mật khẩu thô.
- Phiên bằng cookie HttpOnly, SameSite=Strict, hết hạn sau 7 ngày. Server chỉ lưu bản băm của token.
- Sai mật khẩu 5 lần (theo cặp tên đăng nhập + IP) bị khóa 15 phút.
- OTP chỉ lưu dạng băm, gắn với trình duyệt đã đăng ký (cookie HttpOnly), không dùng lại được sau khi xác thực.
- Mỗi người chỉ thấy và thao tác được trên tài sản, phát hiện, lần quét của chính mình.
- Tên tài sản là duy nhất toàn hệ thống: nếu người khác đã thêm cùng một tên miền, bạn sẽ nhận lỗi "Tài sản đã tồn tại".

## API
Mọi endpoint (trừ `/api/health` và `/api/auth/*` ở trên) cần đăng nhập (cookie phiên).

| Method | Đường dẫn | Việc làm |
|---|---|---|
| POST | /api/auth/register | Bước 1: `{"name","username","email","password"}`, gửi OTP tới email |
| GET | /api/auth/pending | Trạng thái đăng ký đang chờ OTP |
| POST | /api/auth/verify | Bước 2: `{"otp":"123456"}`, tạo tài khoản (không tự đăng nhập) |
| POST | /api/auth/resend | Gửi lại mã OTP |
| POST | /api/auth/forgot | Quên mật khẩu bước 1: `{"email"}`, gửi OTP |
| GET | /api/auth/forgot/status | Trạng thái yêu cầu đang chờ |
| POST | /api/auth/forgot/resend | Gửi lại OTP đặt lại mật khẩu |
| POST | /api/auth/reset | Bước 2: `{"otp","password"}`, đổi mật khẩu |
| GET/POST | /api/admin/users | (admin) Danh sách / tạo tài khoản `{"username","name","email","password","role"}` |
| PATCH/DELETE | /api/admin/users/{id} | (admin) Sửa / xóa tài khoản |
| POST | /api/auth/login | Đăng nhập `{"username","password"}` |
| POST | /api/auth/change-password | Đổi mật khẩu khi đang đăng nhập `{"current_password","new_password"}` |
| POST | /api/auth/logout | Đăng xuất |
| GET | /api/auth/me | Người dùng hiện tại |
| GET | /api/assets | Danh sách tài sản |
| POST | /api/assets | Thêm một tài sản `{"name":"example.com","authorized":true}` |
| POST | /api/assets/bulk | Thêm nhiều tài sản `{"targets":"1.1.1.1\n1.1.1.2","group":"Tên nhóm","authorized":true}` |
| GET | /api/groups | Danh sách nhóm |
| DELETE | /api/groups/{id} | Gỡ nhóm (giữ lại tài sản) |
| POST | /api/groups/{id}/scan | Quét lần lượt từng tài sản trong nhóm |
| DELETE | /api/assets/{id} | Xóa tài sản |
| POST | /api/scans | Bắt đầu quét `{"asset_id":1}` |
| GET | /api/scans | Lịch sử quét (trạng thái `queued` = chờ tới lượt trong nhóm) |
| GET | /api/findings | Danh sách phát hiện |
| PATCH | /api/findings/{id} | Đóng/mở lại `{"open":false}` |
| GET | /api/events | Thay đổi host giữa các lần quét |
| GET | /api/schedules | Lịch quét của từng tài sản (`interval_h` null = chưa đặt) |
| PUT | /api/schedules/{asset_id} | Đặt lịch `{"interval_h":24,"at":"08:30","weekday":0,"tz":420}`: `interval_h` chỉ nhận 1, 6, 12, 24, 168; `at` là HH:MM; `weekday` 0=Thứ hai..6=Chủ nhật (chỉ dùng khi 168); `tz` là phút lệch UTC |
| DELETE | /api/schedules/{asset_id} | Tắt lịch quét |
| GET | /api/reports/export | Xuất báo cáo: `?format=html\|csv\|json&asset_id=&group_id=&include_closed=1` |

Ví dụ gọi bằng curl (lưu cookie phiên vào file):
```
curl -c cj.txt -H "Content-Type: application/json" \
  -d '{"username":"ban","password":"mat-khau-cua-ban"}' http://127.0.0.1:8000/api/auth/login
curl -b cj.txt -H "Content-Type: application/json" \
  -d '{"name":"example.com","authorized":true}' http://127.0.0.1:8000/api/assets
```

## Cấu trúc
```
app/main.py      API, chạy quét nền, phục vụ các trang
app/auth.py      đăng ký + OTP, quên mật khẩu, đăng nhập, phiên
app/admin.py     quản lý tài khoản (chỉ admin)
app/mailer.py    gửi email OTP qua SMTP (không có SMTP thì in ra terminal)
app/scanner.py   subfinder, kiểm tra HTTP/TLS/header, nmap
app/vulns.py     tra CVE theo phiên bản dịch vụ (NVD)
app/reports.py   dựng báo cáo HTML / CSV / JSON
app/db.py        SQLite (có migration tự động)
pages/           index.html (cần đăng nhập), login.html, register.html, verify.html, forgot.html, reset.html
static/auth.css  CSS dùng chung cho trang đăng nhập/đăng ký
static/prefs.js  lưu và áp dụng cài đặt người dùng (chủ đề, màu nhấn, cỡ chữ, ngôn ngữ...)
static/i18n.js   bảng chuỗi tiếng Việt / English và hàm t()
```

## Hướng mở rộng
- Tự đóng phát hiện khi lần quét sau không còn thấy
- Cảnh báo qua Telegram/email khi lịch quét phát hiện thay đổi
- Trang subdomain và đồ thị tài sản, so sánh thay đổi giữa các lần quét
- Tắt đăng ký công khai
