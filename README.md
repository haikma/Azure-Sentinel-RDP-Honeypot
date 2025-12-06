# 🛡️ Triển khai & Phân tích Honeypot Brute-force RDP với Microsoft Sentinel

Dự án này trình bày cách thức xây dựng một Honeypot thực tế trên nền tảng Azure để thu thập, làm giàu (Data Enrichment), và trực quan hóa các cuộc tấn công Brute-force RDP tự động bằng giải pháp SIEM/SOAR của Microsoft Sentinel.

Mục tiêu chính là chuyển đổi log bảo mật thô của Windows thành thông tin tình báo có thể hành động được (Actionable Threat Intelligence).

---

## 🎯 Mục tiêu và Công cụ

| Vai trò | SOC Analyst / Threat Hunter |
| :--- | :--- |
| **Mục tiêu** | Triển khai mô hình Honeypot, chứng minh khả năng xử lý log tùy chỉnh, và trực quan hóa mối đe dọa. |
| **Công cụ chính** | Microsoft Azure (VM/NSG), Microsoft Sentinel, Log Analytics, PowerShell, KQL, ipgeolocation API. |
| **Phạm vi** | Thu thập và phân tích Event ID 4625 (Logon Failure) |

## ⚙️ Chi tiết Triển khai Kỹ thuật

### 1. Cấu hình Honeypot (Azure VM)

- **Triển khai:** Tạo một máy ảo **Windows Server** trên Azure (hoặc VM size nhỏ nhất, ví dụ B1s/B2s).
- **Phơi bày (Exposure):** Cố ý cấu hình **Network Security Group (NSG)** để mở toang tất cả các cổng (`*`) trên Internet, tạo ra môi trường hấp dẫn các botnet.
- **Tắt Tường lửa:** Tắt hoàn toàn **Windows Firewall** bên trong VM để đảm bảo các gói RDP Brute-force được ghi nhận vào Event Log.

### 2. Làm giàu Dữ liệu (Data Enrichment)

Thách thức chính là Event Log 4625 chỉ chứa IP nguồn, không có tọa độ địa lý.

- **PowerShell Scripting:** Đã phát triển script **`Honeypot_Log_Enrichment.ps1`**.
- **Logic Script:** Script liên tục quét Event Log ID 4625 mới, trích xuất IP và gọi **ipgeolocation API** để lấy `latitude`, `longitude`, `country`.
- **Đầu ra:** Ghi log đã được làm giàu vào file tùy chỉnh: `C:\ProgramData\failed_rdp.log`

### 3. Tích hợp SIEM với Custom Log

- **Cài đặt Agent:** Cài đặt Log Analytics Agent lên VM để kết nối với Log Analytics Workspace.
- **Tạo Custom Log:** Cấu hình **Custom Log** trong Log Analytics Workspace để thu thập dữ liệu từ file `failed_rdp.log`.

### 4. Trực quan hóa (Visualization) và Phân tích

- **KQL Query:** Sử dụng truy vấn **KQL** (xem file `RDP_Attack_Map_Query.kql`) để trích xuất và chuyển đổi các trường `latitude` / `longitude` sang định dạng số (`todouble()`).
- **Workbook:** Xây dựng **Workbook** trong Sentinel với Visualization là **Map** (Bản đồ) để trực quan hóa các điểm tấn công, sử dụng `AttackCount` để xác định kích thước chấm điểm.

## 📊 Kết quả & Phân tích Threat Hunting

- **Tần suất tấn công:** Trong vòng **XX giờ** đầu tiên, đã thu thập được **X,XXX+** sự kiện tấn công Brute-force.
- **Nguồn gốc:** Dữ liệu cho thấy các IP tấn công tập trung chủ yếu từ các quốc gia như **Romania, Netherlands, France, United States, và China**, khẳng định sự tồn tại của các botnet chuyên săn lùng RDP.
- **Bằng chứng:** Bản đồ tấn công cung cấp cái nhìn trực quan về **phạm vi địa lý** và **cường độ** của các chiến dịch tấn công.

---
