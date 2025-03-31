# Công Cụ Tự Động Hóa Reconnaissance

Một công cụ mạnh mẽ cho việc thăm dò và đánh giá bảo mật.

## Yêu Cầu Hệ Thống

- Python 3.x
- Git

## Cài Đặt

1. Clone repository:
```bash
git clone https://github.com/dthkhang/automation-recon.git
cd automation-recon
```

2. Cài đặt các gói cần thiết:
```bash
pip install -r requirements.txt
```

3. Thiết lập thư mục wordlist:
```bash
# Tạo thư mục wordlist
mkdir wordlist

# Clone repository SecLists vào thư mục wordlist
cd wordlist
git clone https://github.com/danielmiessler/SecLists.git
cd ..
```

## Sử Dụng

### **Automation Recon - Version 1**  
#### 📌 Chức năng  
- Tool tự động hóa reconnaissance phục vụ pentest.  
- Hỗ trợ chạy song song nhiều tool để tối ưu tốc độ.  
- Tự động lưu kết quả theo cấu trúc thư mục rõ ràng.  
- Hệ thống logging hỗ trợ xuất **JSON/text**, dễ tích hợp vào pipeline tự động.  

#### ⚙️ Kỹ thuật & Kiến trúc  
- Xử lý bất đồng bộ (async) giúp chạy nhiều tool cùng lúc.  
- Tối ưu hóa thời gian bằng kỹ thuật threading/multiprocessing.  
- **Logging**: Ghi log theo timestamp, hỗ trợ **JSON, text**.  
- **Cache**: Sử dụng DNS cache, connection pool để tăng tốc độ.  
- **Rate limiting**: Kiểm soát tài nguyên bằng semaphore.  
- **Error handling**: Cơ chế retry thông minh khi gặp lỗi kết nối.  
- **Cấu hình linh hoạt** qua `Config` class, hỗ trợ YAML/JSON.  

#### 🔧 Các tool tích hợp  
- **Subdomain enum:** `subfinder`, `httpx`  
- **Directory scanning:** `ffuf`  
- **Technology detection:** `webanalyze`  
- **DNS scanning:** `dig`  
- **WHOIS lookup:** `whois`  
- **Port scanning:** `nmap`  

##### 2️⃣ Cài đặt tool  
```bash
# Subdomain scanning
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Directory scanning
go install -v github.com/ffuf/ffuf@latest
# Technology detection
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
```

##### 3️⃣ Chạy tool  
```bash
python3 main.py -u example.com
```

#### 📁 Cấu trúc kết quả  
```plaintext
results/
└── example.com/
    └── 20240328_235959/
        ├── subdomain/       # Thông tin subdomain từ Subfinder, HTTPX
        ├── directory/       # Kết quả scan từ FFUF
        ├── technology/      # Công nghệ phát hiện từ Webanalyze
        ├── dns/             # Record DNS từ Dig
        ├── whois/           # Thông tin WHOIS từ whois lookup
        └── port/            # Scan port từ Nmap
```
> 📌 *Mỗi lần scan, tool sẽ tạo thư mục theo timestamp để dễ quản lý lịch sử.*
---

### **Version 2 (Upcoming)**  
#### 🔥 Tính năng mới  
✅ **AI gợi ý wordlist** dựa trên kết quả scan.  
✅ **Module `--aa` (AI Audit)**:  
   - **AI phân tích kết quả scan** bằng LLM local, đảm bảo bảo mật.  
   - **Đánh giá rủi ro theo WSTG** (Web Security Testing Guide).  
   - **Gợi ý khai thác & fix bug** bằng AI mapping với CVE & attack patterns.  
   - **Hoàn toàn offline**, không gửi dữ liệu ra ngoài.  
   - **Model AI** được fine-tune trên dữ liệu bảo mật thực tế.  
✅ **Chức năng recon mới**