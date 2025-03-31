# Automation Recon Tool

A powerful automation tool for reconnaissance and security assessment.

## Prerequisites

- Python 3.x
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/dthkhang/automation-recon.git
cd automation-recon
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Set up wordlist directory:
```bash
# Create wordlist directory
mkdir wordlist

# Clone SecLists repository into wordlist directory
cd wordlist
git clone https://github.com/danielmiessler/SecLists.git
cd ..
```

## Usage

### **Automation Recon - Version 1**  
#### 📌 Features  
- Automated reconnaissance tool for pentesting.  
- Supports parallel execution of multiple tools for optimized speed.  
- Automatically saves results in a well-structured directory format.  
- Logging system supports **JSON/text**, making it easy to integrate into automation pipelines.  

#### ⚙️ Technologies & Architecture  
- **Asynchronous processing (async)** allows multiple tools to run simultaneously.  
- **Optimized execution** using threading/multiprocessing for better performance.  
- **Logging**: Logs are recorded with timestamps, supporting **JSON and text** formats.  
- **Cache**: Implements DNS caching and connection pooling for faster execution.  
- **Rate limiting**: Resource management using semaphores.  
- **Error handling**: Smart retry mechanism for connection failures.  
- **Flexible configuration** via `Config` class, supporting YAML/JSON.  

#### 🔧 Integrated Tools  
- **Subdomain enumeration:** `subfinder`, `httpx`  
- **Directory scanning:** `ffuf`  
- **Technology detection:** `webanalyze`  
- **DNS scanning:** `dig`  
- **WHOIS lookup:** `whois`   

#### 🚀 Installation & Usage  
##### 1️⃣ Install dependencies  
```bash
pip install -r requirements.txt
```

##### 2️⃣ Install required tools  
```bash
# Subdomain scanning
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Directory scanning
go install -v github.com/ffuf/ffuf@latest
# Technology detection
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
```

##### 3️⃣ Run the tool  
```bash
python3 main.py -u example.com
```

#### 📁 Result Structure  
```plaintext
results/
└── example.com/
    └── 20240328_235959/
        ├── subdomain/       # Subdomain info from Subfinder, HTTPX
        ├── directory/       # Scan results from FFUF
        ├── technology/      # Technology detection from Webanalyze
        ├── dns/             # DNS records from Dig
        ├── whois/           # WHOIS information lookup
        └── port/            # Port scan results from Nmap
```
> 📌 *Each scan creates a timestamped directory for easy history tracking.*  

---

### **Version 2 (Upcoming)**  
#### 🔥 New Features  
✅ **AI-powered wordlist generation** based on scan results.  
✅ **Module `--aa` (AI Audit)**:  
   - **AI-powered scan result analysis** using a local LLM, ensuring security.  
   - **Risk assessment based on WSTG** (Web Security Testing Guide).  
   - **AI-powered exploit & fix recommendations**, mapping findings to CVEs & attack patterns.  
   - **Fully offline processing**, no data is sent externally.  
   - **Custom AI model**, fine-tuned with real-world security data.  
✅ **Additional recon features** for enhanced performance and efficiency.