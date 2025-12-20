# 🛡️ CyberSentinel: AI-Powered Malware Analysis Platform

![Status](https://img.shields.io/badge/Status-Active-success)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.9+-yellow)
![Framework](https://img.shields.io/badge/FastAPI-High%20Performance-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**CyberSentinel** is a next-generation malware analysis engine designed to bridge the gap between static signature matching and heuristic behavioral detection. It combines traditional **Static Analysis**, **Binary Inspection**, **YARA Rule Matching**, and **Generative AI** to provide comprehensive threat intelligence for **20+ programming languages** and **Windows Executables**.

---

## 🚀 Key Features

### 🧠 1. Dual-Core Analysis Engine

#### 🔹 Source Code Analysis (Static)

* **Universal Language Support:** Analyzes **20+ languages** including Python, JavaScript/Node.js, C/C++, Java, Go, Rust, PHP, PowerShell, Bash, Ruby, Perl, Swift, C#, SQL, Batch, VBScript, Lua, R, and Docker.
* **Behavioral Regex Engine:** Detects dangerous behaviors (e.g., `os.system`, `Reflect.define`, `fs.unlink`) instead of relying only on signatures.

#### 🔹 Binary Analysis (PE / Executables)

* **PE Header Inspection:** Examines Windows `.exe` and `.dll` files for suspicious headers, timestamps, and entry points.
* **Deep Section Analysis:** Identifies **UPX packing**, **Writable + Executable** sections, and high-entropy regions.
* **String Extraction:** Extracts ASCII and Unicode strings to uncover hidden URLs, IPs, and commands.

---

### 🔍 2. Advanced Threat Detection

* **Heuristic Risk Scoring:**

  * Weighted scoring system (0–100) distinguishing normal, suspicious, and critical behaviors.

* **Threat Categories:**

  * 🔴 **Critical:** Ransomware, Keyloggers, Reverse Shells, Privilege Escalation
  * 🟠 **Suspicious:** Persistence (Registry/Cron), Network Exfiltration, Obfuscation
  * 🟡 **Warning:** File Tampering, Crypto Mining, SQL Injection

* **Obfuscation Detection:**

  * Detects **Base64**, **Hex**, **ROT13**, **Zlib**, and **Dynamic Evaluation (`eval`, `exec`)**
  * **Auto-Deobfuscation:** Attempts Base64 decoding to reveal hidden payloads automatically

---

### 🤖 3. AI & External Intelligence

* **Generative AI Explainability:**

  * Converts raw detection logs into human-readable explanations
  * Explains *why* a file is malicious or suspicious

* **Interactive AI Chat:**

  * Ask questions like *“What does line 14 do?”* for deep analysis

* **VirusTotal Integration:**

  * SHA256 hash calculation
  * Reputation checks using **70+ antivirus engines**

---

### 📊 4. Reporting & Visualization

* **Real-Time Dashboard:** Dark-mode UI with drag-and-drop file scanning
* **PDF Report Export:** Professional security reports including:

  * File metadata
  * Detected behaviors
  * Risk score
  * AI explanations

---

## 🛠️ Technical Architecture

### 🔧 Backend (Python / FastAPI)

* **FastAPI:** High-performance async API framework
* **SQLAlchemy + SQLite:** Stores analysis history and file metadata
* **PeFile:** Parses Windows PE files
* **YARA:** Advanced malware pattern matching
* **AsyncIO / Aiohttp:** Non-blocking external API calls

### 🎨 Frontend

* **HTML5 / CSS3:** Responsive dark-mode UI
* **Vanilla JavaScript:** Lightweight and fast frontend logic

---

## 📂 Project Structure

```bash
AI-MALWARE-ANALYZER/
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
└── backend/
    ├── main.py
    ├── .env
    ├── requirements.txt
    │
    ├── app/
    │   ├── database.py
    │   ├── models.py
    │   └── schemas.py
    │
    ├── analyzer/
    │   ├── behavior_rules.py
    │   ├── static_analyzer.py
    │   ├── binary_analyzer.py
    │   ├── risk_engine.py
    │   ├── utils.py
    │   ├── yara_engine.py
    │   ├── ai_explainer.py
    │   └── pdf_generator.py
    │
    └── routes/
        └── analyze.py
```

---

## ⚡ Installation & Setup

### ✅ Prerequisites

* Python 3.9+
* Git

---

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/cyber-sentinel.git
cd cyber-sentinel
```

---

### 2️⃣ Backend Setup

```bash
cd backend
python -m venv venv
```

Activate the virtual environment:

```bash
# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### 3️⃣ Environment Configuration

Create a `.env` file inside `backend/`:

```ini
VIRUSTOTAL_API_KEY=your_virustotal_key_here
# Add LLM API keys if required
```

---

### 4️⃣ Run the Backend

```bash
python main.py
```

Server will start at:

```
http://127.0.0.1:8000
```

---

### 5️⃣ Launch Frontend

Open the following file directly in your browser:

```text
frontend/index.html
```

No build step required.

---

## 🧪 Testing with Samples

CyberSentinel safely detects advanced malware techniques using dummy samples:

| Category   | Technique                       | Test Language       |
| ---------- | ------------------------------- | ------------------- |
| Ransomware | File Encryption & Deletion      | Python / Java       |
| Spyware    | Keylogging / Input Capture      | C++ / Python        |
| Rootkits   | Process Injection / Persistence | C / PowerShell      |
| Web Shells | Remote Command Execution        | PHP / JSP           |
| Evasion    | Base64 / Hex Obfuscation        | JavaScript / Python |

---

## 🔮 Roadmap

* [ ] Dynamic Analysis Sandbox (Cuckoo Sandbox)
* [ ] Machine Learning Model (Random Forest on PE headers)
* [ ] Dockerized Backend & Frontend
* [ ] JWT Authentication for APIs

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch

   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. Commit changes

   ```bash
   git commit -m "Add AmazingFeature"
   ```
4. Push to branch

   ```bash
   git push origin feature/AmazingFeature
   ```
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.

---

<p align="center">
Built with ❤️ by <strong>Aayush Thakur</strong> and <strong>Gemini</strong>
</p>
