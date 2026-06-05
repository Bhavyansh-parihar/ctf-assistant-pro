<div align="center">
  <h1>🚩 CTF Assistant Pro</h1>
  <p><strong>Your Ultimate AI-Powered Capture The Flag Companion</strong></p>
  
  [![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org)
  [![Flask](https://img.shields.io/badge/Flask-Web_Framework-green.svg)](https://flask.palletsprojects.com/)
  [![AI](https://img.shields.io/badge/AI-Claude%20%7C%20GPT--4%20%7C%20Gemini-purple.svg)]()
</div>

---

**CTF Assistant Pro** is a full-spectrum, AI-powered toolkit designed to help you dominate any Capture The Flag competition. Whether you are dealing with Web Exploitation, Cryptography, Forensics, OSINT, or Pwn, this tool automates the heavy lifting and analyzes vulnerabilities faster.

## 🚀 Quick Start

Get up and running in seconds:

```bash
# 1. Clone the repository
git clone https://github.com/Bhavyansh-parihar/ctf-assistant-pro.git
cd ctf-assistant-pro

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API Keys
# Create a .env file in the root directory and add your preferred provider keys:
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=AIza...
# OPENAI_API_KEY=sk-proj-...

# 4. Launch the application
python app.py
```
*Now open [http://localhost:5000](http://localhost:5000) in your web browser!*

---

## 🔥 Key Features

| Category | Highlights |
| :--- | :--- |
| **🤖 AI Chat Analyst** | Paste raw challenge data for expert analysis by top-tier LLMs (Claude, GPT-4, Gemini). Automatically generates Python/pwntools exploit scripts. |
| **⚡ Stateful SSH** | Connect directly to boxes with a fully stateful terminal (`cd` works natively!). Includes one-click recon for privilege escalation and crontab vulnerabilities. |
| **🌐 Web Hacking** | Deep probe URLs for hidden paths (`/.env`, `/robots.txt`), craft custom SQLi payloads, and exploit JWT vulnerabilities directly from the dashboard. |
| **🔐 Cryptography** | Universal decoders (Base64/32, ROT, XOR, etc.), RSA vulnerability attackers, and hash identification for quick hashcat/john integration. |
| **🔬 Forensics & Stego** | File type analysis, magic byte detection, and guides for tools like `steghide`, `zsteg`, and `binwalk`. |
| **🕵️ OSINT** | Instant DNS enumeration, WHOIS lookups, automated Google Dork generation, and quick links to Shodan and WayBack Machine. |

---

## 🛠️ Built-in Scripts & Payloads

Stop writing boilerplate code during competitions. CTF Assistant Pro can generate ready-to-use exploit scripts for:
- Auto SQLi Union Extraction & Blind SQLi (Binary Search)
- RSA Full Solvers (4 Attack Methods)
- Multi-byte XOR Recovery
- LSB Steganography Extraction
- Pwntools CTF Shell Templates

---

<div align="center">
  <i>Built with ❤️ for hackers, by hackers.</i>
</div>
