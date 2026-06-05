# CTF Assistant Pro 🚩

Full-spectrum AI-powered CTF toolkit. Covers every challenge type.

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Add your API keys
# Rename or create a .env file in the root directory and add your keys:
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=AIza...
# OPENAI_API_KEY=sk-proj-...

# 3. Run
python app.py

# 4. Open browser
open http://localhost:5000
```

Get API key: https://console.anthropic.com/

---

## Tabs & features

### 🤖 AI Chat
- Paste ANY challenge data — gets analyzed by Claude (expert CTF mode)
- Auto-detects challenge category or pick manually from sidebar
- Writes complete working Python/pwntools/z3 scripts
- Highlights flags in green automatically
- Quick-inject sidebar: RSA, JWT, SQLi, LFI, SSTI, reverse eng, pwntools, z3

### ⚡ SSH Terminal
- Connect with host / port / user / password
- **Stateful terminal**: Preserves current working directory across commands (`cd` works correctly!)
- One-click recon: find flags, SUID bins, sudo -l, env vars, crontab, capabilities, processes
- Full interactive terminal
- "→ AI" sends all output to AI for analysis

### 🌐 Web
- **Deep probe**: auto-scans headers, HTML comments, forms, hidden paths (/robots.txt, /.git, /.env, /admin, /backup etc.)
- **Custom HTTP request**: any method, custom headers, body
- Payload quick-inject: SQLi, XSS, SSTI, LFI, XXE, command injection, JWT alg:none
- **JWT analyzer & attacker**: decode, alg:none attack, weak secret brute, forge tokens
- **SQL injection generator**: union-based, blind boolean, blind time, error-based, file read, stacked queries + auto exploit script
- **LFI/path traversal payloads**: 20+ payloads including PHP filters

### 🔐 Crypto
- **Universal decoder**: base64, base32, hex, ROT13, all-ROT brute, Caesar, Atbash, Vigenere, Bacon, Rail fence, Morse, binary, octal, decimal bytes, XOR, URL, HTML, Unicode, reverse
- **RSA attacker**: small-e cube root, direct decrypt (p,q), factordb link, RsaCtfTool command, Python script
- **XOR brute force**: all 256 single-byte keys, shows printable results + flags
- **Hash identifier**: MD5/SHA1/SHA256/SHA512/bcrypt/etc + hashcat & john commands
- **Frequency analysis**: letter frequency for substitution cipher cracking

### 🔬 Forensics
- File type analyzer by extension + magic bytes detection
- Tool recommender: steghide, zsteg, stegsolve, binwalk, strings, exiftool, Volatility
- Wireshark/tshark filter cheatsheet
- Volatility memory forensics commands
- File carving commands (binwalk, foremost)

### 🕵️ OSINT
- DNS enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA + zone transfer attempt
- Google dork generator (click to open in Google)
- OSINT resource links: crt.sh, Shodan, Wayback, hunter.io, GitHub search, Censys
- Image OSINT: Google Images, Yandex, TinEye links + exiftool commands

### 🖼️ Steganography
- Per-filetype tool guide (image, audio, text)
- Ready-to-use LSB extractor (Python/PIL)
- Spectrogram generator (scipy/matplotlib)
- Whitespace & zero-width character stego notes

### 📡 Network
- Port scanner (checks 50 ports max, shows banners)
- Banner grabber
- Linux privilege escalation checklist (sudo, SUID, cron, capabilities, writable passwd, path hijack)
- Common CTF services: FTP anon, SMB, SMTP, DNS zone xfer, Redis, MongoDB

### 🎲 Misc / Logic
- Encoding identifier (binary, octal, hex, base32/64, morse, bacon, brainfuck, zero-width)
- Zero-width character detector & decoder
- Cipher reference card (Morse, Braille, NATO, Bacon, Polybius, Atbash, Brainfuck)
- Number theory helpers (Python code block)

### 📜 Scripts
7 ready-to-use exploit scripts:
1. Web — auto SQLi union extractor
2. Web — blind SQLi boolean (binary search)
3. Crypto — RSA full solver (4 attack methods)
4. Crypto — XOR multi-byte key recovery (IC method)
5. Forensics — LSB steganography extractor
6. Web — JWT cracker (weak secret + forge)
7. Network — pwntools CTF shell template

---

## Workflow by challenge type

### Given a URL:
1. Web tab → Deep probe the URL
2. Check found paths, HTML comments, headers
3. Try JWT analyzer if you see JWT tokens
4. Use SQLi/LFI/SSTI payloads via custom request
5. → AI with the full response for analysis

### Given SSH host:port:
1. SSH tab → Connect
2. Run quick recon buttons one by one
3. "→ AI" to analyze all output
4. AI will identify privesc path and give exact commands

### Given ciphertext:
1. Crypto tab → paste into universal decoder
2. Try base64, hex, ROT brute first
3. If unknown → Misc tab → encoding identifier
4. Then → AI chat for full analysis

### Given an image:
1. Forensics tab → analyze filename
2. Stego tab → follow the guide for that file type
3. Run: exiftool, strings, binwalk, steghide, zsteg
4. Try LSB script from Stego tab
5. → AI with all findings

### Given a .pcap file:
1. Forensics tab → shows tshark commands
2. Run: tshark filters, follow TCP streams, extract files
3. → AI with extracted data

### Web challenge tips:
- Always check /robots.txt, /.git/HEAD, /.env first (deep probe does this)
- Check HTML source comments (deep probe extracts these)
- Cookie tampering: change role=user → role=admin
- Check X-Powered-By, Server headers for version vulns
- SSTI test: {{7*7}} → if you see 49, it's Jinja2
- LFI → RCE via /proc/self/environ or PHP log poisoning
