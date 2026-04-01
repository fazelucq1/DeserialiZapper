#  💉DeserialiZapper

A lightweight GUI tool for analyzing and re-encoding session cookies, purpose-built for the Insecure Deserialization track of the PortSwigger Web Security Academy.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Purpose](https://img.shields.io/badge/Purpose-PortSwigger%20Labs%20Only-red)

> ⚠️ **Educational use only** — Designed exclusively for [PortSwigger Web Security Academy](https://portswigger.net/web-security) lab environments. Never use against systems you don't own.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Auto-Detection** | Identifies JWT, Java Serialized, Ruby Marshal, PHP Serialize, JSON, Key=Value |
| ✏️ **Edit Params** | Inline parameter editing with pencil button per field |
| 🔄 **Re-Encode** | Reconstructs tampered cookie in correct binary/text format |
| 💣 **ysoserial Generator** | Generates Java deserialization payloads (30 gadget chains) |
| 🌐 **Web UI** | Mirror interface at `http://127.0.0.1:8990` |
| 📜 **Full Log** | Internal console with save support |
| 🚀 **Test Request** | Send tampered cookie directly to lab URL |

---

## 🖥️ Screenshots

<img width="990" height="781" alt="immagine" src="https://github.com/user-attachments/assets/38f45fc7-691b-427f-a43c-e8c3ebd538e7" />
<img width="1318" height="997" alt="immagine" src="https://github.com/user-attachments/assets/20510c5c-14c7-4820-8ca0-8118780f4bec" />


---

## 🚀 Quick Start

### Requirements

- Python 3.10+ (stdlib only — no pip installs needed)
- Tkinter (usually bundled; see below if missing)
- Java JDK 8+ *(only for ysoserial tab)*

### Install & Run

```bash
git clone https://github.com/fazelucq1/portswigger-cookie-analyzer.git
cd portswigger-cookie-analyzer
python tool.py
```

That's it. No virtual environment, no `pip install`.

### Tkinter not found?

```bash
# Ubuntu/Debian
sudo apt install python3-tk

# macOS (Homebrew)
brew install python-tk

# Fedora/RHEL
sudo dnf install python3-tkinter
```

---

## 📦 Supported Cookie Formats

| Format | Detection | Edit Params | Re-Encode |
|--------|-----------|-------------|-----------|
| **JWT** | ✅ `eyJ` prefix + `.` separator | ✅ header + payload claims | ✅ |
| **Java Serialized** | ✅ `0xACED` magic bytes | ✅ field names + values extracted | ✅ binary patch |
| **Ruby Marshal** | ✅ `0x0408` magic bytes | ✅ hash/object fields | ✅ binary patch |
| **PHP Serialize** | ✅ `O:|a:|s:` pattern | ✅ all properties | ✅ |
| **JSON (b64)** | ✅ base64-decoded JSON | ✅ all keys | ✅ |
| **Key=Value** | ✅ URL-encoded pairs | ✅ all pairs | ✅ |

---

## 💣 ysoserial Integration

<img width="1810" height="992" alt="immagine" src="https://github.com/user-attachments/assets/aceede77-a598-4386-9846-af817512e2e9" />


The **ysoserial tab** lets you generate Java deserialization payloads without leaving the tool.

### Setup

1. Tab **💣 ysoserial** → click **📥 Download auto** (fetches from GitHub releases)  
   *or* click **📂 Sfoglia** to point to an existing `ysoserial-all.jar`

2. Select **Gadget Chain** (default: `CommonsCollections4` — works for most PortSwigger labs)

3. Enter your command:
   ```
   rm /home/carlos/morale.txt
   ```

4. Click **🚀 GENERA PAYLOAD**

5. Click **📋 Copia Cookie** → paste into Burp Repeater → Send

### Gadget chains included (30 total)

`CommonsCollections1-7`, `BeanShell1`, `Clojure`, `CommonsBeanutils1`, `Groovy1`, `Hibernate1/2`, `Jdk7u21`, `Jdk8u20`, `ROME`, `Spring1/2`, `URLDNS`, and more.

### Java version handling

The tool auto-detects your Java version and applies the correct flags:

- **Java ≥ 16**: adds `--add-opens` flags automatically
- **Java ≤ 15**: uses simple `java -jar ysoserial.jar Chain 'cmd'`

---

## 🗂️ Project Structure

```
portswigger-cookie-analyzer/
├── tool.py           # Main application (GUI + Web server + all logic)
├── README.md         # This file
├── requirements.txt  # Empty — stdlib only
├── .gitignore        # Python/Java artifacts
└── docs/
    ├── USAGE.md      # Detailed usage guide per lab type
    └── LABS.md       # Which labs this tool helps with
```

---

## 🔧 Web UI

While the GUI is open, a lightweight web server runs at `http://127.0.0.1:8990`.

It mirrors all GUI functionality via REST API:

```
GET  /              → Web UI (HTML)
POST /api/detect    → Detect + decode cookie
POST /api/reencode  → Re-encode with modified params
POST /api/test      → Test request to lab URL
GET  /api/log       → Get log entries
POST /api/log/clear → Clear log
```

---

## 🎯 Supported PortSwigger Lab Types

- **Insecure Deserialization** — Java, PHP, Ruby
- **JWT attacks** — alg:none, HS256→RS256, claim tampering
- **Session management** — cookie parameter tampering
- **Access control** — role/isAdmin escalation via cookie

---

## 📋 Workflow Example — Java Deserialization Lab

```
1. Copy session cookie from Burp
2. Paste into tool → Detect & Decode
   → Detected: Java Serialized (99%)
   → Fields: accessToken, username = "wiener"

3. Tab ✏️ Edit Params → click ✏ on username → type "administrator" → Salva

4. Click ⚡ Re-Encode
   → New cookie: session=rO0ABXNy...

5. Copy → Burp Repeater → replace cookie → Send
```

---

## ⚖️ Legal & Ethics

This tool is built **exclusively** for use with PortSwigger Web Security Academy labs, which are intentionally vulnerable environments provided for learning.

- ✅ Use in PortSwigger lab environments
- ✅ Use in CTF challenges you're authorized to participate in
- ✅ Use in penetration tests where you have written authorization
- ❌ Never use against production systems
- ❌ Never use against systems you don't own or have explicit permission to test

---

## 🤝 Contributing

PRs welcome. Please keep the zero-dependency philosophy (stdlib + tkinter only).

---

## 📄 License

MIT License — see [LICENSE](LICENSE)
