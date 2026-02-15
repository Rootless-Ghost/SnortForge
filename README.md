<div align="center">
  
# 🐽 SnortForge

</div>

<p align="center">
  
  <strong>Snort IDS/IPS Rule Generator & Management Tool</strong>
  
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/License-MIT-9ece6a?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Snort-IDS%2FIPS-f7768e?style=for-the-badge&logo=snort&logoColor=white" alt="Snort">
  <img src="https://img.shields.io/badge/Status-Active-9ece6a?style=for-the-badge" alt="Status">
</p>

<p align="center">
  A web-based application for building, validating, managing, and exporting Snort intrusion detection rules with a clean, dark-themed interface.
</p>

---

##  Overview

SnortForge streamlines the creation and management of Snort IDS/IPS rules. Whether you're writing custom detection rules for a SOC environment, building a ruleset for a home lab, or studying for security certifications — SnortForge provides a structured, error-checked workflow for rule development.

### Key Capabilities

- **Visual Rule Builder** — Form-based rule creation with real-time live preview
- **Syntax Validation** — Server-side validation catches errors and suggests best practices before deployment
- **12 Detection Templates** — Pre-built rules for SQL injection, XSS, brute force, port scans, reverse shells, and more
- **Rule Manager** — Bulk operations: edit, duplicate, delete, import, export
- **Import/Export** — Read `.rules` files and export for direct Snort deployment
- **Dark Theme** — Clean, spacious interface built for extended use

---

##  Screenshots

### Rule Builder
*Build Snort rules visually with a live-updating preview*

![Rule Builder](screenshots/rule_builder.png)

### Rule Manager
*Manage, import, export, and validate your entire ruleset*

![Rule Manager](screenshots/rule_manager.png)

### Templates
*Start from 12 pre-built detection templates across 5 categories*

![Templates](screenshots/templates.png)

---

##  Installation

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Rootless-Ghost/SnortForge.git
cd SnortForge

# 2. Create a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch SnortForge
python app.py
```

Then open your browser to **http://127.0.0.1:5000**

---

##  Usage

### Rule Builder

1. Fill in the **Rule Header** (action, protocol, IPs, ports, direction)
2. Add a descriptive **message** and set the **SID** (>= 1,000,000 for custom rules)
3. Configure **detection options** (content matching, PCRE, depth/offset)
4. Set **flow options** for stateful detection
5. Optionally add **threshold** settings for rate-based alerting
6. Watch the **live preview** update as you type
7. Click **Validate** to check for errors
8. Click **Add to Manager** to store the rule

### Rule Manager

- View all rules with validation status at a glance
- **Import** existing `.rules` files or SnortForge JSON projects
- **Export** your ruleset as `.rules` files ready for Snort deployment
- **Edit**, **duplicate**, or **delete** rules
- Click any row to preview the full rule text

### Templates

Browse **12 pre-built detection templates** organized by category:

| Category | Templates |
|----------|-----------|
| **Web Application** | SQL Injection (Basic & UNION), XSS Script Tag, Directory Traversal |
| **Reconnaissance** | SYN Port Scan, ICMP Ping Sweep, DNS Zone Transfer |
| **Brute Force** | SSH Brute Force, FTP Brute Force |
| **Malware / C2** | Netcat Reverse Shell, DNS Tunneling |
| **Exploit** | SMB EternalBlue Probe |

---

## Project Structure

```
SnortForge/
├── app.py                          # Flask application & API routes
├── snortforge/
│   ├── __init__.py
│   ├── core/
│   │   ├── rule.py                 # Snort rule data model & builder
│   │   ├── validator.py            # Rule validation engine
│   │   ├── templates_data.py       # 12 pre-built detection templates
│   │   └── parser.py               # .rules file parser & importer
│   ├── static/
│   │   ├── css/style.css           # Dark theme stylesheet
│   │   └── js/app.js               # Frontend application logic
│   └── templates/
│       └── index.html              # Main application page
├── screenshots/
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Technical Details

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.8+ |
| **Backend** | Flask 3.0+ |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Architecture** | Flask REST API + Client-side SPA |
| **Rule Engine** | Custom parser + builder with dataclass models |
| **Validation** | Regex-based syntax checking + best practice analysis |
| **Export Formats** | `.rules` (Snort-native), `.json` (SnortForge project) |

### How It Works

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│  Browser UI  │────▶│  Flask API   │────▶│  Rule Engine  │
│  (HTML/JS)   │◀────│  (Python)    │◀────│  (Core)       │
└─────────────┘     └──────────────┘     └───────────────┘
                          │
                    ┌─────┴──────┐
                    │            │
               ┌────▼───┐  ┌────▼────┐
               │Validate│  │ Export   │
               │ Engine │  │ .rules  │
               └────────┘  └─────────┘
```

---

## Roadmap

- [ ] Multi-content rule support (chained content matches)
- [ ] Snort 3 syntax output mode
- [ ] Rule performance scoring
- [ ] Dark/light theme toggle
- [ ] Persistent storage (database backend)
- [ ] Community template sharing

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

</div>
