# 🔐 DNSSEC CLI — DNSSEC Scanner & Trust Chain Analyzer

A professional, developer-friendly command-line toolkit for **DNSSEC scanning**,  
**forensic DNS analysis**, and **trust chain validation**.

Designed for security researchers, penetration testers, SREs, and data scientists  
interested in DNS observability, DNSSEC validation, and domain integrity.

---

## ⭐ Features

- 🚀 Full DNSSEC scanner (`scan`)
- 🔍 Complete DNSSEC chain validation (`validate`)
- 🌳 DNSSEC trust tree visualization (`tree`)
- 🔗 Trust chain summary (`chain`)

---

## 📦 Installation

### From PyPI (recommended)

```bash
pip install dnssec-cli
```

### From Source (GitHub)

```bash
git clone https://github.com/<TU-USUARIO>/dnssec-cli
cd dnssec-cli
pip install .
```

---

## 🧰 Commands

### 🔍 Scan a domain

```bash
dnssec-cli scan unam.mx
```

With validation:

```bash
dnssec-cli scan unam.mx --validate
```

JSON mode:

```bash
dnssec-cli scan unam.mx --json
```

---

### 🔐 Validate DNSSEC

```bash
dnssec-cli validate tec.mx
```

Example output:

```
└── unam.mx.
    ✔ DS OK (keytag 54058)
    └── mx.
        ✔ DS OK (keytag 12884)
        └── .
            ✔ Root trusted (ICANN KSK)
```

---

### 🌳 Print Trust Tree

```bash
dnssec-cli tree semarnat.gob.mx
```

---

### 🔗 Chain Summary

```bash
dnssec-cli chain dnssec-failed.org
```

Example:

```
dnssec-failed.org. → org. → . → BROKEN
```

---

## 🧠 Roadmap (Data Science + AI)

### 📊 DNS Statistical Toolkit

- TTL distribution metrics
- Unstable DNS patterns
- RRset churn analysis
- Anomaly scoring

### 🤖 AI Models

- DNSSEC risk scoring
- Suspicious domain classifier
- Predictive alerts for key rollover failures

### 🌐 Web Dashboard (Flask)

- Visual DNSSEC tree
- REST API
- Reports and analytics

---

## 📁 Project Structure

```
dnssec-cli/
│
├── dnssec_tool/
│   ├── cli.py
│   ├── dig.py
│   ├── parser.py
│   ├── validator.py
│   ├── resolver_chain.py
│   └── __init__.py
│
├── README.md
├── LICENSE
└── pyproject.toml
```

---

## 🤝 Contributing

Pull requests welcome.

---

## 📄 License

MIT License © 2025 — Julio Briones

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!
