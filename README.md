# PassStrength — Textual TUI Password Strength Checker
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
[![Textual](https://img.shields.io/badge/UI-Textual-green)](https://github.com/Textualize/textual)

## Overview
A [Textual](https://github.com/Textualize/textual) (Python) TUI to check password strength by:
- Length  
- Character pool  
- Entropy  

Features:
- Color-coded strength rating  
- Breach-list presence check  
- Policy compliance with per-requirement breakdown  

---

## Run

One-time setup:
```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Launch the TUI:
```bash
.venv/bin/python pass_strength.py
```

CLI mode:
```bash
.venv/bin/python pass_strength.py --cli --policy NIST --password "YourPassword"
```

---

## Policy Frameworks

- Edit `frameworks.json` to configure password requirements (e.g., **NIST**, **HIPAA**, **Simple**).  
- Choose a framework from the dropdown at the top of the app.  
- The app validates the JSON schema and gracefully falls back to a simple policy if invalid.  

### `frameworks.json` format
```json
{
  "default": "NIST",
  "frameworks": {
    "NIST": {
      "min_length": 8,
      "require_lower": true,
      "require_upper": true,
      "require_digits": true,
      "require_symbols": false,
      "min_entropy": 40,
      "desc": "Example NIST-like profile"
    }
  }
}
```

---

## Notes
- Entropy is estimated as:  
  ```
  entropy = length * log2(pool)
  ```
- This app does not check for dictionary words or advanced patterns.  
- The entropy model also accounts for whitespace and (roughly) non-ASCII symbols if present.  
- Update the JSON as needed; the app reloads the selected policy on each run.  
- A local breach list (`breach_top_250.json`) is consulted; exact matches are flagged between **Rating** and **Policy** results.  

---

## Breach List
- File: `breach_top_250.json` (array of common breached passwords, lowercase preferred).  
- Replace or augment with your own list (e.g., from trusted public datasets) without changing the app.  

---

## License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
