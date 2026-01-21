
# HTTP OPTIONS Enumeration Script

This repository provides scripts for enumerating allowed HTTP methods using the `OPTIONS` request. Two implementations are included to support different use cases: a lightweight PowerShell script and a more detailed Bash script powered by **Nmap**.

---

## Available Scripts

### 1. PowerShell Script (`.ps1`)
A fast and lightweight option for quickly checking HTTP `OPTIONS` responses.

**Best for:**
- Quick validation
- Lightweight testing
- Environments where Nmap is not available

---

### 2. Bash Script (Nmap-Based)

The Bash script uses **Nmap** to perform a more comprehensive enumeration of HTTP `OPTIONS` methods and collect additional context about the target.

#### Key Features
- Uses **Nmap** to enumerate HTTP `OPTIONS` methods
- Detects and includes **operating system information** (when available)
- Performs a more detailed scan than the PowerShell version
- Automatically creates a **new results directory per run**

#### Output
Each execution generates a dedicated output directory containing:
- **Raw Nmap output**
- **Parsed CSV file** with summarized results, suitable for reporting or further analysis

Example output structure:
