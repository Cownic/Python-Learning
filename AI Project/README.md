# Project Setup & Firewall Audit Guide

A complete guide for local environment configuration, dependency installation, and firewall rule validation.

---

## 1. Environment Setup

### 1.1 Create Virtual Environment

Initialize an isolated Python virtual environment:

```bash
python -m venv venv
```

Activate the environment based on your operating system:

- **Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate.bat
  ```
- **Windows (PowerShell):**
  ```powershell
  venv\Scripts\Activate.ps1
  ```
- **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```

### 1.2 Install Dependencies

The imports `collections`, `json`, `os`, and `typing` are standard library modules included with Python and do not need to be installed.

Install the required third-party packages using `pip`:

```bash
pip install groq python-dotenv pydantic streamlit
```

Alternatively, you can create a `requirements.txt` file:

```text
groq
python-dotenv
pydantic
streamlit
```

Then install via:

```bash
pip install -r requirements.txt
```

### 1.3 Configure Environment Variables

Create a `.env` file in the root directory of the project:

```ini
GROQ_API_KEY=your_groq_api_key_here
```

> **Note:** Ensure `.env` is added to your `.gitignore` to prevent leaking credentials.

### 1.4 Verify Model Availability

Run the following one-liner to verify your API credentials and list available models:

```bash
python -c "import os; from dotenv import load_dotenv; from groq import Groq; load_dotenv(); print([m.id for m in Groq().models.list().data])"
```

---

## 2. Firewall Audit Checklist

Use this checklist to perform rule hygiene, access boundary validation, and security posture assessments across rulebases.

### 2.1 Default Rules & Access Control
- [ ] **No Any-to-Any Allow:** Confirm that no rule permits `Any -> Any` traffic.
- [ ] **Explicit Any-to-Any Deny:** Ensure an explicit `Any -> Any Deny/Drop` cleanup rule is present at the end of every security policy rulebase.

### 2.2 Zone & Network Segmentation
- [ ] **Production vs. Infrastructure Isolation:** Ensure production environments cannot reach infrastructure management ranges and vice-versa.
- [ ] **Zone Access Boundaries:** Confirm production clients are restricted to **Zone 1** only, with no traversal routes into **Zone 2**.

### 2.3 Port Hardening & Risk Mitigation
- [ ] **Restrict Weak Protocols:** Disallow insecure cleartext ports (e.g., replace HTTP port `80` with HTTPS port `443`).
- [ ] **Block Malicious & Random Ports:** Identify and eliminate rules opening unverified high ports or ports associated with known reverse shells (e.g., `4444`, `1337`).

### 2.4 Rule Optimization & Deduplication
- [ ] **Deduplicate Rules:** Merge identical or shadow rules across policies.
- [ ] **Consolidate Mappings:** Group rules sharing identical source-to-destination pathways (`Source -> Destination`) into consolidated service objects.

### 2.5 Policy Standards & Protocol Hygiene
- [ ] **Exclude Management IP:** Confirm that firewall and host management IPs are strictly excluded from general transit and NAT policies.
- [ ] **Enforce Stateful Inspection:** Audit policies to verify no stateless firewall rules exist where stateful connection tracking is required.
- [ ] **Decommission Legacy Services:** Remove legacy protocols and cipher configurations (e.g., Telnet, FTP, SMBv1, SNMPv1/v2c).