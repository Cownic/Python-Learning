# Switch Configuration Audit Guide

This guide covers setup and use of the native switch configuration auditor, `switch_config_auditor.py`. It compares a baseline and candidate configuration, highlights their changes, checks for selected risky configuration patterns, and can request an AI explanation of the changes.

## 1. Environment Setup

### 1.1 Create and activate a virtual environment

From the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Windows Command Prompt, activate with:

```cmd
.venv\Scripts\activate.bat
```

### 1.2 Install dependencies

Install the packages used by this app:

```bash
python -m pip install streamlit groq python-dotenv
```

### 1.3 Configure Groq

Create a `.env` file beside `switch_config_auditor.py`:

```ini
GROQ_API_KEY=your_groq_api_key_here
```

The app loads the key from this file or the process environment. Keep `.env` out of source control and never share or commit the key. The app uses Groq model `openai/gpt-oss-20b` for its supplemental change-impact assessment.

## 2. Run the App

From the project directory, start the auditor:

```bash
python -m streamlit run switch_config_auditor.py
```

Streamlit prints the local URL to open in a browser, usually `http://localhost:8501`.

## 3. Compare and Audit Configurations

1. Select the switch brand/operating system: Cisco IOS, Arista EOS, Juniper Junos, or Aruba AOS.
2. Upload baseline and candidate files (`.cfg`, `.txt`, `.conf`, or `.log`) or paste their contents. Uploaded files are decoded as UTF-8.
3. Select **Analyze & Audit Configurations**.
4. Review the unified diff, **Risky Configuration Audit**, and—when a Groq key is available—the expandable **AI Change Impact Assessment**.

The app checks both configurations for recognizable syntax matching the selected brand and requires the pair to resolve to the same brand and hostname. Detection is based on a limited set of command signatures, not full vendor parsers; short, mixed, or unsupported configurations may not be confirmed.

### Risk audit coverage

The local, deterministic checks run independently of Groq. They flag visible patterns for:

- Telnet management
- HTTP management
- Default `public` or `private` SNMP community names, and other community-based SNMP
- Trunks configured to allow all VLANs
- Edge/access ports with no visible BPDU protection

Findings are compared between the two files and labeled **New**, **Existing**, or **Resolved**. Evidence is shown with common community, password, and secret values redacted. The checker does not infer that ACLs or Control Plane Policing (CoPP) are missing merely because they do not appear in the supplied text.

The AI assessment is supplemental: it receives the baseline-to-candidate diff, not the complete configuration files, and describes operational impacts and follow-up checks in bullet lists. The diff itself may contain sensitive configuration values, so review it and confirm you are permitted to send it to Groq before running an assessment. If the API key is unavailable or Groq fails, the local risk audit can still be reviewed; the AI section will not be produced.

## 4. Sample Configurations

Use the included synthetic pairs to try the auditor. Select the matching vendor and upload both files from one pair:

- Cisco: `sample-auditor-cisco-baseline.cfg` and `sample-auditor-cisco-candidate.cfg`
- Juniper: `sample-auditor-juniper-baseline.conf` and `sample-auditor-juniper-candidate.conf`
- Aruba: `sample-auditor-aruba-baseline.cfg` and `sample-auditor-aruba-candidate.cfg`

These examples are disposable test data, not production configurations. They may contain intentionally risky settings and must not be treated as OEM guidance.

## 5. Scope and Limitations

The comparison is text-based; it does not normalize vendor syntax or prove that commands are semantically equivalent. Risk checks cover only the patterns listed above and are not exhaustive, OEM-certified, or a complete security assessment. A finding is an indicator to review, not proof of exploitability. Validate recommendations against the exact switch model, software release, network topology, operational requirements, and vendor documentation before making changes.

The app displays results in Streamlit. It does not apply configuration changes to switches or generate a PDF report. Treat uploaded configurations and displayed results as sensitive operational data.
