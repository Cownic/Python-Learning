import collections
import json
import os
from typing import List, Optional
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, Field, ValidationError
import streamlit as st

# Load environment variables from .env file securely
load_dotenv()

# ==========================================
# Schema Definitions
# ==========================================

class FirewallRuleItem(BaseModel):
    rule_id: str = Field(description="Unique rule ID or name")
    action: str = Field(description="'ALLOW' or 'DENY'")
    source: str = Field(description="Source IP/CIDR/Zone or 'ANY'")
    destination: str = Field(description="Destination IP/CIDR/Zone or 'ANY'")
    protocol: str = Field(description="TCP, UDP, ICMP, or ANY")
    port: str = Field(description="Port number, comma-separated list, range, or ANY")
    stateful: bool = Field(default=True, description="Whether the rule enforces stateful session tracking")
    description: Optional[str] = Field(default="", description="Rule description or purpose")

class FirewallAuditInput(BaseModel):
    infra_subnets: List[str] = Field(description="Infrastructure CIDR ranges")
    prod_subnets: List[str] = Field(description="Production CIDR ranges")
    zone_1_subnets: List[str] = Field(default_factory=list, description="Zone 1 (Allowed for Prod clients)")
    zone_2_subnets: List[str] = Field(default_factory=list, description="Zone 2 (Restricted: Prod clients CANNOT access)")
    mgmt_ips_or_subnets: List[str] = Field(default_factory=list, description="Management IPs/Subnets")
    firewall_rules: List[FirewallRuleItem] = Field(description="Firewall rules to audit")

class RuleViolation(BaseModel):
    rule_identifier: str = Field(description="Rule ID (or multiple IDs, or 'GLOBAL')")
    violation_type: str = Field(
        description="One of: ANY_TO_ANY_ALLOW, MISSING_DEFAULT_DENY, SEGMENTATION_LEAK, ZONE_RESTRICTION_VIOLATION, MGMT_IP_EXPOSED, WEAK_OR_RISKY_PORT, LEGACY_SERVICE, STATELESS_RULE, DUPLICATE_OR_MERGE_CANDIDATE"
    )
    severity: str = Field(description="'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'")
    source: str
    destination: str
    port_protocol: str
    explanation: str
    remediation: str

class AuditReport(BaseModel):
    summary: str
    total_violations: int
    has_default_deny: bool = Field(description="Whether a fallback DENY ANY ANY rule exists")
    violations: List[RuleViolation]

AUDIT_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "total_violations": {"type": "integer"},
        "has_default_deny": {"type": "boolean"},
        "violations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_identifier": {"type": "string"},
                    "violation_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                    "port_protocol": {"type": "string"},
                    "explanation": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": [
                    "rule_identifier",
                    "violation_type",
                    "severity",
                    "source",
                    "destination",
                    "port_protocol",
                    "explanation",
                    "remediation",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": [
        "summary",
        "total_violations",
        "has_default_deny",
        "violations",
    ],
    "additionalProperties": False,
}

# ==========================================
# Deterministic Rule Audit: Flag Duplicates & Merges (No Auto-Modifications)
# ==========================================

def find_duplicate_and_merge_candidates(rules: List[FirewallRuleItem]) -> List[RuleViolation]:
    """Identifies and flags duplicate or mergeable rules without modifying them."""
    violations: List[RuleViolation] = []
    
    grouped = collections.defaultdict(list)
    for rule in rules:
        key = (
            rule.source.strip().lower(),
            rule.destination.strip().lower(),
            rule.action.strip().upper(),
            rule.protocol.strip().upper(),
        )
        grouped[key].append(rule)

    for (src, dst, action, proto), group in grouped.items():
        if len(group) > 1:
            rule_ids = [r.rule_id for r in group]
            ports = [r.port.strip() for r in group]
            
            is_exact_dup = len(set(ports)) == 1
            
            if is_exact_dup:
                explanation = f"Rules [{', '.join(rule_ids)}] are exact duplicates sharing source '{src}', destination '{dst}', action '{action}', and port(s) '{ports[0]}'."
                remediation = f"Remove redundant entries and retain only one rule (e.g., keep {rule_ids[0]})."
            else:
                explanation = f"Rules [{', '.join(rule_ids)}] share the exact same source '{src}', destination '{dst}', action '{action}', and protocol '{proto}', but define separate ports: {ports}."
                remediation = f"Consolidate rules [{', '.join(rule_ids)}] into a single rule with combined ports: '{', '.join(ports)}'."

            violations.append(
                RuleViolation(
                    rule_identifier=", ".join(rule_ids),
                    violation_type="DUPLICATE_OR_MERGE_CANDIDATE",
                    severity="LOW" if is_exact_dup else "MEDIUM",
                    source=group[0].source,
                    destination=group[0].destination,
                    port_protocol=f"{proto}/{', '.join(ports)}",
                    explanation=explanation,
                    remediation=remediation
                )
            )

    return violations

# ==========================================
# AI Audit Engine (Groq LPU)
# ==========================================

def run_ai_audit(payload: FirewallAuditInput, model: str = "openai/gpt-oss-20b") -> AuditReport:
    # Safely read key from backend environment only
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is not set on the server.")

    client = Groq(api_key=api_key)

    system_prompt = f"""
You are a Principal Network Security Architect and Firewall Auditor. Evaluate the provided firewall rules without altering them against these baseline checks:

1. ANY-TO-ANY POLICY CHECKS:
   - Violation 'ANY_TO_ANY_ALLOW': Flag ANY rule with source=ANY and destination=ANY where action=ALLOW.
   - Violation 'MISSING_DEFAULT_DENY': Verify if there is an explicit terminal fallback DENY ANY ANY rule. If missing, generate a violation with rule_identifier='GLOBAL'.

2. SEGMENTATION & ZONE RESTRICTIONS:
   - Infra Subnets: {payload.infra_subnets}
   - Production Subnets: {payload.prod_subnets}
   - Zone 1 Subnets (Allowed for Prod): {payload.zone_1_subnets}
   - Zone 2 Subnets (RESTRICTED for Prod): {payload.zone_2_subnets}
   - Violation 'SEGMENTATION_LEAK': Bi-directional traffic between Production and Infrastructure ranges (Prod -> Infra or Infra -> Prod).
   - Violation 'ZONE_RESTRICTION_VIOLATION': Any ALLOW rule where Production clients access Zone 2.

3. MANAGEMENT IP PROTECTION:
   - Management IPs/Subnets: {payload.mgmt_ips_or_subnets}
   - Violation 'MGMT_IP_EXPOSED': Any rule opening Management IPs to production, user subnets, or public internet (0.0.0.0/0).

4. WEAK, UNKNOWN, AND REVERSE SHELL PORTS:
   - Violation 'WEAK_OR_RISKY_PORT':
     * Plaintext protocols: HTTP (80) vs 443, Telnet (23) vs 22, FTP (20/21).
     * Suspicious reverse shell / backdoor listener ports: 4444, 1337, 31337, 6667, 5555, 9001, etc.
     * Overly wide ephemeral ranges (e.g. 1024-65535 or ANY).

5. LEGACY SERVICES:
   - Violation 'LEGACY_SERVICE': Flag obsolete/insecure services: RSH/RLOGIN/REXEC (512-514), NetBIOS (137-139), SMBv1 (445 across non-fileserver boundaries), TFTP (69), unencrypted SNMP (161/162), LDAP (389) without TLS.

6. STATELESS RULES:
   - Violation 'STATELESS_RULE': Flag any rule where 'stateful' is false or session tracking is bypassed.

Return the audit results. The response format enforces the required JSON structure.
"""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload.model_dump(), indent=2)}
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "firewall_audit_report",
                "strict": True,
                "schema": AUDIT_REPORT_SCHEMA,
            },
        },
        temperature=0.0,
        max_completion_tokens=4096
    )

    return AuditReport.model_validate_json(response.choices[0].message.content)

# ==========================================
# Sample Test Data
# ==========================================

SAMPLE_TEST_JSON = {
  "infra_subnets": ["10.10.0.0/16"],
  "prod_subnets": ["10.20.0.0/16"],
  "zone_1_subnets": ["10.30.1.0/24"],
  "zone_2_subnets": ["10.30.2.0/24"],
  "mgmt_ips_or_subnets": ["10.99.0.5/32", "10.99.0.0/24"],
  "firewall_rules": [
    {
      "rule_id": "FW-01",
      "action": "ALLOW",
      "source": "ANY",
      "destination": "ANY",
      "protocol": "ANY",
      "port": "ANY",
      "stateful": True,
      "description": "Any to Any Allow flaw"
    },
    {
      "rule_id": "FW-02",
      "action": "ALLOW",
      "source": "10.20.1.5",
      "destination": "10.10.2.10",
      "protocol": "TCP",
      "port": "80",
      "stateful": True,
      "description": "Prod -> Infra leak + cleartext HTTP port 80"
    },
    {
      "rule_id": "FW-03",
      "action": "ALLOW",
      "source": "10.20.1.100",
      "destination": "10.30.2.50",
      "protocol": "TCP",
      "port": "443",
      "stateful": True,
      "description": "Prod client accessing Zone 2 (Restricted)"
    },
    {
      "rule_id": "FW-04",
      "action": "ALLOW",
      "source": "10.20.1.100",
      "destination": "10.30.1.20",
      "protocol": "TCP",
      "port": "443",
      "stateful": True,
      "description": "Prod client accessing Zone 1 (Allowed)"
    },
    {
      "rule_id": "FW-05",
      "action": "ALLOW",
      "source": "0.0.0.0/0",
      "destination": "10.99.0.5",
      "protocol": "TCP",
      "port": "22",
      "stateful": True,
      "description": "Management IP exposed to public internet"
    },
    {
      "rule_id": "FW-06",
      "action": "ALLOW",
      "source": "10.10.1.5",
      "destination": "10.20.1.25",
      "protocol": "TCP",
      "port": "4444",
      "stateful": True,
      "description": "Known reverse shell listener port"
    },
    {
      "rule_id": "FW-07",
      "action": "ALLOW",
      "source": "10.20.1.10",
      "destination": "10.20.1.20",
      "protocol": "UDP",
      "port": "69",
      "stateful": True,
      "description": "Legacy TFTP service in production"
    },
    {
      "rule_id": "FW-08",
      "action": "ALLOW",
      "source": "10.20.5.0/24",
      "destination": "10.20.6.0/24",
      "protocol": "TCP",
      "port": "8080",
      "stateful": False,
      "description": "Stateless rule flaw"
    },
    {
      "rule_id": "FW-09A",
      "action": "ALLOW",
      "source": "10.20.10.1",
      "destination": "10.20.20.1",
      "protocol": "TCP",
      "port": "8443",
      "stateful": True,
      "description": "Rule to be flagged for merge"
    },
    {
      "rule_id": "FW-09B",
      "action": "ALLOW",
      "source": "10.20.10.1",
      "destination": "10.20.20.1",
      "protocol": "TCP",
      "port": "9443",
      "stateful": True,
      "description": "Same src/dst as FW-09A; candidate to merge"
    }
  ]
}

# ==========================================
# Streamlit UI
# ==========================================

st.set_page_config(page_title="Enterprise Firewall Policy Auditor", layout="wide")
st.title("🛡️ Enterprise Firewall Policy Auditor")

# Check API key presence without showing the key value
has_api_key = bool(os.environ.get("GROQ_API_KEY"))

with st.sidebar:
    st.header("⚙️ Server Status")
    if has_api_key:
        st.success("✅ Backend API Key: Active")
    else:
        st.error("❌ Backend API Key: Missing")
        st.caption("Please configure GROQ_API_KEY in your server's `.env` file or environment.")

col_schema, col_download = st.columns([3, 1])
with col_schema:
    with st.expander("📋 View Expected JSON Schema & Specification"):
        st.code(json.dumps(SAMPLE_TEST_JSON, indent=2), language="json")

with col_download:
    st.download_button(
        label="⬇️ Download Sample Audit JSON",
        data=json.dumps(SAMPLE_TEST_JSON, indent=2),
        file_name="enterprise_firewall_audit_test.json",
        mime="application/json",
        use_container_width=True
    )

st.divider()

uploaded_file = st.file_uploader("Upload Firewall Policy JSON", type=["json"])
parsed_payload = None

if uploaded_file:
    try:
        raw_json = json.load(uploaded_file)
        parsed_payload = FirewallAuditInput.model_validate(raw_json)
        
        st.success(
            f"Policy validated: {len(parsed_payload.firewall_rules)} rules loaded | "
            f"Prod: {len(parsed_payload.prod_subnets)} | "
            f"Infra: {len(parsed_payload.infra_subnets)} | "
            f"Zone 1: {len(parsed_payload.zone_1_subnets)} | "
            f"Zone 2: {len(parsed_payload.zone_2_subnets)} | "
            f"Mgmt IPs: {len(parsed_payload.mgmt_ips_or_subnets)}"
        )

        with st.expander("🔍 View Raw Rules (Unmodified)"):
            st.json([r.model_dump() for r in parsed_payload.firewall_rules])

    except json.JSONDecodeError as err:
        st.error(f"Invalid JSON: {err}")
    except ValidationError as err:
        st.error("JSON does not conform to required schema:")
        st.json(err.errors())

if st.button("🚀 Run Comprehensive Audit", type="primary", disabled=(parsed_payload is None)):
    if not has_api_key:
        st.error("Cannot run audit: Server environment variable `GROQ_API_KEY` is missing.")
    else:
        with st.spinner("Analyzing segmentation, ports, legacy protocols, statelessness, and duplicate rules..."):
            try:
                # 1. Deterministic check for duplicate & mergeable rules (rules remain unaltered)
                dedup_violations = find_duplicate_and_merge_candidates(parsed_payload.firewall_rules)

                # 2. Run LLM security audit
                report = run_ai_audit(parsed_payload)

                # 3. Combine violations
                all_violations = dedup_violations + report.violations
                total_violations = len(all_violations)

                # Global Health Metrics
                m1, m2, m3 = st.columns(3)
                m1.metric("Total Violations / Flags", total_violations)
                m2.metric("Default Deny Fallback", "Configured" if report.has_default_deny else "MISSING")
                m3.metric("Duplicate/Merge Candidates", len(dedup_violations))

                st.subheader("Executive Summary")
                st.write(report.summary)

                if all_violations:
                    st.subheader("Detailed Violations & Recommendations")
                    for v in all_violations:
                        badge_color = "red" if v.severity in ["CRITICAL", "HIGH"] else "orange"
                        with st.expander(f":{badge_color}[**[{v.severity}] {v.violation_type}**] — Rule(s): `{v.rule_identifier}`"):
                            c1, c2, c3 = st.columns(3)
                            c1.markdown(f"**Source:** `{v.source}`")
                            c2.markdown(f"**Destination:** `{v.destination}`")
                            c3.markdown(f"**Port / Protocol:** `{v.port_protocol}`")
                            st.markdown(f"**Risk Analysis:** {v.explanation}")
                            st.info(f"**Recommended Action:** {v.remediation}")
                else:
                    st.success("All rules passed compliance. No policy violations detected.")

            except Exception as e:
                st.error(f"Audit analysis failed: {str(e)}")