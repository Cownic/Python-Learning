import json
import os
from typing import List, Optional
from groq import Groq
from pydantic import BaseModel, Field, ValidationError
import streamlit as st

# ==========================================
# Schema Definitions
# ==========================================

# Expected Input Rule
class FirewallRuleItem(BaseModel):
    rule_id: str = Field(description="Unique rule identifier or name")
    action: str = Field(description="'ALLOW' or 'DENY'")
    source: str = Field(description="Source IP, CIDR block, or range")
    destination: str = Field(description="Destination IP, CIDR block, or range")
    protocol: str = Field(description="TCP, UDP, ICMP, or ANY")
    port: str = Field(description="Port number, comma-separated list, range, or ANY")
    description: Optional[str] = Field(default="", description="Optional context or purpose")

# Expected Root Input JSON
class FirewallAuditInput(BaseModel):
    infra_subnets: List[str] = Field(
        description="List of Infrastructure CIDR ranges (e.g., ['10.10.0.0/16'])"
    )
    prod_subnets: List[str] = Field(
        description="List of Production CIDR ranges (e.g., ['10.20.0.0/16'])"
    )
    firewall_rules: List[FirewallRuleItem] = Field(
        description="List of firewall rules to evaluate"
    )

# Expected Output Schema
class RuleViolation(BaseModel):
    rule_identifier: str = Field(description="Rule ID of the offending rule")
    violation_type: str = Field(description="'SEGMENTATION_LEAK' or 'WEAK_OR_RISKY_PORT'")
    severity: str = Field(description="'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'")
    source: str
    destination: str
    port_protocol: str
    explanation: str
    remediation: str

class AuditReport(BaseModel):
    summary: str
    total_violations: int
    violations: List[RuleViolation]

# ==========================================
# Groq Audit Logic
# ==========================================

def run_audit(payload: FirewallAuditInput, model: str = "openai/gpt-oss-120b") -> AuditReport:
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

    system_prompt = f"""
You are a senior Network Security Auditor. Analyze the provided firewall configuration and evaluate it against these two strict rules:

1. SEGMENTATION LEAK:
   - Infrastructure Subnets: {payload.infra_subnets}
   - Production Subnets: {payload.prod_subnets}
   - Violation: Any direct bi-directional traffic between Production and Infrastructure ranges (Prod -> Infra or Infra -> Prod). Flag any ALLOW rule bridging these segments as a SEGMENTATION_LEAK.

2. WEAK_OR_RISKY_PORT:
   - Weak/Cleartext protocols: e.g., HTTP (80) instead of HTTPS (443), Telnet (23) instead of SSH (22), FTP (21), unencrypted LDAP (389).
   - Suspicious listener / reverse shell ports: e.g., 4444, 1337, 31337, 6667, 5555, 9001.
   - Broad / wildcard port mappings (e.g., 'ANY' or '1-65535') without narrow host pinning.

Return ONLY a valid JSON object matching the requested schema.
Schema:
{json.dumps(AuditReport.model_json_schema(), indent=2)}
"""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload.model_dump(), indent=2)}
        ],
        response_format={"type": "json_object"},
        temperature=0.1
    )

    return AuditReport.model_validate_json(response.choices[0].message.content)

# ==========================================
# Sample Test Data
# ==========================================

SAMPLE_TEST_JSON = {
    "infra_subnets": [
        "10.10.0.0/16",
        "172.16.50.0/24"
    ],
    "prod_subnets": [
        "10.20.0.0/16",
        "192.168.100.0/24"
    ],
    "firewall_rules": [
        {
            "rule_id": "RULE-01",
            "action": "ALLOW",
            "source": "10.20.1.15",
            "destination": "10.10.2.4",
            "protocol": "TCP",
            "port": "80",
            "description": "Production app server connecting to Infrastructure monitoring server over cleartext HTTP"
        },
        {
            "rule_id": "RULE-02",
            "action": "ALLOW",
            "source": "10.10.5.10",
            "destination": "10.20.2.0/24",
            "protocol": "TCP",
            "port": "4444",
            "description": "Infra jumpbox opened to production range on known reverse shell port"
        },
        {
            "rule_id": "RULE-03",
            "action": "ALLOW",
            "source": "0.0.0.0/0",
            "destination": "10.20.1.50",
            "protocol": "TCP",
            "port": "23",
            "description": "Internet ingress via Telnet into production database"
        },
        {
            "rule_id": "RULE-04",
            "action": "ALLOW",
            "source": "10.20.1.0/24",
            "destination": "10.20.2.0/24",
            "protocol": "TCP",
            "port": "443",
            "description": "Intra-production secure traffic (Legitimate baseline)"
        },
        {
            "rule_id": "RULE-05",
            "action": "ALLOW",
            "source": "172.16.50.12",
            "destination": "192.168.100.5",
            "protocol": "TCP",
            "port": "1337",
            "description": "Infra host connecting to Production host on elite/shell port"
        }
    ]
}

# ==========================================
# Streamlit UI
# ==========================================

st.set_page_config(page_title="Firewall Policy Auditor", layout="wide")
st.title("🛡️ AI Firewall Rule Auditor (JSON Engine)")

# Header controls: format reference and test file download
col_desc, col_dl = st.columns([3, 1])

with col_desc:
    with st.expander("📋 View Expected JSON Schema & Example"):
        st.write("Your input JSON must match this structure:")
        st.code(json.dumps(SAMPLE_TEST_JSON, indent=2), language="json")

with col_dl:
    st.download_button(
        label="⬇️ Download Sample Test JSON",
        data=json.dumps(SAMPLE_TEST_JSON, indent=2),
        file_name="test_firewall_rules.json",
        mime="application/json",
        use_container_width=True
    )

st.divider()

uploaded_file = st.file_uploader("Upload Firewall Rules JSON", type=["json"])

parsed_payload = None

if uploaded_file is not None:
    try:
        raw_data = json.load(uploaded_file)
        # Validate against schema
        parsed_payload = FirewallAuditInput.model_validate(raw_data)
        st.success(
            f"Valid configuration loaded: {len(parsed_payload.firewall_rules)} rules | "
            f"{len(parsed_payload.infra_subnets)} Infra subnets | "
            f"{len(parsed_payload.prod_subnets)} Prod subnets"
        )
        
        # Display preview table
        with st.expander("Preview Uploaded Rules"):
            st.json([r.model_dump() for r in parsed_payload.firewall_rules])

    except json.JSONDecodeError as err:
        st.error(f"Malformed JSON: {err}")
    except ValidationError as val_err:
        st.error("JSON does not conform to the required schema:")
        st.json(val_err.errors())

if st.button("Run Audit", type="primary", disabled=(parsed_payload is None)):
    if not os.environ.get("GROQ_API_KEY"):
        st.error("Missing `GROQ_API_KEY` environment variable.")
    else:
        with st.spinner("Auditing rules with Groq..."):
            try:
                report = run_audit(parsed_payload)
                
                st.subheader(f"Audit Summary ({report.total_violations} Violations Found)")
                st.write(report.summary)

                if report.violations:
                    for v in report.violations:
                        color = "red" if v.severity in ["CRITICAL", "HIGH"] else "orange"
                        with st.expander(f":{color}[**[{v.severity}] {v.violation_type}**] — Rule ID: `{v.rule_identifier}`"):
                            c1, c2, c3 = st.columns(3)
                            c1.markdown(f"**Source:** `{v.source}`")
                            c2.markdown(f"**Destination:** `{v.destination}`")
                            c3.markdown(f"**Port/Proto:** `{v.port_protocol}`")
                            st.markdown(f"**Explanation:** {v.explanation}")
                            st.info(f"**Remediation:** {v.remediation}")
                else:
                    st.success("No policy violations detected.")
            except Exception as e:
                st.error(f"Audit execution failed: {str(e)}")