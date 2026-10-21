import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch

from groq import Groq
import switch_config_auditor as auditor
from switch_config_auditor import (
    MODEL_ID,
    SwitchBrand,
    detect_config_brand,
    find_risky_configurations,
    normalize_audit_markdown,
    run_groq_audit,
    validate_config_pair,
)


class SwitchConfigAuditorTests(unittest.TestCase):
    def test_risk_audit_finds_risks_in_candidate_config(self) -> None:
        config = (
            "hostname edge-01\n"
            "ip http server\n"
            "snmp-server community public RO\n"
            "line vty 0 4\n"
            " transport input telnet ssh\n"
            "!\n"
            "interface GigabitEthernet1/0/1\n"
            " spanning-tree portfast\n"
            "!\n"
            "interface GigabitEthernet1/0/48\n"
            " switchport trunk allowed vlan all\n"
            "!\n"
        )

        findings = find_risky_configurations(config, SwitchBrand.CISCO_IOS)

        self.assertEqual(
            {finding.title for finding in findings},
            {
                "Telnet management may be enabled",
                "HTTP management may be enabled",
                "Default SNMP community string is configured",
                "Trunk may allow all VLANs",
                "Edge/access port has no visible BPDU protection",
            },
        )
        self.assertEqual(
            {finding.severity for finding in findings},
            {"HIGH", "MEDIUM"},
        )
        self.assertTrue(all(finding.line_number > 0 for finding in findings))

    def test_risk_audit_ignores_disabled_services_and_guarded_ports(self) -> None:
        config = (
            "no ip http server\n"
            "no snmp-server community public RO\n"
            "interface GigabitEthernet1/0/1\n"
            " spanning-tree portfast\n"
            " spanning-tree bpduguard enable\n"
            "!\n"
        )

        self.assertEqual(
            find_risky_configurations(config, SwitchBrand.CISCO_IOS),
            [],
        )

    def test_risk_audit_detects_telnet_across_supported_brands(self) -> None:
        configs = {
            SwitchBrand.CISCO_IOS: "transport input telnet ssh\n",
            SwitchBrand.ARISTA_EOS: "management telnet\n",
            SwitchBrand.JUNIPER_JUNOS: "set system services telnet\n",
            SwitchBrand.ARUBA_AOS: "telnet-server\n",
        }
        for brand, config in configs.items():
            with self.subTest(brand=brand):
                findings = find_risky_configurations(config, brand)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "HIGH")

    def test_risk_audit_renderer_shows_findings_and_redacts_community(self) -> None:
        expander = Mock(return_value=nullcontext())
        with (
            patch.object(auditor.st, "expander", expander),
            patch.object(auditor.st, "columns", return_value=[Mock(), Mock(), Mock()]),
            patch.object(auditor.st, "markdown") as markdown,
            patch.object(auditor.st, "code") as code,
            patch.object(auditor.st, "write"),
        ):
            auditor.render_risk_findings(
                "snmp-server community monitor-readonly RO\nip http server\n",
                "snmp-server community public RO\n",
                SwitchBrand.CISCO_IOS,
            )

        displayed_code = [call.args[0] for call in code.call_args_list]
        self.assertIn("snmp-server community [REDACTED] RO", displayed_code)
        self.assertNotIn("snmp-server community public RO", displayed_code)
        self.assertIn("Risky Configuration Audit", expander.call_args.args[0])
        finding_labels = [call.args[0] for call in markdown.call_args_list]
        self.assertTrue(any("New · HIGH: Default SNMP" in label for label in finding_labels))
        self.assertTrue(any("Resolved · HIGH: SNMP community" in label for label in finding_labels))
        self.assertTrue(any("Resolved · HIGH: HTTP" in label for label in finding_labels))

    def test_audit_requests_final_answer_with_sufficient_token_budget(self) -> None:
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    create=Mock(
                        return_value=SimpleNamespace(
                            choices=[
                                SimpleNamespace(
                                    finish_reason="stop",
                                    message=SimpleNamespace(
                                        content="### Security assessment\nReview the change."
                                    ),
                                )
                            ]
                        )
                    )
                )
            )
        )

        result = run_groq_audit(
            cast(Groq, fake_client),
            SwitchBrand.CISCO_IOS,
            "edge-01",
            "+ ip http server\n",
        )

        request = fake_client.chat.completions.create.call_args.kwargs
        self.assertEqual(request["model"], MODEL_ID)
        self.assertEqual(request["reasoning_format"], "hidden")
        self.assertEqual(request["max_completion_tokens"], 4096)
        self.assertIn("Do not use tables", request["messages"][0]["content"])
        self.assertNotIn("Risky Configuration Audit", request["messages"][0]["content"])
        self.assertNotIn("FULL CANDIDATE", request["messages"][1]["content"])
        self.assertIn("### Security assessment", result)

    def test_html_break_tags_are_converted_to_newlines(self) -> None:
        markdown = "no ip http server<br>line vty 0 4<BR />transport input ssh"

        self.assertEqual(
            normalize_audit_markdown(markdown),
            "no ip http server\nline vty 0 4\ntransport input ssh",
        )

    def test_detects_supported_vendor_signatures(self) -> None:
        test_cases = (
            (
                SwitchBrand.CISCO_IOS,
                "aaa new-model\nline vty 0 4\n transport input ssh\n",
            ),
            (
                SwitchBrand.ARISTA_EOS,
                "management api http-commands\n"
                "daemon TerminAttr\n"
                "interface Ethernet1\n",
            ),
            (
                SwitchBrand.JUNIPER_JUNOS,
                "set system host-name edge-01\n"
                "set system services ssh\n"
                "set interfaces ge-0/0/1 description uplink\n",
            ),
            (
                SwitchBrand.ARUBA_AOS,
                "interface 1/1/1\n"
                "vlan access 10\n"
                "spanning-tree port-type admin-edge\n",
            ),
            (
                SwitchBrand.ARUBA_AOS,
                "interface 1\n"
                " untagged 10\n"
                " spanning-tree admin-edge-port\n",
            ),
        )
        for expected_brand, config in test_cases:
            with self.subTest(brand=expected_brand):
                self.assertEqual(detect_config_brand(config).brand, expected_brand)

    def test_config_pair_requires_selected_same_brand_and_hostname(self) -> None:
        cisco = "hostname edge-01\naaa new-model\nline vty 0 4\n"
        juniper = (
            "set system host-name edge-01\n"
            "set system services ssh\n"
            "set interfaces ge-0/0/1 description uplink\n"
        )

        self.assertEqual(
            validate_config_pair(cisco, cisco, SwitchBrand.CISCO_IOS),
            (),
        )
        wrong_selected_brand = validate_config_pair(
            cisco,
            cisco,
            SwitchBrand.ARUBA_AOS,
        )
        self.assertTrue(any("but aruba_aos was selected" in error for error in wrong_selected_brand))
        mixed_brand = validate_config_pair(cisco, juniper, SwitchBrand.CISCO_IOS)
        self.assertTrue(any("different brands" in error for error in mixed_brand))
        hostname_mismatch = validate_config_pair(
            cisco,
            cisco.replace("edge-01", "edge-02"),
            SwitchBrand.CISCO_IOS,
        )
        self.assertTrue(any("hostname mismatch" in error for error in hostname_mismatch))

    def test_empty_content_reports_finish_reason(self) -> None:
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    create=Mock(
                        return_value=SimpleNamespace(
                            choices=[
                                SimpleNamespace(
                                    finish_reason="length",
                                    message=SimpleNamespace(content=None),
                                )
                            ]
                        )
                    )
                )
            )
        )

        with self.assertRaisesRegex(RuntimeError, "finish reason: length"):
            run_groq_audit(
                cast(Groq, fake_client),
                SwitchBrand.CISCO_IOS,
                "edge-01",
                "+ ip http server\n",
            )


if __name__ == "__main__":
    unittest.main()
