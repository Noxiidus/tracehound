from __future__ import annotations

from pathlib import Path

from tracehound import scan
from tracehound.models import Severity


def _by_rule(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.rule_id == rule_id]


class TestBruteForceDetections:
    def test_detects_brute_force(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        found = _by_rule(result.findings, "THN-0001")

        assert len(found) == 1
        assert found[0].metadata["source_ip"] == "65.2.161.68"
        assert found[0].metadata["failure_count"] == 24
        assert found[0].severity is Severity.HIGH

    def test_detects_successful_compromise(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        found = _by_rule(result.findings, "THN-0002")

        assert len(found) == 1
        assert found[0].severity is Severity.CRITICAL
        assert found[0].metadata["compromised_user"] == "root"

    def test_legitimate_admin_not_flagged(self, scenario: tuple[Path, Path]) -> None:
        """The administrator logged in cleanly and must not appear as an attacker."""
        result = scan(list(scenario), year=2024)
        offending_ips = {
            f.metadata.get("source_ip") for f in result.findings if "source_ip" in f.metadata
        }
        assert "203.101.190.9" not in offending_ips

    def test_no_findings_on_clean_log(self, tmp_path: Path) -> None:
        from synth import write_auth_log

        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:19:54 host sshd[1]: Accepted password for root from 10.0.0.5 port 1 ssh2",
                "Mar  6 07:19:54 host sshd[2]: pam_unix(sshd:session): session closed for user root",
            ],
        )
        result = scan([path], year=2024)
        assert result.findings == []


class TestPersistenceDetections:
    def test_detects_account_creation(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        found = _by_rule(result.findings, "THN-0010")

        assert len(found) == 1
        assert found[0].metadata["account"] == "cyberjunkie"

    def test_detects_privileged_group_addition(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        found = _by_rule(result.findings, "THN-0011")

        assert len(found) == 1
        assert found[0].metadata["group"] == "sudo"

    def test_correlates_backdoor_account(self, scenario: tuple[Path, Path]) -> None:
        """Creation plus privilege grant should escalate into one critical finding."""
        result = scan(list(scenario), year=2024)
        found = _by_rule(result.findings, "THN-0012")

        assert len(found) == 1
        assert found[0].severity is Severity.CRITICAL
        assert found[0].metadata["account"] == "cyberjunkie"
        assert found[0].metadata["seconds_between"] == 57

    def test_detects_shadow_access(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        reasons = {f.metadata.get("reason") for f in _by_rule(result.findings, "THN-0013")}
        assert "credential store access" in reasons

    def test_detects_remote_download(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        reasons = {f.metadata.get("reason") for f in _by_rule(result.findings, "THN-0013")}
        assert "remote file download" in reasons


class TestFindingOrdering:
    def test_most_severe_first(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_attack_techniques_present(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        assert all(f.attack_techniques for f in result.findings)


class TestTimelineIntegration:
    def test_merges_both_sources(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        assert set(result.timeline.sources()) == {"auth.log", "wtmp"}

    def test_timeline_is_ordered(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        stamps = [e.timestamp for e in result.timeline]
        assert stamps == sorted(stamps)

    def test_scan_accepts_directory(self, scenario: tuple[Path, Path]) -> None:
        directory = scenario[0].parent
        result = scan([directory], year=2024)
        assert len(result.parsed) == 2
