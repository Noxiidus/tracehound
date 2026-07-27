"""Tests for the state-artifact model: fact parsers, the FactBase, and THN-0040..0044."""

from __future__ import annotations

from pathlib import Path

from synth import (
    backdoor_state_scenario,
    write_authorized_keys,
    write_passwd,
    write_sudoers,
    write_unit,
)
from tracehound import Config, scan
from tracehound.factbase import FactBase
from tracehound.models import Fact
from tracehound.parsers import ParseContext, fact_parser_for
from tracehound.parsers.authorized_keys import AuthorizedKeysParser
from tracehound.parsers.group import GroupParser
from tracehound.parsers.passwd import PasswdParser
from tracehound.parsers.sudoers import SudoersParser
from tracehound.parsers.systemd_unit import SystemdUnitParser

CTX = ParseContext(default_year=2024)


class TestFactModel:
    def test_kind_and_name_split_subject(self) -> None:
        fact = Fact(subject="account:root", attribute="uid", value="0", source="passwd")
        assert fact.kind == "account"
        assert fact.name == "root"

    def test_name_without_colon_is_whole_subject(self) -> None:
        fact = Fact(subject="Defaults", attribute="option", value="env_reset", source="sudoers")
        assert fact.kind == "Defaults"
        assert fact.name == "Defaults"


class TestFactBase:
    def _fb(self) -> FactBase:
        fb = FactBase()
        fb.add(
            [
                Fact(subject="account:root", attribute="uid", value="0", source="passwd"),
                Fact(subject="account:root", attribute="shell", value="/bin/bash", source="passwd"),
                Fact(subject="account:mysql", attribute="uid", value="110", source="passwd"),
                Fact(subject="unit:x.service", attribute="exec_start", value="/a", source="s"),
                Fact(subject="unit:x.service", attribute="exec_start", value="/b", source="s"),
            ]
        )
        return fb

    def test_of_kind_returns_distinct_subjects(self) -> None:
        assert self._fb().of_kind("account") == ["account:root", "account:mysql"]

    def test_with_attribute(self) -> None:
        uids = self._fb().with_attribute("uid")
        assert {f.value for f in uids} == {"0", "110"}

    def test_value_returns_first(self) -> None:
        assert self._fb().value("account:root", "shell") == "/bin/bash"
        assert self._fb().value("account:root", "missing") is None

    def test_values_returns_all_repeats(self) -> None:
        assert self._fb().values("unit:x.service", "exec_start") == ["/a", "/b"]

    def test_sort_is_deterministic(self) -> None:
        fb = self._fb()
        fb.sort()
        first = [(f.subject, f.attribute, f.value) for f in fb]
        fb2 = self._fb()
        fb2.facts.reverse()
        fb2.sort()
        assert [(f.subject, f.attribute, f.value) for f in fb2] == first


class TestPasswdParser:
    def test_parses_account_attributes(self, tmp_path: Path) -> None:
        path = write_passwd(tmp_path / "passwd", ["root:x:0:0:Superuser:/root:/bin/bash"])
        facts = list(PasswdParser().parse(path, CTX))
        by_attr = {f.attribute: f.value for f in facts}
        assert by_attr["uid"] == "0"
        assert by_attr["shell"] == "/bin/bash"
        assert by_attr["home"] == "/root"
        assert by_attr["gecos"] == "Superuser"
        assert by_attr["password_field"] == "x"
        assert all(f.subject == "account:root" for f in facts)

    def test_sniff_needs_seven_numeric_fields(self, tmp_path: Path) -> None:
        good = write_passwd(tmp_path / "passwd", ["root:x:0:0::/root:/bin/bash"])
        # A group file has four fields — passwd must not claim it.
        bad = tmp_path / "passwd2"
        bad.write_text("root:x:0:\n", encoding="utf-8")
        assert PasswdParser().sniff(good)
        assert not PasswdParser().sniff(bad)

    def test_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        path = write_passwd(tmp_path / "passwd", ["# comment", "", "root:x:0:0::/root:/bin/bash"])
        subjects = {f.subject for f in PasswdParser().parse(path, CTX)}
        assert subjects == {"account:root"}


class TestGroupParser:
    def test_parses_members(self, tmp_path: Path) -> None:
        path = tmp_path / "group"
        path.write_text("sudo:x:27:alice,bob\n", encoding="utf-8")
        facts = list(GroupParser().parse(path, CTX))
        members = next(f for f in facts if f.attribute == "members")
        assert members.value == "alice,bob"
        assert members.metadata["members"] == ["alice", "bob"]

    def test_group_not_matched_by_passwd(self, tmp_path: Path) -> None:
        path = tmp_path / "group"
        path.write_text("root:x:0:\nsudo:x:27:alice\ndaemon:x:1:\n", encoding="utf-8")
        assert fact_parser_for(path) is not None
        assert fact_parser_for(path).name == "group"  # type: ignore[union-attr]


class TestSudoersParser:
    def test_parses_spec_and_nopasswd(self, tmp_path: Path) -> None:
        path = write_sudoers(
            tmp_path / "sudoers",
            ["Defaults env_reset", "bob ALL=(root) NOPASSWD: /bin/systemctl"],
        )
        facts = list(SudoersParser().parse(path, CTX))
        bob = [f for f in facts if f.subject == "sudo:bob"]
        by_attr = {f.attribute: f.value for f in bob}
        assert by_attr["nopasswd"] == "true"
        assert by_attr["runas"] == "root"
        assert by_attr["commands"] == "/bin/systemctl"
        assert "Defaults" in {f.name for f in facts}

    def test_joins_line_continuations(self, tmp_path: Path) -> None:
        path = write_sudoers(
            tmp_path / "sudoers", ["alice ALL=(ALL) \\", "    /usr/bin/id, /usr/bin/whoami"]
        )
        facts = list(SudoersParser().parse(path, CTX))
        commands = next(f.value for f in facts if f.attribute == "commands")
        assert "id" in commands and "whoami" in commands

    def test_sniff_matches_sudoers_d(self, tmp_path: Path) -> None:
        d = tmp_path / "sudoers.d"
        d.mkdir()
        path = d / "90-custom"
        path.write_text("bob ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
        assert SudoersParser().sniff(path)


class TestAuthorizedKeysParser:
    def test_parses_options_type_comment(self, tmp_path: Path) -> None:
        path = write_authorized_keys(
            tmp_path / "authorized_keys",
            ['from="10.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIblob user@host'],
        )
        facts = list(AuthorizedKeysParser().parse(path, CTX))
        by_attr = {f.attribute: f.value for f in facts}
        assert by_attr["type"] == "ssh-ed25519"
        assert by_attr["comment"] == "user@host"
        assert by_attr["options"] == 'from="10.0.0.1"'

    def test_infers_account_from_path(self, tmp_path: Path) -> None:
        ssh = tmp_path / "home" / "alice" / ".ssh"
        ssh.mkdir(parents=True)
        path = write_authorized_keys(
            ssh / "authorized_keys", ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIblob alice@host"]
        )
        account = next(
            f.value for f in AuthorizedKeysParser().parse(path, CTX) if f.attribute == "account"
        )
        assert account == "alice"

    def test_options_with_spaces_do_not_break_split(self, tmp_path: Path) -> None:
        path = write_authorized_keys(
            tmp_path / "authorized_keys",
            ['command="/bin/bash -i" ssh-rsa AAAAB3NzaC1yc2EAAAAblob evil@kali'],
        )
        facts = list(AuthorizedKeysParser().parse(path, CTX))
        by_attr = {f.attribute: f.value for f in facts}
        assert by_attr["type"] == "ssh-rsa"
        assert by_attr["options"] == 'command="/bin/bash -i"'
        assert by_attr["comment"] == "evil@kali"

    def test_option_containing_key_type_substring(self, tmp_path: Path) -> None:
        """Options must be taken from the tokens before the key type, not by splitting on
        the type string — an option value can contain that string as a substring."""
        path = write_authorized_keys(
            tmp_path / "authorized_keys",
            ['environment="ssh-rsa=1" ssh-rsa AAAAB3NzaC1yc2EAAAAblob user@host'],
        )
        by_attr = {f.attribute: f.value for f in AuthorizedKeysParser().parse(path, CTX)}
        assert by_attr["type"] == "ssh-rsa"
        assert by_attr["options"] == 'environment="ssh-rsa=1"'
        assert by_attr["comment"] == "user@host"


class TestSystemdUnitParser:
    def test_parses_selected_keys(self, tmp_path: Path) -> None:
        path = write_unit(
            tmp_path / "x.service",
            {"Service": {"ExecStart": "/usr/bin/x", "User": "root", "Type": "simple"}},
        )
        facts = list(SystemdUnitParser().parse(path, CTX))
        by_attr = {f.attribute: f.value for f in facts}
        assert by_attr["exec_start"] == "/usr/bin/x"
        assert by_attr["user"] == "root"
        assert by_attr["type"] == "simple"
        assert all(f.subject == "unit:x.service" for f in facts)

    def test_repeated_execstartpre_kept(self, tmp_path: Path) -> None:
        path = tmp_path / "x.service"
        path.write_text(
            "[Service]\nExecStartPre=/bin/a\nExecStartPre=/bin/b\nExecStart=/bin/c\n",
            encoding="utf-8",
        )
        facts = list(SystemdUnitParser().parse(path, CTX))
        pre = [f.value for f in facts if f.attribute == "exec_start_pre"]
        assert pre == ["/bin/a", "/bin/b"]


class TestStateDetections:
    def _scan(self, tmp_path: Path, config: Config | None = None):
        root = backdoor_state_scenario(tmp_path)
        return scan([root], config=config)

    def test_all_five_rules_fire(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path)
        fired = {f.rule_id for f in result.findings}
        assert {"THN-0040", "THN-0041", "THN-0042", "THN-0043", "THN-0044"} <= fired

    def test_duplicate_uid0_names_both_accounts(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path)
        dup = next(f for f in result.findings if f.rule_id == "THN-0040")
        assert set(dup.metadata["accounts"]) == {"root", "systemd-network"}
        assert dup.severity.value == "critical"

    def test_nologin_service_account_not_flagged(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path)
        shells = [f for f in result.findings if f.rule_id == "THN-0044"]
        flagged = {f.metadata["account"] for f in shells}
        assert "postfix" in flagged
        assert "www-data" not in flagged  # has /usr/sbin/nologin
        assert "daemon" not in flagged

    def test_expected_sudo_lines_not_flagged(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path)
        grants = [f for f in result.findings if f.rule_id == "THN-0041"]
        principals = {f.metadata["principal"] for f in grants}
        assert "cyberjunkie" in principals
        assert "root" not in principals
        assert "%sudo" not in principals

    def test_benign_unit_not_flagged(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path)
        units = {f.metadata["unit"] for f in result.findings if f.rule_id == "THN-0043"}
        assert "evil.service" in units
        assert "nginx.service" not in units

    def test_service_account_config_suppresses(self, tmp_path: Path) -> None:
        cfg = Config(service_accounts={"postfix", "cyberjunkie"})
        result = self._scan(tmp_path, cfg)
        shells = {f.metadata["account"] for f in result.findings if f.rule_id == "THN-0044"}
        assert "postfix" not in shells
        # cyberjunkie's sudo grant is suppressed too, since it's now a known account.
        grants = {f.metadata["principal"] for f in result.findings if f.rule_id == "THN-0041"}
        assert "cyberjunkie" not in grants

    def test_disabled_rule_is_skipped(self, tmp_path: Path) -> None:
        cfg = Config(disabled_rules={"THN-0040"})
        result = self._scan(tmp_path, cfg)
        assert not any(f.rule_id == "THN-0040" for f in result.findings)


class TestScanIntegration:
    def test_facts_and_events_coexist(self, tmp_path: Path) -> None:
        """A scan over both a log and a state file populates both stores."""
        root = tmp_path / "mix"
        root.mkdir()
        write_passwd(root / "passwd", ["backdoor:x:0:0::/root:/bin/bash"])
        (root / "auth.log").write_text(
            "Mar  6 06:31:31 h sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2\n",
            encoding="utf-8",
        )
        result = scan([root], year=2024)
        assert len(result.timeline) >= 1
        assert len(result.factbase) >= 1
        assert any(f.rule_id == "THN-0040" for f in result.findings)

    def test_fact_finding_serialises_with_facts(self, tmp_path: Path) -> None:
        result = scan([backdoor_state_scenario(tmp_path)])
        dup = next(f for f in result.findings if f.rule_id == "THN-0040")
        payload = dup.to_dict()
        assert payload["fact_count"] == len(dup.facts)
        assert payload["first_seen"] is None
        assert payload["facts"][0]["subject"].startswith("account:")

    def test_artifact_record_reports_fact_count(self, tmp_path: Path) -> None:
        result = scan([backdoor_state_scenario(tmp_path)])
        passwd_record = next(r for r in result.artifacts if r.path.name == "passwd")
        assert passwd_record.parser == "passwd"
        assert passwd_record.fact_count > 0
        assert passwd_record.event_count == 0
