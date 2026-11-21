from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from kdiag.helm import helm_finding, parse_helm

GOLDEN = [
    ("Error: UPGRADE FAILED: another operation (install/upgrade/rollback) is in progress",
     "HLM-003", True),
    ('Error: rendered manifests contain a resource that already exists. Unable to continue '
     'with install: Service "web" in namespace "shop" exists and cannot be imported into the '
     'current release', "HLM-006", True),
    ("Error: INSTALLATION FAILED: cannot re-use a name that is still in use", "HLM-005", True),
    ("Error: release: not found", "HLM-002", True),
    ("Error: YAML parse error on web/templates/x.yaml: error converting YAML to JSON: "
     "yaml: line 12: mapping values are not allowed in this context", "HLM-004", True),
    ("Error: template: web/templates/deploy.yaml:9:12: executing \"web/templates/deploy.yaml\" "
     "at <.Values.image.tag>: nil pointer evaluating interface {}.tag", "HLM-004", True),
    ('Error: unable to create new content in namespace shop because it is being terminated',
     "HLM-007", True),
    ("Error: UPGRADE FAILED: timed out waiting for the condition", "HLM-001", False),
    ("Error: UPGRADE FAILED: context deadline exceeded", "HLM-009", False),
]


@pytest.mark.parametrize(("text", "kind", "definitive"), GOLDEN)
def test_golden(text: str, kind: str, definitive: bool) -> None:
    r = parse_helm(text)
    assert (r.kind, r.definitive) == (kind, definitive)


def test_ansi_ci_timestamps_and_whitespace() -> None:
    text = ("2026-11-21T10:00:01.123Z \x1b[31mError:\x1b[0m   UPGRADE FAILED:\r\n"
            "2026-11-21T10:00:01.200Z   timed out   waiting for the condition")
    assert parse_helm(text).kind == "HLM-001"


def test_unknown_stays_unknown() -> None:
    r = parse_helm("everything is on fire in a way no pattern knows")
    assert r.kind == "unknown" and helm_finding(r) is None
    assert parse_helm(None).kind == "unknown" and parse_helm("   ").kind == "unknown"


def test_definitive_beats_timeout_when_both_present() -> None:
    r = parse_helm("another operation (upgrade) is in progress\ntimed out waiting for the condition")
    assert r.kind == "HLM-003"
    assert "HLM-001:wait_timeout" in r.all_matches


def test_extracts_resource_names_and_namespace() -> None:
    r = parse_helm('Deployment/shop-web not ready; Pod/shop-web-1 failed in namespace "shop"')
    assert r.extracted["resources"] == ("Deployment/shop-web", "Pod/shop-web-1")
    assert r.extracted["namespaces"] == ("shop",)


def test_outcome_findings_are_not_root_causes() -> None:
    f = helm_finding(parse_helm("timed out waiting for the condition"))
    assert f is not None and f.outcome_only and not f.definitive


def test_huge_input_keeps_tail_and_is_bounded() -> None:
    text = ("noise line\n" * 100_000) + "another operation (upgrade) is in progress"
    r = parse_helm(text)
    assert r.kind == "HLM-003" and r.truncated


@settings(max_examples=200, deadline=500)
@given(st.text(max_size=2000))
def test_fuzz_never_raises_and_is_fast(text: str) -> None:
    r = parse_helm(text)
    assert isinstance(r.kind, str)


@settings(max_examples=50, deadline=1000)
@given(st.text(alphabet=" \t:()/-=\"'abcdefghijklmnopqrstuvwxyz0-9\n", max_size=30000))
def test_fuzz_pattern_alphabet_no_redos(text: str) -> None:
    parse_helm(text)
