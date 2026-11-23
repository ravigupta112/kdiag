from __future__ import annotations

import base64
import pathlib

import pytest
import yaml

from conftest import run
from kdiag.k8s.kubeconfig import KubeconfigRejected, parse_kubeconfig

CA = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").decode()
PUBLIC = "93.184.216.34"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.CANARYTOKENVALUE.sig-part"


def cfg(cluster=None, user=None, server="https://k8s.example.com:6443"):
    c = {"server": server, "certificate-authority-data": CA} | (cluster or {})
    u = {"token": TOKEN} | (user or {})
    return yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config", "current-context": "ctx",
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "clusters": [{"name": "c", "cluster": c}], "users": [{"name": "u", "user": u}]})


async def public(_: str):
    return [PUBLIC]


def parse(text, **kw):
    kw.setdefault("resolver", public)
    return run(parse_kubeconfig(text, **kw))


def rejected(text, **kw) -> KubeconfigRejected:
    with pytest.raises(KubeconfigRejected) as ei:
        parse(text, **kw)
    return ei.value


def test_valid_token_kubeconfig_is_accepted_and_redacted() -> None:
    creds = parse(cfg())
    assert creds.server == "https://k8s.example.com:6443" and creds.token == TOKEN
    assert creds.ca_pem and "BEGIN CERTIFICATE" in creds.ca_pem
    assert "CANARY" not in repr(creds) and "redacted" in repr(creds)


@pytest.mark.parametrize(("kw", "code"), [
    ({"user": {"exec": {"command": "aws", "args": ["eks"]}}}, "exec_plugin"),
    ({"user": {"auth-provider": {"name": "gcp"}}}, "auth_provider"),
    ({"user": {"tokenFile": "/var/run/token"}}, "file_reference"),
    ({"user": {"client-certificate-data": "xx", "client-key-data": "yy"}}, "client_cert_unsupported"),
    ({"user": {"client-key": "/etc/key"}}, "client_cert_unsupported"),
    ({"user": {"username": "a", "password": "b"}}, "basic_auth"),
    ({"user": {"as": "admin"}}, "impersonation"),
    ({"user": {"mystery": 1}}, "unsupported_field"),
    ({"cluster": {"insecure-skip-tls-verify": True}}, "insecure_tls"),
    ({"cluster": {"certificate-authority": "/etc/ca.crt"}}, "file_reference"),
    ({"cluster": {"proxy-url": "http://evil:8080"}}, "proxy"),
    ({"cluster": {"mystery": 1}}, "unsupported_field"),
])
def test_dangerous_fields_are_rejected(kw: dict, code: str) -> None:
    err = rejected(cfg(**kw))
    assert err.code == code
    assert "CANARY" not in err.message and "/etc" not in err.message and "evil" not in err.message


@pytest.mark.parametrize("server", [
    "http://k8s.example.com", "ftp://k8s.example.com", "k8s.example.com", "https://",
    "https://user:pw@k8s.example.com", "https://k8s.example.com/some/path", "https://k8s.example.com/?q=1",
    "https://k8s.example.com:99999",
])
def test_bad_server_urls_are_rejected(server: str) -> None:
    assert rejected(cfg(server=server)).code == "bad_server"


@pytest.mark.parametrize("server", [
    "https://169.254.169.254", "https://127.0.0.1:6443", "https://10.1.2.3", "https://192.168.0.5",
    "https://[::1]:6443", "https://100.64.0.1", "https://0.0.0.0", "https://[::ffff:10.0.0.1]",
])
def test_private_and_metadata_addresses_are_rejected(server: str) -> None:
    assert rejected(cfg(server=server)).code == "private_address"


def test_hostname_resolving_to_private_or_mixed_addresses_is_rejected() -> None:
    async def internal(_: str):
        return ["10.0.0.7"]

    async def mixed(_: str):
        return [PUBLIC, "169.254.169.254"]

    assert rejected(cfg(), resolver=internal).code == "private_address"
    assert rejected(cfg(), resolver=mixed).code == "private_address"
    assert rejected(cfg(server="https://localhost:6443"), resolver=lambda h: _loop()).code == "private_address"


async def _loop() -> list[str]:
    return ["127.0.0.1"]


def test_unresolvable_host_is_rejected() -> None:
    async def nxdomain(_: str):
        raise OSError("nope")

    assert rejected(cfg(), resolver=nxdomain).code == "bad_server"


def test_allowlist_is_strict_but_permits_private_hosts_the_operator_chose() -> None:
    internal = cfg(server="https://k8s.corp.internal:6443")
    assert rejected(internal, allowed_hosts=["*.example.com"]).code == "host_not_allowed"
    assert parse(internal, allowed_hosts=["*.corp.internal"]).server == "https://k8s.corp.internal:6443"
    assert parse(cfg(server="https://10.0.0.5:6443"), allowed_hosts=["10.0.0.5"]).server.endswith("10.0.0.5:6443")
    assert rejected(cfg(server="https://corp.internal"), allowed_hosts=["*.corp.internal"]).code == "host_not_allowed"


def test_allow_private_flag_opens_private_ranges() -> None:
    assert parse(cfg(server="https://10.0.0.5:6443"), allow_private=True).server.endswith("10.0.0.5:6443")


@pytest.mark.parametrize("token", ["", "has space", "line\nbreak", "x" * 9000, 123, None])
def test_bad_tokens_are_rejected(token) -> None:
    assert rejected(cfg(user={"token": token})).code == "no_token"


def test_bad_ca_too_large_bad_yaml_and_no_context() -> None:
    assert rejected(cfg(cluster={"certificate-authority-data": "!!notbase64"})).code == "bad_ca"
    key = base64.b64encode(b"-----BEGIN CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nzz").decode()
    assert rejected(cfg(cluster={"certificate-authority-data": key})).code == "bad_ca"
    assert rejected("x" * 300_000).code == "too_large"
    assert rejected("a: [unclosed").code == "invalid_yaml"
    assert rejected("- just\n- a list").code == "invalid_kubeconfig"
    doc = yaml.safe_load(cfg())
    doc["current-context"] = None
    doc["contexts"].append({"name": "second", "context": {"cluster": "c", "user": "u"}})
    assert rejected(yaml.safe_dump(doc)).code == "no_context"
    assert parse(yaml.safe_dump(doc), context="ctx").token == TOKEN


def test_yaml_tags_cannot_execute_code() -> None:
    evil = "current-context: !!python/object/apply:os.system ['echo pwned']\n"
    assert rejected(evil).code == "invalid_yaml"


def test_rbac_manifest_is_read_only_and_never_grants_secrets() -> None:
    docs = list(yaml.safe_load_all((pathlib.Path(__file__).parent.parent / "deploy" / "rbac.yaml").read_text()))
    rules = [r for d in docs if d and d["kind"] in ("Role", "ClusterRole") for r in d["rules"]]
    assert rules
    for r in rules:
        assert set(r["verbs"]) <= {"get", "list"}
        assert "*" not in r["resources"] and "*" not in r["apiGroups"]
        assert not {"secrets", "configmaps", "pods/exec", "pods/attach", "serviceaccounts/token"} & set(r["resources"])
    resources = {x for r in rules for x in r["resources"]}
    assert {"pods", "pods/log", "events", "deployments", "endpointslices", "nodes"} <= resources
