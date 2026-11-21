from __future__ import annotations

import inspect
import pathlib
import re

import pytest
from pydantic import BaseModel, ValidationError

from kdiag import DiagnosisInput, Target, models

SRC = pathlib.Path(__file__).parent.parent / "src" / "kdiag"
FORBIDDEN_IMPORTS = re.compile(r"\b(subprocess|shlex|pty|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*)\b")
FORBIDDEN_FIELDS = ("password", "token", "kubeconfig", "secret_value", "env_value", "private_key",
                    "credential", "env")


def test_no_command_execution_anywhere_in_source() -> None:
    offenders = [str(p) for p in SRC.rglob("*.py") if FORBIDDEN_IMPORTS.search(p.read_text())]
    assert offenders == []


def test_no_write_verbs_or_mutation_in_source() -> None:
    text = "\n".join(p.read_text() for p in SRC.rglob("*.py"))
    assert not re.search(r"\b(create|patch|delete|replace)_namespaced\w*|\bkubectl\b.*apply", text)


def test_models_cannot_hold_credentials() -> None:
    for _, cls in inspect.getmembers(models, inspect.isclass):
        if issubclass(cls, BaseModel) and cls is not BaseModel:
            for field in cls.model_fields:
                assert field not in FORBIDDEN_FIELDS, f"{cls.__name__}.{field}"


def test_models_are_frozen_and_reject_unknown_fields() -> None:
    t = Target(name="x")
    with pytest.raises(ValidationError):
        t.name = "y"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Target(name="x", kubeconfig="whatever")  # type: ignore[call-arg]


def test_input_validation() -> None:
    with pytest.raises(ValidationError):
        DiagnosisInput(mode="evidence")
    with pytest.raises(ValidationError):
        DiagnosisInput(mode="cluster")
    with pytest.raises(ValidationError):
        DiagnosisInput(mode="evidence", helm_output="x" * 1_000_001)
    with pytest.raises(ValidationError):
        Target(name="")
