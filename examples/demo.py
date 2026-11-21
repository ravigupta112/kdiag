"""Run: python examples/demo.py   (from the project root, after `pip install -e .`)"""
import asyncio

from kdiag import (
    ContainerEvidence,
    DiagnosisInput,
    PodEvidence,
    Target,
    WorkloadRef,
    diagnose,
    render_text,
)
from kdiag.testing import FakeSource

PULL = ('Failed to pull image "registry.example.com/shop/web:2.4.1": rpc error: code = NotFound '
        'desc = failed to resolve reference: not found')
ref = WorkloadRef(kind="Deployment", name="shop-web", namespace="shop-prod")
pod = PodEvidence(
    name="shop-web-6d9f7c-abcde", namespace="shop-prod", phase="Pending",
    containers=(ContainerEvidence(name="web", waiting_reason="ImagePullBackOff",
                                  waiting_message=PULL),),
)

# Mode 2 (cluster): give a target, the source supplies the evidence.
cluster = DiagnosisInput(mode="cluster", target=Target(name="shop-web", namespace="shop-prod"))
print(render_text(asyncio.run(diagnose(cluster, FakeSource([ref], pods=[pod])))))

print("\n--- evidence mode: Helm output only ---")
evidence = DiagnosisInput(mode="evidence",
                          helm_output="Error: UPGRADE FAILED: timed out waiting for the condition")
print(render_text(asyncio.run(diagnose(evidence))))
