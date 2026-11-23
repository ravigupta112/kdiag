"""STO-001 pending PVCs; STO-002 mount/attach failures."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence
from .table import TableRule, pod_events, sub

_N = r"([A-Za-z0-9._-]{1,253})"


class PendingPvcRule(TableRule):
    id, priority, causal_order = "STO-001", 70, 18
    requires = frozenset({"pvcs"})
    table = (
        sub("storageclass_missing", r"storageclass\.storage\.k8s\.io \"[^\"]+\" not found", "high",
            "The StorageClass {detail} does not exist",
            "Fix storageClassName in the chart or create the StorageClass",
            rf"storageclass\.storage\.k8s\.io \"{_N}\" not found"),
        sub("no_storage_class", r"no persistent volumes available for this claim and no storage class is set",
            "high", "The PVC names no StorageClass and the cluster has no default",
            "Set storageClassName or mark a default StorageClass"),
        sub("provisioning_failed", r"ProvisioningFailed|failed to provision volume", "high",
            "The storage provisioner failed to create a volume",
            "Read the provisioner error; check backend quota, zone and permissions"),
        sub("waiting_for_consumer", r"waiting for first consumer", "low",
            "The PVC waits for a pod to be scheduled (WaitForFirstConsumer); usually not a fault itself",
            "Fix the pod's scheduling problem first"),
        sub("pending_unexplained", r"pvc ", "medium",
            "PVC {detail} is Pending and no event explains why",
            "Check the PVC events and the StorageClass provisioner",
            r"pvc ([A-Za-z0-9._-]{1,253}):"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for pvc in ev.pvcs:
            if pvc.phase != "Pending":
                continue
            msgs = [f"{e.reason}: {e.message}" for e in ev.events
                    if e.object_kind == "PersistentVolumeClaim" and e.object_name == pvc.name]
            yield f"pvc/{pvc.name}", f"pvc {pvc.name}: " + " | ".join(msgs)


class MountFailureRule(TableRule):
    id, priority, causal_order = "STO-002", 68, 22
    requires = frozenset({"events"})
    table = (
        sub("multi_attach", r"Multi-Attach error", "high",
            "A ReadWriteOnce volume is already attached to another node",
            "Schedule the pods on one node, use ReadWriteMany, or scale down the old pod first"),
        sub("source_missing", r"(?:secret|configmap) \"[^\"]+\" not found", "high",
            "A volume source ({detail}) does not exist",
            "Create it or fix the volume reference in the chart",
            r"((?:secret|configmap) \"[A-Za-z0-9._-]{1,253}\")"),
        sub("pvc_not_found", r"persistentvolumeclaim \"[^\"]+\" not found", "high",
            "The PersistentVolumeClaim {detail} does not exist",
            "Create the PVC or fix claimName in the chart",
            rf"persistentvolumeclaim \"{_N}\" not found"),
        sub("pvc_unbound", r"unbound immediate PersistentVolumeClaims|pod has unbound", "high",
            "The pod uses a PVC that is not bound yet",
            "Check the PVC status and StorageClass"),
        sub("permission", r"permission denied|operation not permitted", "high",
            "Mounting the volume failed with a permission error",
            "Check fsGroup, runAsUser and the volume's permissions"),
        sub("volume_in_use", r"already (?:used|attached)|is being used", "medium",
            "The volume is already in use by another pod or node",
            "Check which pod holds the volume"),
        sub("attach_failed", r"AttachVolume\.Attach failed|failed to attach", "medium",
            "The cloud disk could not be attached to the node",
            "Check the disk, zone and node limits in the cloud console"),
        sub("mount_timeout", r"timed out waiting for the condition|unable to attach or mount volumes",
            "medium", "Mounting or attaching volumes timed out",
            "Check the volume events for the underlying attach or mount error"),
        sub("mount_failed", r".", "low", "A volume could not be mounted",
            "Read the FailedMount event for the exact error"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        yield from pod_events(ev, {"Pod"}, {"FailedMount", "FailedAttachVolume",
                                            "FailedMapVolume", "FailedDetachVolume"})
