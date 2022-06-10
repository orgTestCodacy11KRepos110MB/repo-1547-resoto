import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Optional, Dict, Type, List, Any, Union, TypeVar

import jsons
from jsons import set_deserializer
from resotolib.json_bender import StringToUnitNumber, CPUCoresToNumber, Bend, S, K, bend, ForallBend, Bender
from resotolib.baseresources import (
    BaseAccount,
    BaseResource,
    BaseInstance,
    BaseRegion,
    InstanceStatus,
    BaseVolume,
    BaseQuota,
    BaseLoadBalancer,
    EdgeType,
)
from resotolib.graph import Graph
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.k8s")


@dataclass(eq=False)
class KubernetesResource(BaseResource):
    kind: ClassVar[str] = "kubernetes_resource"

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("metadata", "uid"),
        "tags": S("metadata", "annotations", default={}),
        "name": S("metadata", "name"),
        "ctime": S("metadata", "creationTimestamp"),
        "mtime": S("status", "conditions")[-1]["lastTransitionTime"],
        "resource_version": S("metadata", "resourceVersion"),
        "namespace": S("metadata", "namespace"),
        "labels": S("metadata", "labels", default={}),
    }

    resource_version: Optional[str] = None
    namespace: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> Json:
        return jsons.dump(  # type: ignore
            self,
            strip_privates=True,
            strip_nulls=True,
            strip_attr=(
                "k8s_name",
                "mapping",
                "phantom",
                "successor_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
                "rtdname",
                "changes",
                "event_log",
                "str_event_log",
                "chksum",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "_graph",
                "graph",
                "max_graph_depth",
                "resource_type",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "uuid",
                "kind",
            ),
        )

    @classmethod
    def from_json(cls: Type["KubernetesResource"], json: Json) -> "KubernetesResource":
        mapped = bend(cls.mapping, json)
        return jsons.load(mapped, cls)  # type: ignore

    @classmethod
    def k8s_name(cls: Type["KubernetesResource"]) -> str:
        return cls.__name__.removeprefix("Kubernetes")

    def update_tag(self, key: str, value: str) -> bool:
        return False

    def delete_tag(self, key: str) -> bool:
        return False

    def delete(self, graph: Graph) -> bool:
        return False

    def connect_in_graph(self, builder: "GraphBuilder", source: Json) -> None:
        # https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
        for ref in bend(S("metadata", "ownerReferences", default=[]), source):
            owner = builder.node(id=ref["uid"])
            block_owner_deletion = ref.get("blockOwnerDeletion", False)
            if owner:
                log.debug(f"Add owner reference from {owner} -> {self}")
                builder.graph.add_edge(owner, self, edge_type=EdgeType.default)
                if block_owner_deletion:
                    builder.graph.add_edge(self, owner, edge_type=EdgeType.delete)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}[{self.name}]"


KubernetesResourceType = TypeVar("KubernetesResourceType", bound=KubernetesResource)


class GraphBuilder:
    def __init__(self, graph: Graph):
        self.graph = graph

    def node(self, clazz: Optional[Type[KubernetesResource]] = None, **node: Any) -> Optional[KubernetesResource]:
        for n in self.graph:
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                return n  # type: ignore
        return None

    def add_edge(
        self, from_node: KubernetesResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if to_n:
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"Add edge: {start.name}:{start.k8s_name()} -> {end.name}:{end.k8s_name()}")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def add_edges_from_selector(
        self,
        from_node: KubernetesResource,
        edge_type: EdgeType,
        selector: Dict[str, str],
        clazz: Optional[type] = None,
    ) -> None:
        for to_n in self.graph:
            is_clazz = isinstance(to_n, clazz) if clazz else True
            if is_clazz and to_n != from_node and selector.items() <= to_n.labels.items():
                log.debug(f"Add edge: {from_node} -> {to_n}")
                self.graph.add_edge(from_node, to_n, edge_type=edge_type)

    def connect_volumes(self, from_node: KubernetesResource, volumes: List[Json]) -> None:
        for volume in volumes:
            if "persistentVolumeClaim" in volume:
                name = volume["persistentVolumeClaim"]["claimName"]
                self.add_edge(
                    from_node,
                    EdgeType.default,
                    name=name,
                    namespace=from_node.namespace,
                    clazz=KubernetesPersistentVolumeClaim,
                )
            elif "configMap" in volume:
                name = volume["configMap"]["name"]
                self.add_edge(
                    from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesConfigMap
                )
            elif "secret" in volume:
                name = volume["secret"]["secretName"]
                self.add_edge(
                    from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesSecret
                )
            elif "projected" in volume:
                # iterate all projected volumes
                self.connect_volumes(from_node, volume["projected"]["sources"])


# region node


@dataclass(eq=False)
class KubernetesNodeStatusAddresses:
    kind: ClassVar[str] = "kubernetes_node_status_addresses"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": S("address"),
        "type": S("type"),
    }
    address: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeCondition:
    kind: ClassVar[str] = "kubernetes_node_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_heartbeat_time": S("lastHeartbeatTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_heartbeat_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active_configmap"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_config_key": S("kubeletConfigKey"),
        "name": S("name"),
        "namespace": S("namespace"),
        "resource_version": S("resourceVersion"),
        "uid": S("uid"),
    }
    kubelet_config_key: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active"
    mapping: ClassVar[Dict[str, Bender]] = {
        "config_map": S("configMap") >> Bend(KubernetesNodeStatusConfigSource.mapping),
    }
    config_map: Optional[KubernetesNodeStatusConfigSource] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusConfig:
    kind: ClassVar[str] = "kubernetes_node_status_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active") >> Bend(KubernetesNodeConfigSource.mapping),
        "assigned": S("assigned") >> Bend(KubernetesNodeConfigSource.mapping),
        "error": S("error"),
    }
    active: Optional[KubernetesNodeConfigSource] = field(default=None)
    assigned: Optional[KubernetesNodeConfigSource] = field(default=None)
    error: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_daemon_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": S("Port"),
    }
    port: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_node_daemon_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_endpoint": S("kubeletEndpoint") >> Bend(KubernetesDaemonEndpoint.mapping),
    }
    kubelet_endpoint: Optional[KubernetesDaemonEndpoint] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusImages:
    kind: ClassVar[str] = "kubernetes_node_status_images"
    mapping: ClassVar[Dict[str, Bender]] = {
        "names": S("names", default=[]),
        "size_bytes": S("sizeBytes", default=0),
    }
    names: List[str] = field(default_factory=list)
    size_bytes: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeSystemInfo:
    kind: ClassVar[str] = "kubernetes_node_system_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "boot_id": S("bootID"),
        "container_runtime_version": S("containerRuntimeVersion"),
        "kernel_version": S("kernelVersion"),
        "kube_proxy_version": S("kubeProxyVersion"),
        "kubelet_version": S("kubeletVersion"),
        "machine_id": S("machineID"),
        "operating_system": S("operatingSystem"),
        "os_image": S("osImage"),
        "system_uuid": S("systemUUID"),
    }
    architecture: Optional[str] = field(default=None)
    boot_id: Optional[str] = field(default=None)
    container_runtime_version: Optional[str] = field(default=None)
    kernel_version: Optional[str] = field(default=None)
    kube_proxy_version: Optional[str] = field(default=None)
    kubelet_version: Optional[str] = field(default=None)
    machine_id: Optional[str] = field(default=None)
    operating_system: Optional[str] = field(default=None)
    os_image: Optional[str] = field(default=None)
    system_uuid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesAttachedVolume:
    kind: ClassVar[str] = "kubernetes_attached_volume"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_path": S("devicePath"),
        "name": S("name"),
    }
    device_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatus:
    kind: ClassVar[str] = "kubernetes_node_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": S("addresses", default=[]) >> ForallBend(KubernetesNodeStatusAddresses.mapping),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesNodeCondition.mapping),
        "config": S("config") >> Bend(KubernetesNodeStatusConfig.mapping),
        "capacity": S("capacity"),
        "daemon_endpoints": S("daemonEndpoints") >> Bend(KubernetesNodeDaemonEndpoint.mapping),
        "images": S("images", default=[]) >> ForallBend(KubernetesNodeStatusImages.mapping),
        "node_info": S("nodeInfo") >> Bend(KubernetesNodeSystemInfo.mapping),
        "phase": S("phase"),
        "volumes_attached": S("volumesAttached", default=[]) >> ForallBend(KubernetesAttachedVolume.mapping),
        "volumes_in_use": S("volumesInUse", default=[]),
    }
    addresses: List[KubernetesNodeStatusAddresses] = field(default_factory=list)
    capacity: Optional[Any] = field(default=None)
    conditions: List[KubernetesNodeCondition] = field(default_factory=list)
    config: Optional[KubernetesNodeStatusConfig] = field(default=None)
    daemon_endpoints: Optional[KubernetesNodeDaemonEndpoint] = field(default=None)
    images: List[KubernetesNodeStatusImages] = field(default_factory=list)
    node_info: Optional[KubernetesNodeSystemInfo] = field(default=None)
    phase: Optional[str] = field(default=None)
    volumes_attached: List[KubernetesAttachedVolume] = field(default_factory=list)
    volumes_in_use: List[str] = field(default_factory=list)


@dataclass
class KubernetesTaint:
    kind: ClassVar[str] = "kubernetes_taint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "effect": S("effect"),
        "key": S("key"),
        "time_added": S("timeAdded"),
        "value": S("value"),
    }
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    time_added: Optional[datetime] = field(default=None)
    value: Optional[str] = field(default=None)


@dataclass
class KubernetesNodeSpec:
    kind: ClassVar[str] = "kubernetes_node_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "external_id": S("externalID"),
        "pod_cidr": S("podCIDR"),
        "pod_cidrs": S("podCIDRs", default=[]),
        "provider_id": S("providerID"),
        "taints": S("taints", default=[]) >> ForallBend(KubernetesTaint.mapping),
        "unschedulable": S("unschedulable"),
    }
    external_id: Optional[str] = field(default=None)
    pod_cidr: Optional[str] = field(default=None)
    pod_cidrs: List[str] = field(default_factory=list)
    provider_id: Optional[str] = field(default=None)
    taints: List[KubernetesTaint] = field(default_factory=list)
    unschedulable: Optional[bool] = field(default=None)


instance_status_map: Dict[str, InstanceStatus] = {
    "Pending": InstanceStatus.BUSY,
    "Running": InstanceStatus.RUNNING,
    "Failed": InstanceStatus.TERMINATED,
    "Succeeded": InstanceStatus.STOPPED,
    "Unknown": InstanceStatus.UNKNOWN,
}


@dataclass(eq=False)
class KubernetesNode(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_node"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "node_status": S("status") >> Bend(KubernetesNodeStatus.mapping),
        "node_spec": S("spec") >> Bend(KubernetesNodeSpec.mapping),
        "provider_id": S("spec", "providerID"),
        "instance_cores": S("status", "capacity", "cpu") >> CPUCoresToNumber(),
        "instance_memory": S("status", "capacity", "memory") >> StringToUnitNumber("GiB"),
        "instance_type": K("kubernetes_node"),
        "instance_status": K(InstanceStatus.RUNNING.value),
    }
    provider_id: Optional[str] = None
    node_status: Optional[KubernetesNodeStatus] = field(default=None)
    node_spec: Optional[KubernetesNodeSpec] = field(default=None)

    def _instance_status_getter(self) -> str:
        return self._instance_status

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = value


# noinspection PyProtectedMember
KubernetesNode.instance_status = property(  # type: ignore
    KubernetesNode._instance_status_getter, KubernetesNode._instance_status_setter
)
# endregion

# region pod


@dataclass(eq=False)
class KubernetesPodStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateRunning:
    kind: ClassVar[str] = "kubernetes_container_state_running"
    mapping: ClassVar[Dict[str, Bender]] = {
        "started_at": S("startedAt"),
    }
    started_at: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateTerminated:
    kind: ClassVar[str] = "kubernetes_container_state_terminated"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": S("containerID"),
        "exit_code": S("exitCode"),
        "finished_at": S("finishedAt"),
        "message": S("message"),
        "reason": S("reason"),
        "signal": S("signal"),
        "started_at": S("startedAt"),
    }
    container_id: Optional[str] = field(default=None)
    exit_code: Optional[int] = field(default=None)
    finished_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    signal: Optional[int] = field(default=None)
    started_at: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateWaiting:
    kind: ClassVar[str] = "kubernetes_container_state_waiting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "reason": S("reason"),
    }
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerState:
    kind: ClassVar[str] = "kubernetes_container_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "running": S("running") >> Bend(KubernetesContainerStateRunning.mapping),
        "terminated": S("terminated") >> Bend(KubernetesContainerStateTerminated.mapping),
        "waiting": S("waiting") >> Bend(KubernetesContainerStateWaiting.mapping),
    }
    running: Optional[KubernetesContainerStateRunning] = field(default=None)
    terminated: Optional[KubernetesContainerStateTerminated] = field(default=None)
    waiting: Optional[KubernetesContainerStateWaiting] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStatus:
    kind: ClassVar[str] = "kubernetes_container_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": S("containerID"),
        "image": S("image"),
        "image_id": S("imageID"),
        "last_state": S("lastState") >> Bend(KubernetesContainerState.mapping),
        "name": S("name"),
        "ready": S("ready"),
        "restart_count": S("restartCount"),
        "started": S("started"),
        "state": S("state") >> Bend(KubernetesContainerState.mapping),
    }
    container_id: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    image_id: Optional[str] = field(default=None)
    last_state: Optional[KubernetesContainerState] = field(default=None)
    name: Optional[str] = field(default=None)
    ready: Optional[bool] = field(default=None)
    restart_count: Optional[int] = field(default=None)
    started: Optional[bool] = field(default=None)
    state: Optional[KubernetesContainerState] = field(default=None)


@dataclass(eq=False)
class KubernetesPodIPs:
    kind: ClassVar[str] = "kubernetes_pod_ips"
    mapping: ClassVar[Dict[str, Bender]] = {"ip": S("ip")}
    ip: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPodStatus:
    kind: ClassVar[str] = "kubernetes_pod_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesPodStatusConditions.mapping),
        "container_statuses": S("containerStatuses", default=[]) >> ForallBend(KubernetesContainerStatus.mapping),
        "ephemeral_container_statuses": S("ephemeralContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerState.mapping),
        "host_ip": S("hostIP"),
        "init_container_statuses": S("initContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerStatus.mapping),
        "message": S("message"),
        "nominated_node_name": S("nominatedNodeName"),
        "phase": S("phase"),
        "pod_ip": S("podIP"),
        "pod_ips": S("podIPs", default=[]) >> ForallBend(KubernetesPodIPs.mapping),
        "qos_class": S("qosClass"),
        "reason": S("reason"),
        "start_time": S("startTime"),
    }
    conditions: List[KubernetesPodStatusConditions] = field(default_factory=list)
    container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    ephemeral_container_statuses: List[KubernetesContainerState] = field(default_factory=list)
    host_ip: Optional[str] = field(default=None)
    init_container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    message: Optional[str] = field(default=None)
    nominated_node_name: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    pod_ip: Optional[str] = field(default=None)
    pod_ips: List[KubernetesPodIPs] = field(default_factory=list)
    qos_class: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@dataclass
class KubernetesContainerPort:
    kind: ClassVar[str] = "kubernetes_container_port"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_port": S("containerPort"),
        "host_ip": S("hostIP"),
        "host_port": S("hostPort"),
        "name": S("name"),
        "protocol": S("protocol"),
    }
    container_port: Optional[int] = field(default=None)
    host_ip: Optional[str] = field(default=None)
    host_port: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass
class KubernetesResourceRequirements:
    kind: ClassVar[str] = "kubernetes_resource_requirements"
    mapping: ClassVar[Dict[str, Bender]] = {
        "limits": S("limits"),
        "requests": S("requests"),
    }
    limits: Optional[Any] = field(default=None)
    requests: Optional[Any] = field(default=None)


@dataclass
class KubernetesSecurityContext:
    kind: ClassVar[str] = "kubernetes_security_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_privilege_escalation": S("allowPrivilegeEscalation"),
        "privileged": S("privileged"),
        "proc_mount": S("procMount"),
        "read_only_root_filesystem": S("readOnlyRootFilesystem"),
        "run_as_group": S("runAsGroup"),
        "run_as_non_root": S("runAsNonRoot"),
        "run_as_user": S("runAsUser"),
        "se_linux_options": S("seLinuxOptions"),
        "seccomp_profile": S("seccompProfile"),
        "windows_options": S("windowsOptions"),
    }
    allow_privilege_escalation: Optional[bool] = field(default=None)
    privileged: Optional[bool] = field(default=None)
    proc_mount: Optional[str] = field(default=None)
    read_only_root_filesystem: Optional[bool] = field(default=None)
    run_as_group: Optional[int] = field(default=None)
    run_as_non_root: Optional[bool] = field(default=None)
    run_as_user: Optional[int] = field(default=None)
    se_linux_options: Optional[Any] = field(default=None)
    seccomp_profile: Optional[Any] = field(default=None)
    windows_options: Optional[Any] = field(default=None)


@dataclass
class KubernetesVolumeDevice:
    kind: ClassVar[str] = "kubernetes_volume_device"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_path": S("devicePath"),
        "name": S("name"),
    }
    device_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@dataclass
class KubernetesVolumeMount:
    kind: ClassVar[str] = "kubernetes_volume_mount"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mount_path": S("mountPath"),
        "mount_propagation": S("mountPropagation"),
        "name": S("name"),
        "read_only": S("readOnly"),
        "sub_path": S("subPath"),
        "sub_path_expr": S("subPathExpr"),
    }
    mount_path: Optional[str] = field(default=None)
    mount_propagation: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    read_only: Optional[bool] = field(default=None)
    sub_path: Optional[str] = field(default=None)
    sub_path_expr: Optional[str] = field(default=None)


@dataclass
class KubernetesContainer:
    kind: ClassVar[str] = "kubernetes_container"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "command": S("command", default=[]),
        "image": S("image"),
        "image_pull_policy": S("imagePullPolicy"),
        "name": S("name"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesContainerPort.mapping),
        "resources": S("resources") >> Bend(KubernetesResourceRequirements.mapping),
        "security_context": S("securityContext") >> Bend(KubernetesSecurityContext.mapping),
        "stdin": S("stdin"),
        "stdin_once": S("stdinOnce"),
        "termination_message_path": S("terminationMessagePath"),
        "termination_message_policy": S("terminationMessagePolicy"),
        "tty": S("tty"),
        "volume_devices": S("volumeDevices", default=[]) >> ForallBend(KubernetesVolumeDevice.mapping),
        "volume_mounts": S("volumeMounts", default=[]) >> ForallBend(KubernetesVolumeMount.mapping),
        "working_dir": S("workingDir"),
    }
    args: List[str] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    image: Optional[str] = field(default=None)
    image_pull_policy: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    ports: List[KubernetesContainerPort] = field(default_factory=list)
    resources: Optional[KubernetesResourceRequirements] = field(default=None)
    security_context: Optional[KubernetesSecurityContext] = field(default=None)
    stdin: Optional[bool] = field(default=None)
    stdin_once: Optional[bool] = field(default=None)
    termination_message_path: Optional[str] = field(default=None)
    termination_message_policy: Optional[str] = field(default=None)
    tty: Optional[bool] = field(default=None)
    volume_devices: List[KubernetesVolumeDevice] = field(default_factory=list)
    volume_mounts: List[KubernetesVolumeMount] = field(default_factory=list)
    working_dir: Optional[str] = field(default=None)


@dataclass
class KubernetesPodSecurityContext:
    kind: ClassVar[str] = "kubernetes_pod_security_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fs_group": S("fsGroup"),
        "fs_group_change_policy": S("fsGroupChangePolicy"),
        "run_as_group": S("runAsGroup"),
        "run_as_non_root": S("runAsNonRoot"),
        "run_as_user": S("runAsUser"),
        "se_linux_options": S("seLinuxOptions"),
        "seccomp_profile": S("seccompProfile"),
        "supplemental_groups": S("supplementalGroups", default=[]),
        "windows_options": S("windowsOptions"),
    }
    fs_group: Optional[int] = field(default=None)
    fs_group_change_policy: Optional[str] = field(default=None)
    run_as_group: Optional[int] = field(default=None)
    run_as_non_root: Optional[bool] = field(default=None)
    run_as_user: Optional[int] = field(default=None)
    se_linux_options: Optional[Any] = field(default=None)
    seccomp_profile: Optional[Any] = field(default=None)
    supplemental_groups: List[int] = field(default_factory=list)
    windows_options: Optional[Any] = field(default=None)


@dataclass
class KubernetesToleration:
    kind: ClassVar[str] = "kubernetes_toleration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "effect": S("effect"),
        "key": S("key"),
        "operator": S("operator"),
        "toleration_seconds": S("tolerationSeconds"),
        "value": S("value"),
    }
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    toleration_seconds: Optional[int] = field(default=None)
    value: Optional[str] = field(default=None)


@dataclass
class KubernetesVolume:
    kind: ClassVar[str] = "kubernetes_volume"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_elastic_block_store": S("awsElasticBlockStore"),
        "azure_disk": S("azureDisk"),
        "azure_file": S("azureFile"),
        "cephfs": S("cephfs"),
        "cinder": S("cinder"),
        "config_map": S("configMap"),
        "csi": S("csi"),
        "downward_api": S("downwardAPI"),
        "empty_dir": S("emptyDir"),
        "ephemeral": S("ephemeral"),
        "fc": S("fc"),
        "flex_volume": S("flexVolume"),
        "flocker": S("flocker"),
        "gce_persistent_disk": S("gcePersistentDisk"),
        "git_repo": S("gitRepo"),
        "glusterfs": S("glusterfs"),
        "host_path": S("hostPath"),
        "iscsi": S("iscsi"),
        "name": S("name"),
        "nfs": S("nfs"),
        "persistent_volume_claim": S("persistentVolumeClaim"),
        "photon_persistent_disk": S("photonPersistentDisk"),
        "portworx_volume": S("portworxVolume"),
        "projected": S("projected"),
        "quobyte": S("quobyte"),
        "rbd": S("rbd"),
        "scale_io": S("scaleIO"),
        "secret": S("secret"),
        "storageos": S("storageos"),
        "vsphere_volume": S("vsphereVolume"),
    }
    aws_elastic_block_store: Optional[Any] = field(default=None)
    azure_disk: Optional[Any] = field(default=None)
    azure_file: Optional[Any] = field(default=None)
    cephfs: Optional[Any] = field(default=None)
    cinder: Optional[Any] = field(default=None)
    config_map: Optional[Any] = field(default=None)
    csi: Optional[Any] = field(default=None)
    downward_api: Optional[Any] = field(default=None)
    empty_dir: Optional[Any] = field(default=None)
    ephemeral: Optional[Any] = field(default=None)
    fc: Optional[Any] = field(default=None)
    flex_volume: Optional[Any] = field(default=None)
    flocker: Optional[Any] = field(default=None)
    gce_persistent_disk: Optional[Any] = field(default=None)
    git_repo: Optional[Any] = field(default=None)
    glusterfs: Optional[Any] = field(default=None)
    host_path: Optional[Any] = field(default=None)
    iscsi: Optional[Any] = field(default=None)
    name: Optional[str] = field(default=None)
    nfs: Optional[Any] = field(default=None)
    persistent_volume_claim: Optional[Any] = field(default=None)
    photon_persistent_disk: Optional[Any] = field(default=None)
    portworx_volume: Optional[Any] = field(default=None)
    projected: Optional[Any] = field(default=None)
    quobyte: Optional[Any] = field(default=None)
    rbd: Optional[Any] = field(default=None)
    scale_io: Optional[Any] = field(default=None)
    secret: Optional[Any] = field(default=None)
    storageos: Optional[Any] = field(default=None)
    vsphere_volume: Optional[Any] = field(default=None)


@dataclass
class KubernetesPodSpec:
    kind: ClassVar[str] = "kubernetes_pod_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_deadline_seconds": S("activeDeadlineSeconds"),
        "automount_service_account_token": S("automountServiceAccountToken"),
        "containers": S("containers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "dns_policy": S("dnsPolicy"),
        "enable_service_links": S("enableServiceLinks"),
        "ephemeral_containers": S("ephemeralContainers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "host_ipc": S("hostIPC"),
        "host_network": S("hostNetwork"),
        "host_pid": S("hostPID"),
        "hostname": S("hostname"),
        "init_containers": S("initContainers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "node_name": S("nodeName"),
        "overhead": S("overhead"),
        "preemption_policy": S("preemptionPolicy"),
        "priority": S("priority"),
        "priority_class_name": S("priorityClassName"),
        "restart_policy": S("restartPolicy"),
        "runtime_class_name": S("runtimeClassName"),
        "scheduler_name": S("schedulerName"),
        "security_context": S("securityContext") >> Bend(KubernetesSecurityContext.mapping),
        "service_account": S("serviceAccount"),
        "service_account_name": S("serviceAccountName"),
        "set_hostname_as_fqdn": S("setHostnameAsFQDN"),
        "share_process_namespace": S("shareProcessNamespace"),
        "subdomain": S("subdomain"),
        "termination_grace_period_seconds": S("terminationGracePeriodSeconds"),
        "tolerations": S("tolerations", default=[]) >> ForallBend(KubernetesToleration.mapping),
        "volumes": S("volumes", default=[]) >> ForallBend(KubernetesVolume.mapping),
    }
    active_deadline_seconds: Optional[int] = field(default=None)
    automount_service_account_token: Optional[bool] = field(default=None)
    containers: List[KubernetesContainer] = field(default_factory=list)
    dns_policy: Optional[str] = field(default=None)
    enable_service_links: Optional[bool] = field(default=None)
    ephemeral_containers: List[KubernetesContainer] = field(default_factory=list)
    host_ipc: Optional[bool] = field(default=None)
    host_network: Optional[bool] = field(default=None)
    host_pid: Optional[bool] = field(default=None)
    hostname: Optional[str] = field(default=None)
    init_containers: List[KubernetesContainer] = field(default_factory=list)
    node_name: Optional[str] = field(default=None)
    preemption_policy: Optional[str] = field(default=None)
    priority: Optional[int] = field(default=None)
    priority_class_name: Optional[str] = field(default=None)
    restart_policy: Optional[str] = field(default=None)
    runtime_class_name: Optional[str] = field(default=None)
    scheduler_name: Optional[str] = field(default=None)
    security_context: Optional[KubernetesPodSecurityContext] = field(default=None)
    service_account: Optional[str] = field(default=None)
    service_account_name: Optional[str] = field(default=None)
    set_hostname_as_fqdn: Optional[bool] = field(default=None)
    share_process_namespace: Optional[bool] = field(default=None)
    subdomain: Optional[str] = field(default=None)
    termination_grace_period_seconds: Optional[int] = field(default=None)
    tolerations: List[KubernetesToleration] = field(default_factory=list)
    volumes: List[KubernetesVolume] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesPod(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_status": S("status") >> Bend(KubernetesPodStatus.mapping),
        "pod_spec": S("spec") >> Bend(KubernetesPodSpec.mapping),
    }
    pod_status: Optional[KubernetesPodStatus] = field(default=None)
    pod_spec: Optional[KubernetesPodSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        volumes = bend(S("spec", "volumes", default=[]), source)
        builder.connect_volumes(self, volumes)


# endregion

# region persistent volume claim
@dataclass(eq=False)
class KubernetesPersistentVolumeClaimStatusConditions:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeClaimStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "allocated_resources": S("allocatedResources"),
        "conditions": S("conditions", default=[])
        >> ForallBend(KubernetesPersistentVolumeClaimStatusConditions.mapping),
        "phase": S("phase"),
        "resize_status": S("resizeStatus"),
    }
    access_modes: List[str] = field(default_factory=list)
    allocated_resources: Optional[str] = field(default=None)
    conditions: List[KubernetesPersistentVolumeClaimStatusConditions] = field(default_factory=list)
    phase: Optional[str] = field(default=None)
    resize_status: Optional[str] = field(default=None)


@dataclass
class KubernetesLabelSelectorRequirement:
    kind: ClassVar[str] = "kubernetes_label_selector_requirement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "operator": S("operator"),
        "values": S("values", default=[]),
    }
    key: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    values: List[str] = field(default_factory=list)


@dataclass
class KubernetesLabelSelector:
    kind: ClassVar[str] = "kubernetes_label_selector"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_expressions": S("matchExpressions", default=[])
        >> ForallBend(KubernetesLabelSelectorRequirement.mapping),
        "match_labels": S("matchLabels"),
    }
    match_expressions: List[KubernetesLabelSelectorRequirement] = field(default_factory=list)
    match_labels: Optional[Dict[str, str]] = field(default=None)


@dataclass
class KubernetesPersistentVolumeClaimSpec:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "resources": S("resources") >> Bend(KubernetesResourceRequirements.mapping),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "storage_class_name": S("storageClassName"),
        "volume_mode": S("volumeMode"),
        "volume_name": S("volumeName"),
    }
    access_modes: List[str] = field(default_factory=list)
    resources: Optional[KubernetesResourceRequirements] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    storage_class_name: Optional[str] = field(default=None)
    volume_mode: Optional[str] = field(default=None)
    volume_name: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeClaim(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_claim_status": S("status") >> Bend(KubernetesPersistentVolumeClaimStatus.mapping),
        "persistent_volume_claim_spec": S("spec") >> Bend(KubernetesPersistentVolumeClaimSpec.mapping),
    }
    persistent_volume_claim_status: Optional[KubernetesPersistentVolumeClaimStatus] = field(default=None)
    persistent_volume_claim_spec: Optional[KubernetesPersistentVolumeClaimSpec] = field(default=None)


# endregion
# region service


@dataclass(eq=False)
class KubernetesLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress_ports"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error"),
        "port": S("port"),
        "protocol": S("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": S("hostname"),
        "ip": S("ip"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesLoadbalancerIngressPorts] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesLoadbalancerStatus:
    kind: ClassVar[str] = "kubernetes_loadbalancer_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": S("ingress", default=[]) >> ForallBend(KubernetesLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesLoadbalancerIngress] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesServiceStatusConditions:
    kind: ClassVar[str] = "kubernetes_service_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesServiceStatus:
    kind: ClassVar[str] = "kubernetes_service_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesServiceStatusConditions.mapping),
        "load_balancer": S("loadBalancer") >> Bend(KubernetesLoadbalancerStatus.mapping),
    }
    conditions: List[KubernetesServiceStatusConditions] = field(default_factory=list)
    load_balancer: Optional[KubernetesLoadbalancerStatus] = field(default=None)


@dataclass
class KubernetesServicePort:
    kind: ClassVar[str] = "kubernetes_service_port"
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_protocol": S("appProtocol"),
        "name": S("name"),
        "node_port": S("nodePort"),
        "port": S("port"),
        "protocol": S("protocol"),
        "target_port": S("targetPort"),
    }
    app_protocol: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    node_port: Optional[int] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)
    target_port: Optional[Union[str, int]] = field(default=None)


@dataclass
class KubernetesServiceSpec:
    kind: ClassVar[str] = "kubernetes_service_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocate_load_balancer_node_ports": S("allocateLoadBalancerNodePorts"),
        "cluster_ip": S("clusterIP"),
        "cluster_ips": S("clusterIPs", default=[]),
        "external_ips": S("externalIPs", default=[]),
        "external_name": S("externalName"),
        "external_traffic_policy": S("externalTrafficPolicy"),
        "health_check_node_port": S("healthCheckNodePort"),
        "internal_traffic_policy": S("internalTrafficPolicy"),
        "ip_families": S("ipFamilies", default=[]),
        "ip_family_policy": S("ipFamilyPolicy"),
        "load_balancer_class": S("loadBalancerClass"),
        "load_balancer_ip": S("loadBalancerIP"),
        "load_balancer_source_ranges": S("loadBalancerSourceRanges", default=[]),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesServicePort.mapping),
        "publish_not_ready_addresses": S("publishNotReadyAddresses"),
        "session_affinity": S("sessionAffinity"),
        "type": S("type"),
    }
    allocate_load_balancer_node_ports: Optional[bool] = field(default=None)
    cluster_ip: Optional[str] = field(default=None)
    cluster_ips: List[str] = field(default_factory=list)
    external_ips: List[str] = field(default_factory=list)
    external_name: Optional[str] = field(default=None)
    external_traffic_policy: Optional[str] = field(default=None)
    health_check_node_port: Optional[int] = field(default=None)
    internal_traffic_policy: Optional[str] = field(default=None)
    ip_families: List[str] = field(default_factory=list)
    ip_family_policy: Optional[str] = field(default=None)
    load_balancer_class: Optional[str] = field(default=None)
    load_balancer_ip: Optional[str] = field(default=None)
    load_balancer_source_ranges: List[str] = field(default_factory=list)
    ports: List[KubernetesServicePort] = field(default_factory=list)
    publish_not_ready_addresses: Optional[bool] = field(default=None)
    session_affinity: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesService(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_service"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "service_status": S("status") >> Bend(KubernetesServiceStatus.mapping),
        "service_spec": S("spec") >> Bend(KubernetesServiceSpec.mapping),
    }
    service_status: Optional[KubernetesServiceStatus] = field(default=None)
    service_spec: Optional[KubernetesServiceSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        selector = bend(S("spec", "selector"), source)
        if selector:
            builder.add_edges_from_selector(self, EdgeType.default, selector, KubernetesPod)


# endregion


@dataclass(eq=False)
class KubernetesPodTemplate(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_template"


@dataclass(eq=False)
class KubernetesClusterInfo:
    kind: ClassVar[str] = "kubernetes_cluster_info"
    major: str
    minor: str
    platform: str


@dataclass(eq=False)
class KubernetesCluster(KubernetesResource, BaseAccount):
    kind: ClassVar[str] = "kubernetes_cluster"
    cluster_info: Optional[KubernetesClusterInfo] = None


@dataclass(eq=False)
class KubernetesConfigMap(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_config_map"


@dataclass(eq=False)
class KubernetesEndpointAddress:
    kind: ClassVar[str] = "kubernetes_endpoint_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip": S("ip"),
        "node_name": S("nodeName"),
        "_target_ref": S("targetRef", "uid"),
    }

    ip: Optional[str] = field(default=None)
    node_name: Optional[str] = field(default=None)
    _target_ref: Optional[str] = field(default=None)

    def target_ref(self) -> Optional[str]:
        return self._target_ref


@dataclass(eq=False)
class KubernetesEndpointPort:
    kind: ClassVar[str] = "kubernetes_endpoint_port"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "port": S("port"),
        "protocol": S("protocol"),
    }

    name: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesEndpointSubset:
    kind: ClassVar[str] = "kubernetes_endpoint_subset"
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": S("addresses", default=[]) >> ForallBend(KubernetesEndpointAddress.mapping),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesEndpointPort.mapping),
    }
    addresses: List[KubernetesEndpointAddress] = field(default_factory=list)
    ports: List[KubernetesEndpointPort] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesEndpoints(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "subsets": S("subsets", default=[]) >> ForallBend(KubernetesEndpointSubset.mapping),
    }

    subsets: List[KubernetesEndpointSubset] = field(default_factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for subset in self.subsets:
            for address in subset.addresses:
                if address.target_ref():
                    builder.add_edge(self, EdgeType.default, id=address.target_ref())


@dataclass(eq=False)
class KubernetesEndpointSlice(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint_slice"


@dataclass(eq=False)
class KubernetesLimitRange(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_limit_range"


@dataclass(eq=False)
class KubernetesNamespaceStatusConditions:
    kind: ClassVar[str] = "kubernetes_namespace_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNamespaceStatus:
    kind: ClassVar[str] = "kubernetes_namespace_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesNamespaceStatusConditions.mapping),
        "phase": S("phase"),
    }
    conditions: List[KubernetesNamespaceStatusConditions] = field(default_factory=list)
    phase: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNamespace(KubernetesResource, BaseRegion):
    kind: ClassVar[str] = "kubernetes_namespace"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "namespace_status": S("status") >> Bend(KubernetesNamespaceStatus.mapping),
    }
    namespace_status: Optional[KubernetesNamespaceStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "phase": S("phase"),
        "reason": S("reason"),
    }
    message: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@dataclass
class KubernetesPersistentVolumeSpec:
    kind: ClassVar[str] = "kubernetes_persistent_volume_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "aws_elastic_block_store": S("awsElasticBlockStore"),
        "azure_disk": S("azureDisk"),
        "azure_file": S("azureFile"),
        "capacity": S("capacity"),
        "cephfs": S("cephfs"),
        "cinder": S("cinder"),
        "claim_ref": S("claimRef"),
        "csi": S("csi"),
        "fc": S("fc"),
        "flex_volume": S("flexVolume"),
        "flocker": S("flocker"),
        "gce_persistent_disk": S("gcePersistentDisk"),
        "glusterfs": S("glusterfs"),
        "host_path": S("hostPath"),
        "iscsi": S("iscsi"),
        "local": S("local"),
        "mount_options": S("mountOptions", default=[]),
        "nfs": S("nfs"),
        "node_affinity": S("nodeAffinity"),
        "persistent_volume_reclaim_policy": S("persistentVolumeReclaimPolicy"),
        "photon_persistent_disk": S("photonPersistentDisk"),
        "portworx_volume": S("portworxVolume"),
        "quobyte": S("quobyte"),
        "rbd": S("rbd"),
        "scale_io": S("scaleIO"),
        "storage_class_name": S("storageClassName"),
        "storageos": S("storageos"),
        "volume_mode": S("volumeMode"),
        "vsphere_volume": S("vsphereVolume"),
    }
    access_modes: List[str] = field(default_factory=list)
    aws_elastic_block_store: Optional[str] = field(default=None)
    azure_disk: Optional[str] = field(default=None)
    azure_file: Optional[str] = field(default=None)
    capacity: Optional[str] = field(default=None)
    cephfs: Optional[str] = field(default=None)
    cinder: Optional[str] = field(default=None)
    claim_ref: Optional[str] = field(default=None)
    csi: Optional[str] = field(default=None)
    fc: Optional[str] = field(default=None)
    flex_volume: Optional[str] = field(default=None)
    flocker: Optional[str] = field(default=None)
    gce_persistent_disk: Optional[str] = field(default=None)
    glusterfs: Optional[str] = field(default=None)
    host_path: Optional[str] = field(default=None)
    iscsi: Optional[str] = field(default=None)
    local: Optional[str] = field(default=None)
    mount_options: List[str] = field(default_factory=list)
    nfs: Optional[str] = field(default=None)
    node_affinity: Optional[str] = field(default=None)
    persistent_volume_reclaim_policy: Optional[str] = field(default=None)
    photon_persistent_disk: Optional[str] = field(default=None)
    portworx_volume: Optional[str] = field(default=None)
    quobyte: Optional[str] = field(default=None)
    rbd: Optional[str] = field(default=None)
    scale_io: Optional[str] = field(default=None)
    storage_class_name: Optional[str] = field(default=None)
    storageos: Optional[str] = field(default=None)
    volume_mode: Optional[str] = field(default=None)
    vsphere_volume: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolume(KubernetesResource, BaseVolume):
    kind: ClassVar[str] = "kubernetes_persistent_volume"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_status": S("status") >> Bend(KubernetesPersistentVolumeStatus.mapping),
        "persistent_volume_spec": S("spec") >> Bend(KubernetesPersistentVolumeSpec.mapping),
        "volume_size": S("spec", "capacity", "storage", default="0") >> StringToUnitNumber("GB"),
        "volume_type": S("spec", "storageClassName"),
        "volume_status": S("status", "phase"),
    }
    persistent_volume_status: Optional[KubernetesPersistentVolumeStatus] = field(default=None)
    persistent_volume_spec: Optional[KubernetesPersistentVolumeSpec] = field(default=None)

    def _volume_status_getter(self) -> str:
        return self._volume_status

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = value

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        claim_ref = bend(S("spec", "claimRef", "uid"), source)
        if claim_ref:
            builder.add_edge(self, EdgeType.default, id=claim_ref, reverse=True)


KubernetesPersistentVolume.volume_status = property(  # type: ignore
    KubernetesPersistentVolume._volume_status_getter, KubernetesPersistentVolume._volume_status_setter
)


@dataclass(eq=False)
class KubernetesReplicationControllerStatusConditions:
    kind: ClassVar[str] = "kubernetes_replication_controller_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicationControllerStatus:
    kind: ClassVar[str] = "kubernetes_replication_controller_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "conditions": S("conditions", default=[])
        >> ForallBend(KubernetesReplicationControllerStatusConditions.mapping),
        "fully_labeled_replicas": S("fullyLabeledReplicas"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicationControllerStatusConditions] = field(default_factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicationController(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replication_controller"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replication_controller_status": S("status") >> Bend(KubernetesReplicationControllerStatus.mapping),
    }
    replication_controller_status: Optional[KubernetesReplicationControllerStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesResourceQuotaStatus:
    kind: ClassVar[str] = "kubernetes_resource_quota_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hard": S("hard"),
        "used": S("used"),
    }
    hard: Optional[Any] = field(default=None)
    used: Optional[Any] = field(default=None)


@dataclass
class KubernetesResourceQuotaSpec:
    kind: ClassVar[str] = "kubernetes_resource_quota_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hard": S("hard"),
        "scope_selector": S("scopeSelector"),
        "scopes": S("scopes", default=[]),
    }
    hard: Optional[Any] = field(default=None)
    scope_selector: Optional[Any] = field(default=None)
    scopes: List[str] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesResourceQuota(KubernetesResource, BaseQuota):
    kind: ClassVar[str] = "kubernetes_resource_quota"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "resource_quota_status": S("status") >> Bend(KubernetesResourceQuotaStatus.mapping),
        "resource_quota_spec": S("spec") >> Bend(KubernetesResourceQuotaSpec.mapping),
    }
    resource_quota_status: Optional[KubernetesResourceQuotaStatus] = field(default=None)
    resource_quota_spec: Optional[KubernetesResourceQuotaSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesSecret(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_secret"


@dataclass(eq=False)
class KubernetesServiceAccount(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_service_account"

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for secret in bend(S("secrets", default=[]), source):
            if name := secret.get("name", None):
                builder.add_edge(self, EdgeType.default, clazz=KubernetesSecret, name=name)


@dataclass(eq=False)
class KubernetesMutatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_mutating_webhook_configuration"


@dataclass(eq=False)
class KubernetesValidatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_validating_webhook_configuration"


@dataclass(eq=False)
class KubernetesControllerRevision(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_controller_revision"


@dataclass(eq=False)
class KubernetesDaemonSetStatusConditions:
    kind: ClassVar[str] = "kubernetes_daemon_set_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonSetStatus:
    kind: ClassVar[str] = "kubernetes_daemon_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesDaemonSetStatusConditions.mapping),
        "current_number_scheduled": S("currentNumberScheduled"),
        "desired_number_scheduled": S("desiredNumberScheduled"),
        "number_available": S("numberAvailable"),
        "number_misscheduled": S("numberMisscheduled"),
        "number_ready": S("numberReady"),
        "number_unavailable": S("numberUnavailable"),
        "observed_generation": S("observedGeneration"),
        "updated_number_scheduled": S("updatedNumberScheduled"),
    }
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDaemonSetStatusConditions] = field(default_factory=list)
    current_number_scheduled: Optional[int] = field(default=None)
    desired_number_scheduled: Optional[int] = field(default=None)
    number_available: Optional[int] = field(default=None)
    number_misscheduled: Optional[int] = field(default=None)
    number_ready: Optional[int] = field(default=None)
    number_unavailable: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    updated_number_scheduled: Optional[int] = field(default=None)


@dataclass
class KubernetesPodTemplateSpec:
    kind: ClassVar[str] = "kubernetes_pod_template_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "spec": S("spec") >> Bend(KubernetesPodSpec.mapping),
    }
    spec: Optional[KubernetesPodSpec] = field(default=None)


@dataclass
class KubernetesDaemonSetSpec:
    kind: ClassVar[str] = "kubernetes_daemon_set_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_daemon_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "daemon_set_status": S("status") >> Bend(KubernetesDaemonSetStatus.mapping),
        "daemon_set_spec": S("spec") >> Bend(KubernetesDaemonSetSpec.mapping),
    }
    daemon_set_status: Optional[KubernetesDaemonSetStatus] = field(default=None)
    daemon_set_spec: Optional[KubernetesDaemonSetSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesDeploymentStatusCondition:
    kind: ClassVar[str] = "kubernetes_deployment_status_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "last_update_time": S("lastUpdateTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    last_update_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDeploymentStatus:
    kind: ClassVar[str] = "kubernetes_deployment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesDeploymentStatusCondition.mapping),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
        "unavailable_replicas": S("unavailableReplicas"),
        "updated_replicas": S("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDeploymentStatusCondition] = field(default_factory=list)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    unavailable_replicas: Optional[int] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@dataclass
class KubernetesRollingUpdateDeployment:
    kind: ClassVar[str] = "kubernetes_rolling_update_deployment"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_surge": S("maxSurge"),
        "max_unavailable": S("maxUnavailable"),
    }
    max_surge: Optional[Union[str, int]] = field(default=None)
    max_unavailable: Optional[Union[str, int]] = field(default=None)


@dataclass
class KubernetesDeploymentStrategy:
    kind: ClassVar[str] = "kubernetes_deployment_strategy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rolling_update": S("rollingUpdate") >> Bend(KubernetesRollingUpdateDeployment.mapping),
        "type": S("type"),
    }
    rolling_update: Optional[KubernetesRollingUpdateDeployment] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass
class KubernetesDeploymentSpec:
    kind: ClassVar[str] = "kubernetes_deployment_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "paused": S("paused"),
        "progress_deadline_seconds": S("progressDeadlineSeconds"),
        "replicas": S("replicas"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "strategy": S("strategy") >> Bend(KubernetesDeploymentStrategy.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    paused: Optional[bool] = field(default=None)
    progress_deadline_seconds: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    strategy: Optional[KubernetesDeploymentStrategy] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesDeployment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_deployment"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "deployment_status": S("status") >> Bend(KubernetesDeploymentStatus.mapping),
        "deployment_spec": S("spec") >> Bend(KubernetesDeploymentSpec.mapping),
    }
    deployment_status: Optional[KubernetesDeploymentStatus] = field(default=None)
    deployment_spec: Optional[KubernetesDeploymentSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        selector = bend(S("spec", "selector", "matchLabels"), source)
        if selector:
            builder.add_edges_from_selector(self, EdgeType.default, selector)


@dataclass(eq=False)
class KubernetesReplicaSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_replica_set_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicaSetStatus:
    kind: ClassVar[str] = "kubernetes_replica_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesReplicaSetStatusCondition.mapping),
        "fully_labeled_replicas": S("fullyLabeledReplicas"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicaSetStatusCondition] = field(default_factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@dataclass
class KubernetesReplicaSetSpec:
    kind: ClassVar[str] = "kubernetes_replica_set_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "replicas": S("replicas"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicaSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replica_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replica_set_status": S("status") >> Bend(KubernetesReplicaSetStatus.mapping),
        "replica_set_spec": S("spec") >> Bend(KubernetesReplicaSetSpec.mapping),
    }
    replica_set_status: Optional[KubernetesReplicaSetStatus] = field(default=None)
    replica_set_spec: Optional[KubernetesReplicaSetSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_stateful_set_status_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSetStatus:
    kind: ClassVar[str] = "kubernetes_stateful_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesStatefulSetStatusCondition.mapping),
        "current_replicas": S("currentReplicas"),
        "current_revision": S("currentRevision"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
        "update_revision": S("updateRevision"),
        "updated_replicas": S("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesStatefulSetStatusCondition] = field(default_factory=list)
    current_replicas: Optional[int] = field(default=None)
    current_revision: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    update_revision: Optional[str] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@dataclass
class KubernetesStatefulSetSpec:
    kind: ClassVar[str] = "kubernetes_stateful_set_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "pod_management_policy": S("podManagementPolicy"),
        "replicas": S("replicas"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "service_name": S("serviceName"),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    pod_management_policy: Optional[str] = field(default=None)
    replicas: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    service_name: Optional[str] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_stateful_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "stateful_set_status": S("status") >> Bend(KubernetesStatefulSetStatus.mapping),
        "stateful_set_spec": S("spec") >> Bend(KubernetesStatefulSetSpec.mapping),
    }
    stateful_set_status: Optional[KubernetesStatefulSetStatus] = field(default=None)
    stateful_set_spec: Optional[KubernetesStatefulSetSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesHorizontalPodAutoscalerStatus:
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "current_cpu_utilization_percentage": S("currentCPUUtilizationPercentage"),
        "current_replicas": S("currentReplicas"),
        "desired_replicas": S("desiredReplicas"),
        "last_scale_time": S("lastScaleTime"),
        "observed_generation": S("observedGeneration"),
    }
    current_cpu_utilization_percentage: Optional[int] = field(default=None)
    current_replicas: Optional[int] = field(default=None)
    desired_replicas: Optional[int] = field(default=None)
    last_scale_time: Optional[datetime] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@dataclass
class KubernetesCrossVersionObjectReference:
    kind: ClassVar[str] = "kubernetes_cross_object_reference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_version": S("apiVersion"),
        "resource_kind": S("kind"),
        "name": S("name"),
    }
    api_version: Optional[str] = field(default=None)
    resource_kind: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@dataclass
class KubernetesHorizontalPodAutoscalerSpec:
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_replicas": S("maxReplicas"),
        "min_replicas": S("minReplicas"),
        "scale_target_ref": S("scaleTargetRef") >> Bend(KubernetesCrossVersionObjectReference.mapping),
        "target_cpu_utilization_percentage": S("targetCPUUtilizationPercentage"),
    }
    max_replicas: Optional[int] = field(default=None)
    min_replicas: Optional[int] = field(default=None)
    scale_target_ref: Optional[KubernetesCrossVersionObjectReference] = field(default=None)
    target_cpu_utilization_percentage: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesHorizontalPodAutoscaler(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "horizontal_pod_autoscaler_status": S("status") >> Bend(KubernetesHorizontalPodAutoscalerStatus.mapping),
        "horizontal_pod_autoscaler_spec": S("spec") >> Bend(KubernetesHorizontalPodAutoscalerSpec.mapping),
    }
    horizontal_pod_autoscaler_status: Optional[KubernetesHorizontalPodAutoscalerStatus] = field(default=None)
    horizontal_pod_autoscaler_spec: Optional[KubernetesHorizontalPodAutoscalerSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJobStatusActive:
    kind: ClassVar[str] = "kubernetes_cron_job_status_active"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_version": S("apiVersion"),
        "field_path": S("fieldPath"),
        "name": S("name"),
        "namespace": S("namespace"),
        "resource_version": S("resourceVersion"),
        "uid": S("uid"),
    }
    api_version: Optional[str] = field(default=None)
    field_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJobStatus:
    kind: ClassVar[str] = "kubernetes_cron_job_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active", default=[]) >> ForallBend(KubernetesCronJobStatusActive.mapping),
        "last_schedule_time": S("lastScheduleTime"),
        "last_successful_time": S("lastSuccessfulTime"),
    }
    active: List[KubernetesCronJobStatusActive] = field(default_factory=list)
    last_schedule_time: Optional[datetime] = field(default=None)
    last_successful_time: Optional[datetime] = field(default=None)


@dataclass
class KubernetesJobSpec:
    kind: ClassVar[str] = "kubernetes_job_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_deadline_seconds": S("activeDeadlineSeconds"),
        "backoff_limit": S("backoffLimit"),
        "completion_mode": S("completionMode"),
        "completions": S("completions"),
        "manual_selector": S("manualSelector"),
        "parallelism": S("parallelism"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "suspend": S("suspend"),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
        "ttl_seconds_after_finished": S("ttlSecondsAfterFinished"),
    }
    active_deadline_seconds: Optional[int] = field(default=None)
    backoff_limit: Optional[int] = field(default=None)
    completion_mode: Optional[str] = field(default=None)
    completions: Optional[int] = field(default=None)
    manual_selector: Optional[bool] = field(default=None)
    parallelism: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    suspend: Optional[bool] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)
    ttl_seconds_after_finished: Optional[int] = field(default=None)


@dataclass
class KubernetesJobTemplateSpec:
    kind: ClassVar[str] = "kubernetes_job_template_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "spec": S("spec") >> Bend(KubernetesJobSpec.mapping),
    }
    spec: Optional[KubernetesJobSpec] = field(default=None)


@dataclass
class KubernetesCronJobSpec:
    kind: ClassVar[str] = "kubernetes_cron_job_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "concurrency_policy": S("concurrencyPolicy"),
        "failed_jobs_history_limit": S("failedJobsHistoryLimit"),
        "job_template": S("jobTemplate") >> Bend(KubernetesJobTemplateSpec.mapping),
        "schedule": S("schedule"),
        "starting_deadline_seconds": S("startingDeadlineSeconds"),
        "successful_jobs_history_limit": S("successfulJobsHistoryLimit"),
        "suspend": S("suspend"),
        "time_zone": S("timeZone"),
    }
    concurrency_policy: Optional[str] = field(default=None)
    failed_jobs_history_limit: Optional[int] = field(default=None)
    job_template: Optional[KubernetesJobTemplateSpec] = field(default=None)
    schedule: Optional[str] = field(default=None)
    starting_deadline_seconds: Optional[int] = field(default=None)
    successful_jobs_history_limit: Optional[int] = field(default=None)
    suspend: Optional[bool] = field(default=None)
    time_zone: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cron_job"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "cron_job_status": S("status") >> Bend(KubernetesCronJobStatus.mapping),
        "cron_job_spec": S("spec") >> Bend(KubernetesCronJobSpec.mapping),
    }
    cron_job_status: Optional[KubernetesCronJobStatus] = field(default=None)
    cron_job_spec: Optional[KubernetesCronJobSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesJobStatusConditions:
    kind: ClassVar[str] = "kubernetes_job_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesJobStatus:
    kind: ClassVar[str] = "kubernetes_job_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active"),
        "completed_indexes": S("completedIndexes"),
        "completion_time": S("completionTime"),
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesJobStatusConditions.mapping),
        "failed": S("failed"),
        "ready": S("ready"),
        "start_time": S("startTime"),
        "succeeded": S("succeeded"),
    }
    active: Optional[int] = field(default=None)
    completed_indexes: Optional[str] = field(default=None)
    completion_time: Optional[datetime] = field(default=None)
    conditions: List[KubernetesJobStatusConditions] = field(default_factory=list)
    failed: Optional[int] = field(default=None)
    ready: Optional[int] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    succeeded: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_job"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "job_status": S("status") >> Bend(KubernetesJobStatus.mapping),
        "job_spec": S("spec") >> Bend(KubernetesJobSpec.mapping),
    }
    job_status: Optional[KubernetesJobStatus] = field(default=None)
    job_spec: Optional[KubernetesJobSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesFlowSchemaStatusConditions:
    kind: ClassVar[str] = "kubernetes_flow_schema_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesFlowSchemaStatus:
    kind: ClassVar[str] = "kubernetes_flow_schema_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesFlowSchemaStatusConditions.mapping),
    }
    conditions: List[KubernetesFlowSchemaStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesFlowSchema(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_flow_schema"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "flow_schema_status": S("status") >> Bend(KubernetesFlowSchemaStatus.mapping),
    }
    flow_schema_status: Optional[KubernetesFlowSchemaStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesPriorityLevelConfigurationStatusConditions:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPriorityLevelConfigurationStatus:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> ForallBend(KubernetesPriorityLevelConfigurationStatusConditions.mapping),
    }
    conditions: List[KubernetesPriorityLevelConfigurationStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesPriorityLevelConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_level_configuration"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "priority_level_configuration_status": S("status") >> Bend(KubernetesPriorityLevelConfigurationStatus.mapping),
    }
    priority_level_configuration_status: Optional[KubernetesPriorityLevelConfigurationStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress_ports"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error"),
        "port": S("port"),
        "protocol": S("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": S("hostname"),
        "ip": S("ip"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesIngressStatusLoadbalancerIngressPorts] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancer:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": S("ingress", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesIngressStatusLoadbalancerIngress] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesIngressStatus:
    kind: ClassVar[str] = "kubernetes_ingress_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer": S("loadBalancer") >> Bend(KubernetesIngressStatusLoadbalancer.mapping),
    }
    load_balancer: Optional[KubernetesIngressStatusLoadbalancer] = field(default=None)


@dataclass
class KubernetesIngressRule:
    kind: ClassVar[str] = "kubernetes_ingress_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "host": S("host"),
        "http": S("http"),
    }
    host: Optional[str] = field(default=None)
    http: Optional[Any] = field(default=None)


@dataclass
class KubernetesIngressTLS:
    kind: ClassVar[str] = "kubernetes_ingress_tls"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hosts": S("hosts", default=[]),
        "secret_name": S("secretName"),
    }
    hosts: List[str] = field(default_factory=list)
    secret_name: Optional[str] = field(default=None)


@dataclass
class KubernetesIngressSpec:
    kind: ClassVar[str] = "kubernetes_ingress_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress_class_name": S("ingressClassName"),
        "rules": S("rules", default=[]) >> ForallBend(KubernetesIngressRule.mapping),
        "tls": S("tls", default=[]) >> ForallBend(KubernetesIngressTLS.mapping),
    }
    ingress_class_name: Optional[str] = field(default=None)
    rules: List[KubernetesIngressRule] = field(default_factory=list)
    tls: List[KubernetesIngressTLS] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesIngress(KubernetesResource, BaseLoadBalancer):
    kind: ClassVar[str] = "kubernetes_ingress"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "ingress_status": S("status") >> Bend(KubernetesIngressStatus.mapping),
        "public_ip_address": S("status", "loadBalancer", "ingress", default=[])[0]["ip"],
        # take the public ip of the first load balancer
        "ingress_spec": S("spec") >> Bend(KubernetesIngressSpec.mapping),
    }
    ingress_status: Optional[KubernetesIngressStatus] = field(default=None)
    ingress_spec: Optional[KubernetesIngressSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_ingress_class"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@dataclass(eq=False)
class KubernetesNetworkPolicyStatusConditions:
    kind: ClassVar[str] = "kubernetes_network_policy_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNetworkPolicyStatus:
    kind: ClassVar[str] = "kubernetes_network_policy_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesNetworkPolicyStatusConditions.mapping),
    }
    conditions: List[KubernetesNetworkPolicyStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesNetworkPolicy(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_network_policy"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "network_policy_status": S("status") >> Bend(KubernetesNetworkPolicyStatus.mapping),
    }
    network_policy_status: Optional[KubernetesNetworkPolicyStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesRuntimeClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_runtime_class"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@dataclass(eq=False)
class KubernetesPodDisruptionBudgetStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPodDisruptionBudgetStatus:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[]) >> ForallBend(KubernetesPodDisruptionBudgetStatusConditions.mapping),
        "current_healthy": S("currentHealthy"),
        "desired_healthy": S("desiredHealthy"),
        "disrupted_pods": S("disruptedPods"),
        "disruptions_allowed": S("disruptionsAllowed"),
        "expected_pods": S("expectedPods"),
        "observed_generation": S("observedGeneration"),
    }
    conditions: List[KubernetesPodDisruptionBudgetStatusConditions] = field(default_factory=list)
    current_healthy: Optional[int] = field(default=None)
    desired_healthy: Optional[int] = field(default=None)
    disrupted_pods: Optional[Any] = field(default=None)
    disruptions_allowed: Optional[int] = field(default=None)
    expected_pods: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@dataclass
class KubernetesPodDisruptionBudgetSpec:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_unavailable": S("maxUnavailable"),
        "min_available": S("minAvailable"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
    }
    max_unavailable: Optional[Union[str, int]] = field(default=None)
    min_available: Optional[Union[str, int]] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)


@dataclass(eq=False)
class KubernetesPodDisruptionBudget(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_disruption_budget_status": S("status") >> Bend(KubernetesPodDisruptionBudgetStatus.mapping),
        "pod_disruption_budget_spec": S("spec") >> Bend(KubernetesPodDisruptionBudgetSpec.mapping),
    }
    pod_disruption_budget_status: Optional[KubernetesPodDisruptionBudgetStatus] = field(default=None)
    pod_disruption_budget_spec: Optional[KubernetesPodDisruptionBudgetSpec] = field(default=None)


@dataclass(eq=False)
class KubernetesClusterRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role"


@dataclass(eq=False)
class KubernetesClusterRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role_binding"


@dataclass(eq=False)
class KubernetesRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role"


@dataclass(eq=False)
class KubernetesRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role_binding"


@dataclass(eq=False)
class KubernetesPriorityClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_class"


@dataclass(eq=False)
class KubernetesCSIDriver(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_driver"


@dataclass(eq=False)
class KubernetesCSINode(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_node"


@dataclass(eq=False)
class KubernetesCSIStorageCapacity(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_storage_capacity"


@dataclass(eq=False)
class KubernetesStorageClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_storage_class"


@dataclass(eq=False)
class KubernetesVolumeError:
    kind: ClassVar[str] = "kubernetes_volume_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "time": S("time"),
    }
    message: Optional[str] = field(default=None)
    time: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesVolumeAttachmentStatus:
    kind: ClassVar[str] = "kubernetes_volume_attachment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_error": S("attachError") >> Bend(KubernetesVolumeError.mapping),
        "attached": S("attached"),
        "attachment_metadata": S("attachmentMetadata"),
        "detach_error": S("detachError") >> Bend(KubernetesVolumeError.mapping),
    }
    attach_error: Optional[KubernetesVolumeError] = field(default=None)
    attached: Optional[bool] = field(default=None)
    attachment_metadata: Optional[Any] = field(default=None)
    detach_error: Optional[KubernetesVolumeError] = field(default=None)


@dataclass
class KubernetesVolumeAttachmentSpec:
    kind: ClassVar[str] = "kubernetes_volume_attachment_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attacher": S("attacher"),
        "node_name": S("nodeName"),
        "source": S("source"),
    }
    attacher: Optional[str] = field(default=None)
    node_name: Optional[str] = field(default=None)
    source: Optional[Any] = field(default=None)


@dataclass(eq=False)
class KubernetesVolumeAttachment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_volume_attachment"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "volume_attachment_status": S("status") >> Bend(KubernetesVolumeAttachmentStatus.mapping),
        "volume_attachment_spec": S("spec") >> Bend(KubernetesVolumeAttachmentSpec.mapping),
    }
    volume_attachment_status: Optional[KubernetesVolumeAttachmentStatus] = field(default=None)
    volume_attachment_spec: Optional[KubernetesVolumeAttachmentSpec] = field(default=None)


workload_resources: List[Type[KubernetesResource]] = [
    KubernetesControllerRevision,
    KubernetesCronJob,
    KubernetesDaemonSet,
    KubernetesDeployment,
    KubernetesHorizontalPodAutoscaler,
    KubernetesJob,
    KubernetesPod,
    KubernetesPodTemplate,
    KubernetesPriorityClass,
    KubernetesReplicaSet,
    KubernetesReplicationController,
    KubernetesStatefulSet,
]
service_resources: List[Type[KubernetesResource]] = [
    KubernetesEndpointSlice,
    KubernetesEndpoints,
    KubernetesIngress,
    KubernetesIngressClass,
    KubernetesService,
]
config_storage_resources: List[Type[KubernetesResource]] = [
    KubernetesCSIDriver,
    KubernetesCSINode,
    KubernetesCSIStorageCapacity,
    KubernetesConfigMap,
    KubernetesPersistentVolume,
    KubernetesPersistentVolumeClaim,
    KubernetesSecret,
    KubernetesStorageClass,
    # KubernetesVolume,
    KubernetesVolumeAttachment,
]
authentication_resources: List[Type[KubernetesResource]] = [
    # KubernetesCertificateSigningRequest,
    # KubernetesTokenRequest,
    # KubernetesTokenReview,
    KubernetesServiceAccount,
]
authorization_resources: List[Type[KubernetesResource]] = [
    # KubernetesLocalSubjectAccessReview,
    # KubernetesSelfSubjectAccessReview,
    # KubernetesSelfSubjectRulesReview,
    # KubernetesSubjectAccessReview,
    KubernetesClusterRole,
    KubernetesClusterRoleBinding,
    KubernetesRole,
    KubernetesRoleBinding,
]
policy_resources: List[Type[KubernetesResource]] = [
    # KubernetesPodSecurityPolicy
    KubernetesLimitRange,
    KubernetesNetworkPolicy,
    KubernetesPodDisruptionBudget,
    KubernetesResourceQuota,
]
extend_resources: List[Type[KubernetesResource]] = [
    # KubernetesCustomResourceDefinition,
    KubernetesMutatingWebhookConfiguration,
    KubernetesValidatingWebhookConfiguration,
]
cluster_resources: List[Type[KubernetesResource]] = [
    # KubernetesApiService,
    # KubernetesBinding
    # KubernetesLease,
    # KubernetesComponentStatus,
    # KubernetesEvent, # ignore events
    KubernetesFlowSchema,
    KubernetesNamespace,
    KubernetesNode,
    KubernetesPriorityLevelConfiguration,
    KubernetesRuntimeClass,
]

all_k8s_resources: List[Type[KubernetesResource]] = (
    workload_resources
    + service_resources
    + config_storage_resources
    + authentication_resources
    + authorization_resources
    + policy_resources
    + extend_resources
    + cluster_resources
)

all_k8s_resources_by_k8s_name: Dict[str, Type[KubernetesResource]] = {a.k8s_name(): a for a in all_k8s_resources}
all_k8s_resources_by_resoto_name: Dict[str, Type[KubernetesResource]] = {a.kind: a for a in all_k8s_resources}


# Work around jsons: it tries to deserialize class vars - it should ignore them.
def no_json(js: Json, tp: type = object, **kwargs: object) -> None:
    return None


# noinspection PyTypeChecker
set_deserializer(no_json, ClassVar)
