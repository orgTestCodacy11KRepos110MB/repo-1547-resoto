from typing import ClassVar, Dict, Optional, List

from attr import define, field

from resoto_plugin_gcp.gcp_client import GcpApiSpec
from resoto_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus
from resotolib.json_bender import Bender, S, Bend, ForallBend, MapDict


@define(eq=False, slots=False)
class GcpContainerCloudRunConfig:
    kind: ClassVar[str] = "gcp_container_cloud_run_config"
    mapping: ClassVar[Dict[str, Bender]] = {"disabled": S("disabled"), "load_balancer_type": S("loadBalancerType")}
    disabled: Optional[bool] = field(default=None)
    load_balancer_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAddonsConfig:
    kind: ClassVar[str] = "gcp_container_addons_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_run_config": S("cloudRunConfig", default={}) >> Bend(GcpContainerCloudRunConfig.mapping),
        "config_connector_config": S("configConnectorConfig", "enabled"),
        "dns_cache_config": S("dnsCacheConfig", "enabled"),
        "gce_persistent_disk_csi_driver_config": S("gcePersistentDiskCsiDriverConfig", "enabled"),
        "gcp_filestore_csi_driver_config": S("gcpFilestoreCsiDriverConfig", "enabled"),
        "gke_backup_agent_config": S("gkeBackupAgentConfig", "enabled"),
        "horizontal_pod_autoscaling": S("horizontalPodAutoscaling", "disabled"),
        "http_load_balancing": S("httpLoadBalancing", "disabled"),
        "kubernetes_dashboard": S("kubernetesDashboard", "disabled"),
        "network_policy_config": S("networkPolicyConfig", "disabled"),
    }
    cloud_run_config: Optional[GcpContainerCloudRunConfig] = field(default=None)
    config_connector_config: Optional[bool] = field(default=None)
    dns_cache_config: Optional[bool] = field(default=None)
    gce_persistent_disk_csi_driver_config: Optional[bool] = field(default=None)
    gcp_filestore_csi_driver_config: Optional[bool] = field(default=None)
    gke_backup_agent_config: Optional[bool] = field(default=None)
    horizontal_pod_autoscaling: Optional[bool] = field(default=None)
    http_load_balancing: Optional[bool] = field(default=None)
    kubernetes_dashboard: Optional[bool] = field(default=None)
    network_policy_config: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAuthenticatorGroupsConfig:
    kind: ClassVar[str] = "gcp_container_authenticator_groups_config"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "security_group": S("securityGroup")}
    enabled: Optional[bool] = field(default=None)
    security_group: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAutoUpgradeOptions:
    kind: ClassVar[str] = "gcp_container_auto_upgrade_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_upgrade_start_time": S("autoUpgradeStartTime"),
        "description": S("description"),
    }
    auto_upgrade_start_time: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeManagement:
    kind: ClassVar[str] = "gcp_container_node_management"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_repair": S("autoRepair"),
        "auto_upgrade": S("autoUpgrade"),
        "upgrade_options": S("upgradeOptions", default={}) >> Bend(GcpContainerAutoUpgradeOptions.mapping),
    }
    auto_repair: Optional[bool] = field(default=None)
    auto_upgrade: Optional[bool] = field(default=None)
    upgrade_options: Optional[GcpContainerAutoUpgradeOptions] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerShieldedInstanceConfig:
    kind: ClassVar[str] = "gcp_container_shielded_instance_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_integrity_monitoring": S("enableIntegrityMonitoring"),
        "enable_secure_boot": S("enableSecureBoot"),
    }
    enable_integrity_monitoring: Optional[bool] = field(default=None)
    enable_secure_boot: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerStandardRolloutPolicy:
    kind: ClassVar[str] = "gcp_container_standard_rollout_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "batch_node_count": S("batchNodeCount"),
        "batch_percentage": S("batchPercentage"),
        "batch_soak_duration": S("batchSoakDuration"),
    }
    batch_node_count: Optional[int] = field(default=None)
    batch_percentage: Optional[float] = field(default=None)
    batch_soak_duration: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBlueGreenSettings:
    kind: ClassVar[str] = "gcp_container_blue_green_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_pool_soak_duration": S("nodePoolSoakDuration"),
        "standard_rollout_policy": S("standardRolloutPolicy", default={})
        >> Bend(GcpContainerStandardRolloutPolicy.mapping),
    }
    node_pool_soak_duration: Optional[str] = field(default=None)
    standard_rollout_policy: Optional[GcpContainerStandardRolloutPolicy] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerUpgradeSettings:
    kind: ClassVar[str] = "gcp_container_upgrade_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_settings": S("blueGreenSettings", default={}) >> Bend(GcpContainerBlueGreenSettings.mapping),
        "max_surge": S("maxSurge"),
        "max_unavailable": S("maxUnavailable"),
        "strategy": S("strategy"),
    }
    blue_green_settings: Optional[GcpContainerBlueGreenSettings] = field(default=None)
    max_surge: Optional[int] = field(default=None)
    max_unavailable: Optional[int] = field(default=None)
    strategy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAutoprovisioningNodePoolDefaults:
    kind: ClassVar[str] = "gcp_container_autoprovisioning_node_pool_defaults"
    mapping: ClassVar[Dict[str, Bender]] = {
        "boot_disk_kms_key": S("bootDiskKmsKey"),
        "disk_size_gb": S("diskSizeGb"),
        "disk_type": S("diskType"),
        "image_type": S("imageType"),
        "management": S("management", default={}) >> Bend(GcpContainerNodeManagement.mapping),
        "min_cpu_platform": S("minCpuPlatform"),
        "oauth_scopes": S("oauthScopes", default=[]),
        "service_account": S("serviceAccount"),
        "shielded_instance_config": S("shieldedInstanceConfig", default={})
        >> Bend(GcpContainerShieldedInstanceConfig.mapping),
        "upgrade_settings": S("upgradeSettings", default={}) >> Bend(GcpContainerUpgradeSettings.mapping),
    }
    boot_disk_kms_key: Optional[str] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    image_type: Optional[str] = field(default=None)
    management: Optional[GcpContainerNodeManagement] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    oauth_scopes: Optional[List[str]] = field(default=None)
    service_account: Optional[str] = field(default=None)
    shielded_instance_config: Optional[GcpContainerShieldedInstanceConfig] = field(default=None)
    upgrade_settings: Optional[GcpContainerUpgradeSettings] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerResourceLimit:
    kind: ClassVar[str] = "gcp_container_resource_limit"
    mapping: ClassVar[Dict[str, Bender]] = {
        "maximum": S("maximum"),
        "minimum": S("minimum"),
        "resource_type": S("resourceType"),
    }
    maximum: Optional[str] = field(default=None)
    minimum: Optional[str] = field(default=None)
    resource_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerClusterAutoscaling:
    kind: ClassVar[str] = "gcp_container_cluster_autoscaling"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoprovisioning_locations": S("autoprovisioningLocations", default=[]),
        "autoprovisioning_node_pool_defaults": S("autoprovisioningNodePoolDefaults", default={})
        >> Bend(GcpContainerAutoprovisioningNodePoolDefaults.mapping),
        "autoscaling_profile": S("autoscalingProfile"),
        "enable_node_autoprovisioning": S("enableNodeAutoprovisioning"),
        "resource_limits": S("resourceLimits", default=[]) >> ForallBend(GcpContainerResourceLimit.mapping),
    }
    autoprovisioning_locations: Optional[List[str]] = field(default=None)
    autoprovisioning_node_pool_defaults: Optional[GcpContainerAutoprovisioningNodePoolDefaults] = field(default=None)
    autoscaling_profile: Optional[str] = field(default=None)
    enable_node_autoprovisioning: Optional[bool] = field(default=None)
    resource_limits: Optional[List[GcpContainerResourceLimit]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBinaryAuthorization:
    kind: ClassVar[str] = "gcp_container_binary_authorization"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "evaluation_mode": S("evaluationMode")}
    enabled: Optional[bool] = field(default=None)
    evaluation_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerStatusCondition:
    kind: ClassVar[str] = "gcp_container_status_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "canonical_code": S("canonicalCode"),
        "code": S("code"),
        "message": S("message"),
    }
    canonical_code: Optional[str] = field(default=None)
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDatabaseEncryption:
    kind: ClassVar[str] = "gcp_container_database_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {"key_name": S("keyName"), "state": S("state")}
    key_name: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerIPAllocationPolicy:
    kind: ClassVar[str] = "gcp_container_ip_allocation_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_ipv4_cidr": S("clusterIpv4Cidr"),
        "cluster_ipv4_cidr_block": S("clusterIpv4CidrBlock"),
        "cluster_secondary_range_name": S("clusterSecondaryRangeName"),
        "create_subnetwork": S("createSubnetwork"),
        "ipv6_access_type": S("ipv6AccessType"),
        "node_ipv4_cidr": S("nodeIpv4Cidr"),
        "node_ipv4_cidr_block": S("nodeIpv4CidrBlock"),
        "services_ipv4_cidr": S("servicesIpv4Cidr"),
        "services_ipv4_cidr_block": S("servicesIpv4CidrBlock"),
        "services_secondary_range_name": S("servicesSecondaryRangeName"),
        "stack_type": S("stackType"),
        "subnetwork_name": S("subnetworkName"),
        "tpu_ipv4_cidr_block": S("tpuIpv4CidrBlock"),
        "use_ip_aliases": S("useIpAliases"),
        "use_routes": S("useRoutes"),
    }
    cluster_ipv4_cidr: Optional[str] = field(default=None)
    cluster_ipv4_cidr_block: Optional[str] = field(default=None)
    cluster_secondary_range_name: Optional[str] = field(default=None)
    create_subnetwork: Optional[bool] = field(default=None)
    ipv6_access_type: Optional[str] = field(default=None)
    node_ipv4_cidr: Optional[str] = field(default=None)
    node_ipv4_cidr_block: Optional[str] = field(default=None)
    services_ipv4_cidr: Optional[str] = field(default=None)
    services_ipv4_cidr_block: Optional[str] = field(default=None)
    services_secondary_range_name: Optional[str] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    subnetwork_name: Optional[str] = field(default=None)
    tpu_ipv4_cidr_block: Optional[str] = field(default=None)
    use_ip_aliases: Optional[bool] = field(default=None)
    use_routes: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLoggingComponentConfig:
    kind: ClassVar[str] = "gcp_container_logging_component_config"
    mapping: ClassVar[Dict[str, Bender]] = {"enable_components": S("enableComponents", default=[])}
    enable_components: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLoggingConfig:
    kind: ClassVar[str] = "gcp_container_logging_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "component_config": S("componentConfig", default={}) >> Bend(GcpContainerLoggingComponentConfig.mapping)
    }
    component_config: Optional[GcpContainerLoggingComponentConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDailyMaintenanceWindow:
    kind: ClassVar[str] = "gcp_container_daily_maintenance_window"
    mapping: ClassVar[Dict[str, Bender]] = {"duration": S("duration"), "start_time": S("startTime")}
    duration: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerTimeWindow:
    kind: ClassVar[str] = "gcp_container_time_window"
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_time": S("endTime"),
        "maintenance_exclusion_options": S("maintenanceExclusionOptions", "scope"),
        "start_time": S("startTime"),
    }
    end_time: Optional[str] = field(default=None)
    maintenance_exclusion_options: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerRecurringTimeWindow:
    kind: ClassVar[str] = "gcp_container_recurring_time_window"
    mapping: ClassVar[Dict[str, Bender]] = {
        "recurrence": S("recurrence"),
        "window": S("window", default={}) >> Bend(GcpContainerTimeWindow.mapping),
    }
    recurrence: Optional[str] = field(default=None)
    window: Optional[GcpContainerTimeWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMaintenanceWindow:
    kind: ClassVar[str] = "gcp_container_maintenance_window"
    mapping: ClassVar[Dict[str, Bender]] = {
        "daily_maintenance_window": S("dailyMaintenanceWindow", default={})
        >> Bend(GcpContainerDailyMaintenanceWindow.mapping),
        "maintenance_exclusions": S("maintenanceExclusions", default={})
        >> MapDict(value_bender=Bend(GcpContainerTimeWindow.mapping)),
        "recurring_window": S("recurringWindow", default={}) >> Bend(GcpContainerRecurringTimeWindow.mapping),
    }
    daily_maintenance_window: Optional[GcpContainerDailyMaintenanceWindow] = field(default=None)
    maintenance_exclusions: Optional[Dict[str, GcpContainerTimeWindow]] = field(default=None)
    recurring_window: Optional[GcpContainerRecurringTimeWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMaintenancePolicy:
    kind: ClassVar[str] = "gcp_container_maintenance_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "resource_version": S("resourceVersion"),
        "window": S("window", default={}) >> Bend(GcpContainerMaintenanceWindow.mapping),
    }
    resource_version: Optional[str] = field(default=None)
    window: Optional[GcpContainerMaintenanceWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMasterAuth:
    kind: ClassVar[str] = "gcp_container_master_auth"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_certificate": S("clientCertificate"),
        "client_certificate_config": S("clientCertificateConfig", "issueClientCertificate"),
        "client_key": S("clientKey"),
        "cluster_ca_certificate": S("clusterCaCertificate"),
        "password": S("password"),
        "username": S("username"),
    }
    client_certificate: Optional[str] = field(default=None)
    client_certificate_config: Optional[bool] = field(default=None)
    client_key: Optional[str] = field(default=None)
    cluster_ca_certificate: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    username: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerCidrBlock:
    kind: ClassVar[str] = "gcp_container_cidr_block"
    mapping: ClassVar[Dict[str, Bender]] = {"cidr_block": S("cidrBlock"), "display_name": S("displayName")}
    cidr_block: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMasterAuthorizedNetworksConfig:
    kind: ClassVar[str] = "gcp_container_master_authorized_networks_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cidr_blocks": S("cidrBlocks", default=[]) >> ForallBend(GcpContainerCidrBlock.mapping),
        "enabled": S("enabled"),
    }
    cidr_blocks: Optional[List[GcpContainerCidrBlock]] = field(default=None)
    enabled: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMonitoringComponentConfig:
    kind: ClassVar[str] = "gcp_container_monitoring_component_config"
    mapping: ClassVar[Dict[str, Bender]] = {"enable_components": S("enableComponents", default=[])}
    enable_components: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMonitoringConfig:
    kind: ClassVar[str] = "gcp_container_monitoring_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "component_config": S("componentConfig", default={}) >> Bend(GcpContainerMonitoringComponentConfig.mapping),
        "managed_prometheus_config": S("managedPrometheusConfig", "enabled"),
    }
    component_config: Optional[GcpContainerMonitoringComponentConfig] = field(default=None)
    managed_prometheus_config: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDNSConfig:
    kind: ClassVar[str] = "gcp_container_dns_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_dns": S("clusterDns"),
        "cluster_dns_domain": S("clusterDnsDomain"),
        "cluster_dns_scope": S("clusterDnsScope"),
    }
    cluster_dns: Optional[str] = field(default=None)
    cluster_dns_domain: Optional[str] = field(default=None)
    cluster_dns_scope: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkConfig:
    kind: ClassVar[str] = "gcp_container_network_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "datapath_provider": S("datapathProvider"),
        "default_snat_status": S("defaultSnatStatus", "disabled"),
        "dns_config": S("dnsConfig", default={}) >> Bend(GcpContainerDNSConfig.mapping),
        "enable_intra_node_visibility": S("enableIntraNodeVisibility"),
        "enable_l4ilb_subsetting": S("enableL4ilbSubsetting"),
        "network": S("network"),
        "private_ipv6_google_access": S("privateIpv6GoogleAccess"),
        "service_external_ips_config": S("serviceExternalIpsConfig", "enabled"),
        "subnetwork": S("subnetwork"),
    }
    datapath_provider: Optional[str] = field(default=None)
    default_snat_status: Optional[bool] = field(default=None)
    dns_config: Optional[GcpContainerDNSConfig] = field(default=None)
    enable_intra_node_visibility: Optional[bool] = field(default=None)
    enable_l4ilb_subsetting: Optional[bool] = field(default=None)
    network: Optional[str] = field(default=None)
    private_ipv6_google_access: Optional[str] = field(default=None)
    service_external_ips_config: Optional[bool] = field(default=None)
    subnetwork: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkPolicy:
    kind: ClassVar[str] = "gcp_container_network_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "provider": S("provider")}
    enabled: Optional[bool] = field(default=None)
    provider: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerGPUSharingConfig:
    kind: ClassVar[str] = "gcp_container_gpu_sharing_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "gpu_sharing_strategy": S("gpuSharingStrategy"),
        "max_shared_clients_per_gpu": S("maxSharedClientsPerGpu"),
    }
    gpu_sharing_strategy: Optional[str] = field(default=None)
    max_shared_clients_per_gpu: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAcceleratorConfig:
    kind: ClassVar[str] = "gcp_container_accelerator_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerator_count": S("acceleratorCount"),
        "accelerator_type": S("acceleratorType"),
        "gpu_partition_size": S("gpuPartitionSize"),
        "gpu_sharing_config": S("gpuSharingConfig", default={}) >> Bend(GcpContainerGPUSharingConfig.mapping),
    }
    accelerator_count: Optional[str] = field(default=None)
    accelerator_type: Optional[str] = field(default=None)
    gpu_partition_size: Optional[str] = field(default=None)
    gpu_sharing_config: Optional[GcpContainerGPUSharingConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeKubeletConfig:
    kind: ClassVar[str] = "gcp_container_node_kubelet_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpu_cfs_quota": S("cpuCfsQuota"),
        "cpu_cfs_quota_period": S("cpuCfsQuotaPeriod"),
        "cpu_manager_policy": S("cpuManagerPolicy"),
        "pod_pids_limit": S("podPidsLimit"),
    }
    cpu_cfs_quota: Optional[bool] = field(default=None)
    cpu_cfs_quota_period: Optional[str] = field(default=None)
    cpu_manager_policy: Optional[str] = field(default=None)
    pod_pids_limit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLinuxNodeConfig:
    kind: ClassVar[str] = "gcp_container_linux_node_config"
    mapping: ClassVar[Dict[str, Bender]] = {"sysctls": S("sysctls")}
    sysctls: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolLoggingConfig:
    kind: ClassVar[str] = "gcp_container_node_pool_logging_config"
    mapping: ClassVar[Dict[str, Bender]] = {"variant_config": S("variantConfig", "variant")}
    variant_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerReservationAffinity:
    kind: ClassVar[str] = "gcp_container_reservation_affinity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "consume_reservation_type": S("consumeReservationType"),
        "key": S("key"),
        "values": S("values", default=[]),
    }
    consume_reservation_type: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeTaint:
    kind: ClassVar[str] = "gcp_container_node_taint"
    mapping: ClassVar[Dict[str, Bender]] = {"effect": S("effect"), "key": S("key"), "value": S("value")}
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeConfig:
    kind: ClassVar[str] = "gcp_container_node_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerators": S("accelerators", default=[]) >> ForallBend(GcpContainerAcceleratorConfig.mapping),
        "advanced_machine_features": S("advancedMachineFeatures", "threadsPerCore"),
        "boot_disk_kms_key": S("bootDiskKmsKey"),
        "confidential_nodes": S("confidentialNodes", "enabled"),
        "disk_size_gb": S("diskSizeGb"),
        "disk_type": S("diskType"),
        "gcfs_config": S("gcfsConfig", "enabled"),
        "gvnic": S("gvnic", "enabled"),
        "image_type": S("imageType"),
        "kubelet_config": S("kubeletConfig", default={}) >> Bend(GcpContainerNodeKubeletConfig.mapping),
        "labels": S("labels"),
        "linux_node_config": S("linuxNodeConfig", default={}) >> Bend(GcpContainerLinuxNodeConfig.mapping),
        "local_ssd_count": S("localSsdCount"),
        "logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerNodePoolLoggingConfig.mapping),
        "machine_type": S("machineType"),
        "metadata": S("metadata"),
        "min_cpu_platform": S("minCpuPlatform"),
        "node_group": S("nodeGroup"),
        "oauth_scopes": S("oauthScopes", default=[]),
        "preemptible": S("preemptible"),
        "reservation_affinity": S("reservationAffinity", default={}) >> Bend(GcpContainerReservationAffinity.mapping),
        "sandbox_config": S("sandboxConfig", "type"),
        "service_account": S("serviceAccount"),
        "shielded_instance_config": S("shieldedInstanceConfig", default={})
        >> Bend(GcpContainerShieldedInstanceConfig.mapping),
        "spot": S("spot"),
        "tags": S("tags", default=[]),
        "taints": S("taints", default=[]) >> ForallBend(GcpContainerNodeTaint.mapping),
        "workload_metadata_config": S("workloadMetadataConfig", "mode"),
    }
    accelerators: Optional[List[GcpContainerAcceleratorConfig]] = field(default=None)
    advanced_machine_features: Optional[str] = field(default=None)
    boot_disk_kms_key: Optional[str] = field(default=None)
    confidential_nodes: Optional[bool] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    gcfs_config: Optional[bool] = field(default=None)
    gvnic: Optional[bool] = field(default=None)
    image_type: Optional[str] = field(default=None)
    kubelet_config: Optional[GcpContainerNodeKubeletConfig] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    linux_node_config: Optional[GcpContainerLinuxNodeConfig] = field(default=None)
    local_ssd_count: Optional[int] = field(default=None)
    logging_config: Optional[GcpContainerNodePoolLoggingConfig] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    metadata: Optional[Dict[str, str]] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    node_group: Optional[str] = field(default=None)
    oauth_scopes: Optional[List[str]] = field(default=None)
    preemptible: Optional[bool] = field(default=None)
    reservation_affinity: Optional[GcpContainerReservationAffinity] = field(default=None)
    sandbox_config: Optional[str] = field(default=None)
    service_account: Optional[str] = field(default=None)
    shielded_instance_config: Optional[GcpContainerShieldedInstanceConfig] = field(default=None)
    spot: Optional[bool] = field(default=None)
    tags: Optional[List[str]] = field(default=None)
    taints: Optional[List[GcpContainerNodeTaint]] = field(default=None)
    workload_metadata_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkTags:
    kind: ClassVar[str] = "gcp_container_network_tags"
    mapping: ClassVar[Dict[str, Bender]] = {"tags": S("tags", default=[])}
    tags: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolAutoConfig:
    kind: ClassVar[str] = "gcp_container_node_pool_auto_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_tags": S("networkTags", default={}) >> Bend(GcpContainerNetworkTags.mapping)
    }
    network_tags: Optional[GcpContainerNetworkTags] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeConfigDefaults:
    kind: ClassVar[str] = "gcp_container_node_config_defaults"
    mapping: ClassVar[Dict[str, Bender]] = {
        "gcfs_config": S("gcfsConfig", "enabled"),
        "logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerNodePoolLoggingConfig.mapping),
    }
    gcfs_config: Optional[bool] = field(default=None)
    logging_config: Optional[GcpContainerNodePoolLoggingConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolDefaults:
    kind: ClassVar[str] = "gcp_container_node_pool_defaults"
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_config_defaults": S("nodeConfigDefaults", default={}) >> Bend(GcpContainerNodeConfigDefaults.mapping)
    }
    node_config_defaults: Optional[GcpContainerNodeConfigDefaults] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolAutoscaling:
    kind: ClassVar[str] = "gcp_container_node_pool_autoscaling"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoprovisioned": S("autoprovisioned"),
        "enabled": S("enabled"),
        "location_policy": S("locationPolicy"),
        "max_node_count": S("maxNodeCount"),
        "min_node_count": S("minNodeCount"),
        "total_max_node_count": S("totalMaxNodeCount"),
        "total_min_node_count": S("totalMinNodeCount"),
    }
    autoprovisioned: Optional[bool] = field(default=None)
    enabled: Optional[bool] = field(default=None)
    location_policy: Optional[str] = field(default=None)
    max_node_count: Optional[int] = field(default=None)
    min_node_count: Optional[int] = field(default=None)
    total_max_node_count: Optional[int] = field(default=None)
    total_min_node_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeNetworkConfig:
    kind: ClassVar[str] = "gcp_container_node_network_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_pod_range": S("createPodRange"),
        "network_performance_config": S("networkPerformanceConfig", "totalEgressBandwidthTier"),
        "pod_ipv4_cidr_block": S("podIpv4CidrBlock"),
        "pod_range": S("podRange"),
    }
    create_pod_range: Optional[bool] = field(default=None)
    network_performance_config: Optional[str] = field(default=None)
    pod_ipv4_cidr_block: Optional[str] = field(default=None)
    pod_range: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBlueGreenInfo:
    kind: ClassVar[str] = "gcp_container_blue_green_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_instance_group_urls": S("blueInstanceGroupUrls", default=[]),
        "blue_pool_deletion_start_time": S("bluePoolDeletionStartTime"),
        "green_instance_group_urls": S("greenInstanceGroupUrls", default=[]),
        "green_pool_version": S("greenPoolVersion"),
        "phase": S("phase"),
    }
    blue_instance_group_urls: Optional[List[str]] = field(default=None)
    blue_pool_deletion_start_time: Optional[str] = field(default=None)
    green_instance_group_urls: Optional[List[str]] = field(default=None)
    green_pool_version: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerUpdateInfo:
    kind: ClassVar[str] = "gcp_container_update_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_info": S("blueGreenInfo", default={}) >> Bend(GcpContainerBlueGreenInfo.mapping)
    }
    blue_green_info: Optional[GcpContainerBlueGreenInfo] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePool:
    kind: ClassVar[str] = "gcp_container_node_pool"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscaling": S("autoscaling", default={}) >> Bend(GcpContainerNodePoolAutoscaling.mapping),
        "conditions": S("conditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "config": S("config", default={}) >> Bend(GcpContainerNodeConfig.mapping),
        "initial_node_count": S("initialNodeCount"),
        "instance_group_urls": S("instanceGroupUrls", default=[]),
        "locations": S("locations", default=[]),
        "management": S("management", default={}) >> Bend(GcpContainerNodeManagement.mapping),
        "max_pods_constraint": S("maxPodsConstraint", "maxPodsPerNode"),
        "name": S("name"),
        "network_config": S("networkConfig", default={}) >> Bend(GcpContainerNodeNetworkConfig.mapping),
        "pod_ipv4_cidr_size": S("podIpv4CidrSize"),
        "self_link": S("selfLink"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "update_info": S("updateInfo", default={}) >> Bend(GcpContainerUpdateInfo.mapping),
        "upgrade_settings": S("upgradeSettings", default={}) >> Bend(GcpContainerUpgradeSettings.mapping),
        "version": S("version"),
    }
    autoscaling: Optional[GcpContainerNodePoolAutoscaling] = field(default=None)
    conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    config: Optional[GcpContainerNodeConfig] = field(default=None)
    initial_node_count: Optional[int] = field(default=None)
    instance_group_urls: Optional[List[str]] = field(default=None)
    locations: Optional[List[str]] = field(default=None)
    management: Optional[GcpContainerNodeManagement] = field(default=None)
    max_pods_constraint: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    network_config: Optional[GcpContainerNodeNetworkConfig] = field(default=None)
    pod_ipv4_cidr_size: Optional[int] = field(default=None)
    self_link: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    update_info: Optional[GcpContainerUpdateInfo] = field(default=None)
    upgrade_settings: Optional[GcpContainerUpgradeSettings] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerFilter:
    kind: ClassVar[str] = "gcp_container_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"event_type": S("eventType", default=[])}
    event_type: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerPubSub:
    kind: ClassVar[str] = "gcp_container_pub_sub"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "filter": S("filter", default={}) >> Bend(GcpContainerFilter.mapping),
        "topic": S("topic"),
    }
    enabled: Optional[bool] = field(default=None)
    filter: Optional[GcpContainerFilter] = field(default=None)
    topic: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNotificationConfig:
    kind: ClassVar[str] = "gcp_container_notification_config"
    mapping: ClassVar[Dict[str, Bender]] = {"pubsub": S("pubsub", default={}) >> Bend(GcpContainerPubSub.mapping)}
    pubsub: Optional[GcpContainerPubSub] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerPrivateClusterConfig:
    kind: ClassVar[str] = "gcp_container_private_cluster_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_private_endpoint": S("enablePrivateEndpoint"),
        "enable_private_nodes": S("enablePrivateNodes"),
        "master_global_access_config": S("masterGlobalAccessConfig", "enabled"),
        "master_ipv4_cidr_block": S("masterIpv4CidrBlock"),
        "peering_name": S("peeringName"),
        "private_endpoint": S("privateEndpoint"),
        "public_endpoint": S("publicEndpoint"),
    }
    enable_private_endpoint: Optional[bool] = field(default=None)
    enable_private_nodes: Optional[bool] = field(default=None)
    master_global_access_config: Optional[bool] = field(default=None)
    master_ipv4_cidr_block: Optional[str] = field(default=None)
    peering_name: Optional[str] = field(default=None)
    private_endpoint: Optional[str] = field(default=None)
    public_endpoint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerResourceUsageExportConfig:
    kind: ClassVar[str] = "gcp_container_resource_usage_export_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_destination": S("bigqueryDestination", "datasetId"),
        "consumption_metering_config": S("consumptionMeteringConfig", "enabled"),
        "enable_network_egress_metering": S("enableNetworkEgressMetering"),
    }
    bigquery_destination: Optional[str] = field(default=None)
    consumption_metering_config: Optional[bool] = field(default=None)
    enable_network_egress_metering: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerCluster(GcpResource):
    kind: ClassVar[str] = "gcp_container_cluster"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="container",
        version="v1",
        accessors=["projects", "locations", "clusters"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="clusters",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "cluster_addons_config": S("addonsConfig", default={}) >> Bend(GcpContainerAddonsConfig.mapping),
        "cluster_authenticator_groups_config": S("authenticatorGroupsConfig", default={})
        >> Bend(GcpContainerAuthenticatorGroupsConfig.mapping),
        "cluster_autopilot": S("autopilot", "enabled"),
        "cluster_autoscaling": S("autoscaling", default={}) >> Bend(GcpContainerClusterAutoscaling.mapping),
        "cluster_binary_authorization": S("binaryAuthorization", default={})
        >> Bend(GcpContainerBinaryAuthorization.mapping),
        "cluster_cluster_ipv4_cidr": S("clusterIpv4Cidr"),
        "cluster_conditions": S("conditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "cluster_confidential_nodes": S("confidentialNodes", "enabled"),
        "cluster_cost_management_config": S("costManagementConfig", "enabled"),
        "cluster_create_time": S("createTime"),
        "cluster_current_master_version": S("currentMasterVersion"),
        "cluster_current_node_count": S("currentNodeCount"),
        "cluster_current_node_version": S("currentNodeVersion"),
        "cluster_database_encryption": S("databaseEncryption", default={})
        >> Bend(GcpContainerDatabaseEncryption.mapping),
        "cluster_default_max_pods_constraint": S("defaultMaxPodsConstraint", "maxPodsPerNode"),
        "cluster_enable_kubernetes_alpha": S("enableKubernetesAlpha"),
        "cluster_enable_tpu": S("enableTpu"),
        "cluster_endpoint": S("endpoint"),
        "cluster_expire_time": S("expireTime"),
        "cluster_identity_service_config": S("identityServiceConfig", "enabled"),
        "cluster_initial_cluster_version": S("initialClusterVersion"),
        "cluster_initial_node_count": S("initialNodeCount"),
        "cluster_instance_group_urls": S("instanceGroupUrls", default=[]),
        "cluster_ip_allocation_policy": S("ipAllocationPolicy", default={})
        >> Bend(GcpContainerIPAllocationPolicy.mapping),
        "cluster_legacy_abac": S("legacyAbac", "enabled"),
        "cluster_location": S("location"),
        "cluster_locations": S("locations", default=[]),
        "cluster_logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerLoggingConfig.mapping),
        "cluster_logging_service": S("loggingService"),
        "cluster_maintenance_policy": S("maintenancePolicy", default={}) >> Bend(GcpContainerMaintenancePolicy.mapping),
        "cluster_master_auth": S("masterAuth", default={}) >> Bend(GcpContainerMasterAuth.mapping),
        "cluster_master_authorized_networks_config": S("masterAuthorizedNetworksConfig", default={})
        >> Bend(GcpContainerMasterAuthorizedNetworksConfig.mapping),
        "cluster_mesh_certificates": S("meshCertificates", "enableCertificates"),
        "cluster_monitoring_config": S("monitoringConfig", default={}) >> Bend(GcpContainerMonitoringConfig.mapping),
        "cluster_monitoring_service": S("monitoringService"),
        "cluster_network": S("network"),
        "cluster_network_config": S("networkConfig", default={}) >> Bend(GcpContainerNetworkConfig.mapping),
        "cluster_network_policy": S("networkPolicy", default={}) >> Bend(GcpContainerNetworkPolicy.mapping),
        "cluster_node_config": S("nodeConfig", default={}) >> Bend(GcpContainerNodeConfig.mapping),
        "cluster_node_ipv4_cidr_size": S("nodeIpv4CidrSize"),
        "cluster_node_pool_auto_config": S("nodePoolAutoConfig", default={})
        >> Bend(GcpContainerNodePoolAutoConfig.mapping),
        "cluster_node_pool_defaults": S("nodePoolDefaults", default={}) >> Bend(GcpContainerNodePoolDefaults.mapping),
        "cluster_node_pools": S("nodePools", default=[]) >> ForallBend(GcpContainerNodePool.mapping),
        "cluster_notification_config": S("notificationConfig", default={})
        >> Bend(GcpContainerNotificationConfig.mapping),
        "cluster_private_cluster_config": S("privateClusterConfig", default={})
        >> Bend(GcpContainerPrivateClusterConfig.mapping),
        "cluster_release_channel": S("releaseChannel", "channel"),
        "cluster_resource_labels": S("resourceLabels"),
        "cluster_resource_usage_export_config": S("resourceUsageExportConfig", default={})
        >> Bend(GcpContainerResourceUsageExportConfig.mapping),
        "cluster_services_ipv4_cidr": S("servicesIpv4Cidr"),
        "cluster_shielded_nodes": S("shieldedNodes", "enabled"),
        "cluster_status": S("status"),
        "cluster_status_message": S("statusMessage"),
        "cluster_subnetwork": S("subnetwork"),
        "cluster_tpu_ipv4_cidr_block": S("tpuIpv4CidrBlock"),
        "cluster_vertical_pod_autoscaling": S("verticalPodAutoscaling", "enabled"),
        "cluster_workload_identity_config": S("workloadIdentityConfig", "workloadPool"),
    }
    cluster_addons_config: Optional[GcpContainerAddonsConfig] = field(default=None)
    cluster_authenticator_groups_config: Optional[GcpContainerAuthenticatorGroupsConfig] = field(default=None)
    cluster_autopilot: Optional[bool] = field(default=None)
    cluster_autoscaling: Optional[GcpContainerClusterAutoscaling] = field(default=None)
    cluster_binary_authorization: Optional[GcpContainerBinaryAuthorization] = field(default=None)
    cluster_cluster_ipv4_cidr: Optional[str] = field(default=None)
    cluster_conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    cluster_confidential_nodes: Optional[bool] = field(default=None)
    cluster_cost_management_config: Optional[bool] = field(default=None)
    cluster_create_time: Optional[str] = field(default=None)
    cluster_current_master_version: Optional[str] = field(default=None)
    cluster_current_node_count: Optional[int] = field(default=None)
    cluster_current_node_version: Optional[str] = field(default=None)
    cluster_database_encryption: Optional[GcpContainerDatabaseEncryption] = field(default=None)
    cluster_default_max_pods_constraint: Optional[str] = field(default=None)
    cluster_enable_kubernetes_alpha: Optional[bool] = field(default=None)
    cluster_enable_tpu: Optional[bool] = field(default=None)
    cluster_endpoint: Optional[str] = field(default=None)
    cluster_expire_time: Optional[str] = field(default=None)
    cluster_identity_service_config: Optional[bool] = field(default=None)
    cluster_initial_cluster_version: Optional[str] = field(default=None)
    cluster_initial_node_count: Optional[int] = field(default=None)
    cluster_instance_group_urls: Optional[List[str]] = field(default=None)
    cluster_ip_allocation_policy: Optional[GcpContainerIPAllocationPolicy] = field(default=None)
    cluster_legacy_abac: Optional[bool] = field(default=None)
    cluster_location: Optional[str] = field(default=None)
    cluster_locations: Optional[List[str]] = field(default=None)
    cluster_logging_config: Optional[GcpContainerLoggingConfig] = field(default=None)
    cluster_logging_service: Optional[str] = field(default=None)
    cluster_maintenance_policy: Optional[GcpContainerMaintenancePolicy] = field(default=None)
    cluster_master_auth: Optional[GcpContainerMasterAuth] = field(default=None)
    cluster_master_authorized_networks_config: Optional[GcpContainerMasterAuthorizedNetworksConfig] = field(
        default=None
    )
    cluster_mesh_certificates: Optional[bool] = field(default=None)
    cluster_monitoring_config: Optional[GcpContainerMonitoringConfig] = field(default=None)
    cluster_monitoring_service: Optional[str] = field(default=None)
    cluster_network: Optional[str] = field(default=None)
    cluster_network_config: Optional[GcpContainerNetworkConfig] = field(default=None)
    cluster_network_policy: Optional[GcpContainerNetworkPolicy] = field(default=None)
    cluster_node_config: Optional[GcpContainerNodeConfig] = field(default=None)
    cluster_node_ipv4_cidr_size: Optional[int] = field(default=None)
    cluster_node_pool_auto_config: Optional[GcpContainerNodePoolAutoConfig] = field(default=None)
    cluster_node_pool_defaults: Optional[GcpContainerNodePoolDefaults] = field(default=None)
    cluster_node_pools: Optional[List[GcpContainerNodePool]] = field(default=None)
    cluster_notification_config: Optional[GcpContainerNotificationConfig] = field(default=None)
    cluster_private_cluster_config: Optional[GcpContainerPrivateClusterConfig] = field(default=None)
    cluster_release_channel: Optional[str] = field(default=None)
    cluster_resource_labels: Optional[Dict[str, str]] = field(default=None)
    cluster_resource_usage_export_config: Optional[GcpContainerResourceUsageExportConfig] = field(default=None)
    cluster_services_ipv4_cidr: Optional[str] = field(default=None)
    cluster_shielded_nodes: Optional[bool] = field(default=None)
    cluster_status: Optional[str] = field(default=None)
    cluster_status_message: Optional[str] = field(default=None)
    cluster_subnetwork: Optional[str] = field(default=None)
    cluster_tpu_ipv4_cidr_block: Optional[str] = field(default=None)
    cluster_vertical_pod_autoscaling: Optional[bool] = field(default=None)
    cluster_workload_identity_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDetails:
    kind: ClassVar[str] = "gcp_container_details"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpContainerStatus:
    kind: ClassVar[str] = "gcp_container_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "details": S("details", default=[]) >> ForallBend(GcpContainerDetails.mapping),
        "message": S("message"),
    }
    code: Optional[int] = field(default=None)
    details: Optional[List[GcpContainerDetails]] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMetric:
    kind: ClassVar[str] = "gcp_container_metric"
    mapping: ClassVar[Dict[str, Bender]] = {
        "double_value": S("doubleValue"),
        "int_value": S("intValue"),
        "name": S("name"),
        "string_value": S("stringValue"),
    }
    double_value: Optional[float] = field(default=None)
    int_value: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    string_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerOperationProgress:
    kind: ClassVar[str] = "gcp_container_operation_progress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metrics": S("metrics", default=[]) >> ForallBend(GcpContainerMetric.mapping),
        "name": S("name"),
        "status": S("status"),
    }
    metrics: Optional[List[GcpContainerMetric]] = field(default=None)
    name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerOperation(GcpResource):
    kind: ClassVar[str] = "gcp_container_operation"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="container",
        version="v1",
        accessors=["projects", "locations", "operations"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="operations",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "operation_cluster_conditions": S("clusterConditions", default=[])
        >> ForallBend(GcpContainerStatusCondition.mapping),
        "operation_detail": S("detail"),
        "operation_end_time": S("endTime"),
        "operation_error": S("error", default={}) >> Bend(GcpContainerStatus.mapping),
        "operation_location": S("location"),
        "operation_nodepool_conditions": S("nodepoolConditions", default=[])
        >> ForallBend(GcpContainerStatusCondition.mapping),
        "operation_operation_type": S("operationType"),
        "operation_progress": S("progress", default={}) >> Bend(GcpContainerOperationProgress.mapping),
        "operation_start_time": S("startTime"),
        "operation_status": S("status"),
        "operation_status_message": S("statusMessage"),
        "operation_target_link": S("targetLink"),
    }
    operation_cluster_conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    operation_detail: Optional[str] = field(default=None)
    operation_end_time: Optional[str] = field(default=None)
    operation_error: Optional[GcpContainerStatus] = field(default=None)
    operation_location: Optional[str] = field(default=None)
    operation_nodepool_conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    operation_operation_type: Optional[str] = field(default=None)
    operation_progress: Optional[GcpContainerOperationProgress] = field(default=None)
    operation_start_time: Optional[str] = field(default=None)
    operation_status: Optional[str] = field(default=None)
    operation_status_message: Optional[str] = field(default=None)
    operation_target_link: Optional[str] = field(default=None)


resources = [GcpContainerCluster, GcpContainerOperation]
