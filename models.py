"""VPN Detector 数据模型 — TypedDict 定义。"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, TypedDict


class FlowRecord(TypedDict, total=False):
    flow_id: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    proto: str
    start_ts: Optional[float]
    end_ts: Optional[float]
    duration: float
    packet_count: int
    byte_count: int
    out_bytes: int
    in_bytes: int
    ul_dl_ratio: Optional[float]
    dominant_payload_size: int
    dominant_payload_ratio: float
    mtu_fill_ratio: float
    iat_under_1ms_ratio: float
    rst_ratio: float
    syn_count: int
    has_tls_handshake: bool
    tls_clienthello_count: int
    alpn_present: bool
    top_sni: List[Tuple[str, int]]
    top_dns: List[Tuple[str, int]]
    top_protocols: List[Tuple[str, int]]
    top_ja3: List[Tuple[str, int]]
    top_ja4: List[Tuple[str, int]]


class FileFeature(TypedDict, total=False):
    source_archive: str
    pcap_member: str
    file_name: str
    file_size_bytes: Optional[int]
    total_packets: int
    tcp_packets: int
    udp_packets: int
    ip_proto_counts: Dict[str, int]
    protocol_counts: Dict[str, int]
    port_counts_top: List[Tuple[str, int]]
    sni_top: List[Tuple[str, int]]
    dns_top: List[Tuple[str, int]]
    ja3_top: List[Tuple[str, int]]
    ja4_top: List[Tuple[str, int]]
    tls_clienthello_count: int
    tls_alpn_present_count: int
    tls_alpn_missing_count: int
    alpn_missing_ratio: float
    nonstandard_tls_flow_count: int
    no_tls_large_flow_count: int
    udp500_count: int
    udp4500_count: int
    udp53_count: int
    udp53_large_count: int
    malformed_count: int
    total_payload_bytes: int
    top_endpoint: str
    top_endpoint_ratio: float
    single_flow_dominance: float
    flow_count: int
    long_flow_count: int
    dominant_payload_size: int
    dominant_payload_ratio: float
    mtu_fill_ratio: float
    max_flow_mtu_fill_ratio: float
    max_flow_iat_under_1ms_ratio: float
    max_flow_duration: float
    risk_tld_count: int
    max_domain_entropy: float
    extract_error: str
    # V2 新增字段
    single_cipher_suite: Optional[str]
    cipher_suite_unique_count: int
    quic_frame_count: int
    random_local_domain_count: int
    wpad_query_count: int
    ssh_syn_count: int
    ssh_syn_periodic: bool
    esp_in_udp_like: bool
    # 固定块比例
    block_1300_ratio: float
    block_1370_ratio: float
    block_1400_ratio: float
    block_1448_ratio: float
    block_1452_ratio: float
    block_1310_ratio: float
    block_1344_ratio: float
    block_1428_ratio: float
    block_1378_ratio: float


class RuleMatch(TypedDict):
    rule_id: str
    category: str
    confidence: int
    evidence: str


class ComboDetail(TypedDict):
    tls_spoof: int
    raw_encrypted: int
    endpoint_behavior: int
    dns_sni_anomaly: int
    ja4_fingerprint: int
    port_protocol: int


class DetectionResult(TypedDict):
    source_archive: str
    pcap_member: str
    file_name: str
    verdict: str
    vpn_family: str
    confidence: int
    risk_score: float
    matched_rules: List[str]
    combo_score: Optional[int]
    combo_detail: ComboDetail
    evidence: List[str]
    top_endpoint: str
    top_endpoint_ratio: float
    top_sni: List[Tuple[str, int]]
    top_dns: List[Tuple[str, int]]
    dominant_payload_size: int
    dominant_payload_ratio: float
    best_block: int
    best_block_ratio: float
    notes: str


class ExtractRecord(TypedDict):
    file_feature: FileFeature
    top_flows: List[FlowRecord]
