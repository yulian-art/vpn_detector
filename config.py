"""VPN Detector 共享配置入口。

本文件不再手写规则常量，而是从仓库根目录的 rules_config.json 加载。
这样 Python 与 Go 两套实现都引用同一份规则/常量事实源。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _default_config_path() -> Path:
    """定位仓库内置共享配置，保持普通源码运行时不需要额外参数。"""

    return Path(__file__).resolve().parent / "rules_config.json"


def load_shared_rule_config(path: str | os.PathLike[str] | None = None) -> Dict[str, Any]:
    """读取共享规则配置。

    优先级：
    1. 函数显式传入路径；
    2. 环境变量 VPN_DETECTOR_RULE_CONFIG；
    3. 仓库根目录 rules_config.json。
    """

    raw_path = path or os.environ.get("VPN_DETECTOR_RULE_CONFIG") or _default_config_path()
    config_path = Path(raw_path)
    with config_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


_SHARED_CONFIG = load_shared_rule_config()
_CONSTANTS: Dict[str, Any] = _SHARED_CONFIG.get("constants", {})

# 下面继续导出旧变量名，让已有模块保持兼容。
CONFIG_VERSION: str = str(_SHARED_CONFIG.get("version", "unknown"))
RULE_DEFINITIONS: List[Dict[str, Any]] = list(_SHARED_CONFIG.get("rules", []))

BLOCK_SIZES: List[int] = [int(x) for x in _CONSTANTS.get("block_sizes", [])]
BLOCK_FAMILY: Dict[int, str] = {
    int(k): str(v)
    for k, v in dict(_CONSTANTS.get("block_family", {})).items()
}

STANDARD_TLS_PORTS = {int(x) for x in _CONSTANTS.get("standard_tls_ports", [])}
SPECIAL_PORTS = {int(x) for x in _CONSTANTS.get("special_ports", [])}

DOMAIN_KEYWORDS: List[str] = [str(x) for x in _CONSTANTS.get("domain_keywords", [])]
RISK_TLDS: List[str] = [str(x) for x in _CONSTANTS.get("risk_tlds", [])]

JA4_BROWSER_PATTERNS: List[str] = [str(x) for x in _CONSTANTS.get("ja4_browser_patterns", [])]
JA4_NON_BROWSER_PATTERNS: List[str] = [
    str(x) for x in _CONSTANTS.get("ja4_non_browser_patterns", [])
]
JA4_GOLANG_PATTERN: str = str(_CONSTANTS.get("ja4_golang_pattern", ""))
CHROME_JA4_PREFIX: str = str(_CONSTANTS.get("chrome_ja4_prefix", ""))

ISO_COUNTRY_CODES = {str(x) for x in _CONSTANTS.get("iso_country_codes", [])}
FAMOUS_ENTERPRISE_SNI: List[str] = [
    str(x) for x in _CONSTANTS.get("famous_enterprise_sni", [])
]

# VPN_FAMILY_RULES 保留旧的二元组格式，便于外部旧代码继续导入。
VPN_FAMILY_RULES: List[Tuple[List[str], str]] = [
    ([str(sig) for sig in item.get("signals", [])], str(item.get("family", "")))
    for item in _CONSTANTS.get("vpn_family_rules", [])
]
