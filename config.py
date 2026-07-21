"""
VPN Detector 全局常量 — 单一来源。
从 19 个 VPN 分析报告中提取，不与 YAML 重复定义。
"""

# ── TCP 载荷固定块大小 ──
BLOCK_SIZES = [1300, 1370, 1400, 1448, 1452, 1310, 1344, 1428, 1378]

# 固定块 → VPN 对应关系
BLOCK_FAMILY: dict[int, str] = {
    1300: "ShadowsocksR/SSR",
    1370: "VLess/VMess",
    1400: "极光VPN/天行VPN",
    1448: "闪电VPN",
    1452: "HolaVPN",
    1310: "番茄VPN/GOST",
    1344: "NordVPN",
    1428: "老王VPN",
    1378: "CyberGhost/IPsec",
}

# ── 端口 ──
STANDARD_TLS_PORTS = {443, 8443, 9443}

SPECIAL_PORTS = {
    5608,   # 闪电VPN 数据端口
    65311,  # 闪电VPN 注册端口
    22225, 22226,  # HolaVPN P2P
    11581, 11582, 11681,  # 天行VPN
    11000,  # 快帆
    3128,   # SecurePaidVPN
    8388,   # Shadowsocks
    22231,  # VLess
    51820,  # WireGuard
    1194, 1195,  # OpenVPN
}

# ── 域名关键词（从分析报告 1.1 节 + 1.3 节提取） ──
DOMAIN_KEYWORDS = [
    # 闪电VPN
    "nodesni", "kunlun04dns", "sdv2-",
    # 番茄VPN/GOST
    "gosttwo", "shdowsocks",
    # 老王VPN (7个域名模式)
    "ahahub", "ahapivot", "hubebay", "hubups", "hubdhl", "jsq456",
    "helloaha", "xinguawl", "footprintdns",
    # WizVpn
    "wizvpn.net",
    # 天行VPN
    "skylinevpn", "skylinenode",
    # 快帆
    "kuaifan.co", "wifiin.cn",
    # SecurePaidVPN
    "securepaidvpn",
    # HolaVPN (CDN 域名模式)
    "su89-cdn", "c6gj-static", "x-cdn-static", "zspeed-cdn",
    "zagent",
    # Clash
    "clashverge",
    # CyberGhost
    "cyberghostvpn",
    # SSR/VLess/VMess 共享域名
    "shdufysuf",
    # Clash/UltraSurf 廉价 TLD 域名模式
    "mujica.one", "closedai.cfd", "closedai.date",
    "biliworld.top", "love-live.top",
    # VLess
    "mizulina.top",
    # UltraSurf 随机域名模式
    "kbz0pwvxmv", "yg5sjx5kzy",
    "webdrone.club", "zebpay.site",
    "carolinafreigh.fun", "jewelscollecti.icu",
    "vogelsenmeer.xyz", "southwestcoast.pro", "jgwynphotoarts.pro",
]

# ── 高风险 TLD ──
RISK_TLDS = [
    ".icu", ".fun", ".xyz", ".club", ".site",
    ".top", ".cfd", ".date", ".one", ".pro",
]

# ── JA4 浏览器指纹模式 ──
JA4_BROWSER_PATTERNS = [
    # Chrome 126+ 系列: t13d151[0-9]h[0-9]
    r"^t13d151[0-9]h[0-9]_.*",
    # Firefox 系列: t13d131[0-9]h[0-9]
    r"^t13d131[0-9]h[0-9]_.*",
    # Safari 系列
    r"^t13d141[0-9]h[0-9]_.*",
    # Edge (based on Chromium)
    r"^t13d151[0-9]h[0-9]_.*",
]

# ── 非浏览器 JA4 特征 (cipher suite 数量异常) ──
# 闪电VPN: t13d1910h2 (19 密码套件, 超出所有浏览器)
# 番茄/GOST: t13d171000 (17 密码套件, Go 原生)
# 快帆: t10d060600 (TLS 1.0, 6 密码套件)
JA4_NON_BROWSER_PATTERNS = [
    r"^t13d19",    # 19 密码套件 (闪电VPN)
    r"^t13d17",    # 17 密码套件 (番茄/GOST)
    r"^t10d0[0-9]", # TLS 1.0 (快帆)
]

# Go TLS 指纹
JA4_GOLANG_PATTERN = r"^t13d1011h2_.*"

# Chrome JA4 前缀 (用于 ALPN 检测)
CHROME_JA4_PREFIX = r"^t13d151[0-9]h"

# ── ISO 国家码 (用于区域化节点命名检测) ──
ISO_COUNTRY_CODES = {
    "hk", "jp", "sg", "us", "nl", "ru", "lu", "gb", "tw",
    "kr", "de", "fr", "ca", "au", "in", "br",
}

# ── 知名企业 SNI 前缀 (用于检测 SNI-IP 不匹配，极光VPN 特征) ──
# 正常流量中这些企业域名的 SNI 应该连接其自有 IP
FAMOUS_ENTERPRISE_SNI = [
    "www.intel.com", "www.tesla.com", "www.ibm.com",
    "www.oracle.com", "www.cisco.com", "aws.amazon.com",
    "www.deloitte.com", "www.pwc.com", "www.sap.com",
    "www.bmw.com", "www.honda.com", "www.americanexpress.com",
    "www.costco.com", "www.emirates.com", "www.mathworks.com",
    "kpmg.com", "www.volvogroup.com", "www.mazda.com",
]

# ── VPN Family 推断规则表 (data-driven) ──
# 每个条目: (conditions, family_name)
# condition 为特征 dict 上的 lambda 或字符串匹配
VPN_FAMILY_RULES: list[tuple[list[str], str]] = [
    (["isakmp", "ike", "esp"], "IPsec/CyberGhost"),
    (["wg", "wireguard"], "WireGuard/NordVPN/StrongVPN"),
    (["gosttwo", "shdowsocks", "1310_block"], "番茄VPN/GOST"),
    (["nodesni", "kunlun04dns", "1448_block", "sdv2-"], "闪电VPN"),
    (["hola", "zagent", "22225_port", "1452_block"], "HolaVPN"),
    (["nord", "udp53_masquerade", "1344_block"], "NordVPN"),
    (["securepaidvpn", "3128_port"], "SecurePaidVPN"),
    (["1300_block"], "ShadowsocksR/SSR"),
    (["1370_block_tls"], "VLess"),
    (["1370_block_no_tls"], "VMess"),
    (["clashverge"], "Clash"),
    (["ahahub", "ahapivot", "hubdhl", "hubups", "1428_block"], "老王VPN"),
    (["skylinevpn", "skylinenode", "11581_port", "11582_port", "1400_block"], "天行VPN"),
    (["1400_block"], "极光VPN/天行VPN"),
    (["wizvpn"], "WizVPN"),
    (["kuaifan", "wifiin.cn", "tls10"], "快帆"),
    (["ultrasurf", "quic_tls_dual", "cheap_tld_storm"], "UltraSurf"),
    (["strongvpn"], "StrongVPN"),
    (["openvpn", "1194_port"], "OpenVPN"),
]
