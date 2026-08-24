"""
NetWatch VPS Selection & Leaderboard Engine (选品榜单 & CN被墙小鸡榜)
Server-side pre-computed VPS performance rankings, route assessments,
and price-to-performance evaluators.
"""

import time
import logging

logger = logging.getLogger(__name__)

# Curated VPS Leaderboard Dataset
VPS_DATASET = [
    # ── Category 1: 🚫 CN被墙小鸡榜 (CN-Blocked High-Value VPS / 离岸便宜神机) ──
    {
        "id": "vps_rn_la_01",
        "category": "cn_blocked",
        "provider": "RackNerd",
        "plan_name": "LA KVM Special 2.5G",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "Los Angeles (DC-02)",
        "vcpu": 2,
        "ram_gb": 2.5,
        "disk_gb": 40,
        "disk_type": "SSD Cached",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 4.0,
        "price_usd_yr": 16.88,
        "price_usd_mo": 1.41,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 中国大陆 IP 阻断 / TCP Timeout (套CDN/海外专用)",
        "global_status": "BLAZING",
        "global_latency_ms": 12,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": False
        },
        "pros": ["年付仅$16.88", "4TB超大月流量", "洛杉矶DC02千兆极速", "套Cloudflare建站神器"],
        "ideal_for": ["套 Cloudflare CDN 建站", "Docker 容器集群", "海外爬虫与数据采集", "Telegram Bot & Webhook", "海外反代中转"],
        "recommend_score": 98,
        "coupon_code": "RN-SPECIAL-LA",
        "buy_url": "https://www.racknerd.com",
        "in_stock": True,
        "tags": ["特惠被墙", "大流量", "高性价比", "套CDN"]
    },
    {
        "id": "vps_cc_sc2_01",
        "category": "cn_blocked",
        "provider": "CloudCone",
        "plan_name": "SC2 Flash Deal 3G",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "Los Angeles (Multacom)",
        "vcpu": 2,
        "ram_gb": 3.0,
        "disk_gb": 60,
        "disk_type": "Pure SSD RAID10",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 3.0,
        "price_usd_yr": 18.50,
        "price_usd_mo": 1.54,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 大陆直连丢包阻断 (适合离岸Docker与自动化任务)",
        "global_status": "BLAZING",
        "global_latency_ms": 14,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": False,
            "tiktok": True,
            "disney": True
        },
        "pros": ["3GB大内存", "60GB高速SSD", "支持按小时计费", "自带免费备份快照"],
        "ideal_for": ["海外自动化流水线", "轻量数据库", "Nextcloud 网盘", "套CDN动静分离"],
        "recommend_score": 95,
        "coupon_code": "CC-FLASH-SC2",
        "buy_url": "https://cloudcone.com",
        "in_stock": True,
        "tags": ["特惠被墙", "大内存", "按小时计费"]
    },
    {
        "id": "vps_buyvm_lv_01",
        "category": "cn_blocked",
        "provider": "BuyVM (FranTech)",
        "plan_name": "Slice 1024 + Block Storage",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "Las Vegas",
        "vcpu": 1,
        "ram_gb": 1.0,
        "disk_gb": 20,
        "disk_type": "NVMe Storage",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 99.0,  # Unlimited
        "price_usd_yr": 24.00,
        "price_usd_mo": 2.00,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 IP受阻断 / 1Gbps不限流量 (挂载大盘PT/存储神器)",
        "global_status": "BLAZING",
        "global_latency_ms": 18,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["1Gbps 真正不限流量", "支持$1.25/月挂载256G大硬盘", "AMD Ryzen 3900X CPU", "广播IP自由度高"],
        "ideal_for": ["PT/BT 离线下载", "自建海外S3/WebDAV网盘", "Docker 挂载大盘服务", "套CDN多媒体站点"],
        "recommend_score": 96,
        "coupon_code": "BUYVM-UNLIMITED",
        "buy_url": "https://buyvm.net",
        "in_stock": True,
        "tags": ["特惠被墙", "不限流量", "挂载大盘", "PT神器"]
    },
    {
        "id": "vps_hetzner_cax11",
        "category": "cn_blocked",
        "provider": "Hetzner Cloud",
        "plan_name": "CAX11 ARM 64",
        "region": "Europe",
        "flag": "🇩🇪",
        "datacenter": "Falkenstein / Nuremberg",
        "vcpu": 2,
        "ram_gb": 4.0,
        "disk_gb": 40,
        "disk_type": "NVMe SSD",
        "bandwidth_gbps": 10.0,
        "traffic_tb": 20.0,
        "price_usd_yr": 45.00,
        "price_usd_mo": 3.75,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 欧洲对华直连绕路阻断 / 10Gbps 20TB 欧洲机皇",
        "global_status": "BLAZING",
        "global_latency_ms": 8,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["Ampere ARM 2核4G", "10Gbps 上行带宽", "20TB 庞大月流量", "欧洲顶尖机房SLA"],
        "ideal_for": ["高并发海外API后端", "Docker 编译构建服务器", "套 Cloudflare 欧洲源站", "Matrix/Mastodon 联邦实例"],
        "recommend_score": 97,
        "coupon_code": "HETZNER-EU-TOP",
        "buy_url": "https://www.hetzner.com/cloud",
        "in_stock": True,
        "tags": ["特惠被墙", "10Gbps带宽", "20TB流量", "4G内存"]
    },
    {
        "id": "vps_ovh_vps1",
        "category": "cn_blocked",
        "provider": "OVHcloud",
        "plan_name": "Value VPS-1",
        "region": "Europe",
        "flag": "🇫🇷",
        "datacenter": "Gravelines / Roubaix",
        "vcpu": 1,
        "ram_gb": 2.0,
        "disk_gb": 40,
        "disk_type": "NVMe SSD",
        "bandwidth_gbps": 0.25,
        "traffic_tb": 99.0,
        "price_usd_yr": 42.00,
        "price_usd_mo": 3.50,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 大陆连通性差 / 自带 1Tbps 传奇 VAC Anti-DDoS",
        "global_status": "HEALTHY",
        "global_latency_ms": 22,
        "unlock": {
            "chatgpt": True,
            "claude": False,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["顶级 Anti-DDoS 高防", "不限流量", "企业级硬件稳定度", "NVMe 读写 1.5GB/s"],
        "ideal_for": ["防攻击反向代理", "自建 DNS 服务器", "对外开放 API 节点", "海外备份服务器"],
        "recommend_score": 91,
        "coupon_code": "OVH-VALUE-DEF",
        "buy_url": "https://www.ovhcloud.com",
        "in_stock": True,
        "tags": ["特惠被墙", "高防DDoS", "不限流量"]
    },
    {
        "id": "vps_colocrossing_01",
        "category": "cn_blocked",
        "provider": "ColoCrossing",
        "plan_name": "Cloud 1GB Promo",
        "region": "US East",
        "flag": "🇺🇸",
        "datacenter": "Buffalo / New York",
        "vcpu": 1,
        "ram_gb": 1.0,
        "disk_gb": 25,
        "disk_type": "SSD Storage",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 2.0,
        "price_usd_yr": 11.99,
        "price_usd_mo": 1.00,
        "cn_status": "BLOCKED",
        "cn_desc": "🚫 GFW 阻断 / 年付仅$11.99 白菜价小鸡",
        "global_status": "HEALTHY",
        "global_latency_ms": 32,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": False,
            "tiktok": False,
            "disney": False
        },
        "pros": ["年付仅$11.99 (月付$1)", "原生美东机房", "千兆上行", "极低养鸡成本"],
        "ideal_for": ["海外探针监控", "低频 Webhook 接收", "Telegram 推送 Bot", "临时测试沙箱"],
        "recommend_score": 89,
        "coupon_code": "CC-11BUCKS",
        "buy_url": "https://colocrossing.com",
        "in_stock": True,
        "tags": ["特惠被墙", "白菜价", "年付$11"]
    },

    # ── Category 2: 🏆 综合高性价比神机榜 (Value VPS) ──
    {
        "id": "vps_rn_sjc_02",
        "category": "value",
        "provider": "RackNerd",
        "plan_name": "San Jose New Year 3G",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "San Jose (Silicon Valley)",
        "vcpu": 2,
        "ram_gb": 3.0,
        "disk_gb": 55,
        "disk_type": "Pure SSD",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 5.0,
        "price_usd_yr": 25.80,
        "price_usd_mo": 2.15,
        "cn_status": "STANDARD",
        "cn_desc": "⚡ 联通4837/电信直连 (非高峰期优良)",
        "global_status": "BLAZING",
        "global_latency_ms": 11,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["3GB内存+5TB流量", "圣何塞硅谷直连", "稳定性极佳", "支持中英文面板"],
        "ideal_for": ["中型 Web 项目", "自建 CI/CD", "多容器部署", "个人海外开发环境"],
        "recommend_score": 96,
        "coupon_code": "RN-SJC-VAL",
        "buy_url": "https://www.racknerd.com",
        "in_stock": True,
        "tags": ["综合推荐", "圣何塞直连", "5TB流量"]
    },
    {
        "id": "vps_netcup_rs1000",
        "category": "value",
        "provider": "Netcup",
        "plan_name": "Root Server RS 1000 G11",
        "region": "Europe",
        "flag": "🇩🇪",
        "datacenter": "Nuremberg",
        "vcpu": 4,
        "ram_gb": 8.0,
        "disk_gb": 256,
        "disk_type": "NVMe SSD (Enterprise)",
        "bandwidth_gbps": 2.5,
        "traffic_tb": 80.0,
        "price_usd_yr": 96.00,
        "price_usd_mo": 8.00,
        "cn_status": "STANDARD",
        "cn_desc": "⚡ 欧洲大盘强劲独享核心 / 80TB 流量",
        "global_status": "BLAZING",
        "global_latency_ms": 9,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["独享4核AMD EPYC", "8GB ECC内存", "256G企业级NVMe", "80TB巨量月配额"],
        "ideal_for": ["高负载数据库", "自建GitLab/Nexus", "多应用集群", "大容量网盘"],
        "recommend_score": 97,
        "coupon_code": "NETCUP-RS1000",
        "buy_url": "https://www.netcup.eu",
        "in_stock": True,
        "tags": ["独享核心", "8G内存", "256G大盘", "企业级性能"]
    },

    # ── Category 3: 🚀 CN直连精品线路榜 (CN Direct Low Latency - CN2 GIA / 9929 / CMI) ──
    {
        "id": "vps_dmit_lax_pro",
        "category": "direct_cn",
        "provider": "DMIT",
        "plan_name": "PVM.LAX.Pro.Pocket",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "Los Angeles",
        "vcpu": 1,
        "ram_gb": 1.0,
        "disk_gb": 20,
        "disk_type": "SSD Storage",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 1.0,
        "price_usd_yr": 88.00,
        "price_usd_mo": 7.33,
        "cn_status": "OPTIMIZED",
        "cn_desc": "🚀 三网回程 CN2 GIA + 9929 顶级优质直连 (Ping < 140ms)",
        "global_status": "BLAZING",
        "global_latency_ms": 10,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["三网 CN2 GIA 顶级线路", "高峰期 0 丢包", "美西超低 135ms 延迟", "全天候千兆跑满"],
        "ideal_for": ["国内免备案极速建站", "远程桌面与低延迟中继", "高要求海外协同办公"],
        "recommend_score": 99,
        "coupon_code": "DMIT-LAX-PRO",
        "buy_url": "https://www.dmit.io",
        "in_stock": True,
        "tags": ["CN2 GIA", "三网直连", "低延迟极速"]
    },
    {
        "id": "vps_bwh_dc9_gia",
        "category": "direct_cn",
        "provider": "BandwagonHost (搬瓦工)",
        "plan_name": "DC9 CN2 GIA-E Limited",
        "region": "US West",
        "flag": "🇺🇸",
        "datacenter": "Los Angeles (DC9)",
        "vcpu": 1,
        "ram_gb": 1.0,
        "disk_gb": 20,
        "disk_type": "SSD RAID10",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 0.5,
        "price_usd_yr": 79.99,
        "price_usd_mo": 6.66,
        "cn_status": "OPTIMIZED",
        "cn_desc": "🚀 企业级 CN2 GIA 线路 / 高可靠 SLA 99.99%",
        "global_status": "BLAZING",
        "global_latency_ms": 12,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["搬瓦工金牌服务", "支持一键切换多机房", "CN2 GIA 稳定无断流", "快照备份一键还原"],
        "ideal_for": ["企业出海直连", "跨境电商店铺管理", "高要求低延迟应用"],
        "recommend_score": 98,
        "coupon_code": "BWHCCNCXVV",
        "buy_url": "https://bandwagonhost.com",
        "in_stock": True,
        "tags": ["搬瓦工", "CN2 GIA", "一键迁机房"]
    },

    # ── Category 4: 🎬 流媒体与AI全解锁榜 (Streaming & AI Full Unlock) ──
    {
        "id": "vps_vpsnet_sg_01",
        "category": "unlock",
        "provider": "V.PS",
        "plan_name": "Singapore Performance Mini",
        "region": "Singapore",
        "flag": "🇸🇬",
        "datacenter": "Singapore Equinix",
        "vcpu": 1,
        "ram_gb": 1.0,
        "disk_gb": 15,
        "disk_type": "NVMe SSD",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 1.0,
        "price_usd_yr": 69.95,
        "price_usd_mo": 5.82,
        "cn_status": "OPTIMIZED",
        "cn_desc": "🎬 新加坡原生IP / ChatGPT & Netflix 原生全解锁",
        "global_status": "BLAZING",
        "global_latency_ms": 6,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["原生新加坡住宅/商业纯净IP", "全绿流媒体解锁", "ChatGPT/Claude 零风控", "东南亚极速中枢"],
        "ideal_for": ["AI 对话与 Agent 部署", "TikTok 东南亚运营", "Netflix/Disney+ 4K 影音", "新加坡落地出口"],
        "recommend_score": 97,
        "coupon_code": "VPS-SG-UNL",
        "buy_url": "https://v.ps",
        "in_stock": True,
        "tags": ["全解锁", "新加坡原生", "AI零风控"]
    },
    {
        "id": "vps_hosthatch_tokyo",
        "category": "unlock",
        "provider": "HostHatch",
        "plan_name": "Tokyo NVMe 2G",
        "region": "Japan",
        "flag": "🇯🇵",
        "datacenter": "Tokyo (Equinix TY8)",
        "vcpu": 1,
        "ram_gb": 2.0,
        "disk_gb": 25,
        "disk_type": "NVMe SSD",
        "bandwidth_gbps": 1.0,
        "traffic_tb": 2.0,
        "price_usd_yr": 35.00,
        "price_usd_mo": 2.91,
        "cn_status": "STANDARD",
        "cn_desc": "🎬 日本原生出口 / AbemaTV / DMM / Netflix 解锁",
        "global_status": "BLAZING",
        "global_latency_ms": 15,
        "unlock": {
            "chatgpt": True,
            "claude": True,
            "netflix": True,
            "tiktok": True,
            "disney": True
        },
        "pros": ["日本原生双栈 IPv4+IPv6", "2GB RAM + NVMe 高性能", "年付$35特惠", "全绿动漫游戏解锁"],
        "ideal_for": ["日本流媒体与手游中继", "AI Agent 原生调用", "海外跨境电商"],
        "recommend_score": 94,
        "coupon_code": "HH-TYO-SPECIAL",
        "buy_url": "https://hosthatch.com",
        "in_stock": True,
        "tags": ["日本原生", "双栈IPv6", "全绿解锁"]
    }
]

# Pre-computed cached categories metadata
CATEGORIES_META = [
    {
        "id": "cn_blocked",
        "name": "CN被墙小鸡榜",
        "subtitle": "IP受阻断 / 极致性价比 / 适合套Cloudflare CDN、Docker、海外爬虫、大盘PT",
        "badge": "🚫 CN BLOCKED SPECIAL",
        "color": "#FF6B6B",
        "icon": "🚫"
    },
    {
        "id": "value",
        "name": "综合高性价比神机榜",
        "subtitle": "多核大内存 / 超大流量配额 / 平衡稳定的海外开发与建站神器",
        "badge": "🏆 TOP VALUE",
        "color": "#72F59A",
        "icon": "🏆"
    },
    {
        "id": "direct_cn",
        "name": "CN直连精品线路榜",
        "subtitle": "三网回程 CN2 GIA / 9929 / CMI / 4837 优质极速低延迟直连线路",
        "badge": "🚀 CN DIRECT LOW-LATENCY",
        "color": "#62D9CC",
        "icon": "🚀"
    },
    {
        "id": "unlock",
        "name": "流媒体与AI全解锁榜",
        "subtitle": "原生纯净住宅/商业IP / ChatGPT、Claude、TikTok、Netflix 4K 全解锁",
        "badge": "🎬 FULL UNLOCK & STREAMING",
        "color": "#BD93F9",
        "icon": "🎬"
    }
]

# In-Memory Cache Store for Leaderboard Queries
_LEADERBOARD_CACHE = {}

def get_leaderboard_data(category: str = "all", sort_by: str = "recommend", search: str = "", region: str = "all") -> dict:
    """
    Get filtered and sorted VPS leaderboard data with instant in-memory retrieval.
    """
    items = list(VPS_DATASET)

    # 1. Filter by Category
    if category and category != "all":
        items = [x for x in items if x["category"] == category]

    # 2. Filter by Region
    if region and region != "all":
        items = [x for x in items if region.lower() in x["region"].lower() or region.lower() in x["datacenter"].lower()]

    # 3. Filter by Search Query
    if search:
        kw = search.lower().strip()
        items = [
            x for x in items
            if kw in x["provider"].lower()
            or kw in x["plan_name"].lower()
            or kw in x["datacenter"].lower()
            or kw in x["region"].lower()
            or any(kw in tag.lower() for tag in x.get("tags", []))
            or any(kw in pro.lower() for pro in x.get("pros", []))
        ]

    # 4. Sorting
    if sort_by == "price_asc":
        items.sort(key=lambda x: x["price_usd_yr"])
    elif sort_by == "price_desc":
        items.sort(key=lambda x: x["price_usd_yr"], reverse=True)
    elif sort_by == "ram":
        items.sort(key=lambda x: x["ram_gb"], reverse=True)
    elif sort_by == "bandwidth":
        items.sort(key=lambda x: x["traffic_tb"], reverse=True)
    elif sort_by == "score":
        items.sort(key=lambda x: x["recommend_score"], reverse=True)
    else:  # Default 'recommend'
        items.sort(key=lambda x: x["recommend_score"], reverse=True)

    # Summary Statistics
    cn_blocked_count = len([x for x in VPS_DATASET if x["category"] == "cn_blocked"])
    total_count = len(VPS_DATASET)
    min_price_blocked = min([x["price_usd_yr"] for x in VPS_DATASET if x["category"] == "cn_blocked"], default=0.0)

    return {
        "categories": CATEGORIES_META,
        "selected_category": category,
        "total_items": len(items),
        "total_dataset": total_count,
        "cn_blocked_count": cn_blocked_count,
        "min_price_blocked": min_price_blocked,
        "items": items,
        "timestamp": time.time()
    }
