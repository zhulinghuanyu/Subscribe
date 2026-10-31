import base64
import json
import re
import time
import html
import os
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import yaml
import cloudscraper
from bs4 import BeautifulSoup

TARGET_URL = "https://yfamilys.com/subscribe"
BEIJING_TZ = timezone(timedelta(hours=8))
SUB_APIS = [
     "https://api.v1.mk/sub",
     "https://url.v1.mk/sub",
     "https://sub.xeton.dev/sub",
     "https://subapi.cmliussss.net/sub",
     "https://subapi.fxxk.dedyn.io/sub",
     "https://api.dler.io/sub"
]
EXCLUDE_KEYWORDS = [
    "cloudflareinsights.com",
    "google-analytics.com",
    "googletagmanager.com",
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".ico",
    ".svg",
    "github.com",
    "githubusercontent.com",
]
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}
SUB_CLIENT_HEADERS = {
    "User-Agent": "v2rayN/6.23"
}
NODE_SCHEMES = (
    "vmess://", "ss://", "ssr://", "trojan://", "vless://",
    "hysteria2://", "hy2://", "tuic://", "hysteria://"
)

# ===============================
# 自定义 YAML Dumper 以实现 proxies 单行输出
# ===============================
class FlowDict(dict):
    pass
class FlowDumper(yaml.SafeDumper):
    pass
def _represent_flow_dict(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items(), flow_style=True)
FlowDumper.add_representer(FlowDict, _represent_flow_dict)
def convert_to_flow(obj):
    if isinstance(obj, dict):
        return FlowDict({k: convert_to_flow(v) for k, v in obj.items()})
    elif isinstance(obj, list):
        return [convert_to_flow(i) for i in obj]
    return obj

# ===============================
# 安全写文件
# ===============================
def safe_write(filename, content):
    tmp = filename + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, filename)

# ===============================
# 清洗时间戳注释行
# ===============================
TIME_COMMENT_RE = re.compile(r"^\s*(//|#).*\d{4}-\d{2}-\d{2}.*$", re.I)
def strip_time_comments(content):
    lines = [ln for ln in content.splitlines() if not TIME_COMMENT_RE.match(ln)]
    return "\n".join(lines).strip()

# ===============================
# 本地 Clash 转换工具
# ===============================
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)
def _q(params, key, default=""):
    v = params.get(key)
    return v[0] if v else default
def decode_node_lines(content):
    content = content.strip()
    lines = [l.strip() for l in content.splitlines()
             if l.strip() and not l.strip().startswith(("//", "#"))]
    if any(l.lower().startswith(NODE_SCHEMES) for l in lines):
        return [l for l in lines if l.lower().startswith(NODE_SCHEMES)]
    try:
        b64 = re.sub(r"\s+", "", content)
        dec = b64d(b64).decode("utf-8")
        dl = [l.strip() for l in dec.splitlines() if l.strip().lower().startswith(NODE_SCHEMES)]
        if dl:
            return dl
    except Exception:
        pass
    return lines
def parse_node(line, idx):
    line = line.strip()
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    p = urlparse(line)
    name = unquote(p.fragment) if p.fragment else None
    if scheme == "vmess":
        body = line.split("://", 1)[1].split("#")[0]
        data = json.loads(b64d(body).decode("utf-8"))
        proxy = {
            "name": data.get("ps") or name or f"vmess-{idx}",
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": "auto",
            "udp": True,
        }
        net = (data.get("net") or "tcp").lower()
        if data.get("tls") == "tls":
            proxy["tls"] = True
            sni = data.get("sni") or data.get("host")
            if sni:
                proxy["servername"] = sni
        if net == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path": data.get("path") or "/",
                "headers": {"Host": data.get("host") or proxy["server"]}
            }
        elif net == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": data.get("path") or ""}
        elif net == "h2":
            proxy["network"] = "h2"
            opts = {"path": data.get("path") or "/"}
            if data.get("host"):
                opts["host"] = [data["host"]]
            proxy["h2-opts"] = opts
        return proxy
    if scheme == "ss":
        body = line.split("://", 1)[1].split("#")[0]
        if "@" in body:
            userinfo, _, hostport = body.rpartition("@")
            try:
                dec = b64d(unquote(userinfo)).decode("utf-8")
            except Exception:
                dec = unquote(userinfo)
            method, _, password = dec.partition(":")
            host, _, port = hostport.rpartition(":")
        else:
            dec = b64d(body).decode("utf-8")
            method, _, rest = dec.partition(":")
            password, _, hostport = rest.partition("@")
            host, _, port = hostport.rpartition(":")
        if not (method and password and host and port):
            return None
        return {
            "name": name or f"ss-{idx}",
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    if scheme == "ssr":
        dec = b64d(line.split("://", 1)[1]).decode("utf-8")
        main, _, qs = dec.partition("/?")
        host, port, protocol, method, obfs, pwd_b64 = main.split(":")
        params = parse_qs(qs)
        proxy = {
            "name": b64d(_q(params, "remarks")).decode("utf-8") if _q(params, "remarks") else (name or f"ssr-{idx}"),
            "type": "ssr",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": b64d(pwd_b64).decode("utf-8"),
            "obfs": obfs,
            "protocol": protocol,
            "udp": True,
        }
        if _q(params, "obfsparam"):
            proxy["obfs-param"] = b64d(_q(params, "obfsparam")).decode("utf-8")
        if _q(params, "protoparam"):
            proxy["protocol-param"] = b64d(_q(params, "protoparam")).decode("utf-8")
        return proxy
    if scheme == "trojan":
        params = parse_qs(p.query)
        proxy = {
            "name": name or f"trojan-{idx}",
            "type": "trojan",
            "server": p.hostname,
            "port": p.port or 443,
            "password": unquote(p.username or ""),
            "udp": True
        }
        sni = _q(params, "sni") or _q(params, "peer")
        if sni:
            proxy["sni"] = sni
        if _q(params, "allowInsecure") in ("1", "true", "True"):
            proxy["skip-cert-verify"] = True
        net = _q(params, "type", "tcp")
        if net == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path": _q(params, "path", "/"),
                "headers": {"Host": _q(params, "host", proxy["server"])}
            }
        elif net == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": _q(params, "serviceName", "")}
        return proxy
    if scheme == "vless":
        params = parse_qs(p.query)
        proxy = {
            "name": name or f"vless-{idx}",
            "type": "vless",
            "server": p.hostname,
            "port": p.port or 443,
            "uuid": unquote(p.username or ""),
            "udp": True
        }
        security = _q(params, "security", "none")
        if security in ("tls", "reality"):
            proxy["tls"] = True
            sni = _q(params, "sni")
            if sni:
                proxy["servername"] = sni
            if security == "reality":
                proxy["reality-opts"] = {
                    "public-key": _q(params, "pbk"),
                    "short-id": _q(params, "sid")
                }
                fp = _q(params, "fp")
                if fp:
                    proxy["client-fingerprint"] = fp
        flow = _q(params, "flow")
        if flow:
            proxy["flow"] = flow
        net = _q(params, "type", "tcp")
        if net == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path": _q(params, "path", "/"),
                "headers": {"Host": _q(params, "host", proxy["server"])}
            }
        elif net == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {
                "grpc-service-name": _q(params, "serviceName", "") or _q(params, "path", "")
            }
        return proxy
    if scheme in ("hysteria2", "hy2"):
        params = parse_qs(p.query)
        proxy = {
            "name": name or f"hy2-{idx}",
            "type": "hysteria2",
            "server": p.hostname,
            "port": p.port or 443,
            "password": unquote(p.username or ""),
            "udp": True
        }
        sni = _q(params, "sni") or _q(params, "peer")
        if sni:
            proxy["sni"] = sni
        if _q(params, "insecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True
        obfs = _q(params, "obfs")
        if obfs:
            proxy["obfs"] = obfs
            if _q(params, "obfs-password"):
                proxy["obfs-password"] = _q(params, "obfs-password")
        return proxy
    if scheme == "tuic":
        params = parse_qs(p.query)
        proxy = {
            "name": name or f"tuic-{idx}",
            "type": "tuic",
            "server": p.hostname,
            "port": p.port or 443,
            "uuid": unquote(p.username or ""),
            "password": unquote(p.password or ""),
            "udp": True
        }
        sni = _q(params, "sni")
        if sni:
            proxy["sni"] = sni
        if _q(params, "insecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True
        return proxy     
    return None
def build_clash_yaml(node_lines):
    proxies, used = [], set()
    for idx, line in enumerate(node_lines, 1):
        try:
            proxy = parse_node(line, idx)
        except Exception as e:
            print(f"⚠️ 解析节点失败，跳过: {e}")
            continue
        if not proxy or not proxy.get("server"):
            continue
        nm, n = proxy["name"], 1
        while nm in used:
            n += 1
            nm = f"{proxy['name']} {n}"
        proxy["name"] = nm
        used.add(nm)
        proxies.append(proxy)
    if not proxies:
        return None
    names = [x["name"] for x in proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": convert_to_flow(proxies),
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择"] + names
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            },
            {
                "name": "🐟 漏网之鱼",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"]
            },
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🐟 漏网之鱼"
        ],
    }
    return yaml.dump(config, Dumper=FlowDumper, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)

# ===============================
# 简化 Clash YAML (去除臃肿的规则)
# ===============================
def simplify_clash_yaml(yaml_content):
    try:
        config = yaml.safe_load(yaml_content)
        if not config or not isinstance(config, dict):
            return yaml_content          
        proxies = config.get("proxies", [])
        if not proxies:
            return yaml_content
        names = [p.get("name") for p in proxies if p.get("name")]
        config["proxies"] = convert_to_flow(proxies)
        config["proxy-groups"] = [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择"] + names
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            },
            {
                "name": "🐟 漏网之鱼",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"]
            },
        ]
        config["rules"] = [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🐟 漏网之鱼"
        ]
        for key in ["rule-providers", "tun", "ebpf", "script", "ruleset", "proxy-provider"]:
            config.pop(key, None)          
        return yaml.dump(config, Dumper=FlowDumper, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)
    except Exception as e:
        print(f"⚠️ 简化 Clash YAML 失败: {e}")
        return yaml_content

# ===============================
# README 更新
# ===============================
def update_readme(raw_content):
    bt = "```"
    update_time = datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S (UTC+8)")
    if raw_content.startswith("http"):
        display = raw_content
    else:
        count = len([x for x in raw_content.splitlines() if x.strip()])
        display = f"已成功抓取 {count} 条节点"
    content = f"""# 🚀 BestSub 自动订阅更新
自动抓取 yfamilys 最新订阅。
---
## Clash订阅
{bt}text
https://raw.githubusercontent.com/zhulinghuanyu/BestSub/main/clash.yaml
{bt}
## V2Ray订阅
{bt}text
https://raw.githubusercontent.com/zhulinghuanyu/BestSub/main/v2ray.txt
{bt}
## 原始订阅
{bt}text
https://raw.githubusercontent.com/zhulinghuanyu/BestSub/main/links.txt
{bt}
---
更新时间:
{bt}text
{update_time}
{bt}
当前状态:
{bt}text
{display}
{bt}
"""
    old = ""
    if os.path.exists("README.md"):
        with open("README.md", encoding="utf-8") as f:
            old = f.read()
    if old != content:
        safe_write("README.md", content)
        print("📝 README 更新")
    else:
        print("README 无变化")

# ===============================
# 请求重试
# ===============================
def request_retry(scraper, url, **kwargs):
    last_error = None
    for i in range(4):  # 多试一次
        try:
            # 每次重试稍微换一下指纹，提高成功率
            if i > 0:
                scraper = cloudscraper.create_scraper(
                    browser={"browser": "chrome", "platform": "windows", "desktop": True}
                )
                time.sleep(2 + i * 1.5)  # 递增等待

            res = scraper.get(url, **kwargs)
            text = res.text or ""

            # 成功条件：状态码 200 且页面里真正有订阅链接
            has_real_content = (
                res.status_code == 200
                and (
                    "urlBox" in text
                    or re.search(r"https://yfamilys\.com/subscribe/[A-Za-z0-9_\-]{10,}", text)
                )
            )

            if has_real_content:
                print(f"✅ 第 {i+1} 次请求成功 (status={res.status_code}, len={len(text)})")
                return res

            # 记录失败原因，方便调试
            challenge = any(k in text for k in ["Just a moment", "cf-browser-verification", "challenge-platform", "Checking your browser"])
            print(f"⚠️ 第 {i+1}/4 次失败: status={res.status_code}, len={len(text)}, challenge={challenge}")
            last_error = f"status={res.status_code}, challenge={challenge}"

        except Exception as e:
            print(f"⚠️ 第 {i+1}/4 次异常: {e}")
            last_error = str(e)
            time.sleep(3)

    raise Exception(f"请求失败:{url} | 最后错误: {last_error}")

# ===============================
# 判断订阅 URL
# ===============================
def is_valid_sub_url(url):
    clean_url = url.lower().split("#")[0]
    if any(x in clean_url for x in EXCLUDE_KEYWORDS):
        return False
    if "yfamilys.com/subscribe/" in clean_url and clean_url.rstrip('/') != "https://yfamilys.com/subscribe":
        return True
    keys = ["sub", "token", "subscribe", "clash", "v2ray", "node", ".yaml", ".txt"]
    return any(x in clean_url for x in keys)

# ===============================
# 转换订阅（在线 API）
# ===============================
def convert_sub(scraper, target, raw_input):
    timestamp = int(time.time())
    if not raw_input.startswith("http"):
        node_lines = [line.strip() for line in raw_input.splitlines() if line.strip()]
        sub_param = "|".join(node_lines)
    else:
        sub_param = raw_input
    for api in SUB_APIS:
        try:
            print(f"🔄 尝试转换 API: {api} -> {target}")
            params = {
                "target": target,
                "url": sub_param,
                "insert": "false",
                "_t": timestamp
            }
            res = scraper.get(api, params=params, headers=DEFAULT_HEADERS, timeout=30)
            if res.status_code != 200:
                print(f" ↳ 状态码异常: {res.status_code}")
                continue
            text = res.text.strip()
            if "<html" in text.lower():
                print(" ↳ 返回 HTML 错误页")
                continue
            if target == "clash":
                if "proxies:" in text and len(text) > 100:
                    return text
                print(" ↳ 返回内容不含有效 proxies 配置")
            if target == "v2ray":
                if len(text) > 50:
                    return text
                print(" ↳ 返回内容过短")
        except Exception as e:
            print("API 转换异常:", e)
    return None

# ===============================
# 主抓取逻辑
# ===============================
def fetch_links():
    print("🌐 请求 yfamilys 网页...")
    scraper = cloudscraper.create_scraper(
        browser={
            "browser": "chrome",
            "platform": "windows",
            "desktop": True
        },
        delay=10,          # 给 JS 挑战更多时间
        # interpreter="nodejs"  # 如果 CI 装了 node，可以打开，成功率更高
    )
    response = request_retry(scraper, TARGET_URL, headers=DEFAULT_HEADERS, timeout=45)
    html_text = html.unescape(response.text)
    extracted = None
    node_pattern = (
        r"(?:vmess|vless|trojan|ss|ssr|"
        r"hysteria|hysteria2|hy2|tuic)"
        r"://[^\s<\"'>]+"
    )
    nodes = re.findall(node_pattern, html_text, re.I)
    if nodes:
        nodes = list(dict.fromkeys(nodes))
        extracted = "\n".join(nodes)
        print(f"✅ 提取到 {len(nodes)} 个独立节点")
    else:
        pattern = r"https://yfamilys\.com/subscribe/[A-Za-z0-9_\-?=&]+"
        results = re.findall(pattern, html_text)
        valid_links = [r for r in results if r.rstrip('/') != "https://yfamilys.com/subscribe"]
        if valid_links:
            extracted = valid_links[0]
            print("✅ 提取到动态订阅链接:", extracted)
        else:
            soup = BeautifulSoup(html_text, "html.parser")
            urls = [a["href"] for a in soup.find_all("a", href=True)]
            urls += re.findall(r"https?://[^\s<\"'>]+", html_text)
            for u in dict.fromkeys(urls):
                if is_valid_sub_url(u):
                    extracted = u
                    break
    if not extracted:
        raise Exception("❌ 未在页面中查找到有效节点或动态链接")
    safe_write("links.txt", extracted)

    # -----------------------------
    # V2Ray 节点更新逻辑 (标准 Base64 格式)
    # -----------------------------
    v2ray_content = None
    node_lines = []
    if extracted.startswith("http"):
        try:
            print("⬇️ 正在直连拉取订阅内容...")
            direct_res = scraper.get(extracted, headers=SUB_CLIENT_HEADERS, timeout=15)
            text = direct_res.text.strip()
            text_lower = text.lower()
            is_html = "<html" in text_lower
            looks_like_clash_yaml = (
                "proxies:" in text_lower
                or text_lower.lstrip().startswith(("- {", "- name:", "proxy-groups:", "rules:"))
            )
            has_valid_node_schemes = any(
                line.strip().lower().startswith(NODE_SCHEMES)
                for line in text.splitlines()
            )
            if (direct_res.status_code == 200
                    and len(text) > 30
                    and not is_html
                    and has_valid_node_schemes
                    and not looks_like_clash_yaml):
                v2ray_content = text
                print("✅ 直连成功获取 V2Ray 节点内容")
            else:
                if looks_like_clash_yaml:
                    print("ℹ️ 直连内容为 Clash YAML 格式，转用 API 获取纯净 V2Ray 节点")
                elif is_html:
                    print("ℹ️ 直连返回 HTML，转用 API 转换")
                else:
                    print("ℹ️ 直连内容不符合纯 V2Ray 节点格式，转用 API 转换")
        except Exception as e:
            print(f"⚠️ 直连拉取失败，尝试通过 API 转换: {e}")
        if not v2ray_content:
            v2ray_content = convert_sub(scraper, "v2ray", extracted)
        if not v2ray_content:
            raise Exception("❌ V2Ray 内容获取及转换均失败")
        v2ray_content = strip_time_comments(v2ray_content)
        if not v2ray_content:
            raise Exception("❌ V2Ray 内容清洗后为空")
        node_lines = decode_node_lines(v2ray_content)
        if not any(l.lower().startswith(NODE_SCHEMES) for l in node_lines):
            print("⚠️ 解码后无有效节点 URI，强制重新通过 API 转换...")
            v2ray_content = convert_sub(scraper, "v2ray", extracted)
            if not v2ray_content:
                raise Exception("❌ V2Ray 强制转换失败")
            v2ray_content = strip_time_comments(v2ray_content)
            node_lines = decode_node_lines(v2ray_content)
    else:
        node_lines = [
            l for l in extracted.splitlines()
            if l.strip() and l.strip().lower().startswith(NODE_SCHEMES)
        ]
        if not node_lines:
            node_lines = [l for l in extracted.splitlines() if l.strip()]
    if not node_lines:
        raise Exception("❌ 未提取到有效的 V2Ray 节点")
    pure_nodes = [l for l in node_lines if l.strip().lower().startswith(NODE_SCHEMES)]
    if not pure_nodes:
        raise Exception("❌ 过滤后无有效节点 URI，无法生成 V2Ray 订阅")
    raw_nodes_text = "\n".join(pure_nodes)
    b64_v2ray = base64.b64encode(raw_nodes_text.encode("utf-8")).decode("utf-8")
    safe_write("v2ray.txt", b64_v2ray)
    print(f"✅ v2ray.txt 更新完成 (标准单行 Base64 格式，共 {len(pure_nodes)} 个节点)")

    # -----------------------------
    # Clash 订阅更新逻辑（在线 API 优先，本地转换兜底）
    # -----------------------------
    clash_content = convert_sub(scraper, "clash", extracted)
    if clash_content:
        clash_content = simplify_clash_yaml(clash_content)
    else:
        print("⚠️ 在线转换 API 全部失效，启用本地 Clash 转换...")
        clash_content = build_clash_yaml(pure_nodes)   
    if not clash_content:
        raise Exception("❌ Clash 配置转换失败")
    clash_content = strip_time_comments(clash_content)
    if not clash_content:
        raise Exception("❌ Clash 配置清洗后为空")
    safe_write("clash.yaml", clash_content)
    print("✅ clash.yaml 更新完成")

    update_readme(extracted)
    print("🎉 所有任务执行完成！")
if __name__ == "__main__":
    fetch_links()
