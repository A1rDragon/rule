#!/usr/bin/env python3
# scripts/ms_endpoints_to_openclash.py
import sys, os, requests, ipaddress, json

OUT_PATH = os.environ.get("OUT_PATH", "generated/openclash_rules.txt")
TARGET_IP = os.environ.get("TARGET_IP")  # 可选，不传则只生成与 Store 相关的规则
URL = os.environ.get("MS_ENDPOINTS_URL", "https://endpoints.office.com/endpoints/worldwide")

def load_json(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()

def ip_in_networks(ip_str, networks):
    ip = ipaddress.ip_address(ip_str)
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
            if ip in net:
                return True
        except Exception:
            pass
    return False

def main():
    try:
        data = load_json(URL)
    except Exception as e:
        print("Failed to download endpoints JSON:", e)
        sys.exit(2)

    matched_cidrs = set()
    matched_domains = set()

    # 先收集与 Microsoft Store 相关的常见域名（可扩展）
    store_domains = [
        "displaycatalog.mp.microsoft.com",
        "purchase.md.mp.microsoft.com",
        "licensing.mp.microsoft.com",
        "storeedgefd.dsx.mp.microsoft.com",
        "msstoreedge.net",
        "store.microsoft.com",
        "pti.store.microsoft.com"
    ]
    for d in store_domains:
        matched_domains.add(d)

    # 如果提供 TARGET_IP，则查找包含该 IP 的 CIDR 并收集该 endpoint 的域名
    if TARGET_IP:
        try:
            ip_obj = ipaddress.ip_address(TARGET_IP)
        except Exception as e:
            print("Invalid TARGET_IP:", e)
            sys.exit(3)
        for entry in data:
            addrs = entry.get("ips") or entry.get("addresses") or entry.get("ipsAddresses") or []
            if not isinstance(addrs, list):
                continue
            for a in addrs:
                try:
                    if "/" in a:
                        net = ipaddress.ip_network(a, strict=False)
                        if ip_obj in net:
                            matched_cidrs.add(str(net))
                    else:
                        if ip_obj == ipaddress.ip_address(a):
                            matched_cidrs.add(a + "/32")
                except Exception:
                    pass
            # 如果该 entry 命中，收集其域名/urls/fqdns
            if any(ip_obj in ipaddress.ip_network(x, strict=False) if "/" in x else ip_obj == ipaddress.ip_address(x) for x in addrs if isinstance(x,str)):
                for key in ("urls","fqdns","domains"):
                    if key in entry and isinstance(entry[key], list):
                        for d in entry[key]:
                            if isinstance(d, str) and "." in d:
                                matched_domains.add(d.lstrip("*."))
    # 写文件
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        f.write("# Generated OpenClash rules\n")
        for cidr in sorted(matched_cidrs):
            f.write(f"IP-CIDR,{cidr},DIRECT\n")
        for dom in sorted(matched_domains):
            f.write(f"DOMAIN-SUFFIX,{dom},DIRECT\n")
    print("Wrote", OUT_PATH)
    sys.exit(0)

if __name__ == "__main__":
    main()
