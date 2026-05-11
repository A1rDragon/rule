import requests
import json

def generate_list():
    # 微软官方 Endpoint 接口
    url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
    
    try:
        data = requests.get(url).json()
    except Exception as e:
        print(f"Fetch failed: {e}")
        return

    domains = set()
    ips = set()

    for entry in data:
        # 提取域名
        if "urls" in entry:
            for u in entry["urls"]:
                # 清理通配符，例如 *.microsoft.com -> microsoft.com
                clean_url = u.replace("*.", "")
                domains.add(clean_url)
        
        # 提取 IP 段
        if "ips" in entry:
            for ip in entry["ips"]:
                ips.add(ip)

    # 写入文件，采用 Clash Classical 格式
    with open("microsoft_direct.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        
        # 写入域名规则
        for d in sorted(list(domains)):
            f.write(f"  - DOMAIN-SUFFIX,{d}\n")
            
        # 写入 IP 规则
        for i in sorted(list(ips)):
            if ":" in i:
                f.write(f"  - IP-CIDR6,{i},no-resolve\n")
            else:
                f.write(f"  - IP-CIDR,{i},no-resolve\n")

if __name__ == "__main__":
    generate_list()
