import yaml
import re

def load_policy(policy_file="policy.yaml"):
    """
    policy.yaml 파일을 읽어서 허용 정책을 로드합니다.
    """
    with open(policy_file, "r") as f:
        data = yaml.safe_load(f)
    return data["policy"]

def parse_open_ports(nmap_output, target):
    """
    nmap 스캔 결과에서 열린 포트 목록을 추출합니다.
    """
    open_ports = []
    for line in nmap_output.split("\n"):
        match = re.search(r"(\d+_)/tcp\s+open", line)
        if match:
            open_ports.append(int(match.group(1)))
    return open_ports

def check_policy(target, open_ports, policy):
    """
    열린 포트가 정책에 허용된 포트인지 확인합니다.
    허용되지 않은 포트가 열려있으면 취약점으로 탐지합니다.
    """
    violations = []

    for rule in policy:
        if rule["dst"] == target:
            allowed_ports = rule["ports"]
            for port in open_ports:
                if port not in allowed_ports:
                    violations.append({
                        "target": target,
                        "port": port,
                        "ncode": "N-06",
                        "description": f"허용되지 않은 포트 {port} 열려있음",
                        "risk": "상"
                    })
    return violations

if __name__ == "__main__":
    policy = load_policy()
    print("정책 로드 완료:")
    for rule in policy:
        print(f"  {rule['src']} → {rule['dst']} : {rule['ports']}")