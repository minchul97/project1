import subprocess

def scan_host(target, ports="1-10000"):
    """
    대상 호스트와 서비스를 스캔합니다.
    """
    print(f"[*] 스캔 시작: {target}")

    cmd = ["nmap", "-sV", "-p", ports, "--open", target]
    result = subprocess.run(cmd, capture_output=True, text=True)

    print(result.stdout)
    return result.stdout

def scan_network(targets):
    """
    여러 대상을 순서대로 스캔합니다.
    """
    results = {}
    for target in targets:
        results[target] = scan_host(target)
    return results

if __name__ == "__main__":
    targets = [
        "10.0.0.10",
        "192.168.10.20",
        "192.168.10.30",
        "192.168.10.40",
        "192.168.30.10",
    ]
    results = scan_network(targets)
    for target, result in results.items():
        print(f"\n{'='*50}")
        print(f"[{target}]")
        print(result)    