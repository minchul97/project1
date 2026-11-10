import socket

def check(target, port=23):
    """
    N-08: Telnet 평문 프로토콜 사용 여부 점검
    Telnet(기본 23포트)이 열려있으면 평문 통신 취약점으로 판단합니다.
    """
    result = {
        "ncode": "N-08",
        "item": "Telnet 평문 프로토콜 사용",
        "target": f"{target}:{port}",
        "vulnerable": False,
        "risk": "중",
        "detail": "",
        "action": "Telnet 서비스 비활성화 후 SSH 사용"
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        conn = sock.connect_ex((target, port))

        if conn == 0:
            rsult["vulnerable"] = True
            result["detail"] = f"Telnet {port} 포트 열려있음 (평문 통신)"
        else:
            result["detail"] = f"Telnet {port} 포트 차단됨"

        sock.close()

    except Exception as e:
        result["detail"] = f"점검 실패 ({type(e).__name__})"

    return result


if __name__ == "__main__":
    target = "192.168.10.20"
    r = check(target)
    print(f"[{r['ncode']}] {r['item']}")
    print(f"  대상: {r['target']}")
    print(f"  취약 여부: {'취약' if r['vulnerable'] else '양호'}")
    print(f"  상세: {r['detail']}")