import socket

def check(target, port=3306):
    """
    N-27: DB 외부 노출 여부 점검
    외부에서 DB 포트(기본 3306)에 접속 가능하면 취약점으로 판단합니다.
    """
    result = {
        "ncode": "N-27",
        "item": "DB 외부 노출",
        "target": f"{target}:{port}",
        "vulnerable": False,
        "risk": "상",
        "detail": "",
        "action": "MariaDB bind-address를 127.0.0.1로 설정하여 외부 접근 차단"
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        conn = sock.connect_ex((target, port))

        if conn == 0:
            result["vulnerable"] = True
            result["detail"] = f"외부에서 {port} 포트 접속 성공"
        else:
            result["detail"] = f"{port} 포트 접근 차단됨"

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