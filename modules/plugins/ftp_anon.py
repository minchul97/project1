from ftplib import FTP

def check(target,port=21):
    """
    N-21: FTP 익명 접속 허용 여부 점검
    익명(anonymous) 로그인이 가능하면 취약점으로 판단됩니다.
    """
    result = {
        "ncode": "N-21",
        "item": "FTP 익명 접속 허용",
        "target": f"{target}:{port}",
        "vulnerable": False,
        "risk": "중",
        "detail": "",
        "action": "vsftpd.coonf에서 anonymous_enable=NO 설정"
    }

    try:
        ftp = FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login()

        result["vulnerable"] = True
        result["detail"] = "익명(anonymous) 로그인 성공"
        ftp.quit()

    except Exception as e:
        result["detail"] = f"익명 로그인 차단됨 ({type(e).__name__})"

    return result


if __name__ == "__main__":
    target = "192.168.10.30"
    r = check(target)
    print(f"[{r['ncode']}] {r['item']}")
    print(f"  대상: {r['target']}")
    print(f"  취약 여부: {'취약' if r['vulnerable'] else '양호'}")
    print(f"  상세: {r['detail']}")