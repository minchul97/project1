import dns.zone
import dns.query
import dns.resolver

def check(target, domain="4trust.lab"):
    """
    N-36: DNS Zone Transfer 허용 여부 점검
    외부에서 Zone Transfer(AXFR)가 가능하면 취약점으로 판단합니다.
    """
    result = {
        "ncode": "N-36",
        "item": "DNS Zone Transfer 허용",
        "target": f"{target} ({domain})",
        "vulnerable": False,
        "risk": "상",
        "detail": "",
        "action": "named.conf에서 allow-transfer를 { none; } 또는 특정 IP로 제한"
    }

    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(target, domain, timeout=5)
        )

        records = []
        for name, node in zone.nodes.items():
            records.append(str(name))

        result["vulnerable"] = True
        result["detail"] = f"Zone Transfer 성공, 레코드 {len(records)}개 노출"

    except Exception as e:
        result["detail"] = f"Zone Transfer 차단됨 ({type(e).__name__})"

    return result


if __name__ == "__main__":
    target = "10.0.0.10"
    r = check(target)
    print(f"[{r['ncode']}] {r['item']}")
    print(f"  대상: {r['target']}")
    print(f"  취약 여부: {'취약' if r['vulnerable'] else '양호'}")
    print(f"  상세: {r['detail']}")