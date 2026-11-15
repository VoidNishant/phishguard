"""
Comprehensive Unit & Regression Test Suite for PhishGuard.
Validates:
1. Benign sites and search engines
2. False-positive resistance on ccTLDs (.co.uk, .com.au)
3. False-positive resistance on reputable developer/reference platforms (GitHub, Wikipedia)
4. Detection of IDN Homograph / Punycode attacks
5. Detection of RFC 3986 '@' userinfo tricks
6. Detection of IP address hostname evasion
7. Detection of Brand Spoofing in subdomains
8. Detection of pseudo-protocols (javascript:, data:)
9. Detection of non-standard port anomalies
10. Graceful handling of malformed inputs without exceptions
"""

from detector import PhishGuardEngine
from features import extract_features, extract_domain_components, is_ip_address

def run_full_audit_test_suite():
    engine = PhishGuardEngine()
    print("=" * 65)
    print("[*] STARTING PHISHGUARD AUDIT TEST SUITE")
    print("=" * 65)

    tests_passed = 0
    total_tests = 0

    def assert_test(condition, test_name, detail=""):
        nonlocal tests_passed, total_tests
        total_tests += 1
        if condition:
            tests_passed += 1
            print(f" [PASS] {test_name} {f'({detail})' if detail else ''}")
        else:
            print(f" [FAIL] {test_name} -> FAILED: {detail}")
            assert False, f"Test failed: {test_name}"

    # 1. Benign Standard
    u1 = "https://www.google.com/search?q=cybersecurity"
    r1 = engine.analyze(u1)
    assert_test(r1["verdict"] == "LEGITIMATE / SAFE" and r1["composite_risk_score"] < 25, "Standard Benign URL", f"Score: {r1['composite_risk_score']}%")

    # 2. ccTLD False-Positive Check (PayPal UK)
    u2 = "https://www.paypal.co.uk"
    r2 = engine.analyze(u2)
    assert_test(r2["verdict"] == "LEGITIMATE / SAFE", "ccTLD False-Positive Check (.co.uk)", f"Score: {r2['composite_risk_score']}%")

    # 3. Reputable Reference Platform False-Positive Check (Wikipedia PayPal)
    u3 = "https://en.wikipedia.org/wiki/PayPal"
    r3 = engine.analyze(u3)
    assert_test(r3["verdict"] == "LEGITIMATE / SAFE", "Reputable Platform Reference (Wikipedia)", f"Score: {r3['composite_risk_score']}%")

    # 4. GitHub Developer Repo False-Positive Check
    u4 = "https://github.com/paypal/rest-api-sdk-python"
    r4 = engine.analyze(u4)
    assert_test(r4["verdict"] == "LEGITIMATE / SAFE", "Developer Platform Reference (GitHub)", f"Score: {r4['composite_risk_score']}%")

    # 5. IDN Homograph / Punycode Attack
    u5 = "http://xn--pypal-4ve.com/signin"
    r5 = engine.analyze(u5)
    has_homograph_rule = any(x["rule"].rule_id == "R_PUNYCODE_HOMOGRAPH" for x in r5["triggered_rules"])
    assert_test(r5["verdict"] == "PHISHING / MALICIOUS" and has_homograph_rule, "IDN Homograph Punycode Attack", f"Score: {r5['composite_risk_score']}%")

    # 6. Raw IP Hostname Evasion
    u6 = "http://192.168.1.101/secure/login.php?user=target"
    r6 = engine.analyze(u6)
    has_ip_rule = any(x["rule"].rule_id == "R_IP_HOST" for x in r6["triggered_rules"])
    assert_test(r6["verdict"] == "PHISHING / MALICIOUS" and has_ip_rule, "Raw IP Hostname Evasion", f"Score: {r6['composite_risk_score']}%")

    # 7. RFC 3986 '@' Userinfo Trick
    u7 = "http://google.com@attacker-site.com/login"
    r7 = engine.analyze(u7)
    has_at_rule = any(x["rule"].rule_id == "R_AT_SYMBOL" for x in r7["triggered_rules"])
    assert_test(r7["verdict"] == "PHISHING / MALICIOUS" and has_at_rule, "RFC 3986 Userinfo '@' Trick", f"Score: {r7['composite_risk_score']}%")

    # 8. Subdomain Brand Impersonation
    u8 = "http://paypal.com.account-update.xyz/login.php"
    r8 = engine.analyze(u8)
    has_brand_rule = any(x["rule"].rule_id == "R_BRAND_SPOOF" for x in r8["triggered_rules"])
    assert_test(r8["verdict"] == "PHISHING / MALICIOUS" and has_brand_rule, "Subdomain Brand Spoofing", f"Score: {r8['composite_risk_score']}%")

    # 9. Client-side Pseudo-Protocol (XSS / Payload)
    u9 = "javascript:alert(document.cookie)"
    r9 = engine.analyze(u9)
    assert_test(r9["verdict"] == "PHISHING / MALICIOUS" and r9["composite_risk_score"] == 100.0, "Script Pseudo-Protocol Block", f"Score: {r9['composite_risk_score']}%")

    # 10. Non-Standard Web Port Anomaly
    u10 = "http://attacker-server.com:4444/login.php"
    r10 = engine.analyze(u10)
    has_port_rule = any(x["rule"].rule_id == "R_NON_STANDARD_PORT" for x in r10["triggered_rules"])
    assert_test(r10["verdict"] in ["PHISHING / MALICIOUS", "SUSPICIOUS"] and has_port_rule, "Non-Standard Port Anomaly", f"Score: {r10['composite_risk_score']}%")

    # 11. Malformed Input Handled Gracefully (Empty / No Scheme)
    r11 = engine.analyze("https://")
    assert_test("error" in r11, "Malformed Hostless URL Handled Gracefully", r11.get("error", ""))

    # 12. Safe IP Dissection
    d_ip = engine.dissect_url("http://192.168.1.1/login")
    assert_test(d_ip["subdomain"] == "(none - IP)" and d_ip["tld"] == "(none - IP)", "IP Dissection Format Validation", f"subdomain: {d_ip['subdomain']}")

    print("=" * 65)
    print(f"[SUCCESS] AUDIT COMPLETE: {tests_passed}/{total_tests} Tests Passed Successfully! (100%)")
    print("=" * 65)


if __name__ == "__main__":
    run_full_audit_test_suite()
