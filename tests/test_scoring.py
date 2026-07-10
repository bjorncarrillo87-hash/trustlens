"""Deterministic scoring tests with a mocked ledger.

Run: python tests/test_scoring.py   (no pytest needed)

These pin down the *ends* of the scale (clear scam -> danger, locked legit token ->
trusted) and the identity-aware nuances, so recalibrating weights can't silently
break the verdicts that matter.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustlens import ledger, scoring  # noqa: E402


def hexstr(s: str) -> str:
    return s.encode("ascii").hex().upper()


def mock_ledger(*, flags, domain=None, regular_key=False, signer_list=False,
                supply=1000.0, currency="ABC", holders=None, amm_xrp=None):
    """Patch the ledger module with a fixed token profile."""
    account_data = {"Sequence": 100}
    if domain:
        account_data["Domain"] = hexstr(domain)
    if regular_key:
        account_data["RegularKey"] = "rSomeRegularKey"
    if signer_list:
        account_data["signer_lists"] = [{"SignerEntries": [{"SignerEntry": {}}]}]

    # Real signatures now take an optional ledger_index (pinned by score_token to
    # avoid the cross-node pagination drift found 2026-07-10); mocks accept and
    # ignore it so they match without asserting on the exact value passed.
    ledger.account_info = lambda issuer: {
        "account_data": account_data, "account_flags": flags, "ledger_index": 999,
    }
    ledger.gateway_balances = lambda issuer, ledger_index="validated": {
        "obligations": {currency: str(supply)}
    }
    ledger.account_lines = lambda issuer, cur, ledger_index="validated", **kw: {
        "balances": holders if holders is not None else [], "capped": False
    }
    ledger.amm_info = lambda issuer, cur, ledger_index="validated": (
        {"amount": str(int(amm_xrp * 1_000_000))} if amm_xrp else None
    )


PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


# 1. Clear rug: anonymous, active (can mint), clawback, few concentrated holders, no AMM.
mock_ledger(
    flags={"disableMasterKey": False, "allowTrustLineClawback": True},
    domain=None, currency="MOON", supply=1000.0, holders=[900.0, 50.0, 50.0], amm_xrp=None,
)
r = scoring.score_token("rScam", "MOON").to_dict()
check("anonymous rug -> danger", r["verdict"] == "danger", f"got {r['score']}/{r['verdict']}")
check("anonymous rug flags mint risk",
      any(x["signal"] == "issuer_active_anon" for x in r["reasons"]))
check("anonymous rug flags clawback",
      any(x["signal"] == "clawback_anon_issuer" for x in r["reasons"]))

# 2. Impersonation: token named RLUSD from an anonymous issuer.
mock_ledger(
    flags={"disableMasterKey": False}, domain=None, currency="RLUSD",
    supply=1000.0, holders=[500.0, 500.0], amm_xrp=None,
)
r = scoring.score_token("rFakeRipple", "RLUSD").to_dict()
check("impersonation triggers", any(x["signal"] == "impersonation" for x in r["reasons"]))
check("impersonation -> danger/risky", r["verdict"] in ("danger", "risky"),
      f"got {r['score']}/{r['verdict']}")

# 3. Locked legit token: blackholed, domain, no freeze, many holders, deep AMM.
mock_ledger(
    flags={"disableMasterKey": True, "noFreeze": True}, domain="example.com",
    currency="GOOD", supply=1_000_000.0,
    holders=[100.0] * 300, amm_xrp=50_000,
)
r = scoring.score_token("rGood", "GOOD").to_dict()
check("blackholed legit -> trusted", r["verdict"] == "trusted", f"got {r['score']}/{r['verdict']}")
check("blackhole reason present",
      any(x["signal"] == "issuer_blackholed" for x in r["reasons"]))

# 4. Fake blackhole via multisig without a domain must NOT read as blackholed.
mock_ledger(
    flags={"disableMasterKey": True}, domain=None, signer_list=True,
    currency="TRIX", supply=1000.0, holders=[400.0, 300.0, 300.0], amm_xrp=None,
)
r = scoring.score_token("rMultisig", "TRIX").to_dict()
check("multisig != blackholed", not r["facts"]["blackholed"], str(r["facts"]))

# 5. Nonexistent issuer.
ledger.account_info = lambda issuer: {"error": "actNotFound"}
r = scoring.score_token("rNope", "ABC").to_dict()
check("missing issuer -> danger/0", r["score"] == 0 and r["verdict"] == "danger")

print(f"\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
