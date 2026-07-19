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
                supply=1000.0, currency="ABC", holders=None, amm_xrp=None,
                toml_verified=None, capped=False):
    """Patch the ledger module with a fixed token profile.

    ``toml_verified`` mocks the xrp-ledger.toml check added 2026-07-10 (real
    domain ownership proof, not just a Domain field being set): True/False/None
    matching ``ledger.verify_toml_domain``'s own return contract. Only matters
    when ``domain`` is also set -- score_token skips the check entirely otherwise.
    """
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
        "balances": holders if holders is not None else [], "capped": capped
    }
    ledger.amm_info = lambda issuer, cur, ledger_index="validated": (
        {"amount": str(int(amm_xrp * 1_000_000))} if amm_xrp else None
    )
    ledger.verify_toml_domain = lambda domain, issuer: toml_verified


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

# 3. Locked legit token: blackholed, VERIFIED domain, no freeze, many holders, deep AMM.
mock_ledger(
    flags={"disableMasterKey": True, "noFreeze": True}, domain="example.com",
    currency="GOOD", supply=1_000_000.0,
    holders=[100.0] * 300, amm_xrp=50_000, toml_verified=True,
)
r = scoring.score_token("rGood", "GOOD").to_dict()
check("blackholed legit -> trusted", r["verdict"] == "trusted", f"got {r['score']}/{r['verdict']}")
check("blackhole reason present",
      any(x["signal"] == "issuer_blackholed" for x in r["reasons"]))

# 3b. Same domain field, but its xrp-ledger.toml does NOT list this address (a
# scammer typing in a domain they don't own). Must NOT get any of the "verified
# identity" downstream benefits -- this is the exact loophole the toml check closes.
mock_ledger(
    flags={"disableMasterKey": False, "allowTrustLineClawback": True}, domain="ripple.com",
    currency="FAKE", supply=1000.0, holders=[900.0, 100.0], amm_xrp=None, toml_verified=False,
)
r = scoring.score_token("rLiar", "FAKE").to_dict()
check("unverified domain claim is flagged",
      any(x["signal"] == "domain_unverified" for x in r["reasons"]))
check("unverified domain does NOT soften clawback",
      any(x["signal"] == "clawback_anon_issuer" for x in r["reasons"]),
      "expected the anon-issuer clawback path, not the verified-issuer one")
check("unverified domain does NOT get the multisig/verified-identity credit",
      not any(x["signal"] in ("issuer_active_verified", "issuer_governed_multisig") for x in r["reasons"]))

# 3c. Domain set but its toml couldn't be checked (network/parse issue on our end) --
# must be treated as neutral/unverifiable, not a suspicion signal, and should land in
# the MIDDLE tier for issuer-control/clawback too -- not the fully-anonymous tier
# (that regression was caught live 2026-07-10: USDC/USDT/SOLO, all real, all with a
# real domain that simply has no published toml, dropped from trusted/caution into
# risky/danger before this middle tier existed).
mock_ledger(
    flags={"disableMasterKey": False, "allowTrustLineClawback": True}, domain="example.org",
    currency="XYZ", supply=1000.0, holders=[500.0, 500.0], amm_xrp=None, toml_verified=None,
)
r = scoring.score_token("rUnknown", "XYZ").to_dict()
check("unverifiable domain is neutral, not accusatory",
      any(x["signal"] == "domain_set_unverifiable" for x in r["reasons"]))
check("unverifiable domain does NOT get flagged as a lie",
      not any(x["signal"] == "domain_unverified" for x in r["reasons"]))
check("unverifiable domain gets the middle issuer-control tier, not fully anon",
      any(x["signal"] == "issuer_active_domain_unverified" for x in r["reasons"]),
      "expected the middle tier, not issuer_active_anon")
check("unverifiable domain gets the middle clawback tier, not fully anon",
      any(x["signal"] == "clawback_domain_unverified" for x in r["reasons"]),
      "expected the middle tier, not clawback_anon_issuer")

# 3d. No domain at all, but a wide holder base and deep liquidity a fresh drainer
# couldn't fake. Real usage should still earn the middle tier -- added 2026-07-10
# per Bjorn's call ("go strict, but stay consistent with what the impersonation
# check already does for established tokens") after USDC/USDT/SOLO dropped too far
# under the plain domain-based middle tier alone.
mock_ledger(
    flags={"disableMasterKey": False, "allowTrustLineClawback": True}, domain=None,
    currency="ESTB", supply=1_000_000.0, holders=[100.0] * 300, amm_xrp=5_000,
)
r = scoring.score_token("rEstablished", "ESTB").to_dict()
check("no-domain but established gets the middle issuer-control tier",
      any(x["signal"] == "issuer_active_established_footprint" for x in r["reasons"]),
      "expected the footprint-rescue tier, not issuer_active_anon")
check("no-domain but established gets the middle clawback tier",
      any(x["signal"] == "clawback_established_footprint" for x in r["reasons"]),
      "expected the footprint-rescue tier, not clawback_anon_issuer")

# 3e. A PROVEN mismatch (real toml exists, actively does NOT list this address) must
# NOT be rescued by established footprint -- real evidence of a lie is worse than
# merely lacking proof, even if the token also has real holders/liquidity.
mock_ledger(
    flags={"disableMasterKey": False, "allowTrustLineClawback": True}, domain="ripple.com",
    currency="LIAR2", supply=1_000_000.0, holders=[100.0] * 300, amm_xrp=5_000, toml_verified=False,
)
r = scoring.score_token("rProvenLiarButBig", "LIAR2").to_dict()
check("established footprint does NOT rescue a proven domain mismatch",
      any(x["signal"] == "issuer_active_anon" for x in r["reasons"]),
      "a proven mismatch should still fall to the harshest tier despite real usage")
check("established footprint does NOT rescue a proven clawback mismatch",
      any(x["signal"] == "clawback_anon_issuer" for x in r["reasons"]))

# 3f. Top-holder concentration must disclose when it's a SAMPLE, not the full
# holder set -- added 2026-07-15. account_lines isn't sorted by balance, so once
# the walk hits the page cap (a very-widely-held token like SOLO), the "top
# holder" found is only the largest one seen in that partial sample; presenting
# it as if exhaustive would contradict the whole "no black box" premise.
mock_ledger(
    flags={"disableMasterKey": False}, domain=None,
    currency="BIG", supply=1_000_000.0, holders=[900.0, 100.0], amm_xrp=None, capped=True,
)
r = scoring.score_token("rHugeHolderCount", "BIG").to_dict()
check("capped walk sets top_holder_sampled fact", r["facts"].get("top_holder_sampled") is True)
concentrated = next((x for x in r["reasons"] if x["signal"] == "supply_concentrated"), None)
check("sampled concentration reason discloses it's a sample",
      concentrated is not None and "sample" in concentrated["label"].lower(),
      str(concentrated))

# 3g. Same token, NOT capped -- must NOT carry the sampling caveat (this is the
# common case: most tokens have far fewer holders than the page cap).
mock_ledger(
    flags={"disableMasterKey": False}, domain=None,
    currency="SMALL", supply=1_000_000.0, holders=[900.0, 100.0], amm_xrp=None, capped=False,
)
r = scoring.score_token("rNormalHolderCount", "SMALL").to_dict()
check("uncapped walk does NOT set top_holder_sampled", r["facts"].get("top_holder_sampled") is False)
concentrated = next((x for x in r["reasons"] if x["signal"] == "supply_concentrated"), None)
check("uncapped concentration reason has no sampling caveat",
      concentrated is not None and "sample" not in concentrated["label"].lower(),
      str(concentrated))

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
