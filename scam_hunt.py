"""Scam-hunt validation pass.

Batch-scores a curated set of real, currently-live XRPL tokens: known
impersonation/scam candidates (sourced from XRPSCAN's public token list,
2026-07-09 — see trustlens/README.md or session notes for how candidates were
found) alongside known-good reference tokens. This both stress-tests scoring
calibration against real data and produces the numbers for a proof-anchored post.

Usage:
    python scam_hunt.py
"""
import json

from trustlens.scoring import score_token

# (label, issuer, currency, category) -- category is just for grouping the printout.
CASES = [
    # --- known-good reference tokens ---
    ("RLUSD (real, Ripple)", "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", "RLUSD", "good"),
    ("SOLO (real, Sologenic)", "rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz", "SOLO", "good"),

    # --- the 4-in-1 impersonation farm: one wallet, created 2026-07-06,
    #     issuing fake BTC + ETH + USDC + USDT simultaneously (2 holders each) ---
    ("BTC (FAKE - impersonation farm)", "rGESkMDtLd4ot85wCTxhzVf647UbYcWiTy", "BTC", "scam"),
    ("ETH (FAKE - impersonation farm)", "rGESkMDtLd4ot85wCTxhzVf647UbYcWiTy", "ETH", "scam"),
    ("USDC (FAKE - impersonation farm)", "rGESkMDtLd4ot85wCTxhzVf647UbYcWiTy", "USDC", "scam"),
    ("USDT (FAKE - impersonation farm)", "rGESkMDtLd4ot85wCTxhzVf647UbYcWiTy", "USDT", "scam"),

    # --- fake OUSD pair, both created 2026-07-03 (right after the OUSD scam
    #     alert covered by GrimmReaper/crypto.news on 2026-07-02) ---
    ("OUSD (FAKE #1)", "rHo7VUbSgooxiDdPktPsvZXCjqx9Ejxz56", "OUSD", "scam"),
    ("OUSD (FAKE #2)", "rJiZUhWHkyXcnNDksJzhRfkKkfaxvkBj8J", "OUSD", "scam"),

    # --- real blue-chip issuers, for direct side-by-side contrast ---
    ("BTC (real, Bitstamp-style gateway)", "rchGBxcD1A1C2tdxF6papQYZ8kjRKMYcL", "BTC", "good"),
    ("ETH (real gateway)", "rcA8X3TVMST1n3CJeAdGk1RdRCHii7N2h", "ETH", "good"),
    ("USDC (real gateway)", "rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE", "USDC", "good"),
    ("USDT (real gateway)", "rDnNaxiXctUarwQPvjjfHyhzhBxKu8yJNC", "USDT", "good"),
]


def main() -> None:
    results = []
    for label, issuer, currency, category in CASES:
        try:
            r = score_token(issuer, currency).to_dict()
            results.append({"label": label, "category": category, **r})
            print(f"{r['score']:>3}  {r['verdict']:<8}  {label}")
        except Exception as exc:  # noqa: BLE001 - keep going, report the failure
            print(f"ERR         {label}  ({exc})")
            results.append({"label": label, "category": category, "error": str(exc)})

    good = [r for r in results if r.get("category") == "good" and "score" in r]
    scam = [r for r in results if r.get("category") == "scam" and "score" in r]
    if good and scam:
        avg_good = sum(r["score"] for r in good) / len(good)
        avg_scam = sum(r["score"] for r in scam) / len(scam)
        print(f"\nAverage score, known-good tokens: {avg_good:.0f}/100")
        print(f"Average score, known-scam tokens: {avg_scam:.0f}/100")

    with open("scam_hunt_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nFull results written to scam_hunt_results.json")


if __name__ == "__main__":
    main()
