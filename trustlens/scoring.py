"""TrustLens scoring engine.

Given an XRPL token (issuer + currency), produce a 0-100 trust score plus the
*reasons* behind it. The whole point is transparency: every point added or removed
is an explicit, named signal a human (or an agent) can inspect. No black boxes.

Score reads as: 100 = strongest safety signals, 0 = strongest rug/scam signals.
This is a risk heuristic, not financial advice or a guarantee.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import ledger

# Names that scammers impersonate on XRPL. An *unverified* issuer using one of
# these is a classic drainer pattern (fake RLUSD / fake "Ripple payout" tokens).
IMPERSONATION_NAMES = {
    "XRP", "RLUSD", "RIPPLE", "USD", "USDC", "USDT", "BTC", "ETH",
    "XRPL", "RIPPLEUSD", "STABLE", "REWARD", "AIRDROP", "CLAIM",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "good": 4}


@dataclass
class Reason:
    """One named contribution to the score."""

    signal: str          # machine key, e.g. "issuer_blackholed"
    label: str           # human sentence
    severity: str        # good | low | medium | high | critical
    points: int          # signed contribution to the score


@dataclass
class TokenScore:
    issuer: str
    currency: str
    currency_name: str
    score: int
    verdict: str
    reasons: list[Reason] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    disclaimer: str = (
        "TrustLens is an on-ledger risk heuristic, not financial advice and not a "
        "guarantee of safety. Always do your own research."
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reasons"] = sorted(
            d["reasons"], key=lambda r: SEVERITY_ORDER.get(r["severity"], 9)
        )
        return d


def normalize_currency(code: str) -> str:
    """Turn user input into a ledger currency code.

    Accepts a 3-char code ("USD"), a 40-char hex code, or a longer human name
    ("SOLO", "MyToken") which is encoded to the 160-bit hex form the ledger uses.
    """
    code = code.strip()
    if len(code) == 3:
        return code
    if len(code) == 40 and all(c in "0123456789abcdefABCDEF" for c in code):
        return code.upper()
    return code.encode("ascii", errors="ignore").hex().upper().ljust(40, "0")


def decode_currency(code: str) -> str:
    """Human-readable currency name. XRPL codes are 3-char ASCII or 40-char hex."""
    if len(code) == 40:
        try:
            raw = bytes.fromhex(code)
            text = raw.rstrip(b"\x00").decode("ascii", errors="ignore").strip()
            return text or code
        except ValueError:
            return code
    return code


def _verdict(score: int) -> str:
    if score >= 75:
        return "trusted"
    if score >= 55:
        return "caution"
    if score >= 35:
        return "risky"
    return "danger"


def score_token(issuer: str, currency: str) -> TokenScore:
    """Fetch live mainnet data and compute the trust score for one token.

    ``currency`` may be a 3-char code, a token name, or 40-char hex; it is
    normalized to the ledger currency code here so every caller (CLI, API, MCP)
    behaves identically.
    """
    currency = normalize_currency(currency)
    currency_name = decode_currency(currency)
    reasons: list[Reason] = []
    facts: dict[str, Any] = {}

    info = ledger.account_info(issuer)
    if info.get("error"):
        # Issuer account doesn't exist / never activated -> nothing to trust.
        return TokenScore(
            issuer=issuer,
            currency=currency,
            currency_name=currency_name,
            score=0,
            verdict="danger",
            reasons=[
                Reason(
                    "issuer_not_found",
                    "Issuer account does not exist on the ledger.",
                    "critical",
                    0,
                )
            ],
            facts={"account_error": info.get("error")},
        )

    account_data = info.get("account_data", {})
    flags = info.get("account_flags", {})
    domain_hex = account_data.get("Domain")
    has_regular_key = bool(account_data.get("RegularKey"))
    # A signer list (multisig) means the account can still sign even with the master
    # key disabled -- so it is NOT truly blackholed.
    signer_lists = account_data.get("signer_lists") or info.get("signer_lists") or []
    has_signer_list = any(
        sl.get("SignerEntries") for sl in signer_lists if isinstance(sl, dict)
    )
    sequence = account_data.get("Sequence", 0)

    # --- Baseline. We build up from a neutral midpoint. ---
    score = 50

    # --- Identity first: every other signal is judged in light of who the issuer is. ---
    # An anonymous issuer that can mint more supply is a rug risk; a domain-verified
    # one doing the same is a normal managed stablecoin. Resolve identity up front.
    domain = None
    if domain_hex:
        try:
            domain = bytes.fromhex(domain_hex).decode("ascii", errors="ignore").strip()
        except ValueError:
            domain = None
    facts["domain"] = domain
    domain_verified = bool(domain)  # MVP: a domain is set. Full xrp-ledger.toml check is a later pass.
    if domain_verified:
        score += 8
        reasons.append(
            Reason(
                "domain_set",
                f"Issuer publishes a domain ({domain}) linking an off-ledger identity.",
                "good",
                8,
            )
        )
    else:
        score -= 6
        reasons.append(
            Reason(
                "no_domain",
                "Issuer publishes no domain: no off-ledger identity to hold accountable.",
                "medium",
                -6,
            )
        )

    # --- Issuer control: can they mint more or move the rug? ---
    disabled_master = bool(flags.get("disableMasterKey"))
    blackholed = disabled_master and not has_regular_key and not has_signer_list
    facts["blackholed"] = bool(blackholed)
    facts["multisig_issuer"] = bool(has_signer_list)
    if blackholed:
        score += 22
        reasons.append(
            Reason(
                "issuer_blackholed",
                "Issuer is blackholed (master key disabled, no regular key or signer list): "
                "supply is fixed and the issuer can no longer sign transactions.",
                "good",
                22,
            )
        )
    elif disabled_master and has_signer_list and domain_verified:
        score += 8
        reasons.append(
            Reason(
                "issuer_governed_multisig",
                "Master key is disabled and the account is governed by a multisig under a "
                "verified identity - an accountable, institutional-style setup.",
                "good",
                8,
            )
        )
    elif domain_verified:
        score -= 3
        reasons.append(
            Reason(
                "issuer_active_verified",
                "Issuer can still sign and mint more supply, but publishes a verified "
                "identity - normal for a managed stablecoin.",
                "low",
                -3,
            )
        )
    else:
        score -= 14
        reasons.append(
            Reason(
                "issuer_active_anon",
                "Anonymous issuer can still sign and mint more supply at will: "
                "infinite-mint / rug risk.",
                "high",
                -14,
            )
        )

    # --- Freeze / clawback: can the issuer seize or lock holders' tokens? ---
    if flags.get("globalFreeze"):
        score -= 30
        reasons.append(
            Reason(
                "global_freeze_on",
                "Global Freeze is currently ON: holders cannot trade this token right now.",
                "critical",
                -30,
            )
        )
    if flags.get("noFreeze"):
        score += 8
        reasons.append(
            Reason(
                "no_freeze",
                "Issuer has permanently given up the ability to freeze this token (NoFreeze).",
                "good",
                8,
            )
        )

    # Clawback is expected/legitimate for a domain-verified regulated stablecoin,
    # but on an anonymous token it means the issuer can seize your balance.
    clawback = flags.get("allowTrustLineClawback")
    facts["clawback_enabled"] = bool(clawback)
    if clawback:
        if domain_verified:
            score -= 3
            reasons.append(
                Reason(
                    "clawback_verified_issuer",
                    "Issuer can claw back tokens, but publishes a domain - typical of a "
                    "regulated stablecoin rather than a scam.",
                    "low",
                    -3,
                )
            )
        else:
            score -= 16
            reasons.append(
                Reason(
                    "clawback_anon_issuer",
                    "Issuer can claw back (seize) your tokens and publishes no domain.",
                    "high",
                    -16,
                )
            )

    # An impersonation *name* alone isn't enough to convict: a fresh drainer with 2
    # holders and no liquidity is a very different animal from a long-running,
    # widely-held, liquid token that simply never set an on-chain Domain flag (common
    # among older/legacy gateways). Detect the name collision here, but wait until
    # holder/liquidity footprint is known (below) before deciding how hard to penalize.
    impersonation_candidate = currency_name.upper() in IMPERSONATION_NAMES and not domain_verified

    # --- Supply distribution & holders ---
    gb = ledger.gateway_balances(issuer)
    obligations = gb.get("obligations", {}) or {}
    supply = None
    try:
        supply = float(obligations.get(currency)) if obligations.get(currency) else None
    except (TypeError, ValueError):
        supply = None
    facts["circulating_supply"] = supply

    lines = ledger.account_lines(issuer, currency)
    balances = lines["balances"]
    holder_count = len(balances)
    facts["holder_count"] = holder_count if not lines["capped"] else f"{holder_count}+"
    facts["holders_capped"] = lines["capped"]

    if holder_count == 0:
        score -= 20
        reasons.append(
            Reason(
                "no_holders",
                "No trustlines hold this token: nobody has taken it up.",
                "high",
                -20,
            )
        )
    elif holder_count < 20 and not lines["capped"]:
        score -= 10
        reasons.append(
            Reason(
                "few_holders",
                f"Only {holder_count} holders: thin distribution, easy to move the price.",
                "medium",
                -10,
            )
        )
    elif holder_count >= 200 or lines["capped"]:
        score += 8
        reasons.append(
            Reason(
                "many_holders",
                f"Broad distribution ({facts['holder_count']} holders).",
                "good",
                8,
            )
        )

    # Top-holder concentration (excluding the issuer's own obligations view).
    if balances:
        total_held = sum(balances)
        top = max(balances)
        top_share = top / total_held if total_held else 0
        facts["top_holder_share"] = round(top_share, 4)
        # For a verified issuer the biggest holder is usually a treasury/AMM/exchange,
        # not a rug wallet, so we weight concentration more gently in that case.
        soften = 0.5 if domain_verified else 1.0
        if top_share >= 0.6:
            pts = -round(18 * soften)
            score += pts
            reasons.append(
                Reason(
                    "supply_concentrated",
                    f"A single holder controls {top_share:.0%} of circulating supply - "
                    "high rug/dump risk.",
                    "high" if not domain_verified else "medium",
                    pts,
                )
            )
        elif top_share >= 0.35:
            pts = -round(8 * soften)
            score += pts
            reasons.append(
                Reason(
                    "supply_somewhat_concentrated",
                    f"Top holder controls {top_share:.0%} of supply.",
                    "medium",
                    pts,
                )
            )

    # --- Liquidity: is there an AMM pool to exit into? ---
    amm = ledger.amm_info(issuer, currency)
    if amm:
        try:
            xrp_side = amm.get("amount")
            xrp_drops = float(xrp_side) if isinstance(xrp_side, str) else 0.0
            xrp_amount = xrp_drops / 1_000_000
        except (TypeError, ValueError):
            xrp_amount = 0.0
        facts["amm_xrp_liquidity"] = round(xrp_amount, 2)
        if xrp_amount >= 1000:
            score += 10
            reasons.append(
                Reason(
                    "amm_liquid",
                    f"AMM pool holds ~{xrp_amount:,.0f} XRP of liquidity: there is a way out.",
                    "good",
                    10,
                )
            )
        else:
            score += 3
            reasons.append(
                Reason(
                    "amm_thin",
                    f"An AMM pool exists but is thin (~{xrp_amount:,.0f} XRP).",
                    "low",
                    3,
                )
            )
    else:
        facts["amm_xrp_liquidity"] = 0
        score -= 6
        reasons.append(
            Reason(
                "no_amm",
                "No CURRENCY/XRP AMM pool found: harder to exit the position.",
                "medium",
                -6,
            )
        )

    # --- Impersonation, resolved: penalize hardest when the footprint looks like a
    # fresh drainer (thin holders, no real liquidity); soften when the token shows
    # real usage a 2-holder scam would never have, while still flagging the missing
    # on-chain identity proof. ---
    if impersonation_candidate:
        established = holder_count >= 50 or lines["capped"] or facts["amm_xrp_liquidity"] >= 500
        if established:
            score -= 10
            reasons.append(
                Reason(
                    "impersonation_but_established",
                    f"Token name '{currency_name}' mimics a well-known asset and the issuer "
                    "is unverified, but real usage (holders/liquidity) is inconsistent with a "
                    "fresh drainer. Still verify the issuer independently.",
                    "medium",
                    -10,
                )
            )
        else:
            score -= 25
            reasons.append(
                Reason(
                    "impersonation",
                    f"Token name '{currency_name}' mimics a well-known asset, the issuer is "
                    "unverified, and holders/liquidity are thin - a common fresh-drainer "
                    "pattern on XRPL.",
                    "critical",
                    -25,
                )
            )

    score = max(0, min(100, score))
    return TokenScore(
        issuer=issuer,
        currency=currency,
        currency_name=currency_name,
        score=score,
        verdict=_verdict(score),
        reasons=reasons,
        facts=facts,
    )
