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


def list_currencies(issuer: str) -> list[dict[str, str]]:
    """Every currency a given issuer actually has in circulation, decoded.

    An XRPL issuer account can issue more than one token (a single gateway
    commonly issues USD, EUR, BTC, etc from one address), so "issuer" alone
    doesn't always uniquely identify a token. This lets a caller ask "what
    does this address even issue?" before -- or instead of -- picking one.
    """
    gb = ledger.gateway_balances(issuer)
    codes = sorted((gb.get("obligations") or {}).keys())
    return [{"currency": c, "currency_name": decode_currency(c)} for c in codes]


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

    # Pin every remaining lookup in this call to the exact ledger account_info just
    # resolved. xrplcluster.com load-balances across many nodes; without this, each
    # subsequent call independently re-resolves "validated" against whichever node
    # answers it, and since the ledger advances every ~3-5s that's a moving target --
    # confirmed live to silently truncate pagination and drop the AMM lookup entirely.
    pinned_ledger = info.get("ledger_index", "validated")

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

    # A Domain field alone proves nothing -- anyone can set it to any string,
    # including a domain they don't own. Real verification requires that domain's
    # own xrp-ledger.toml to list this exact address back (a two-way link only the
    # real domain owner can produce). Every downstream "verified identity" benefit
    # below (softer clawback treatment, multisig-governance credit, impersonation
    # exemption, softer concentration weighting) now requires that real proof, not
    # just a bare Domain field -- previously any of those could be unlocked by
    # setting Domain to literally any string, including one the issuer never owned.
    toml_result: bool | None = ledger.verify_toml_domain(domain, issuer) if domain else None
    facts["domain_toml_verified"] = toml_result
    domain_verified = toml_result is True

    if domain_verified:
        score += 10
        reasons.append(
            Reason(
                "domain_verified",
                f"Issuer's domain ({domain}) publishes an xrp-ledger.toml file that verifies "
                "this exact address - a real, two-way-confirmed identity link.",
                "good",
                10,
            )
        )
    elif domain and toml_result is False:
        score -= 10
        reasons.append(
            Reason(
                "domain_unverified",
                f"Issuer publishes a domain ({domain}), but it does NOT verify this address "
                "(no matching xrp-ledger.toml entry) - the domain doesn't confirm ownership.",
                "high",
                -10,
            )
        )
    elif domain:
        # toml_result is None: couldn't determine (our network/timeout/parse issue),
        # not a signal about the issuer. Smaller partial credit either way rather
        # than fully rewarding or punishing based on our own connectivity.
        score += 4
        reasons.append(
            Reason(
                "domain_set_unverifiable",
                f"Issuer publishes a domain ({domain}), but its xrp-ledger.toml could not be "
                "checked right now - verification incomplete, not necessarily suspicious.",
                "low",
                4,
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

    # An impersonation *name* alone isn't enough to convict: a fresh drainer with 2
    # holders and no liquidity is a very different animal from a long-running,
    # widely-held, liquid token that simply never set an on-chain Domain flag (common
    # among older/legacy gateways). Detect the name collision here, but wait until
    # holder/liquidity footprint is known (below) before deciding how hard to penalize.
    impersonation_candidate = currency_name.upper() in IMPERSONATION_NAMES and not domain_verified

    # --- Supply distribution & holders (moved ahead of issuer-control/clawback so
    # both can use `established`, below, the same way impersonation already did) ---
    gb = ledger.gateway_balances(issuer, pinned_ledger)
    obligations = gb.get("obligations", {}) or {}
    supply = None
    try:
        supply = float(obligations.get(currency)) if obligations.get(currency) else None
    except (TypeError, ValueError):
        supply = None
    facts["circulating_supply"] = supply

    # Public XRPL RPC infra can still return an inconsistent (usually truncated,
    # never fabricated) trustline walk even with a pinned ledger + sticky endpoint
    # (confirmed live 2026-07-10: repeated identical calls varied 260/785/1546+
    # holders for the same real token, with no error signal to retry on). A walk
    # can only ever UNDER-count real holders, never invent extra ones, so one retry
    # and keeping whichever attempt found more is a cheap, defensible bias toward
    # the more-complete answer -- not a guarantee, but meaningfully better than one
    # shot. If this keeps mattering, the real fix is a dedicated/paid RPC provider.
    lines = ledger.account_lines(issuer, currency, pinned_ledger)
    retry = ledger.account_lines(issuer, currency, pinned_ledger)
    if len(retry["balances"]) > len(lines["balances"]):
        lines = retry
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
    amm = ledger.amm_info(issuer, currency, pinned_ledger)
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

    # A token with a real, wide holder base and real liquidity is very hard for a
    # fresh drainer to fake -- every actual scam found in this codebase's own
    # scam-hunt (2026-07-09) had 1-2 holders and zero liquidity, no exceptions.
    # Real usage this substantial is itself meaningful evidence, independent of
    # whether a domain happens to be cryptographically verified yet. Used below
    # by issuer-control, clawback, AND impersonation (previously each computed
    # this -- or an inconsistent version of it -- separately).
    established = holder_count >= 50 or lines["capped"] or facts["amm_xrp_liquidity"] >= 500

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
    elif domain and toml_result is None:
        # Domain set but we genuinely couldn't determine ownership (no toml published
        # at all -- common even for legitimate businesses, confirmed live: Circle's
        # own USDC issuer domain has no such file). Deliberately NOT the same
        # treatment as `toml_result is False` (a domain that HAS a real toml but
        # explicitly doesn't list this address -- actual evidence of a mismatch,
        # which stays in the harsher anon-equivalent tier below). Treating "couldn't
        # check" the same as fully anonymous overcorrected known-good real gateways
        # (USDC/USDT/SOLO) into "risky"/"danger" once the domain block stopped
        # giving free credit for a merely-set field.
        score -= 8
        reasons.append(
            Reason(
                "issuer_active_domain_unverified",
                "Issuer can still sign and mint more supply; publishes a domain but it "
                "isn't cryptographically verified - moderate risk, between anonymous "
                "and proven.",
                "medium",
                -8,
            )
        )
    elif established and toml_result is not False:
        # No domain at all, but real usage a fresh drainer couldn't fake. NOT
        # reached when toml_result is False (a PROVEN mismatch) -- actual evidence
        # the issuer lied about a specific domain is a stronger red flag than merely
        # lacking any claim, and shouldn't be forgiven just because the token also
        # has real holders/liquidity.
        score -= 8
        reasons.append(
            Reason(
                "issuer_active_established_footprint",
                "Issuer can still sign and mint more supply and publishes no domain, but "
                "real usage (holders/liquidity) is inconsistent with a fresh drainer - "
                "moderate risk, still verify independently.",
                "medium",
                -8,
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
        elif domain and toml_result is None:
            score -= 9
            reasons.append(
                Reason(
                    "clawback_domain_unverified",
                    "Issuer can claw back tokens; publishes a domain but it isn't "
                    "cryptographically verified - moderate risk.",
                    "medium",
                    -9,
                )
            )
        elif established and toml_result is not False:
            score -= 9
            reasons.append(
                Reason(
                    "clawback_established_footprint",
                    "Issuer can claw back tokens and publishes no domain, but real usage "
                    "(holders/liquidity) is inconsistent with a fresh drainer - moderate risk.",
                    "medium",
                    -9,
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

    # --- Impersonation, resolved: penalize hardest when the footprint looks like a
    # fresh drainer (thin holders, no real liquidity); soften when the token shows
    # real usage a 2-holder scam would never have, while still flagging the missing
    # on-chain identity proof. ---
    if impersonation_candidate:
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
