"""Read-only XRPL mainnet data access for TrustLens.

Everything here is a plain JSON-RPC call against a public XRPL node. No keys, no
signing, no state changes -- this module only ever *reads* the ledger. That is
deliberate: scoring a token must never be able to touch funds.
"""
from __future__ import annotations

import ipaddress
import socket
import time
import tomllib
from typing import Any

import requests

# Public mainnet JSON-RPC endpoints, tried in order. All read-only.
RPC_ENDPOINTS = [
    "https://xrplcluster.com/",
    "https://s1.ripple.com:51234/",
    "https://s2.ripple.com:51234/",
]

_TIMEOUT = 20

# Errors a rippled node returns as a normal HTTP 200 + JSON body (no exception raised
# by `requests`) when THAT SPECIFIC backend node can't currently answer -- not when
# the thing being asked about doesn't exist. Confirmed live via raw curl against
# xrplcluster.com (2026-07-10): back-to-back identical requests alternated between
# clean success and `{"error":"noNetwork","error_message":"InsufficientNetworkMode"}`,
# with server_info reporting all endpoints healthy throughout. A hostname like
# xrplcluster.com fronts many individual nodes; any single request can land on one
# that's transiently unable to serve "validated" queries even while the cluster as a
# whole is fine. Treating this the same as "account not found" was silently scoring
# real tokens as nonexistent (score 0/danger) during a momentary node hiccup.
_TRANSIENT_RPC_ERRORS = {"noNetwork"}


class LedgerError(RuntimeError):
    """Raised when every endpoint fails or the ledger returns an error we can't use."""


def rpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Call an XRPL JSON-RPC method, failing over across endpoints.

    Returns the ``result`` object. Ledger-level "not found" style errors are
    returned as-is (with an ``error`` key) so callers can distinguish "account
    doesn't exist" from "network is down". Transient per-node errors (see
    ``_TRANSIENT_RPC_ERRORS``) are retried against the next endpoint rather than
    returned as if they were a definitive answer.
    """
    payload = {"method": method, "params": [params]}
    last_exc: Exception | None = None
    for base in RPC_ENDPOINTS:
        try:
            resp = requests.post(base, json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            result = resp.json().get("result", {})
            if result.get("error") in _TRANSIENT_RPC_ERRORS:
                last_exc = LedgerError(f"{base} returned transient error: {result.get('error')}")
                time.sleep(0.2)
                continue
            return result
        except Exception as exc:  # noqa: BLE001 - endpoint fell over, try the next
            last_exc = exc
            time.sleep(0.2)
    raise LedgerError(f"all XRPL endpoints failed for {method}: {last_exc}")


def _rpc_sticky(method: str, params: dict[str, Any], session: requests.Session, sticky: list[str | None]) -> dict[str, Any]:
    """Like ``rpc``, but pins to ONE endpoint across a sequence of calls (tracked in
    the ``sticky`` one-item list) instead of retrying the full endpoint list fresh
    every time.

    Needed for multi-page ``marker``-based pagination: pinning ``ledger_index`` alone
    (see ``account_lines``) fixed single-shot calls like ``amm_info``, but pagination
    still drifted (confirmed live: holder count varied 1546+/capped vs 1292/uncapped
    across identical back-to-back calls). A hostname like ``xrplcluster.com`` load-
    balances across many backend nodes; a marker returned by node A resuming a walk
    isn't guaranteed to mean the same thing to node B, even for the same ledger. This
    keeps one physical node answering every page of one walk instead of a fresh,
    possibly-different node per page -- but falls back to the full endpoint list (and
    adopts whichever succeeds as the new sticky endpoint) if the sticky one degrades
    mid-walk, rather than hard-failing the whole walk over one bad node.
    """
    payload = {"method": method, "params": [params]}
    candidates = (
        [sticky[0]] + [e for e in RPC_ENDPOINTS if e != sticky[0]] if sticky[0] else RPC_ENDPOINTS
    )
    last_exc: Exception | None = None
    for base in candidates:
        try:
            resp = session.post(base, json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            result = resp.json().get("result", {})
            if result.get("error") in _TRANSIENT_RPC_ERRORS:
                last_exc = LedgerError(f"{base} returned transient error: {result.get('error')}")
                time.sleep(0.2)
                continue
            sticky[0] = base
            return result
        except Exception as exc:  # noqa: BLE001 - endpoint fell over, try the next
            last_exc = exc
            time.sleep(0.2)
    raise LedgerError(f"all XRPL endpoints failed for {method}: {last_exc}")


def account_info(address: str) -> dict[str, Any]:
    """Issuer account root + decoded account flags, or {'error': ...} if absent.

    ``signer_lists`` is requested because an account with the master key disabled
    but a multisig signer list is NOT blackholed -- it can still sign. Scoring needs
    to see that to avoid being fooled by a fake blackhole.
    """
    return rpc(
        "account_info",
        {"account": address, "ledger_index": "validated", "signer_lists": True},
    )


def gateway_balances(issuer: str, ledger_index: int | str = "validated") -> dict[str, Any]:
    """Total obligations (i.e. circulating supply) issued by ``issuer`` per currency."""
    return rpc(
        "gateway_balances",
        {"account": issuer, "ledger_index": ledger_index, "strict": True},
    )


def account_lines(
    issuer: str, currency: str, ledger_index: int | str = "validated", max_pages: int = 6, page: int = 400
) -> dict[str, Any]:
    """Walk trustlines to the issuer for one currency.

    From the issuer's point of view each line's ``balance`` is negative (the issuer
    owes the holder), so the holder's balance is the absolute value. We cap the walk
    at ``max_pages`` so a token with hundreds of thousands of holders can't hang a
    scoring request -- when capped we report ``holders_capped=True``.

    ``ledger_index`` should be a specific, already-resolved integer (not the string
    "validated") whenever more than one RPC call will be made against the same data,
    e.g. from ``score_token`` -- see ``_rpc_sticky`` for why pagination also pins to
    one endpoint for the whole walk, not just one ledger snapshot.
    """
    holders: list[float] = []
    marker: Any = None
    capped = False
    session = requests.Session()
    sticky: list[str | None] = [None]
    for i in range(max_pages):
        params: dict[str, Any] = {
            "account": issuer,
            "ledger_index": ledger_index,
            "limit": page,
        }
        if marker is not None:
            params["marker"] = marker
        result = _rpc_sticky("account_lines", params, session, sticky)
        for line in result.get("lines", []):
            if line.get("currency") != currency:
                continue
            try:
                bal = abs(float(line.get("balance", "0")))
            except (TypeError, ValueError):
                continue
            if bal > 0:
                holders.append(bal)
        marker = result.get("marker")
        if marker is None:
            break
        if i == max_pages - 1:
            capped = True
    return {"balances": holders, "capped": capped}


def amm_info(issuer: str, currency: str, ledger_index: int | str = "validated") -> dict[str, Any] | None:
    """AMM pool for CURRENCY/XRP, or None if no such pool exists."""
    result = rpc(
        "amm_info",
        {
            "asset": {"currency": "XRP"},
            "asset2": {"currency": currency, "issuer": issuer},
            "ledger_index": ledger_index,
        },
    )
    if result.get("error"):
        return None
    return result.get("amm")


_TOML_TIMEOUT = 8
_TOML_MAX_BYTES = 512 * 1024  # generous for a real toml (ripple.com's own is ~4KB)


def _resolves_to_public_address(host: str) -> bool:
    """Refuse to fetch a domain whose hostname resolves to a private/internal address.

    ``domain`` is on-chain data an issuer sets on their OWN account -- effectively
    attacker-controlled input, since anyone can create an issuer account and set
    Domain to anything. Fetching it unconditionally is a classic SSRF vector: an
    attacker could point Domain at a cloud metadata endpoint, localhost, or an
    internal-only service, using this public, unauthenticated scoring endpoint as
    a proxy into infrastructure it should never be able to reach. Resolve first
    and refuse anything that isn't a normal public address.

    Known gap, accepted rather than over-engineered for a read-only scoring tool:
    this doesn't defend against DNS rebinding (a different IP being returned
    between this check and the actual request) -- a fully airtight fix would
    resolve once and connect directly to the pinned IP. Standard resolve-then-
    check is the proportionate mitigation here, not a guarantee.
    """
    try:
        infos = socket.getaddrinfo(host, 443)
    except Exception:  # noqa: BLE001 - can't resolve -> can't fetch either way
        return False
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False
    return bool(infos)


def verify_toml_domain(domain: str, issuer: str) -> bool | None:
    """Check whether ``domain`` actually claims ``issuer`` back.

    An account's on-chain Domain field alone proves nothing -- anyone can set it
    to any string, including a domain they don't own. Real verification (per
    https://xrpl.org/docs/references/xrp-ledger-toml) requires that domain's own
    https://{domain}/.well-known/xrp-ledger.toml to list this exact address back
    -- a two-way link only the domain's real owner can produce.

    Returns True (verified), False (the file exists, parsed, and lists other
    accounts/issuers but not this one -- a real, meaningful non-match), or None
    (no evidence either way: missing file, network/timeout/parse error, or a file
    with nothing checkable in it). A missing file is deliberately NOT treated as
    a negative signal -- confirmed live 2026-07-10 that even Circle's real USDC
    issuer domain 404s here; most legitimate issuers simply haven't adopted this
    optional standard, so treating "absent" the same as "actively lying" would
    punish real businesses, not just scammers.
    """
    host = domain.strip()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0].strip()
    if not host:
        return None
    if not _resolves_to_public_address(host):
        return None

    try:
        # allow_redirects=False deliberately: a redirect target isn't re-checked
        # against _resolves_to_public_address, so following one would reopen the
        # SSRF gap the resolve-first check above exists to close. A handful of
        # real domains that redirect apex->www (confirmed live: circle.com does
        # this) will read as unverifiable rather than checked -- an acceptable,
        # safe default given the existing "unverifiable is neutral" design.
        resp = requests.get(
            f"https://{host}/.well-known/xrp-ledger.toml",
            timeout=_TOML_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
    except Exception:  # noqa: BLE001 - our fetch failing isn't evidence about the issuer
        return None
    if resp.status_code != 200:
        return None

    declared_length = resp.headers.get("Content-Length")
    if declared_length and declared_length.isdigit() and int(declared_length) > _TOML_MAX_BYTES:
        return None  # declares itself too big to be a real toml file -- don't fetch it

    try:
        body = resp.raw.read(_TOML_MAX_BYTES + 1, decode_content=True)
    except Exception:  # noqa: BLE001
        return None
    if len(body) > _TOML_MAX_BYTES:
        return None  # oversized/streaming response -- refuse rather than buffer it all
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None

    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001 - malformed file: can't determine, don't guess
        return None

    # The officially documented spec only covers [[ACCOUNTS]] (address=) and
    # [[CURRENCIES]] (issuer=), but real issuers in practice also use undocumented
    # [[ISSUERS]] (address=) and [[TOKENS]] (issuer=) tables -- confirmed live:
    # ripple.com's own toml lists RLUSD's issuer under [[ISSUERS]]/[[TOKENS]], NOT
    # [[ACCOUNTS]]. Checking only the documented section would fail to verify
    # Ripple's own stablecoin. Accept a match in any of the four.
    tables = [
        (data.get("ACCOUNTS"), "address"),
        (data.get("CURRENCIES"), "issuer"),
        (data.get("ISSUERS"), "address"),
        (data.get("TOKENS"), "issuer"),
    ]
    saw_checkable_entry = False
    for entries, field in tables:
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            saw_checkable_entry = True
            if entry.get(field) == issuer:
                return True

    # File exists and parsed. If it lists other accounts/issuers but not this one,
    # that's a real non-match. If it has nothing checkable at all (e.g. only
    # [[VALIDATORS]]), we have no evidence either way -- don't guess.
    return False if saw_checkable_entry else None
