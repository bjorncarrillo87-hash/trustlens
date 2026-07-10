"""Read-only XRPL mainnet data access for TrustLens.

Everything here is a plain JSON-RPC call against a public XRPL node. No keys, no
signing, no state changes -- this module only ever *reads* the ledger. That is
deliberate: scoring a token must never be able to touch funds.
"""
from __future__ import annotations

import time
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
