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


class LedgerError(RuntimeError):
    """Raised when every endpoint fails or the ledger returns an error we can't use."""


def rpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Call an XRPL JSON-RPC method, failing over across endpoints.

    Returns the ``result`` object. Ledger-level "not found" style errors are
    returned as-is (with an ``error`` key) so callers can distinguish "account
    doesn't exist" from "network is down".
    """
    payload = {"method": method, "params": [params]}
    last_exc: Exception | None = None
    for base in RPC_ENDPOINTS:
        try:
            resp = requests.post(base, json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            result = resp.json().get("result", {})
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


def gateway_balances(issuer: str) -> dict[str, Any]:
    """Total obligations (i.e. circulating supply) issued by ``issuer`` per currency."""
    return rpc(
        "gateway_balances",
        {"account": issuer, "ledger_index": "validated", "strict": True},
    )


def account_lines(issuer: str, currency: str, max_pages: int = 6, page: int = 400) -> dict[str, Any]:
    """Walk trustlines to the issuer for one currency.

    From the issuer's point of view each line's ``balance`` is negative (the issuer
    owes the holder), so the holder's balance is the absolute value. We cap the walk
    at ``max_pages`` so a token with hundreds of thousands of holders can't hang a
    scoring request -- when capped we report ``holders_capped=True``.
    """
    holders: list[float] = []
    marker: Any = None
    capped = False
    for i in range(max_pages):
        params: dict[str, Any] = {
            "account": issuer,
            "ledger_index": "validated",
            "limit": page,
        }
        if marker is not None:
            params["marker"] = marker
        result = rpc("account_lines", params)
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


def amm_info(issuer: str, currency: str) -> dict[str, Any] | None:
    """AMM pool for CURRENCY/XRP, or None if no such pool exists."""
    result = rpc(
        "amm_info",
        {
            "asset": {"currency": "XRP"},
            "asset2": {"currency": currency, "issuer": issuer},
            "ledger_index": "validated",
        },
    )
    if result.get("error"):
        return None
    return result.get("amm")
