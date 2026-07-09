"""Demo: an AI agent pays for a TrustLens score via x402 on XRPL.

This is the whole agentic loop end to end:
  1. agent GETs the metered endpoint,
  2. gets an HTTP 402 with an XRPL payment challenge,
  3. signs + submits a testnet XRP payment,
  4. retries and receives the trust score,
  5. we print the on-ledger settlement tx hash as proof.

Usage: python paid_agent.py [ISSUER] [CURRENCY]
"""
import sys

import requests
from xrpl.wallet import Wallet

from x402_xrpl.clients.requests import x402_requests
from x402_xrpl.clients.base import decode_payment_response

TESTNET_RPC = "https://s.altnet.rippletest.net:51234/"
BUYER_SEED = open("C:/Users/bjorn/XGROW/x402-sandbox/buyer_seed.txt").read().strip()

issuer = sys.argv[1] if len(sys.argv) > 1 else "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"
currency = sys.argv[2] if len(sys.argv) > 2 else "RLUSD"
url = f"http://127.0.0.1:8080/api/score/pro?issuer={issuer}&currency={currency}"

wallet = Wallet.from_seed(BUYER_SEED)
print(f"Agent wallet : {wallet.classic_address}")
print(f"Requesting   : {currency} score (pays on 402)...\n")

session = x402_requests(wallet, rpc_url=TESTNET_RPC, network_filter="xrpl:1", scheme_filter="exact")
resp = session.get(url, timeout=180)

print("HTTP status  :", resp.status_code)
data = resp.json()
print(f"Score        : {data['score']}/100 -> {data['verdict'].upper()}  ({data['currency_name']})")

if "PAYMENT-RESPONSE" in resp.headers:
    settle = decode_payment_response(resp.headers["PAYMENT-RESPONSE"])
    txid = settle.get("transaction") or settle.get("txHash") or settle
    print(f"\nPAID. settlement tx: {txid}")
    print(f"explorer          : https://testnet.xrpl.org/transactions/{txid}")
else:
    print("\n(no PAYMENT-RESPONSE header returned)")
