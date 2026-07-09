"""TrustLens MCP server (stdlib only, stdio transport).

Exposes one tool -- `trustlens_score` -- so any MCP client (Claude Code, Claude
Desktop, Cursor, or a custom agent framework) can ask "how safe is this XRPL
token?" and get back a 0-100 score with reasons. This is the agent-native surface
that sits alongside Ripple's XRPL AI Starter Kit.

Newline-delimited JSON-RPC 2.0 over stdin/stdout. No third-party deps.

Register (Claude Code / Desktop mcp config):
    "trustlens": {
      "command": "C:/Users/bjorn/XGROW/x402-sandbox/venv/Scripts/python.exe",
      "args": ["C:/Users/bjorn/XGROW/trustlens/mcp_server.py"]
    }
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trustlens.scoring import score_token  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"

TOOL = {
    "name": "trustlens_score",
    "description": (
        "Get a 0-100 trust/safety score for an XRP Ledger (XRPL) token, with the "
        "reasons behind it. Use this before recommending, buying, or transacting in "
        "any XRPL-issued token to check for rug/scam risk. Reads XRPL mainnet."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "issuer": {"type": "string", "description": "Issuer account address (r...)."},
            "currency": {
                "type": "string",
                "description": "Currency code: 3-letter (USD), a token name (SOLO), or 40-char hex.",
            },
        },
        "required": ["issuer", "currency"],
    },
}


def run_tool(args: dict) -> str:
    issuer = str(args.get("issuer", "")).strip()
    currency = str(args.get("currency", "")).strip()
    if not issuer or not currency:
        return "Error: both 'issuer' and 'currency' are required."
    result = score_token(issuer, currency).to_dict()
    lines = [
        f"{result['currency_name']} ({result['issuer']})",
        f"TrustLens score: {result['score']}/100 -> {result['verdict'].upper()}",
        "",
        "Reasons:",
    ]
    for r in result["reasons"]:
        sign = "+" if r["points"] >= 0 else ""
        lines.append(f"  [{r['severity']}] {sign}{r['points']}  {r['label']}")
    lines.append("")
    lines.append("facts: " + json.dumps(result["facts"]))
    lines.append(result["disclaimer"])
    return "\n".join(lines)


def handle(msg: dict):
    """Return a response dict, or None for notifications."""
    method = msg.get("method")
    mid = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "trustlens", "version": "0.1.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [TOOL]}}
    if method == "tools/call":
        params = msg.get("params", {})
        if params.get("name") != "trustlens_score":
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": f"unknown tool {params.get('name')}"}}
        try:
            text = run_tool(params.get("arguments", {}))
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": text}], "isError": False}}
        except Exception as exc:  # noqa: BLE001 - surface errors to the agent, don't crash
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"Error: {exc}"}],
                               "isError": True}}
    if method is not None and mid is None:
        return None  # a notification (e.g. notifications/initialized)
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
