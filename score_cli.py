"""Quick CLI to score a token from the terminal (for testing/build-in-public).

Usage:
    python score_cli.py <ISSUER> <CURRENCY>
    python score_cli.py rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De 524C555344000000000000000000000000000000
"""
import json
import sys

from trustlens.scoring import score_token


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    issuer, currency = sys.argv[1], sys.argv[2]
    result = score_token(issuer, currency).to_dict()
    print(f"\n  {result['currency_name']}  ({issuer})")
    print(f"  SCORE: {result['score']}/100  ->  {result['verdict'].upper()}\n")
    for r in result["reasons"]:
        sign = "+" if r["points"] >= 0 else ""
        print(f"   [{r['severity']:>8}] {sign}{r['points']:>3}  {r['label']}")
    print("\n  facts:", json.dumps(result["facts"], indent=2))


if __name__ == "__main__":
    main()
