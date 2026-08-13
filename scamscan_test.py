"""scamscan tests. No network, no API key, no cost.

The three checks that matter here are all about the same thing: a query that
never ran must never be reported as a query that found nothing. Scam discovery
inverts the usual bias — an empty queue is read as "this brand is clean", so a
silent failure is a false negative someone acts on.

    python scamscan_test.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scamscan import (HuntError, extract_artifacts, fingerprint,
                      impersonation_score, lexicon_score, parse_json_array,
                      registrable, score_finding, search_failures)

CFG = json.load(open(Path(__file__).parent / "config.json"))


def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    return bool(cond)


# --- stand-ins for the SDK's response objects -----------------------------

class Block:
    def __init__(self, type, **kw):
        self.type = type
        for k, v in kw.items():
            setattr(self, k, v)


class Err:
    def __init__(self, error_code):
        self.type = "web_search_tool_result_error"
        self.error_code = error_code


class Resp:
    def __init__(self, content, stop_reason="end_turn"):
        self.content = content
        self.stop_reason = stop_reason


def main():
    ok = True

    print("\nartifact extraction")
    a = extract_artifacts("Send your PIN. Paybill 247247. wa.me/254712345678")
    ok &= check("finds a PIN request", "pin_request" in a)
    ok &= check("finds a paybill", "paybill" in a)
    ok &= check("finds a WhatsApp link", "whatsapp" in a)
    ok &= check("clean text yields nothing",
                extract_artifacts("Our branches open at 9am.") == {})

    print("\nimpersonation")
    ok &= check("an official domain is hard-zeroed",
                impersonation_score("https://safaricom.co.ke/help", CFG["brand"])[0] == 0)
    ok &= check("a lookalike host scores",
                impersonation_score("http://mpesa-verify.co.ke/login", CFG["brand"])[0] > 0)
    ok &= check("east african eTLD+1 is handled",
                registrable("www.foo.bar.co.ke") == "bar.co.ke")
    ok &= check("homoglyph folding catches cyrillic",
                impersonation_score("http://ѕafaricom-login.com", CFG["brand"])[0] > 0)

    print("\nlexicon")
    hits, _ = lexicon_score("guaranteed returns, double your money", CFG["lexicon"])
    ok &= check("weighted multilingual terms accumulate", hits > 0)
    ok &= check("swahili terms are scored",
                lexicon_score("namba ya siri", CFG["lexicon"])[0] > 0)
    ok &= check("score is capped at 100",
                lexicon_score(" ".join(CFG["lexicon"]["en"]), CFG["lexicon"])[0] <= 100)

    print("\ndedupe")
    a1 = {"url": "https://scam.example/a", "summary": "Send your pin now to win"}
    a2 = {"url": "https://scam.example/b", "summary": "Send your pin now to win"}
    b1 = {"url": "https://other.example/a", "summary": "Send your pin now to win"}
    ok &= check("same site + same copy collapses",
                fingerprint(a1) == fingerprint(a2))
    ok &= check("different site stays separate — cross-site reuse is signal",
                fingerprint(a1) != fingerprint(b1))

    print("\na missing model_confidence must not silently demote a finding")
    strong = {"url": "http://mpesa-verify.co.ke/login",
              "title": "verify", "quoted_evidence": "send your pin",
              "summary": "guaranteed returns, double your money. Paybill 247247"}
    without = score_finding(dict(strong), CFG)
    with_conf = score_finding({**strong, "model_confidence": 0.9}, CFG)
    zeroed = score_finding({**strong, "model_confidence": 0.0}, CFG)

    ok &= check("absent confidence is excluded, not scored as zero",
                without["score"] > zeroed["score"])
    ok &= check("and the run records which families it scored on",
                "model" not in without["scored_on"]
                and "model" in with_conf["scored_on"])
    ok &= check("an explicit 0.0 still counts against the finding",
                zeroed["model_score"] == 0.0)
    # The precise property: average over the families that reported, so the
    # score is the mean of three, not of three plus a phantom zero.
    local_mean = round((without["lexicon_score"] + without["artifact_score"]
                        + without["impersonation_score"]) / 3, 1)
    ok &= check("the score is the mean of the families that reported",
                without["score"] == local_mean)
    ok &= check("which is worth ~25% of the range on this fixture",
                without["score"] - (local_mean * 3 / 4) > 15)
    ok &= check("a malformed confidence is ignored, not crashed on",
                isinstance(score_finding({**strong, "model_confidence": "n/a"},
                                         CFG)["score"], float))
    ok &= check("scores stay within 0-100",
                0 <= score_finding({**strong, "model_confidence": 9.9},
                                   CFG)["score"] <= 100)

    print("\na failed web search must not look like a clean brand")
    # The API reports these as HTTP 200 with an error object in the result
    # block — nothing raises, so they have to be detected explicitly.
    for code in ("max_uses_exceeded", "too_many_requests", "unavailable"):
        resp = Resp([Block("web_search_tool_result", content=Err(code)),
                     Block("text", text="[]")])
        ok &= check(f"{code} is detected", search_failures(resp) == [code])

    good = Resp([Block("web_search_tool_result", content=[{"url": "https://x"}]),
                 Block("text", text="[]")])
    ok &= check("a successful search reports no failure", search_failures(good) == [])
    ok &= check("a response with no search block is not a failure",
                search_failures(Resp([Block("text", text="[]")])) == [])

    print("\nparsing")
    ok &= check("tolerates markdown fences",
                parse_json_array('```json\n[{"url": "x"}]\n```') == [{"url": "x"}])
    ok &= check("tolerates surrounding prose",
                len(parse_json_array('Here you go: [{"url": "x"}] hope that helps')) == 1)
    ok &= check("malformed JSON yields empty rather than raising",
                parse_json_array("[{oops") == [])
    ok &= check("HuntError is distinct from a generic failure",
                issubclass(HuntError, Exception)
                and HuntError is not Exception)

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
