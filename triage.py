"""
triage.py — offline batch triage of .eml files using the Gmail Malicious Scorer backend.

Reuses the exact same pipeline as the API (backend.main.analyze_email): sanitizer,
header / content / URL / attachment analyzers, VirusTotal hash lookup, LLM feature
extraction and the 70/30 aggregator. The only new part is the .eml parser, which
replaces what the Gmail Add-on (addon/Code.gs) did client-side.

It also prints "analyst extras" — raw facts (Return-Path, DKIM d=, originating IP,
URL domains, attachment hashes) that the scorer doesn't score but an analyst needs.

Usage:
    python triage.py <folder-or-files...> [-o out_dir] [--no-llm] [--no-vt] [--no-rdap]

Outputs (in out_dir, default ./triage_out):
    results.csv   one row per email — quick sorting / overview
    results.json  full detail per email (signals, extras)
    report.md     per-email section with auto findings + empty analyst-verdict fields
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import backend.main as scorer  # noqa: E402
from backend.analyzers import reputation_analyzer as reputation  # noqa: E402
from backend.models.email_request import (  # noqa: E402
    AttachmentMeta,
    EmailAnalysisRequest,
    EmailHeaders,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^"'\s>]+)""", re.I)
_PIXEL_RE = re.compile(r"<img[^>]*(width=[\"']?1[\"']?|height=[\"']?1[\"']?)[^>]*/?>", re.I)
_IP_RE = re.compile(r"[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]")
_PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)", re.I)
_MAX_URLS = 30  # same cap as the add-on


# ---------------------------------------------------------------- parsing ---

def _domain(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    m = re.search(r"@([\w.\-]+)", email_addr or addr)
    return m.group(1).lower().strip(".") if m else None


def _auth_value(auth_results: str, protocol: str) -> str | None:
    # same logic as extractAuthValue() in addon/Code.gs
    m = re.search(protocol + r"=(\w+)", auth_results, re.I)
    return m.group(1).lower() if m else None


def _decode_part(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _walk(msg):
    """Collect bodies and attachments. Embedded message/rfc822 parts are recorded as
    attachments (forwarded originals) and NOT merged into the outer body."""
    text, html, attachments = [], [], []
    for part in msg.iter_parts() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()

        if ctype == "message/rfc822":
            inner = part.get_payload(0) if isinstance(part.get_payload(), list) else None
            raw = inner.as_bytes() if inner is not None else b""
            attachments.append({
                "name": filename or f"{(inner or {}).get('subject', 'embedded')}.eml",
                "mime_type": ctype,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            })
            continue

        if part.is_multipart():
            t, h, a = _walk(part)
            text += t; html += h; attachments += a
            continue

        if disp == "attachment" or (filename and disp != "inline") or (
            filename and not ctype.startswith("text/")
        ):
            data = part.get_payload(decode=True) or b""
            attachments.append({
                "name": filename or "unnamed",
                "mime_type": ctype,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest() if data else None,
            })
        elif ctype == "text/plain":
            text.append(_decode_part(part))
        elif ctype == "text/html":
            html.append(_decode_part(part))
    return text, html, attachments


def parse_eml(path: Path) -> tuple[EmailAnalysisRequest, dict]:
    msg = BytesParser(policy=policy.default).parse(path.open("rb"))

    # The top-most Authentication-Results is the one added by the receiving server
    auth_list = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    auth = str(auth_list[0]) if auth_list else ""
    # Full auth blob incl. Mimecast's "-Original" and ARC headers, so the backend
    # can detect a security relay that rewrote the message and broke SPF/DKIM/DMARC.
    auth_blob = "\n".join(
        f"{h}: {v}"
        for h in ("Authentication-Results", "Authentication-Results-Original", "ARC-Authentication-Results")
        for v in (msg.get_all(h) or [])
    )
    received = [str(r) for r in (msg.get_all("Received") or [])]

    text_parts, html_parts, att = _walk(msg)
    body_text = "\n".join(text_parts)
    body_html = _PIXEL_RE.sub("", "\n".join(html_parts))

    urls = list(dict.fromkeys(_HREF_RE.findall(body_html) + _URL_RE.findall(body_html or body_text)))
    urls = [u.rstrip(".,;") for u in urls][:_MAX_URLS]

    from_hdr = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "") or None

    request = EmailAnalysisRequest(
        message_id=str(msg.get("Message-ID", path.name)),
        subject=str(msg.get("Subject", "") or ""),
        headers=EmailHeaders(
            spf=_auth_value(auth, "spf"),
            dkim=_auth_value(auth, "dkim"),
            dmarc=_auth_value(auth, "dmarc"),
            from_address=from_hdr or None,
            # add-on stored the last Received in list order = the origin hop
            received_from=received[-1] if received else None,
            reply_to=reply_to,
            received_chain="\n".join(received) or None,
            auth_results=auth_blob or None,
            sent_date=str(msg.get("Date", "") or "") or None,
        ),
        body_text=body_text or None,
        body_html=body_html or None,
        urls=urls,
        attachments=[AttachmentMeta(name=a["name"], mime_type=a["mime_type"], sha256=a["sha256"]) for a in att],
    )
    return request, _extras(msg, auth, received, urls, att, from_hdr, reply_to)


def _extras(msg, auth, received, urls, att, from_hdr, reply_to) -> dict:
    from_d = _domain(from_hdr)
    rp_d = _domain(str(msg.get("Return-Path", "") or ""))
    mid_d = _domain(str(msg.get("Message-ID", "") or ""))
    dkim_d = re.findall(r"header\.d=([\w.\-]+)", auth, re.I) or re.findall(
        r"\bd=([\w.\-]+)", str(msg.get("DKIM-Signature", "") or ""))

    # Originating IP: oldest hop (last Received) with a public IP
    origin_ip = None
    for hop in reversed(received):
        from_clause = re.split(r"\sby\s", hop, maxsplit=1)[0]  # only the sending side of the hop
        for ip in _IP_RE.findall(from_clause):
            if not _PRIVATE_IP.match(ip):
                origin_ip = ip
                break
        if origin_ip:
            break
    if not origin_ip:  # Microsoft: "spf=pass (sender IP is 1.2.3.4)"
        m = re.search(r"sender IP is ([\d.]+)", auth)
        origin_ip = m.group(1) if m else None

    url_domains = sorted({re.sub(r"^www\.", "", (re.match(r"https?://([^/:?#]+)", u, re.I) or [None, ""])[1].lower())
                          for u in urls} - {""})

    def _aligned(d):
        return bool(from_d and d and (d == from_d or d.endswith("." + from_d) or from_d.endswith("." + d)))

    return {
        "from": from_hdr,
        "from_domain": from_d,
        "reply_to": reply_to,
        "return_path_domain": rp_d,
        "return_path_mismatch": bool(rp_d and from_d and not _aligned(rp_d)),
        "message_id_domain": mid_d,
        "dkim_signing_domains": sorted(set(d.lower() for d in dkim_d)),
        "dkim_aligned_with_from": any(_aligned(d.lower()) for d in dkim_d),
        "auth_results_present": bool(auth),
        "auth_results_raw": auth[:500],
        "to": [a for _, a in getaddresses(msg.get_all("To", []))],
        "date": str(msg.get("Date", "") or ""),
        "x_mailer": str(msg.get("X-Mailer", "") or msg.get("User-Agent", "") or ""),
        "hops": len(received),
        "origin_ip": origin_ip,
        "url_count": len(urls),
        "url_domains": url_domains,
        "attachments": att,
    }


# -------------------------------------------------------------- run / out ---

def collect(paths: list[str]) -> list[Path]:
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".eml", ".txt", ""))
        elif p.is_file():
            files.append(p)
    return files


def main():
    ap = argparse.ArgumentParser(description="Batch phishing triage for .eml files")
    ap.add_argument("inputs", nargs="+", help=".eml files or folders")
    ap.add_argument("-o", "--out", default="triage_out")
    ap.add_argument("--no-llm", action="store_true", help="rule engine only (no Claude API call)")
    ap.add_argument("--no-vt", action="store_true", help="skip all VirusTotal lookups (files + domains)")
    ap.add_argument("--no-rdap", action="store_true", help="skip domain-age (RDAP) lookups")
    ap.add_argument("--vt-interval", type=float, default=15,
                    help="seconds between VirusTotal calls (free API = 4/min -> 15; premium -> 0)")
    args = ap.parse_args()

    if args.no_vt:
        os.environ["VIRUSTOTAL_API_KEY"] = ""
    if args.no_rdap:
        os.environ["RDAP_ENABLED"] = "0"
    os.environ["VT_MIN_INTERVAL"] = str(args.vt_interval)

    # When the LLM is off or fails, its empty 30% share would drag every score down.
    # Mark that case with llm_score=-1 and let the aggregator fall back to rules only.
    _llm, _agg = scorer.analyze_with_llm, scorer.aggregate

    def llm_or_flag(subject, body):
        if args.no_llm:
            return -1, "LLM disabled (--no-llm) - rule engine only.", []
        score, expl, sig = _llm(subject, body)
        if expl.startswith("AI analysis unavailable"):
            return -1, expl + " - rule engine only.", sig
        return score, expl, sig

    scorer.analyze_with_llm = llm_or_flag
    scorer.aggregate = lambda rule, llm, available=True: _agg(rule, llm, available and llm >= 0)
    files = collect(args.inputs)
    if not files:
        sys.exit("No input files found.")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results = []

    for i, f in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {f.name}", end=" ... ", flush=True)
        try:
            req, extras = parse_eml(f)
            res = scorer.analyze_email(req)
            # cached by the reputation analyzer during scoring — no extra network calls here
            extras["domain_intel"] = [reputation.lookup(d)
                                      for d in reputation.domains_for(extras["from_domain"], req.urls)]
            row = {"file": f.name, "subject": req.subject, **res.model_dump(), "extras": extras}
            print(f"{res.score:>3}  {res.verdict_label}")
        except Exception as e:  # keep going on a malformed file
            row = {"file": f.name, "error": f"{type(e).__name__}: {e}"}
            print("ERROR", row["error"])
        results.append(row)

    ok = sorted((r for r in results if "error" not in r), key=lambda r: -r["score"])
    bad = [r for r in results if "error" in r]

    (out / "results.json").write_text(json.dumps(ok + bad, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_csv(out / "results.csv", ok + bad)
    _write_md(out / "report.md", ok + bad)
    print(f"\n{len(ok)} scored, {len(bad)} errors -> {out.resolve()}")


def _write_csv(path: Path, rows: list[dict]):
    cols = ["file", "score", "verdict", "subject", "from", "reply_to", "return_path_domain",
            "spf", "dkim", "dmarc", "dkim_aligned", "origin_ip", "url_count", "url_domains",
            "attachments", "domain_intel", "high_signals", "explanation", "error"]
    with path.open("w", newline="", encoding="utf-8-sig") as fh:  # BOM so Excel shows Hebrew
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            if "error" in r:
                w.writerow({"file": r["file"], "error": r["error"]})
                continue
            x = r["extras"]
            w.writerow({
                "file": r["file"], "score": r["score"], "verdict": r["verdict_label"],
                "subject": r["subject"], "from": x["from"], "reply_to": x["reply_to"],
                "return_path_domain": x["return_path_domain"],
                "spf": _sig_val(r, "spf"), "dkim": _sig_val(r, "dkim"), "dmarc": _sig_val(r, "dmarc"),
                "dkim_aligned": x["dkim_aligned_with_from"], "origin_ip": x["origin_ip"],
                "url_count": x["url_count"], "url_domains": " ".join(x["url_domains"][:8]),
                "attachments": "; ".join(a["name"] for a in x["attachments"]),
                "domain_intel": "; ".join(_intel(d) for d in x.get("domain_intel", [])),
                "high_signals": "; ".join(s["type"] for s in r["signals"] if s["severity"] == "high"),
                "explanation": r["explanation"],
            })


def _intel(d: dict) -> str:
    age = f"{d['age_days']}d old" if d["age_days"] is not None else "age ?"
    vt = (f"VT {d['vt_malicious']}/{d['vt_suspicious']} mal/sus"
          if d["vt_malicious"] is not None else "VT ?")
    return f"{d['domain']} ({age}, {vt})"


def _sig_val(r, proto):
    m = re.search(proto + r"=(\w+)", r["extras"]["auth_results_raw"], re.I)
    return m.group(1).lower() if m else ("" if r["extras"]["auth_results_present"] else "n/a")


def _write_md(path: Path, rows: list[dict]):
    L = ["# Email triage report", "",
         "| # | File | Score | Auto verdict | Subject |", "|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        if "error" in r:
            L.append(f"| {i} | {r['file']} | – | ERROR | {r['error'][:60]} |")
        else:
            L.append(f"| {i} | {r['file']} | {r['score']} | {r['verdict_label']} | {r['subject'][:70]} |")
    for i, r in enumerate(rows, 1):
        L += ["", "---", f"## {i}. {r['file']}", ""]
        if "error" in r:
            L.append(f"Parse error: `{r['error']}`")
            continue
        x = r["extras"]
        L += [f"**Subject:** {r['subject']}  ",
              f"**From:** `{x['from']}`  ",
              f"**Reply-To:** `{x['reply_to'] or '-'}` · **Return-Path domain:** `{x['return_path_domain'] or '-'}`"
              + (" ⚠ mismatch" if x["return_path_mismatch"] else ""),
              f"**Auth:** {x['auth_results_raw'] or '_no Authentication-Results header_'}  ",
              f"**DKIM d=:** {', '.join(x['dkim_signing_domains']) or '-'} (aligned with From: {x['dkim_aligned_with_from']})  ",
              f"**Origin IP:** {x['origin_ip'] or '-'} · **Hops:** {x['hops']} · **Mailer:** {x['x_mailer'] or '-'}  ",
              f"**URL domains ({x['url_count']} URLs):** {', '.join(x['url_domains']) or '-'}  ",
              f"**Domain intel:** {'; '.join(_intel(d) for d in x.get('domain_intel', [])) or '-'}  "]
        if x["attachments"]:
            L.append("**Attachments:**")
            L += [f"- `{a['name']}` ({a['mime_type']}, {a['size']} B) sha256 `{a['sha256']}`" for a in x["attachments"]]
        L += ["", f"**Auto score:** {r['score']} — {r['verdict_label']}", "",
              f"> {r['explanation']}", "", "**Signals:**"]
        L += [f"- [{s['severity']}] {s['description']}" for s in r["signals"]] or ["- none"]
        L += ["", "**Analyst verdict:** _Malicious / Suspicious / Benign_  ",
              "**Category:** _credential phishing / BEC / malware / scam / spam / legit_  ",
              "**Confidence:** _High / Medium / Low_  ",
              "**Key evidence:**  ", "**Would AI alone get this right? Why:**  "]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
