#!/usr/bin/env python3
"""Export a curated subset of Inspect .eval trajectories as static JSON for docs/traces.

Reads only the zip/JSON structure of .eval files (no inspect_ai needed). Writes:
  <out>/manifest.json         models, CWEs, framings, selection params
  <out>/index.json            one row per selected PR with every model's verdict
  <out>/prs/<slug>.json       PR text, diff and one trajectory per model

Usage (from repo root):
  python3 docs/tools/export_traces.py --per-cwe 12 --seed 0
"""
import argparse
import json
import random
import re
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = [ROOT / "logs" / "results_nips", ROOT / "logs" / "filtering_releases"]
RETAINED = ROOT / "retained_sample_ids.json"
DIR_RE = re.compile(r"^(?P<model>.+)_gitea_plain_(?P<cwe>cwe\d+)$")

TOOL_OUT_LIMIT = 4000
DIFF_LIMIT = 30000
TEXT_LIMIT = 12000

MODEL_LABELS = {
    "claude-opus-4-7": "Claude Opus 4.7",
    "claude-sonnet-4-6": "Claude Sonnet 4.6",
    "claude-haiku-4-5": "Claude Haiku 4.5",
    "gpt-5.5": "GPT-5.5",
    "gpt-5.4-nano": "GPT-5.4-nano",
    "gpt-oss-120b": "gpt-oss-120b",
    "glm-5": "GLM-5",
    "kimi-k2.5": "Kimi K2.5",
    "DeepSeek-V4-Flash": "DeepSeek-V4-Flash",
    "grok-code-fast-1": "Grok Code Fast 1",
}


def model_key(raw):
    for k in MODEL_LABELS:
        if k.lower() in raw.lower():
            return k
    return raw


def clip(s, n):
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + f"\n… [truncated {len(s) - n} chars]"


def load_samples(dir_path):
    """Latest-wins dedupe of full sample records across the dir's .eval files."""
    by_id = {}
    for ev in sorted(dir_path.glob("*.eval")):
        try:
            with zipfile.ZipFile(ev) as z:
                for name in z.namelist():
                    if name.startswith("samples/") and name.endswith(".json"):
                        d = json.loads(z.read(name))
                        by_id[d["id"]] = d
        except Exception as e:  # corrupt/partial log
            print(f"skip {ev.name}: {e}")
    return by_id


def text_of(content, att):
    """Return (text, reasoning) from message content (str or list of parts)."""
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    text, reasoning = [], []
    for p in content or []:
        if isinstance(p, str):
            text.append(p)
        elif p.get("type") == "text":
            text.append(p.get("text", ""))
        elif p.get("type") == "reasoning":
            reasoning.append(p.get("reasoning") or p.get("summary") or "")
    out = "\n".join(text)
    if out.startswith("attachment://"):
        out = att.get(out[len("attachment://"):], out)
    return out, "\n".join(r for r in reasoning if r)


def build_trace(s):
    att = s.get("attachments") or {}
    steps = []
    for m in s["messages"]:
        role = m["role"]
        if role in ("system", "user"):
            continue
        text, reasoning = text_of(m.get("content"), att)
        step = {"role": role}
        if role == "tool":
            step["fn"] = m.get("function")
            step["text"] = clip(text, TOOL_OUT_LIMIT)
            if m.get("error"):
                step["error"] = clip(m["error"].get("message") if isinstance(m["error"], dict) else m["error"], 500)
        else:
            step["text"] = clip(text, TEXT_LIMIT)
            if reasoning:
                step["reasoning"] = clip(reasoning, TEXT_LIMIT)
            calls = [
                {"fn": c.get("function"), "args": json.loads(json.dumps(c.get("arguments", {})))}
                for c in (m.get("tool_calls") or [])
            ]
            if calls:
                step["calls"] = calls
        steps.append(step)
    sc = s.get("scores", {})
    det = sc.get("detection_scorer", {})
    sec = sc.get("security_reason_scorer", {})
    usage = next(iter((s.get("model_usage") or {}).values()), {})
    return {
        "blocked": det.get("value") == 1.0,
        "detection": det.get("value"),
        "outcome": det.get("answer"),
        "security_reason": sec.get("answer"),
        "judge": clip(sec.get("explanation"), 1500),
        "steps": steps,
        "tokens": usage.get("total_tokens"),
        "seconds": float(s["total_time"]) if s.get("total_time") else None,
    }


def first_diff(s):
    att = s.get("attachments") or {}
    for m in s["messages"]:
        if m["role"] == "tool" and m.get("function") == "github_list_pr_files":
            text, _ = text_of(m.get("content"), att)
            return clip(text, DIFF_LIMIT)
    return ""


def slug(sample_id):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", sample_id)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "traces" / "data"))
    ap.add_argument("--per-cwe", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--min-models", type=int, default=6)
    a = ap.parse_args()

    retained = json.loads(RETAINED.read_text())
    runs = defaultdict(dict)  # (cwe, sample_id) -> {model: sample}
    for src in SOURCES:
        for d in sorted(src.iterdir()) if src.exists() else []:
            m = DIR_RE.match(d.name)
            if not (m and d.is_dir()):
                continue
            mk, cwe = model_key(m["model"]), m["cwe"]
            keep = set(retained.get(cwe, []))
            for sid, s in load_samples(d).items():
                if sid in keep and "detection_scorer" in (s.get("scores") or {}):
                    runs[(cwe, sid)][mk] = s
    print(f"{len(runs)} retained PRs with at least one run")

    rng = random.Random(a.seed)
    chosen = []
    for cwe in sorted(retained):
        cands = [(sid, r) for (c, sid), r in runs.items() if c == cwe and len(r) >= a.min_models]
        mixed = [x for x in cands if 0 < sum(t["scores"]["detection_scorer"]["value"] == 1.0 for t in x[1].values()) < len(x[1])]
        rng.shuffle(mixed)
        rng.shuffle(cands)
        # prefer disagreement cases, spread across framings
        picked, seen_fr = [], defaultdict(int)
        for sid, r in mixed + [x for x in cands if x not in mixed]:
            fr = sid.rsplit("-", 1)[-1]
            if seen_fr[fr] >= 2 and len(picked) < a.per_cwe - 1 and len(mixed) > a.per_cwe:
                continue
            picked.append((cwe, sid, r))
            seen_fr[fr] += 1
            if len(picked) >= a.per_cwe:
                break
        chosen += picked
    print(f"selected {len(chosen)} PRs")

    out = Path(a.out)
    (out / "prs").mkdir(parents=True, exist_ok=True)
    index, models_seen, framings = [], set(), set()
    for cwe, sid, r in chosen:
        any_s = next(iter(r.values()))
        md = any_s["metadata"]
        pr = (md.get("pr_details") or {}).get(str(md.get("pr_number")), {})
        framing = md.get("axis3") if md.get("axis3") not in (None, "undefined") else sid.rsplit("-", 1)[-1]
        framings.add(framing)
        traces = {mk: build_trace(s) for mk, s in r.items()}
        models_seen |= set(traces)
        diff = next((d for d in (first_diff(s) for s in r.values()) if d), "")
        doc = {
            "id": sid, "slug": slug(sid), "cwe": cwe, "repo": md.get("repo"),
            "pr_number": md.get("pr_number"), "framing": framing,
            "axis1": md.get("axis1"), "axis2": md.get("axis2"),
            "title": pr.get("title"), "body": clip(pr.get("body"), TEXT_LIMIT),
            "files_changed": md.get("files_changed"), "diff": diff,
            "traces": traces,
        }
        (out / "prs" / f"{slug(sid)}.json").write_text(json.dumps(doc, separators=(",", ":")))
        index.append({
            "slug": slug(sid), "cwe": cwe, "repo": md.get("repo"), "title": pr.get("title"),
            "framing": framing, "axis1": md.get("axis1"), "axis2": md.get("axis2"),
            "verdicts": {mk: t["blocked"] for mk, t in traces.items()},
        })
    (out / "index.json").write_text(json.dumps(index, separators=(",", ":")))
    (out / "manifest.json").write_text(json.dumps({
        "models": {k: MODEL_LABELS.get(k, k) for k in sorted(models_seen)},
        "cwes": sorted({i["cwe"] for i in index}),
        "framings": sorted(framings),
        "n_prs": len(index), "per_cwe": a.per_cwe, "seed": a.seed,
        "note": "Curated subset of the retained challenge split; plain prompt; tool outputs truncated.",
    }, indent=1))
    print("wrote", out)


if __name__ == "__main__":
    main()
