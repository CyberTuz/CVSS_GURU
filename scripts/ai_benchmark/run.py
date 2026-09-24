"""
Benchmark AI Scorer prompts x OpenRouter models against NVD reference vectors.

Metrics per (prompt, model):
  exact   share of cases where the full 8-metric vector equals NVD's
  metric  per-metric accuracy averaged over the 8 base metrics
  sev     share of cases with the same severity band as NVD
  mae     mean absolute error of the base score
  valid   share of responses that parsed into a valid vector
  cost    USD reported by OpenRouter, latency p50 in seconds

A hard budget stops the run once the cumulative spend (tracked in
results/spend.json) reaches --budget USD.

Usage:
    python scripts/ai_benchmark/run.py --prompt v2 --split dev --models openai/gpt-6-luna qwen/qwen3.8-flash
    python scripts/ai_benchmark/run.py --report
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

import httpx
from dotenv import dotenv_values

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from app.cvss_calculators.cvss31 import CVSS31Calculator  # noqa: E402
from app.ai_prompt import parse_ai_json  # noqa: E402
from prompts import PROMPTS  # noqa: E402

RESULTS = HERE / "results"
SPEND = RESULTS / "spend.json"
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
VALID = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}
CALC = CVSS31Calculator()


def parse_vector(vec: str) -> dict:
    return dict(p.split(":") for p in vec.split("/")[1:])


def score(metrics: dict) -> tuple[float, str]:
    r = CALC.calculate(metrics)
    return r["base_score"], r["base_severity"]


def load_spend() -> float:
    return json.loads(SPEND.read_text())["usd"] if SPEND.exists() else 0.0


def add_spend(usd: float) -> float:
    total = load_spend() + usd
    SPEND.write_text(json.dumps({"usd": round(total, 6)}))
    return total


async def score_case(client, key, model, prompt_fn, case, sem, budget, effort):
    async with sem:
        if load_spend() >= budget:
            return {"id": case["id"], "error": "budget"}
        body = {
            "model": model,
            "messages": prompt_fn(case["description"]),
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "usage": {"include": True},
            "max_tokens": 6000,
        }
        if effort != "default":
            body["reasoning"] = {"effort": effort}
        t0 = time.perf_counter()
        for attempt in range(3):
            try:
                r = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "X-Title": "CVSS Guru AI benchmark"},
                    json=body, timeout=180,
                )
                data = r.json()
                if (r.status_code == 429 or "error" in data) and attempt < 2:
                    await asyncio.sleep(4 * (attempt + 1))
                    continue
                break
            except (httpx.TimeoutException, httpx.TransportError, json.JSONDecodeError) as exc:
                data = {"error": str(exc)}
                await asyncio.sleep(3)
        latency = time.perf_counter() - t0
        usage = data.get("usage") or {}
        cost = float(usage.get("cost") or 0)
        add_spend(cost)
        out = {"id": case["id"], "latency": round(latency, 2), "cost": cost,
               "tokens_in": usage.get("prompt_tokens"), "tokens_out": usage.get("completion_tokens")}
        try:
            content = data["choices"][0]["message"]["content"]
            parsed = parse_ai_json(content)
            m = {k: str(parsed["metrics"][k]).strip().upper()[:1] for k in METRICS}
            if any(m[k] not in VALID[k] for k in METRICS):
                raise ValueError(f"invalid metric values {m}")
            out["metrics"] = m
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
            if "error" in data:
                out["error"] = f"api: {str(data['error'])[:160]}"
        return out


async def run(models, prompt, split, repeat, budget, concurrency, effort):
    key = dotenv_values(ROOT / ".env").get("OPENROUTER_API_KEY")
    cases = [c for c in json.loads((HERE / "dataset.json").read_text(encoding="utf-8"))
             if split == "all" or c["split"] == split]
    RESULTS.mkdir(exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        for model in models:
            for rep in range(repeat):
                t0 = time.perf_counter()
                rows = await asyncio.gather(*[
                    score_case(client, key, model, PROMPTS[prompt], c, sem, budget, effort) for c in cases
                ])
                variant = prompt if effort == "default" else f"{prompt}-{effort}"
                tag = f"{variant}__{split}__{model.replace('/', '_').replace(':', '~')}__r{rep}"
                (RESULTS / f"{tag}.json").write_text(json.dumps(rows, indent=1))
                s = summarize(rows, {c["id"]: c for c in cases})
                print(f"{variant} {split:4s} {model:42s} r{rep} exact={s['exact']:.0%} metric={s['metric']:.1%} "
                      f"sev={s['sev']:.0%} mae={s['mae']:.2f} valid={s['valid']:.0%} cost=${s['cost']:.4f} "
                      f"p50={s['p50']:.1f}s  (wall {time.perf_counter() - t0:.0f}s, total spend ${load_spend():.3f})",
                      flush=True)
                if load_spend() >= budget:
                    print("Budget reached — stopping.")
                    return


def summarize(rows, ref):
    ok = [r for r in rows if "metrics" in r]
    n = len(rows)
    exact = metric_hits = sev = 0
    errs = []
    per_metric = {k: 0 for k in METRICS}
    for r in ok:
        truth = parse_vector(ref[r["id"]]["vector"])
        hits = [r["metrics"][k] == truth[k] for k in METRICS]
        for k, h in zip(METRICS, hits):
            per_metric[k] += h
        metric_hits += sum(hits)
        exact += all(hits)
        ps, psev = score(r["metrics"])
        ts, tsev = score(truth)
        sev += psev == tsev
        errs.append(abs(ps - ts))
    # invalid answers count as wrong everywhere
    return {
        "exact": exact / n, "metric": metric_hits / (8 * n), "sev": sev / n,
        "mae": statistics.mean(errs) if errs else 10.0, "valid": len(ok) / n,
        "cost": sum(r.get("cost", 0) for r in rows),
        "p50": statistics.median([r["latency"] for r in rows if "latency" in r] or [0]),
        "per_metric": {k: v / n for k, v in per_metric.items()},
        "n": n,
    }


def report():
    ref = {c["id"]: c for c in json.loads((HERE / "dataset.json").read_text(encoding="utf-8"))}
    groups = {}
    for f in sorted(RESULTS.glob("*__*.json")):
        prompt, split, model, rep = f.stem.split("__")
        groups.setdefault((prompt, split, model), []).append(json.loads(f.read_text()))
    print(f"{'prompt':9s} {'split':5s} {'model':44s} {'runs':>4s} {'exact':>6s} {'metric':>7s} {'sev':>5s} {'mae':>5s} "
          f"{'valid':>6s} {'$/100':>7s} {'p50 s':>6s}  weakest metrics")
    for (prompt, split, model), runs in sorted(groups.items()):
        ss = [summarize(r, ref) for r in runs]
        avg = {k: statistics.mean(s[k] for s in ss) for k in ("exact", "metric", "sev", "mae", "valid", "cost", "p50")}
        pm = {k: statistics.mean(s["per_metric"][k] for s in ss) for k in METRICS}
        weakest = ", ".join(f"{k} {v:.0%}" for k, v in sorted(pm.items(), key=lambda kv: kv[1])[:3])
        per100 = avg["cost"] / ss[0]["n"] * 100
        print(f"{prompt:9s} {split:5s} {model.replace('_', '/', 1).replace('~', ':'):44s} {len(runs):4d} {avg['exact']:6.0%} {avg['metric']:7.1%} "
              f"{avg['sev']:5.0%} {avg['mae']:5.2f} {avg['valid']:6.0%} {per100:7.3f} {avg['p50']:6.1f}  {weakest}")
    print(f"\nTotal spend tracked: ${load_spend():.3f}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=[])
    ap.add_argument("--prompt", default="v2", choices=list(PROMPTS))
    ap.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--budget", type=float, default=2.5)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--effort", default="default", choices=["default", "minimal", "low", "medium", "high"])
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    if a.report:
        report()
    else:
        asyncio.run(run(a.models, a.prompt, a.split, a.repeat, a.budget, a.concurrency, a.effort))
