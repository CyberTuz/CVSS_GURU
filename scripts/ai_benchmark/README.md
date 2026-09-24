# AI Scorer benchmark

Measures how well the AI Scorer prompt + an OpenRouter model reproduce the CVSS v3.1
vectors assigned by NVD analysts.

- `build_dataset.py`: samples 45 CVEs published Feb–May 2024 whose v3.1 vector was
  assigned by NVD (`nvd@nist.gov`, Primary), stratified over 19 vulnerability classes
  (XSS, SQLi, kernel bugs, Bluetooth, physical access, race conditions, ...).
  15 are a **dev** split (used to write the prompt), 30 a held-out **test** split.
- `prompts.py`: `v1` (original prompt), `v2`, `v3`, and `prod` (whatever `app/ai_prompt.py` uses).
- `run.py`: runs prompt × models with a hard spend cap, stores raw results in `results/`.

```bash
python scripts/ai_benchmark/run.py --prompt prod --split test --repeat 2 --models openai/gpt-6-luna
python scripts/ai_benchmark/run.py --report
```

Metrics: **metric** = per-metric accuracy over the 8 base metrics (invalid replies count as
wrong), **exact** = whole vector identical, **sev** = same severity band, **MAE** = mean
absolute base-score error, **valid** = replies that parsed into a valid vector.

## Results (September 2026, held-out test split, 30 CVEs)

Averages over 2 runs unless noted; total benchmark cost ≈ $1.02.

| Prompt | Model | Metric | Exact | MAE | Valid | $ / 1000 analyses | p50 latency |
|---|---|---:|---:|---:|---:|---:|---:|
| v1 (old) | nvidia/nemotron-3-super-120b-a12b:free | 73.4% | 15% | 2.03 | 100% | 0 | 16 s |
| v1 (old) | openai/gpt-6-luna (1 run) | 75.8% | 20% | 1.94 | 100% | 0.50 | 8.0 s |
| v1 (old) | google/gemini-3.5-flash-lite (1 run) | 83.3% | 27% | 1.16 | 100% | 1.08 | 1.8 s |
| **v3** | **nvidia/nemotron-3-super-120b-a12b:free**, effort low (4 runs) | **83.2%** | 26% | **1.18** | 100% | **0** | 13 s |
| **v3** | **openai/gpt-6-luna** | 81.2% | 27% | 1.39 | 100% | **0.35** | 5.5 s |
| **v3** | **z-ai/glm-5.3-flash**, effort low | 81.5% | 32% | 1.24 | 98% | **0.24** | **3.3 s** |
| v3 | anthropic/claude-haiku-4.5 | 82.1% | 30% | 1.24 | 100% | 3.54 | 4.6 s |
| v3 | openai/gpt-6-luna-pro | 80.4% | 27% | 1.43 | 100% | 1.27 | 9.7 s |
| v3 | google/gemini-3.5-flash-lite (4 runs) | 77–80% | 30% | 1.09 | 90% | 1.10 | 1.7 s |
| v3 | deepseek/deepseek-v4.1-flash | 76.7% | 32% | 1.12 | 92% | 1.20 | 15 s |

Dropped on the dev split: qwen/qwen3.8-flash and nvidia/nemotron-3.5-lightning (reasoning
runs out of tokens, 53–80% valid), mistralai/mistral-small-2603 (provider rate-limited
80% of requests), google/gemma-4-31b-it (accurate but ~58 s latency),
google/gemini-3.8-flash (no better than cheap models at 4× the cost).

## Findings

- **The prompt matters more than the model.** On the same model, v1 → v3 cut the score
  error roughly in half (Nemotron MAE 2.03 → 1.18, GPT-6 Luna 1.94 → 1.39). The old prompt's
  "pick the lower score when unsure" rule systematically under-scored compared with NVD,
  which follows the CVSS User Guide's "reasonable worst case".
- **Cheap models are as good as expensive ones here.** The top models sit within ~3 points
  of each other, which is inside run-to-run noise (±2–3 points on 30 cases). Claude Haiku
  costs 10× GPT-6 Luna for the same accuracy.
- **Reliability and latency separate the candidates**, not accuracy: reasoning models can
  burn their token budget and return nothing; `reasoning.effort=low` fixes this for GLM and
  Nemotron. Gemini Flash-Lite is the fastest but returns malformed JSON 5–13% of the time
  with the v3 prompt.
- **Ceiling:** part of the error is label noise. NVD sometimes sets privileges from
  information not in the description (e.g. a plugin SQLi scored PR:L with no mention of
  authentication), which no prompt can recover. PR, C and I remain the weakest metrics.
- v3 also isolates the user's text in its own message and tells the model to ignore
  instructions inside it; an injected "output 10.0" was ignored in manual testing.

## Recommendation

- Public site: `openai/gpt-6-luna` (default) — 100% valid replies, ~5 s, ~$0.35 per 1000
  analyses. Alternative: `z-ai/glm-5.3-flash` with `OPENROUTER_REASONING_EFFORT=low`
  (faster and cheaper, 1 malformed reply in 60).
- Local mode / zero cost: `nvidia/nemotron-3-super-120b-a12b:free` with
  `OPENROUTER_REASONING_EFFORT=low` — best score in this benchmark, but ~13 s and subject to
  OpenRouter free-tier limits.
