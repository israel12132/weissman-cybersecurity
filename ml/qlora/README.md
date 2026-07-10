# Weissman "Own Brain" — QLoRA fine-tuning

This is **Workstream C Stage 2**: turn a generic open-weight model into a *security-specialised
local brain* trained on Weissman's own accumulated wins. It stays 100% on-box — no external API,
no data egress — and is served by the same local vLLM the platform already talks to.

> Stage 1 (RAG) is already live: `supreme_council_memory` + `pentest_winning_paths` (pgvector)
> give the model long-term institutional recall with **zero training**. Stage 2 below is the
> optional next step once those tables hold enough real wins (~1k+ examples).

## Why this is "your brain" (and its honest limits)

There is no proprietary frontier model here and there doesn't need to be. The differentiator is
a **small model specialised on what worked in *your* environment** — WAF bypasses your fleet
found, payloads that actually confirmed, strategies the Supreme Council won with. A 7-8B QLoRA
adapter captures that, runs on a single 16-24GB GPU, and is fully yours. It will not out-reason
a frontier model on general tasks; it wins on *your* domain because it was trained on *your* data.

## Pipeline

```
DB memory tables ─1─▶ corpus.jsonl ─2─▶ corpus.clean.jsonl ─3─▶ LoRA adapter ─4─▶ vLLM ─▶ WEISSMAN_LLM_*
```

### 1. Export the corpus (no GPU needed)

```bash
pip install psycopg2-binary
DATABASE_URL='postgres://weissman_app:...@host/weissman' \
  python export_corpus.py --out corpus.jsonl --min-wins 1
```

Pulls real, persisted rows from `supreme_council_memory`, `sovereign_learning_buffer`
(synthesized), `pentest_winning_paths`, and validated `genesis_vaccine_vault`. Never fabricated.
If you get <200 examples, keep running the platform so the memory grows, then re-export.

### 2. Scrub the corpus (mandatory — no GPU needed)

```bash
python scrub_corpus.py --in corpus.jsonl --out corpus.clean.jsonl
```

Redacts secrets/PII (private keys, JWTs, AWS/GitHub/Slack/API keys, `password=…`, emails),
de-duplicates, and drops too-short examples — so the model can't memorise and later regurgitate
a client's live secret. **Always train on the scrubbed file.**

### 3. Train the QLoRA adapter (CUDA GPU)

```bash
pip install -r requirements.txt
# Validate the corpus + token stats first, no GPU:
python train_qlora.py --corpus corpus.clean.jsonl --dry-run
# Then train (held-out eval split + fixed seed by default):
python train_qlora.py \
  --base Qwen/Qwen2.5-7B-Instruct \
  --corpus corpus.clean.jsonl \
  --out ./weissman-lora \
  --epochs 3
```

4-bit NF4 base + LoRA (r=16) → trainable params <1%. Fits ~16GB (7B) / ~24GB (8B) VRAM.
Good bases: `Qwen/Qwen2.5-7B-Instruct`, `meta-llama/Llama-3.1-8B-Instruct`,
`mistralai/Mistral-7B-Instruct-v0.3`.

### 4. Serve the adapter with vLLM (local, sovereign)

```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-7B-Instruct \
  --enable-lora \
  --lora-modules weissman=./weissman-lora \
  --port 8000
```

Then point the platform at it (already the local-first default after Workstream C Stage 1):

```bash
WEISSMAN_LLM_BASE_URL=http://127.0.0.1:8000/v1
WEISSMAN_LLM_MODEL=weissman            # the LoRA module name
WEISSMAN_COUNCIL_SINGLE_MODEL=weissman # run the whole council on your brain (one model)
```

## Continuous improvement loop

Re-export + re-train on a schedule (e.g. monthly) so the brain keeps learning from new wins.
The autonomous self-improvement engine (`/self-improve`) can propose "retrain the local model —
N new winning examples since last adapter" as a `new_module`/`improve_module` item for your
approval.

## Safety

Training data is authorized-engagement output only. The system prompt in `train_qlora.py`
pins the model to "operate within an approved scope". Keep the adapter and corpus in your
private infrastructure — they encode your clients' findings.
