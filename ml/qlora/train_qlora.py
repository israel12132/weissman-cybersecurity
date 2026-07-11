#!/usr/bin/env python3
"""
QLoRA fine-tune of a small open-weight base on the Weissman corpus.

Produces a LoRA adapter that specialises a 7-8B model on your own security wins,
runnable on a single 16-24GB GPU. The adapter is served locally by vLLM — no external
API, no data egress — so the platform gets "its own brain" while staying sovereign.

Pipeline:  export_corpus.py -> scrub_corpus.py -> train_qlora.py -> merge/serve via vLLM

Usage:
    # Validate the corpus + token stats without a GPU:
    python train_qlora.py --corpus corpus.jsonl --dry-run

    # Train (requires a CUDA GPU):
    python train_qlora.py \\
        --base Qwen/Qwen2.5-7B-Instruct \\
        --corpus corpus.jsonl \\
        --out ./weissman-lora \\
        --epochs 3

Requires a CUDA GPU for training. See requirements.txt (versions are pinned).
"""
import argparse
import json
import statistics


def build_prompt(ex, eos):
    """Chat-style instruction formatting. Matches an instruct base's expected shape."""
    instr = ex.get("instruction", "").strip()
    inp = ex.get("input", "").strip()
    user = instr if not inp else f"{instr}\n\n{inp}"
    out = ex.get("output", "").strip()
    return (
        f"<|im_start|>system\nYou are Weissman, an authorized offensive-security assistant. "
        f"Only operate within an approved scope.<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n{out}{eos}"
    )


def load_rows(path):
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    if not rows:
        raise SystemExit("empty corpus — run export_corpus.py (then scrub_corpus.py) first")
    return rows


def dry_run(args):
    """Validate the corpus + report token-length stats without loading a model/GPU."""
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(args.base)
    eos = tok.eos_token or "</s>"
    rows = load_rows(args.corpus)
    lengths = [len(tok(build_prompt(r, eos)).input_ids) for r in rows]
    over = sum(1 for n in lengths if n > args.max_seq)
    lengths.sort()
    p95 = lengths[int(0.95 * (len(lengths) - 1))]
    print(f"corpus: {len(rows)} examples")
    print(
        f"tokens/example: min={min(lengths)} mean={statistics.mean(lengths):.0f} "
        f"p95={p95} max={max(lengths)}"
    )
    print(f"over max_seq ({args.max_seq}): {over} ({100 * over / len(rows):.1f}%) will be truncated")
    print("dry-run OK — corpus is loadable and tokenizes.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--corpus", default="corpus.jsonl")
    ap.add_argument("--out", default="./weissman-lora")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-seq", type=int, default=2048)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--eval-frac", type=float, default=0.1, help="held-out fraction (0 disables)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="validate corpus + token stats, no GPU")
    args = ap.parse_args()

    if args.dry_run:
        dry_run(args)
        return

    # Heavy imports kept inside main so --help / --dry-run work without a GPU stack installed.
    import torch
    from datasets import Dataset
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        set_seed,
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from trl import SFTConfig, SFTTrainer

    set_seed(args.seed)

    tok = AutoTokenizer.from_pretrained(args.base)
    tok.pad_token = tok.pad_token or tok.eos_token
    eos = tok.eos_token or "</s>"

    rows = load_rows(args.corpus)
    ds = Dataset.from_list([{"text": build_prompt(r, eos)} for r in rows])

    # Held-out eval split so we can see whether we're generalising vs. memorising.
    eval_ds = None
    if args.eval_frac and 0 < args.eval_frac < 1 and len(ds) >= 10:
        split = ds.train_test_split(test_size=args.eval_frac, seed=args.seed)
        ds, eval_ds = split["train"], split["test"]

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.base, quantization_config=bnb, device_map="auto", torch_dtype=torch.bfloat16
    )
    model = prepare_model_for_kbit_training(model)
    lora = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    # TRL >= 0.12: dataset_text_field / max_seq_length / packing live in SFTConfig, and the
    # tokenizer is passed as processing_class (the old SFTTrainer kwargs were removed).
    cfg = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        bf16=True,
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch" if eval_ds is not None else "no",
        load_best_model_at_end=eval_ds is not None,
        metric_for_best_model="eval_loss" if eval_ds is not None else None,
        greater_is_better=False,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        optim="paged_adamw_8bit",
        seed=args.seed,
        dataset_text_field="text",
        max_seq_length=args.max_seq,
        packing=False,
        report_to=[],
    )
    trainer = SFTTrainer(
        model=model,
        args=cfg,
        train_dataset=ds,
        eval_dataset=eval_ds,
        processing_class=tok,
    )
    trainer.train()
    if eval_ds is not None:
        print("eval:", trainer.evaluate())
    trainer.model.save_pretrained(args.out)
    tok.save_pretrained(args.out)
    print(f"\nLoRA adapter saved -> {args.out}")
    print("Serve it: see ml/qlora/README.md (vLLM --enable-lora).")


if __name__ == "__main__":
    main()
