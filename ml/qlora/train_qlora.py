#!/usr/bin/env python3
"""
QLoRA fine-tune of a small open-weight base on the Weissman corpus.

Produces a LoRA adapter that specialises a 7-8B model on your own security wins,
runnable on a single 16-24GB GPU. The adapter is served locally by vLLM — no external
API, no data egress — so the platform gets "its own brain" while staying sovereign.

Pipeline:  export_corpus.py  ->  train_qlora.py  ->  merge/serve via vLLM (see README.md)

Usage:
    python train_qlora.py \\
        --base Qwen/Qwen2.5-7B-Instruct \\
        --corpus corpus.jsonl \\
        --out ./weissman-lora \\
        --epochs 3

Requires a CUDA GPU. See requirements.txt.
"""
import argparse
import json


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
    args = ap.parse_args()

    # Heavy imports kept inside main so --help works without a GPU stack installed.
    import torch
    from datasets import Dataset
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        TrainingArguments,
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from trl import SFTTrainer

    tok = AutoTokenizer.from_pretrained(args.base)
    tok.pad_token = tok.pad_token or tok.eos_token
    eos = tok.eos_token or "</s>"

    rows = [json.loads(l) for l in open(args.corpus, encoding="utf-8") if l.strip()]
    if not rows:
        raise SystemExit("empty corpus — run export_corpus.py first")
    ds = Dataset.from_list([{"text": build_prompt(r, eos)} for r in rows])

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

    targs = TrainingArguments(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        bf16=True,
        logging_steps=10,
        save_strategy="epoch",
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        optim="paged_adamw_8bit",
        report_to=[],
    )
    trainer = SFTTrainer(
        model=model, args=targs, train_dataset=ds,
        dataset_text_field="text", max_seq_length=args.max_seq, tokenizer=tok,
    )
    trainer.train()
    trainer.model.save_pretrained(args.out)
    tok.save_pretrained(args.out)
    print(f"\nLoRA adapter saved -> {args.out}")
    print("Serve it: see ml/qlora/README.md (vLLM --enable-lora).")


if __name__ == "__main__":
    main()
