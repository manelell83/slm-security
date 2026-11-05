# %% [markdown]
# # 03 — Approche B : détecteur SLM affiné (QLoRA) + base RAG
# 1. Jeu étiqueté Python (CyberNative DPO : `chosen` = sûr, `rejected` = vulnérable ; repli CVEfixes),
#    dédupliqué, filtré anti-fuite vs SecurityEval, split 80/10/10 **par paire** stratifié (graine fixe).
#    **SecurityEval n'est jamais utilisé pour l'entraînement ni pour la base RAG.**
# 2. Base RAG (train uniquement) : exemples vulnérables + CWE + correctif, règles Bandit→CWE, résumés CWE ;
#    bge-small-en-v1.5 + FAISS-cpu.
# 3. QLoRA par SLM (5 adaptateurs sur Drive) : nf4, compute fp16, r=16, α=32, dropout 0.05, all-linear,
#    max_len 768, batch 2 × accum 8, lr 2e-4, 1 epoch, gradient checkpointing, paged_adamw_8bit.
#    Reprise automatique depuis le dernier checkpoint si la session coupe.

# %%
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "transformers", "accelerate", "peft",
                "bitsandbytes", "datasets", "sentence-transformers", "faiss-cpu", "scikit-learn"], check=True)

# %%
import json, time, pandas as pd, torch
import slmsec as S
S.ensure_dirs()
MODELS_TO_TRAIN = S.MODEL_KEYS   # ex. ["qwen2.5-coder-1.5b"] pour entraîner un seul modèle par session

# %% [markdown]
# ## 1. Jeu de données étiqueté (CPU)

# %%
paths = {s: S.D["data"] / f"det_{s}.csv" for s in ["train", "val", "test"]}
if all(p.exists() for p in paths.values()):
    tr, va, te = (S.read_csv(paths[s]) for s in ["train", "val", "test"])
    print("Splits existants réutilisés")
else:
    pairs, src = S.load_vuln_dataset()
    print(f"Source : {src} — {len(pairs)} paires Python")
    print("Exemple :", json.dumps({k: str(v)[:150] for k, v in pairs[0].items()}, ensure_ascii=False, indent=1))
    secev = S.load_securityeval()   # sert UNIQUEMENT au filtre anti-fuite
    tr, va, te, stats = S.build_detection_splits(pairs, secev)
    for s, d in zip(["train", "val", "test"], [tr, va, te]):
        S.save_csv(d, paths[s])
    st = pd.DataFrame([dict(stats, source=src, train=len(tr), val=len(va), test=len(te),
                            vuln_train=int(tr["label"].sum()))])
    S.save_csv(st, S.D["results"] / "dataset_stats.csv")
    print(st.T)
# Vérifications : pas de paire partagée entre splits, équilibre des classes
assert not (set(tr["pair_id"]) & set(te["pair_id"])) and not (set(tr["pair_id"]) & set(va["pair_id"]))
print(pd.concat([tr, va, te]).groupby(["split", "label"]).size().unstack())
print(tr[tr["label"] == 1]["cwe"].value_counts().head(15))

# %% [markdown]
# ## 2. Base RAG (train uniquement)

# %%
if (S.D["rag"] / "index.faiss").exists():
    rag = S.RAG.load()
    print("Index RAG existant :", len(rag.docs), "documents")
else:
    docs = S.rag_documents(tr)
    rag = S.RAG.build(docs)
    print("Index RAG construit :", len(docs), "documents",
          pd.Series([d["kind"] for d in docs]).value_counts().to_dict())
# Test rapide de récupération
ex = te[te["label"] == 1].iloc[0]
print("CWE réel :", ex["cwe"])
for d in rag.search(ex["code"]):
    print(f"  {d['score']:.3f} [{d['kind']}] {d['text'][:90]!r}")
rag = None   # libère l'encodeur (il sera rechargé en P4)
S.free_vram()

# %% [markdown]
# ## 3. Entraînement QLoRA (un SLM à la fois)

# %%
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import DataCollatorForSeq2Seq, Trainer, TrainingArguments
from transformers.trainer_utils import get_last_checkpoint


def train_one(key):
    out = S.D["adapters"] / key
    if (out / "adapter_config.json").exists():
        print(f"{key} : adaptateur déjà présent, on saute")
        return None
    S.free_vram()
    model, tok = S.load_model(key, mode="4bit")
    tok.padding_side = "right"
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True,
                                            gradient_checkpointing_kwargs={"use_reentrant": False})
    model = get_peft_model(model, LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
                                             target_modules="all-linear", task_type="CAUSAL_LM"))
    for p in model.parameters():          # paramètres entraînables en fp32 (évite l'erreur d'unscale fp16)
        if p.requires_grad and p.dtype != torch.float32:
            p.data = p.data.float()
    model.print_trainable_parameters()

    f_tr, skip_tr = S.make_train_features(tok, key, tr)
    f_va, _ = S.make_train_features(tok, key, va.head(100))
    print(f"{key} : {len(f_tr)} exemples d'entraînement ({skip_tr} > {S.DET_MAX_LEN} tokens écartés)")
    ckpt_dir = S.D["adapters"] / f"{key}_ckpt"
    args = TrainingArguments(
        output_dir=str(ckpt_dir), per_device_train_batch_size=2, gradient_accumulation_steps=8,
        per_device_eval_batch_size=2, learning_rate=2e-4, num_train_epochs=1, lr_scheduler_type="cosine",
        warmup_ratio=0.03, max_grad_norm=0.3, fp16=True, bf16=False, optim="paged_adamw_8bit",
        gradient_checkpointing=True, gradient_checkpointing_kwargs={"use_reentrant": False},
        logging_steps=10, save_strategy="steps", save_steps=40, save_total_limit=2,
        report_to="none", seed=S.SEED, dataloader_num_workers=0, remove_unused_columns=False)
    trainer = Trainer(model=model, args=args, train_dataset=Dataset.from_list(f_tr),
                      eval_dataset=Dataset.from_list(f_va),
                      data_collator=DataCollatorForSeq2Seq(tok, padding=True, label_pad_token_id=-100,
                                                           pad_to_multiple_of=8))
    last = get_last_checkpoint(str(ckpt_dir)) if ckpt_dir.exists() else None
    if last:
        print("Reprise depuis", last)
    torch.cuda.reset_peak_memory_stats()
    t0 = time.time()
    res = trainer.train(resume_from_checkpoint=last)
    minutes = (time.time() - t0) / 60
    ev = trainer.evaluate()
    model.save_pretrained(str(out))
    tok.save_pretrained(str(out))
    row = dict(model=key, n_train=len(f_tr), n_skipped=skip_tr, steps=res.global_step,
               train_loss=res.training_loss, eval_loss=ev.get("eval_loss"), minutes=round(minutes, 1),
               peak_vram_gb=round(torch.cuda.max_memory_allocated() / 1e9, 2))
    log_path = S.D["results"] / "train_log.csv"
    old = S.try_csv(log_path)
    S.save_csv(pd.concat([old[old["model"] != key], pd.DataFrame([row])]) if old is not None
               else pd.DataFrame([row]), log_path)
    return row

# %%
for key in MODELS_TO_TRAIN:
    S.log(f"QLoRA {key}")
    print(train_one(key))
    S.free_vram()
    print(f"VRAM après libération : {S.vram_gb():.2f} Go")

# %%
# Contrôle : un adaptateur répond bien au format JSON (3 exemples du val)
key = MODELS_TO_TRAIN[0]
with S.loaded(key, mode="4bit", adapter=S.D["adapters"] / key) as h:
    for r, out in zip(va.head(3).to_dict("records"), S.detect_batch(h, list(va.head(3)["code"]))):
        print(r["label"], r["cwe"], "->", out["pred"], out["cwe_pred"], out["json_valid"], out["explanation"])

# %%
S.build_report()
print("Phase P3 terminée — mettre à jour PROGRESS.md")
