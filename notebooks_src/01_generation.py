# %% [markdown]
# # 01 — Génération de code par les 5 SLMs (SecurityEval)
# - N prompts SecurityEval distincts (1 par CWE), **mêmes prompts pour tous les modèles**, 1 échantillon.
# - temperature 0.2, top-p 0.95, max_new_tokens 512, graine fixe (protocole de Hasan et al., 2026).
# - Extraction robuste + `extraction_ok` ; jusqu'à 2 régénérations si l'extraction échoue (bug 1).
# - Stable-Code-3B en mode complétion + stop strings + repetition_penalty + coupe des répétitions (bug 2).
# - Pic VRAM et latence mesurés. Checkpoint : `gen/<modele>.jsonl`, une ligne par prompt.

# %%
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "transformers", "accelerate"], check=True)

# %%
import time, pandas as pd, torch
import slmsec as S
S.ensure_dirs()
sel = S.read_csv(S.D["data"] / "prompts_selected.csv")
print(len(sel), "prompts ;", sel["cwe_expected"].nunique(), "CWE")
# Pour ne lancer qu'une partie : MODELS_TO_RUN = ["qwen2.5-coder-1.5b"]
MODELS_TO_RUN = S.MODEL_KEYS

# %%
def generate_one(h, row, idx):
    """Génère pour un prompt, régénère jusqu'à MAX_REGEN fois si l'extraction échoue."""
    key, fmt = h.key, S.MODELS[h.key]["fmt"]
    text = S.build_gen_prompt(h.tok, key, row["prompt"])
    raws, rec = [], None
    for attempt in range(1 + S.MAX_REGEN):
        seed = S.SEED + 1000 * attempt + idx
        S.set_seed(seed)
        outs, st = S.generate_text(h.model, h.tok, [text], S.gen_kwargs(key), stop_strings=S.gen_stops(key))
        raw = outs[0]
        raws.append(raw)
        code, ok, why, rep = S.extract_code(raw, fmt, row["prompt"],
                                            prefix=row["prompt"] if fmt == "completion" else None)
        rec = dict(model=key, prompt_id=row["prompt_id"], cwe_expected=row["cwe_expected"], prompt_idx=idx,
                   code=code, raw=raw, extraction_ok=ok, extraction_reason=why, repetition_cut=rep,
                   attempts=attempt + 1, first_attempt_ok=(attempt == 0 and ok), seed=seed,
                   latency_s=round(st["latency_s"], 3), new_tokens=st["new_tokens"][0],
                   tok_per_s=round(st["new_tokens"][0] / max(st["latency_s"], 1e-6), 2),
                   peak_vram_gb=round(st["peak_vram_gb"], 3), load_vram_gb=round(h.load_vram_gb, 3))
        if ok:
            break
    rec["raw_attempts"] = raws
    return rec

# %%
# Boucle principale : un seul modèle en VRAM à la fois ; reprise automatique après coupure
for key in MODELS_TO_RUN:
    path = S.D["gen"] / f"{key}.jsonl"
    done = {r["prompt_id"] for r in S.read_jsonl(path)}
    todo = [(i, r) for i, r in enumerate(sel.to_dict("records")) if r["prompt_id"] not in done]
    if not todo:
        print(f"{key} : déjà fait ({len(done)} prompts)")
        continue
    S.log(f"Génération {key} : {len(todo)} prompts restants")
    with S.loaded(key, mode="fp16") as h:
        print(f"VRAM après chargement : {h.load_vram_gb:.2f} Go")
        for idx, row in todo:
            rec = generate_one(h, row, idx)
            S.append_jsonl(path, rec)
            print(f"  {row['prompt_id']:30s} ok={rec['extraction_ok']} essais={rec['attempts']} "
                  f"{rec['latency_s']:.1f}s {rec['peak_vram_gb']:.2f}Go")

# %%
# Consolidation : generations.csv + synthèse (taux d'échec d'extraction reporté)
recs = [r for k in S.MODEL_KEYS for r in S.read_jsonl(S.D["gen"] / f"{k}.jsonl")]
gen = pd.DataFrame(recs).drop(columns=["raw_attempts"]).drop_duplicates(["model", "prompt_id"], keep="last")
S.save_csv(gen, S.D["results"] / "generations.csv")
summ = gen.groupby("model").agg(
    generated=("prompt_id", "count"),
    extraction_ok_rate=("extraction_ok", "mean"),
    extraction_fail_initial_rate=("first_attempt_ok", lambda s: 1 - s.mean()),
    extraction_fail_final=("extraction_ok", lambda s: int((~s.astype(bool)).sum())),
    mean_attempts=("attempts", "mean"),
    repetition_cut=("repetition_cut", "sum"),
    latency_mean_s=("latency_s", "mean"),
    tok_per_s=("tok_per_s", "mean"),
    peak_vram_gb=("peak_vram_gb", "max"),
    load_vram_gb=("load_vram_gb", "max"),
).reset_index()
S.save_csv(summ, S.D["results"] / "generation_summary.csv")
summ

# %%
# Raisons d'échec d'extraction et aperçu d'un code par modèle
print(gen.groupby(["model", "extraction_reason"]).size().to_string())
for key in S.MODEL_KEYS:
    g = gen[gen["model"] == key]
    if len(g):
        print(f"\n===== {key} | {g.iloc[0]['prompt_id']} | ok={g.iloc[0]['extraction_ok']}\n{g.iloc[0]['code'][:600]}")

# %%
S.build_report()
print("Phase P1 terminée — mettre à jour PROGRESS.md")
