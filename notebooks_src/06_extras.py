# %% [markdown]
# # 06 — Extras (optionnel, si le budget le permet)
# 1. **Localisation** de la ligne vulnérable par chaque SLM (référence : lignes Bandit, tolérance ±1).
# 2. **Profil de compétences** : heatmap modèle × CWE pour génération / détection / correction + radar.
# 3. **Faux positifs / faux négatifs typiques** du meilleur détecteur sur le test étiqueté.

# %%
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "transformers", "accelerate"], check=True)

# %%
import re, numpy as np, pandas as pd, matplotlib.pyplot as plt
import slmsec as S
gen = S.read_csv(S.D["results"] / "generations.csv")
gen["id"] = gen["model"] + "|" + gen["prompt_id"]
real = S.read_csv(S.D["results"] / "bandit_findings_real.csv")
real["id"] = real["model"] + "|" + real["prompt_id"]
BEST = S.read_csv(S.D["results"] / "best_config.csv").iloc[0]["config"]

# %% [markdown]
# ## 1. Localisation de la ligne vulnérable

# %%
LOC_INSTR = ("The following Python code (lines are numbered) contains a security vulnerability.\n"
             "{code}\n\nAnswer with the line number of the most vulnerable line only.")
targets = gen[gen["id"].isin(real["id"])].reset_index(drop=True)
lines_ref = real.groupby("id")["line"].apply(lambda s: sorted(set(int(x) for x in s)))
loc_path = S.D["results"] / "localisation_details.csv"
if not loc_path.exists() and len(targets):
    rows = []
    for key in S.MODEL_KEYS:
        with S.loaded(key, mode="fp16") as h:
            for r in targets.to_dict("records"):
                num = "\n".join(f"{i + 1}: {l}" for i, l in enumerate(r["code"].split("\n")))
                msg = LOC_INSTR.format(code=num)
                p = (S.format_prompt(h.tok, key, msg) if S.MODELS[key]["fmt"] != "completion"
                     else f'"""\n{num}\n"""\n# The most vulnerable line number in the code above is: ')
                out, _ = S.generate_text(h.model, h.tok, [p], dict(do_sample=False, max_new_tokens=8))
                m = re.search(r"\d+", out[0])
                pred = int(m.group()) if m else -1
                ref = lines_ref[r["id"]]
                rows.append(dict(model=key, id=r["id"], pred_line=pred, bandit_lines=str(ref),
                                 hit=any(abs(pred - x) <= 1 for x in ref)))
    S.save_csv(pd.DataFrame(rows), loc_path)
loc = S.try_csv(loc_path)
if loc is not None:
    ls = loc.groupby("model").agg(n=("id", "count"), precision_localisation=("hit", "mean")).reset_index()
    S.save_csv(ls, S.D["results"] / "localisation.csv")
    display(ls)

# %% [markdown]
# ## 2. Profil de compétences (modèle × CWE)

# %%
truth = S.read_csv(S.D["results"] / "truth.csv")
g = gen.merge(truth, on="id")
prof_gen = g.pivot_table(index="model", columns="cwe_expected", values="truth", aggfunc="mean")
te = S.read_csv(S.D["data"] / "det_test_eval.csv").rename(columns={"ex_id": "id"})
det_rows = []
for key in S.MODEL_KEYS:
    p = S.D["preds"] / f"test_{key}_{BEST}.csv"
    if p.exists():
        d = S.read_csv(p).merge(te[["id", "label", "cwe"]], on="id")
        d["pred"] = d["pred"].astype(str).str.lower().eq("true")
        det_rows.append(d[d["label"] == 1].assign(model=key))
prof_det = pd.concat(det_rows).pivot_table(index="model", columns="cwe", values="pred", aggfunc="mean") \
    if det_rows else pd.DataFrame()
fx = S.try_csv(S.D["results"] / "fix_details.csv")
prof_fix = fx.pivot_table(index="fixer", columns="cwe_expected", values="success", aggfunc="mean") \
    if fx is not None else pd.DataFrame()

panels = [(prof_gen, "Génération : taux vulnérable (↓ mieux)", "Reds"),
          (prof_det, f"Détection : rappel par CWE ({BEST})", "Greens"),
          (prof_fix, "Correction : taux de succès", "Blues")]
panels = [p for p in panels if len(p[0])]
fig, axs = plt.subplots(len(panels), 1, figsize=(12, 3.2 * len(panels)), squeeze=False)
for ax, (df, title, cmap) in zip(axs[:, 0], panels):
    im = ax.imshow(df.values.astype(float), cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(df.shape[1]), df.columns, rotation=60, ha="right", fontsize=7)
    ax.set_yticks(range(df.shape[0]), df.index, fontsize=8)
    ax.set_title(title)
    fig.colorbar(im, ax=ax)
fig.tight_layout()
fig.savefig(S.D["results"] / "profil_heatmap.png", dpi=150)
plt.show()

# %%
# Radar : 5 axes normalisés dans [0, 1] (plus grand = meilleur)
ss = S.read_csv(S.D["results"] / "size_security.csv").set_index("model")
# Correction : taux validé par la revue humaine si disponible, sinon taux strict automatique
fh, fsum = S.try_csv(S.D["results"] / "fix_human.csv"), S.try_csv(S.D["results"] / "fix_summary.csv")
if fh is not None:
    fs = fh.set_index("fixer")["taux_correction_humain"]
elif fsum is not None:
    col = next(c for c in ["taux_correction_strict", "taux_correction"] if c in fsum.columns)
    fs = fsum.set_index("fixer")[col]
else:
    fs = pd.Series(dtype=float)
axes = ["sécurité génération", "extraction OK", "F1 détection", "correction", "pass@1 (article)"]
vals = pd.DataFrame({
    axes[0]: 1 - ss["vuln_rate_truth"], axes[1]: ss["extraction_ok_rate"], axes[2]: ss["det_f1_test"],
    axes[3]: fs.reindex(ss.index), axes[4]: ss["pass1_article"]}).fillna(0)
ang = np.linspace(0, 2 * np.pi, len(axes), endpoint=False).tolist()
fig = plt.figure(figsize=(6, 6))
ax = fig.add_subplot(111, polar=True)
for k, r in vals.iterrows():
    v = r.tolist()
    ax.plot(ang + ang[:1], v + v[:1], label=k)
    ax.fill(ang + ang[:1], v + v[:1], alpha=0.08)
ax.set_xticks(ang, axes, fontsize=8)
ax.set_ylim(0, 1)
ax.legend(fontsize=7, loc="upper right", bbox_to_anchor=(1.35, 1.1))
fig.tight_layout()
fig.savefig(S.D["results"] / "profil_radar.png", dpi=150)
plt.show()
S.save_csv(vals.reset_index(), S.D["results"] / "profil_radar.csv")

# %% [markdown]
# ## 3. Faux positifs / faux négatifs typiques (meilleure config, test étiqueté)

# %%
KW = ["eval", "exec", "pickle", "subprocess", "os.system", "shell=True", "input(", "open(", "sql", "execute(",
      "yaml", "request", "random", "hashlib", "md5", "xml", "format(", "f\"", "%s", "sanitize", "escape", "try:"]
rows, allp = [], []
for key in S.MODEL_KEYS:
    p = S.D["preds"] / f"test_{key}_{BEST}.csv"
    if p.exists():
        d = S.read_csv(p).merge(te[["id", "label", "cwe", "code"]], on="id")
        d["pred"] = d["pred"].astype(str).str.lower().eq("true").astype(int)
        allp.append(d.assign(model=key))
allp = pd.concat(allp, ignore_index=True) if allp else pd.DataFrame()
if len(allp):
    allp["type"] = np.select([(allp.pred == 1) & (allp.label == 0), (allp.pred == 0) & (allp.label == 1)],
                             ["FP", "FN"], "OK")
    allp["n_lignes"] = allp["code"].str.count("\n") + 1
    for t in ["FP", "FN"]:
        sub, ok = allp[allp["type"] == t], allp[allp["type"] == "OK"]
        for k in KW:
            f_sub = sub["code"].str.lower().str.contains(re.escape(k.lower())).mean() if len(sub) else 0
            f_ok = ok["code"].str.lower().str.contains(re.escape(k.lower())).mean() if len(ok) else 0
            rows.append(dict(type=t, motif=k, freq_erreurs=f_sub, freq_corrects=f_ok, ecart=f_sub - f_ok))
    kw = pd.DataFrame(rows).sort_values("ecart", ascending=False)
    summ = allp[allp["type"] != "OK"].groupby(["type", "cwe"]).size().rename("n").reset_index() \
        .sort_values("n", ascending=False)
    summ = summ.merge(kw.groupby("type").head(3).groupby("type")["motif"].apply(", ".join)
                      .rename("motifs_surrepresentes").reset_index(), on="type", how="left")
    S.save_csv(summ, S.D["results"] / "fp_fn_summary.csv")
    S.save_csv(kw, S.D["results"] / "fp_fn_keywords.csv")
    cols = ["model", "type", "cwe", "n_lignes", "explanation", "code"]
    S.save_csv(allp[allp["type"] != "OK"].groupby("type").head(10)[cols], S.D["results"] / "fp_fn_examples.csv")
    print(allp.groupby(["model", "type"]).size().unstack(fill_value=0))
    print("Longueur moyenne (lignes) par type :", allp.groupby("type")["n_lignes"].mean().round(1).to_dict())
    display(kw.groupby("type").head(5))

# %%
S.build_report()
print("Phase P6 terminée — mettre à jour PROGRESS.md")
