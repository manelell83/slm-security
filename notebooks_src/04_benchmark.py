# %% [markdown]
# # 04 — Benchmarking des détecteurs
# **Partie GPU** (checkpointée dans `preds/`) : chaque SLM chargé une fois en 4-bit exécute les 4 configurations
# `base` (zero-shot), `base_rag`, `lora`, `lora_rag` sur (i) le test étiqueté et (ii) les codes générés en P1.
#
# **Partie CPU** : a) métriques sur le test (accuracy, precision, recall, F1, MCC, IC bootstrap 95 %, McNemar,
# par CWE, JSON invalide, latence, VRAM) ; b) matrice générateurs × détecteurs ; c) vérité terrain
# (`annotation_humaine.csv` ou pseudo-vérité par vote ≥ 3/6) ; d) lien taille / pass@1 / sécurité.

# %%
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "transformers", "accelerate", "peft",
                "bitsandbytes", "sentence-transformers", "faiss-cpu", "bandit", "statsmodels", "scikit-learn"],
               check=True)

# %%
import itertools, json, numpy as np, pandas as pd, matplotlib.pyplot as plt
import slmsec as S
S.ensure_dirs()
te = S.read_csv(S.D["data"] / "det_test.csv")
gen = S.read_csv(S.D["results"] / "generations.csv")
gen["extraction_ok"] = gen["extraction_ok"].astype(str).str.lower().eq("true")
gen["id"] = gen["model"] + "|" + gen["prompt_id"]
gen_ok = gen[gen["extraction_ok"]].reset_index(drop=True)

# Sous-échantillon du test (stratifié sur le label, figé sur Drive)
ev_path = S.D["data"] / "det_test_eval.csv"
if ev_path.exists():
    ev = S.read_csv(ev_path)
else:
    n = min(S.TEST_EVAL_N, len(te))
    ev = te if n == len(te) else te.groupby("label", group_keys=False).apply(
        lambda g: g.sample(int(round(n * len(g) / len(te))), random_state=S.SEED))
    S.save_csv(ev, ev_path)
ev = ev.rename(columns={"ex_id": "id"}).reset_index(drop=True)
items = {"test": ev[["id", "code"]], "gen": gen_ok[["id", "code"]]}
print(len(ev), "exemples de test évalués ;", len(gen_ok), "codes générés")

# %%
# Contextes RAG calculés une seule fois (identiques pour tous les SLMs)
ctx_path = S.D["data"] / "rag_contexts.json"
if ctx_path.exists():
    ctxs = json.loads(ctx_path.read_text(encoding="utf-8"))
else:
    rag = S.RAG.load()
    ctxs = {scope: {i: rag.context(c) for i, c in zip(df["id"], df["code"])} for scope, df in items.items()}
    S.write_text(ctx_path, json.dumps(ctxs, ensure_ascii=False))
    rag = None
    S.free_vram()
print({k: len(v) for k, v in ctxs.items()})

# %% [markdown]
# ## Partie GPU : inférence des 4 configurations (un SLM à la fois)

# %%
def pred_path(scope, key, cfg):
    return S.D["preds"] / f"{scope}_{key}_{cfg}.csv"


def run_model(key):
    todo = [(s, c) for c in S.CONFIGS for s in items if not pred_path(s, key, c).exists()]
    if not todo:
        print(key, ": déjà fait")
        return
    has_adapter = (S.D["adapters"] / key / "adapter_config.json").exists()
    with S.loaded(key, mode="4bit") as h:
        for cfg in S.CONFIGS:
            if cfg == "lora":
                if not has_adapter:
                    print(f"{key} : pas d'adaptateur LoRA (exécuter 03) -> configs LoRA sautées")
                    break
                S.attach_adapter(h, key)
            for scope, df in items.items():
                if (scope, cfg) not in todo:
                    continue
                ctx = [ctxs[scope][i] for i in df["id"]] if cfg.endswith("rag") else None
                out = pd.DataFrame(S.detect_batch(h, list(df["code"]), ctx))
                out.insert(0, "id", df["id"].values)
                out["detector"], out["config"] = key, cfg
                S.save_csv(out, pred_path(scope, key, cfg))
                print(f"  {key}/{cfg}/{scope} : JSON valide {out['json_valid'].mean():.0%}, "
                      f"{out['latency_s'].mean():.2f} s/ex")


for key in S.MODEL_KEYS:
    S.log(f"Inférence détecteur {key}")
    run_model(key)

# %%
# Bandit sur le même test étiqueté
bp = S.D["preds"] / "test_bandit_static.csv"
if not bp.exists():
    rows = []
    for r in ev.to_dict("records"):
        v = S.bandit_verdict(S.run_bandit(r["code"])[0])
        rows.append(dict(id=r["id"], pred=v["pred"], cwe_pred=v["cwe_pred"], explanation=v["explanation"],
                         json_valid=None, latency_s=None, peak_vram_gb=0.0, detector="bandit", config="static"))
    S.save_csv(pd.DataFrame(rows), bp)

# %% [markdown]
# ## a) Métriques sur le test étiqueté

# %%
def load_preds(scope):
    dfs = [S.read_csv(p) for p in S.D["preds"].glob(f"{scope}_*.csv")]
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


pt = load_preds("test").merge(ev[["id", "label", "cwe"]], on="id")
pt["pred"] = pt["pred"].astype(str).str.lower().eq("true").astype(int)
rows = []
for (det, cfg), g in pt.groupby(["detector", "config"]):
    m = S.bin_metrics(g["label"], g["pred"])
    lo, hi = S.bootstrap_ci(g["label"], g["pred"], "f1")
    mlo, mhi = S.bootstrap_ci(g["label"], g["pred"], "mcc")
    tp = g[(g["label"] == 1) & (g["pred"] == 1) & (g["cwe"] != "CWE-Other")]
    jv = g["json_valid"].astype(str).str.lower()
    rows.append(dict(detector=det, config=cfg, n=len(g), **m, f1_ci95=f"[{lo:.2f}, {hi:.2f}]",
                     mcc_ci95=f"[{mlo:.2f}, {mhi:.2f}]",
                     cwe_acc_tp=(tp["cwe_pred"] == tp["cwe"]).mean() if len(tp) else np.nan,
                     json_invalid_rate=(jv == "false").mean() if det != "bandit" else np.nan,
                     latency_s=pd.to_numeric(g["latency_s"], errors="coerce").mean(),
                     peak_vram_gb=pd.to_numeric(g["peak_vram_gb"], errors="coerce").max()))
met = pd.DataFrame(rows).sort_values(["detector", "config"])
S.save_csv(met, S.D["results"] / "det_metrics_test.csv")
met

# %%
# Meilleure configuration = F1 moyen maximal sur les 5 SLMs (départage : MCC)
agg = met[met["detector"] != "bandit"].groupby("config")[["f1", "mcc"]].mean().sort_values(["f1", "mcc"],
                                                                                           ascending=False)
BEST = agg.index[0]
S.save_csv(pd.DataFrame([dict(config=BEST, f1_mean=agg.iloc[0]["f1"], mcc_mean=agg.iloc[0]["mcc"])]),
           S.D["results"] / "best_config.csv")
print(agg, "\nMeilleure configuration :", BEST)

# Graphique F1 + IC
fig, ax = plt.subplots(figsize=(10, 4))
lab = met["detector"] + "/" + met["config"]
err = np.array([[f - float(c.strip("[]").split(",")[0]), float(c.strip("[]").split(",")[1]) - f]
                for f, c in zip(met["f1"], met["f1_ci95"])]).T
ax.bar(lab, met["f1"], yerr=err, capsize=3)
ax.set_ylabel("F1 (IC 95 % bootstrap)")
ax.tick_params(axis="x", rotation=75)
fig.tight_layout()
fig.savefig(S.D["results"] / "det_f1_test.png", dpi=150)
plt.show()

# %%
# McNemar entre configurations (même SLM) et meilleure config vs Bandit
wide = pt.pivot_table(index="id", columns=["detector", "config"], values="pred").dropna(axis=1)
yv = ev.set_index("id").loc[wide.index, "label"].values
pairs = [("base", "base_rag"), ("base", "lora"), ("lora", "lora_rag"), ("base_rag", "lora_rag")]
mc = []
for key in S.MODEL_KEYS:
    for c1, c2 in pairs + [(BEST, "bandit")]:
        a = (key, c1)
        b = ("bandit", "static") if c2 == "bandit" else (key, c2)
        if a in wide and b in wide:
            mc.append(dict(model=key, config_1=c1, config_2=c2, **S.mcnemar_test(yv, wide[a], wide[b])))
mc = pd.DataFrame(mc)
if len(mc):
    mc["significatif_5pct"] = mc["pvalue"] < 0.05
S.save_csv(mc, S.D["results"] / "mcnemar.csv")
mc

# %%
# Rappel par CWE (exemples vulnérables du test)
pv = pt[pt["label"] == 1]
rec = pv.pivot_table(index="cwe", columns=["detector", "config"], values="pred", aggfunc="mean")
rec.columns = [f"{d}/{c}" for d, c in rec.columns]
rec.insert(0, "n", pv.groupby("cwe")["id"].nunique())
S.save_csv(rec.reset_index(), S.D["results"] / "det_recall_by_cwe.csv")
rec.round(2)

# %% [markdown]
# ## b) Rôles échangés : 5 générateurs × 5 détecteurs (+ Bandit), meilleure configuration

# %%
pg = load_preds("gen")
pg = pg[pg["config"] == BEST]
pg["pred"] = pg["pred"].astype(str).str.lower().eq("true").astype(int)
bd = S.read_csv(S.D["results"] / "detections_bandit.csv")
bd = bd[bd["extraction_ok"].astype(str).str.lower().eq("true")].copy()
bd["id"] = bd["generator"] + "|" + bd["prompt_id"]
bd["pred"] = bd["pred"].astype(str).str.lower().eq("true").astype(int)
votes = pg.pivot_table(index="id", columns="detector", values="pred")
votes["bandit"] = bd.set_index("id")["pred"]
DETS = [k for k in S.MODEL_KEYS if k in votes] + ["bandit"]
votes = votes[DETS].dropna()
votes["generator"] = [i.split("|")[0] for i in votes.index]
cross = votes.groupby("generator")[DETS].mean().reindex([k for k in S.MODEL_KEYS if k in set(votes["generator"])])
S.save_csv(cross.reset_index(), S.D["results"] / "cross_matrix.csv")

fig, ax = plt.subplots(figsize=(7, 5))
im = ax.imshow(cross.values, cmap="Reds", vmin=0, vmax=1)
ax.set_xticks(range(len(DETS)), DETS, rotation=40, ha="right")
ax.set_yticks(range(len(cross)), cross.index)
for i, j in itertools.product(range(cross.shape[0]), range(cross.shape[1])):
    ax.text(j, i, f"{cross.values[i, j]:.2f}", ha="center", va="center", fontsize=8)
ax.set_xlabel("détecteur")
ax.set_ylabel("générateur")
ax.set_title(f"Taux de codes jugés vulnérables ({BEST})")
fig.colorbar(im)
fig.tight_layout()
fig.savefig(S.D["results"] / "cross_matrix.png", dpi=150)
plt.show()
cross.round(2)

# %% [markdown]
# ## c) Vérité terrain : annotation humaine, sinon pseudo-vérité (vote ≥ 3/6)

# %%
votes["votes"] = votes[DETS].sum(axis=1)
votes["pseudo_label"] = (votes["votes"] >= 3).astype(int)
ann_path = S.D["results"] / "annotation_humaine.csv"
if not ann_path.exists():
    ann = gen[["id", "model", "prompt_id", "cwe_expected", "extraction_ok", "code"]].copy()
    ann = ann.merge(votes[["votes", "pseudo_label"]], left_on="id", right_index=True, how="left")
    ann = ann.merge(bd[["id", "rules"]].rename(columns={"rules": "bandit_rules"}), on="id", how="left")
    ann["label_humain"], ann["commentaire"] = "", ""
    S.save_csv(ann, ann_path)
    print("annotation_humaine.csv créé : remplir label_humain (1 = vulnérable, 0 = sûr) puis relancer.")
ann = S.read_csv(ann_path)
hum = pd.to_numeric(ann["label_humain"], errors="coerce")
filled = hum.notna() & ann["extraction_ok"].astype(str).str.lower().eq("true")
truth = votes[["pseudo_label"]].rename(columns={"pseudo_label": "truth"})
human = dict(zip(ann.loc[filled, "id"], hum[filled].astype(int)))
truth["truth"] = [human.get(i, t) for i, t in zip(truth.index, truth["truth"])]
n_h = sum(i in human for i in truth.index)
SOURCE = "humaine" if n_h == len(truth) else ("PSEUDO-VÉRITÉ (vote ≥ 3/6)" if n_h == 0
                                               else f"mixte ({n_h} humaines, reste pseudo-vérité)")
truth["source"] = ["humaine" if i in human else "pseudo" for i in truth.index]
S.save_csv(truth.reset_index(), S.D["results"] / "truth.csv")
S.save_csv(pd.DataFrame([dict(source=SOURCE, n=len(truth), n_humaines=n_h)]), S.D["results"] / "truth_source.csv")
print("Vérité terrain :", SOURCE)

# %%
# Performance des détecteurs vs vérité ; auto-détection vs détection croisée
y = truth["truth"]
dvt = pd.DataFrame([dict(detector=d, **S.bin_metrics(y, votes[d]), source=SOURCE) for d in DETS])
S.save_csv(dvt, S.D["results"] / "det_vs_truth.csv")
svc = []
for d in [k for k in DETS if k != "bandit"]:
    own, oth = votes["generator"] == d, votes["generator"] != d
    svc.append(dict(detector=d, n_own=int(own.sum()),
                    flag_rate_own=votes.loc[own, d].mean(), flag_rate_others=votes.loc[oth, d].mean(),
                    acc_own=(votes.loc[own, d] == y[own]).mean(), acc_others=(votes.loc[oth, d] == y[oth]).mean()))
svc = pd.DataFrame(svc)
S.save_csv(svc, S.D["results"] / "self_vs_cross.csv")
display(dvt.round(3), svc.round(3))

# %%
# Accord entre détecteurs : kappa de Cohen (paires) et kappa de Fleiss (global)
from sklearn.metrics import cohen_kappa_score
from statsmodels.stats.inter_rater import aggregate_raters, fleiss_kappa
K = pd.DataFrame([[cohen_kappa_score(votes[a], votes[b]) if a != b else 1.0 for b in DETS] for a in DETS],
                 index=DETS, columns=DETS)
fk = fleiss_kappa(aggregate_raters(votes[DETS].astype(int).values)[0])
S.save_csv(K.reset_index().rename(columns={"index": "detector"}), S.D["results"] / "kappa_cohen.csv")
S.save_csv(pd.DataFrame([dict(fleiss_kappa=fk, cohen_mean=K.values[np.triu_indices(len(DETS), 1)].mean(),
                              n_codes=len(votes), config=BEST)]), S.D["results"] / "kappa_summary.csv")
fig, ax = plt.subplots(figsize=(6, 5))
im = ax.imshow(K.values, cmap="viridis", vmin=-1, vmax=1)
ax.set_xticks(range(len(DETS)), DETS, rotation=40, ha="right")
ax.set_yticks(range(len(DETS)), DETS)
for i, j in itertools.product(range(len(DETS)), range(len(DETS))):
    ax.text(j, i, f"{K.values[i, j]:.2f}", ha="center", va="center", fontsize=8, color="w")
ax.set_title(f"Kappa de Cohen (Fleiss = {fk:.2f})")
fig.colorbar(im)
fig.tight_layout()
fig.savefig(S.D["results"] / "kappa_cohen.png", dpi=150)
plt.show()

# %% [markdown]
# ## d) Taille / pass@1 (article) / sécurité / coûts

# %%
from scipy.stats import pearsonr, spearmanr
gs = S.read_csv(S.D["results"] / "generation_summary.csv").set_index("model")
bs = S.read_csv(S.D["results"] / "bandit_summary.csv").set_index("model")
f1b = met[met["config"] == BEST].set_index("detector")
rows = []
for k, v in S.MODELS.items():
    g = votes[votes["generator"] == k]
    rows.append(dict(model=k, size_b=v["size_b"], pass1_article=v["pass1"],
                     vuln_rate_bandit=bs.loc[k, "vuln_rate_pct"] / 100 if k in bs.index else np.nan,
                     vuln_rate_truth=y[g.index].mean() if len(g) else np.nan,
                     extraction_ok_rate=gs.loc[k, "extraction_ok_rate"] if k in gs.index else np.nan,
                     gen_latency_s=gs.loc[k, "latency_mean_s"] if k in gs.index else np.nan,
                     gen_peak_vram_gb=gs.loc[k, "peak_vram_gb"] if k in gs.index else np.nan,
                     det_f1_test=f1b.loc[k, "f1"] if k in f1b.index else np.nan,
                     det_latency_s=f1b.loc[k, "latency_s"] if k in f1b.index else np.nan))
ss = pd.DataFrame(rows)
S.save_csv(ss, S.D["results"] / "size_security.csv")
cor = []
for x, t in [("size_b", "vuln_rate_truth"), ("size_b", "vuln_rate_bandit"), ("pass1_article", "vuln_rate_truth"),
             ("pass1_article", "vuln_rate_bandit"), ("size_b", "det_f1_test"), ("pass1_article", "det_f1_test"),
             ("gen_peak_vram_gb", "vuln_rate_truth")]:
    d = ss[[x, t]].dropna()
    if len(d) >= 3 and d[x].nunique() > 1 and d[t].nunique() > 1:
        rs, ps = spearmanr(d[x], d[t])
        rp, pp = pearsonr(d[x], d[t])
        cor.append(dict(x=x, y=t, n=len(d), spearman=rs, p_spearman=ps, pearson=rp, p_pearson=pp))
cor = pd.DataFrame(cor)
S.save_csv(cor, S.D["results"] / "correlations.csv")
display(ss.round(3), cor.round(3))

fig, axs = plt.subplots(1, 3, figsize=(13, 4))
for ax, (x, t) in zip(axs, [("size_b", "vuln_rate_truth"), ("pass1_article", "vuln_rate_truth"),
                            ("size_b", "det_f1_test")]):
    ax.scatter(ss[x], ss[t])
    for r in ss.itertuples():
        ax.annotate(r.model, (getattr(r, x), getattr(r, t)), fontsize=7)
    ax.set_xlabel(x)
    ax.set_ylabel(t)
fig.suptitle(f"Taille / pass@1 / sécurité (vérité : {SOURCE})")
fig.tight_layout()
fig.savefig(S.D["results"] / "size_security.png", dpi=150)
plt.show()

# %%
S.build_report()
print("Phase P4 terminée — mettre à jour PROGRESS.md")
