# %% [markdown]
# # 02 — Approche A : analyse statique (Bandit, Semgrep optionnel)
# Corrections : ligne / extrait issus du `line_number` de Bandit et dédupliqués (bug 3) ;
# alertes d'import B401–B413 séparées des vraies vulnérabilités (bug 4) ; observations
# générées à partir des données (bug 5). **CPU uniquement.**
#
# Sortie standard : `results/detections_bandit.csv` (même format pour tous les détecteurs :
# `generator, prompt_id, cwe_expected, detector, config, pred, cwe_pred, explanation, ...`).

# %%
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
RUN_SEMGREP = False   # passer à True pour ajouter Semgrep (p/python), plus lent
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "bandit"] + (["semgrep"] if RUN_SEMGREP else []),
               check=True)

# %%
import pandas as pd, matplotlib.pyplot as plt
import slmsec as S
gen = S.read_csv(S.D["results"] / "generations.csv")
gen["extraction_ok"] = gen["extraction_ok"].astype(str).str.lower().eq("true")
gen["code"] = gen["code"].fillna("")
print(len(gen), "codes générés ;", int(gen["extraction_ok"].sum()), "extraits correctement")

# %%
# Analyse Bandit de chaque code extrait (les codes non extraits sont exclus des taux, mais comptés)
det_rows, find_rows = [], []
for r in gen.to_dict("records"):
    base = dict(generator=r["model"], prompt_id=r["prompt_id"], cwe_expected=r["cwe_expected"],
                detector="bandit", config="static", extraction_ok=r["extraction_ok"])
    if not r["extraction_ok"]:
        det_rows.append(dict(base, pred=None, pred_any=None, json_valid=None, bandit_error="extraction_failed"))
        continue
    findings, err = S.run_bandit(r["code"])
    v = S.bandit_verdict(findings)
    det_rows.append(dict(base, **v, json_valid=None, bandit_error=err or ""))
    for f in findings:
        find_rows.append(dict(model=r["model"], prompt_id=r["prompt_id"], cwe_expected=r["cwe_expected"], **f))
det = pd.DataFrame(det_rows)
findings = pd.DataFrame(find_rows, columns=["model", "prompt_id", "cwe_expected", "rule", "name", "severity",
                                            "confidence", "line", "snippet", "text", "cwe", "informational"])
findings = findings.drop_duplicates(["model", "prompt_id", "rule", "line"])
findings["informational"] = findings["informational"].astype(bool)
S.save_csv(det, S.D["results"] / "detections_bandit.csv")
S.save_csv(findings, S.D["results"] / "bandit_findings_all.csv")
S.save_csv(findings[~findings["informational"]].drop(columns=["informational"]),
           S.D["results"] / "bandit_findings_real.csv")
S.save_csv(findings[findings["informational"]], S.D["results"] / "bandit_findings_info.csv")
print(findings.groupby(["informational", "rule"]).size().to_string())

# %%
# Synthèse par modèle : vraies vulnérabilités (MEDIUM+) vs alertes informatives
gs = S.try_csv(S.D["results"] / "generation_summary.csv")
rows = []
for key in S.MODEL_KEYS:
    d, g = det[det["generator"] == key], gen[gen["model"] == key]
    a = d[d["extraction_ok"]]
    f = findings[findings["model"] == key]
    real = f[~f["informational"]]
    row = dict(model=key, generated=len(g), analyzed=len(a),
               extraction_ok_rate=len(a) / max(1, len(g)),
               extraction_fail_initial=int((~g["first_attempt_ok"].astype(str).str.lower().eq("true")).sum()),
               vulnerable=int(a["pred"].astype(bool).sum()),
               vuln_rate_pct=100 * a["pred"].astype(bool).mean() if len(a) else 0.0,
               vulnerable_any_sev=int(a["pred_any"].astype(bool).sum()),
               n_real=len(real), n_info=int(f["informational"].sum()))
    for sev in ["HIGH", "MEDIUM", "LOW"]:
        row[f"real_{sev}"] = int((real["severity"] == sev).sum())
    if gs is not None and key in set(gs["model"]):
        s = gs[gs["model"] == key].iloc[0]
        row.update(latency_mean_s=s["latency_mean_s"], peak_vram_gb=s["peak_vram_gb"])
    rows.append(row)
summary = pd.DataFrame(rows)
S.save_csv(summary, S.D["results"] / "bandit_summary.csv")
summary

# %%
# Taux de vulnérabilité par CWE attendu (quels prompts piègent les modèles ?)
a = det[det["extraction_ok"]].copy()
a["pred"] = a["pred"].astype(bool)
by_cwe = a.pivot_table(index="cwe_expected", columns="generator", values="pred", aggfunc="mean")
S.save_csv(by_cwe.reset_index(), S.D["results"] / "bandit_vuln_by_cwe.csv")
by_cwe

# %%
# Observations générées à partir des données (une par modèle)
obs = S.make_observations(summary, findings)
S.save_csv(obs, S.D["results"] / "observations.csv")
for r in obs.itertuples():
    print(f"- {r.model} : {r.observation}")

# %%
# Graphique : vulnérabilités réelles vs alertes d'import informatives
fig, ax = plt.subplots(figsize=(8, 4))
x = range(len(summary))
ax.bar([i - 0.2 for i in x], summary["vuln_rate_pct"], width=0.4, label="codes vulnérables (MEDIUM+ réel) %")
ax.bar([i + 0.2 for i in x], summary["n_info"], width=0.4, label="alertes d'import informatives (nb)", alpha=0.6)
ax.set_xticks(list(x))
ax.set_xticklabels(summary["model"], rotation=20, ha="right")
ax.legend()
ax.set_title(f"Bandit sur {S.N_PROMPTS} prompts SecurityEval")
fig.tight_layout()
fig.savefig(S.D["results"] / "bandit_vuln_rate.png", dpi=150)
plt.show()

# %%
# Semgrep (optionnel) : nombre de règles déclenchées par code
if RUN_SEMGREP:
    sg = []
    for r in gen[gen["extraction_ok"]].to_dict("records"):
        ids = S.run_semgrep(r["code"])
        sg.append(dict(generator=r["model"], prompt_id=r["prompt_id"], detector="semgrep", config="static",
                       pred=bool(ids) if ids is not None else None, rules=";".join(ids or [])))
    S.save_csv(pd.DataFrame(sg), S.D["results"] / "detections_semgrep.csv")
    print(pd.DataFrame(sg).groupby("generator")["pred"].mean())

# %%
S.build_report()
print("Phase P2 terminée — mettre à jour PROGRESS.md")
