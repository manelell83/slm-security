# %% [markdown]
# # 05 — Correction automatique des codes vulnérables
# Chaque code jugé vulnérable (vérité de P4 : humaine sinon pseudo-vérité) est corrigé par **chacun** des 5 SLMs
# (auto-correction si correcteur = générateur, sinon correction croisée). Le correcteur reçoit : code + CWE +
# explication du détecteur de référence + exemple sûr récupéré par RAG. Au plus 2 itérations.
#
# **Succès brut** = `ast.parse` OK ∧ aucune alerte Bandit réelle MEDIUM+ ∧ le détecteur LoRA+RAG d'un **autre** modèle
# juge le code sûr.
# **Succès strict** = succès brut ∧ code réellement modifié (AST différent) ∧ fonctions/arguments conservés ∧ pas
# réécrit de zéro (similarité ≥ 0.30) ∧ aucun nom non défini (pyflakes) ∧ appels stdlib conformes à leur signature.
# **Revue humaine** : chaque succès strict est relu (cellule « Revue ») → vrai taux de correction (`fix_human.csv`).
#
# Checkpoints (Drive) : `fix/iter1_gen.jsonl`, `fix/iter1_valid.jsonl`, `fix/iter2_gen_v2.jsonl`,
# `fix/iter2_valid_v2.jsonl`. **Si ces fichiers existent, le notebook ne régénère rien (pas besoin de GPU)** :
# on peut le relancer en entier (Exécution → Tout exécuter) autant de fois que nécessaire.

# %%
# Montage de Drive + dépendances
import os, sys, subprocess
from google.colab import drive
drive.mount("/content/drive")
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
if BASE not in sys.path:
    sys.path.insert(0, BASE)
# slmsec.py doit être dans BASE : s'il manque, on le demande (choisir slmsec.py dans la fenêtre)
if not os.path.exists(f"{BASE}/slmsec.py"):
    import shutil
    from google.colab import files
    print("slmsec.py absent de", BASE, "-> sélectionner le fichier slmsec.py du projet")
    up = files.upload()
    shutil.move(list(up)[0], f"{BASE}/slmsec.py")
print("slmsec.py présent :", os.path.exists(f"{BASE}/slmsec.py"))
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "transformers", "accelerate", "peft",
                "bitsandbytes", "sentence-transformers", "faiss-cpu", "bandit", "pyflakes"], check=True)

# %%
# Chargement des données de P1–P4
import ast, difflib, importlib, inspect, io, re
import numpy as np, pandas as pd
import slmsec as S
importlib.reload(S)
S.ensure_dirs()
gen = S.read_csv(S.D["results"] / "generations.csv")
gen["id"] = gen["model"] + "|" + gen["prompt_id"]
truth = S.read_csv(S.D["results"] / "truth.csv")
BEST = S.read_csv(S.D["results"] / "best_config.csv").iloc[0]["config"]
met = S.read_csv(S.D["results"] / "det_metrics_test.csv")
REF = met[(met["config"] == BEST) & (met["detector"] != "bandit")].sort_values("f1", ascending=False).iloc[0]["detector"]
vul = gen.merge(truth[truth["truth"] == 1][["id", "source"]], on="id")
FIXERS = S.MODEL_KEYS
VALIDATORS = [k for k in S.MODEL_KEYS if (S.D["adapters"] / k / "adapter_config.json").exists()]
print(f"{len(vul)} codes vulnérables | détecteur de référence : {REF}/{BEST} | vérité : {vul['source'].unique()}")
print("Validateurs LoRA disponibles :", VALIDATORS)

# %%
# Entrées du correcteur (calculées une seule fois) : CWE + explication + alertes Bandit + exemple sûr RAG
inp_path = S.D["fix"] / "fix_inputs.csv"
if inp_path.exists():
    inp = S.read_csv(inp_path)
else:
    ref = S.read_csv(S.D["preds"] / f"gen_{REF}_{BEST}.csv").set_index("id")
    rag = S.RAG.load()
    rows = []
    for r in vul.to_dict("records"):
        f, _ = S.run_bandit(r["code"])
        real = [x for x in f if not x["informational"]]
        rd = ref.loc[r["id"]] if r["id"] in ref.index else None
        if rd is not None and str(rd["pred"]).lower() == "true":
            cwe, expl, src = S.norm_cwe(rd["cwe_pred"]), str(rd["explanation"]), f"{REF}/{BEST}"
        elif real:
            cwe, expl, src = S.norm_cwe(real[0]["cwe"]), real[0]["text"], "bandit"
        else:
            cwe = S.norm_cwe(r["cwe_expected"])
            expl, src = S.CWE_DESC.get(cwe, ""), "prompt"
        rows.append(dict(id=r["id"], generator=r["model"], prompt_id=r["prompt_id"], cwe_expected=r["cwe_expected"],
                         code=r["code"], cwe=cwe, explanation=expl, info_source=src,
                         bandit_orig=";".join(sorted({x["rule"] for x in real if S.SEV[x["severity"]] >= 2})),
                         bandit_text="; ".join(f"line {x['line']}: {x['rule']} {x['text']}" for x in real)[:600],
                         safe_example=rag.safe_example(r["code"], cwe)[:900]))
    inp = pd.DataFrame(rows)
    S.save_csv(inp, inp_path)
    rag = None
    S.free_vram()
inp = inp.fillna("")
by_id = inp.set_index("id")
print(inp.groupby("info_source").size().to_string())

# %% [markdown]
# ## Prompt de correction et choix du validateur

# %%
FIX_INSTR = """The following Python code contains a security vulnerability.
Vulnerability: {cwe} - {expl}
Static analyzer findings: {bandit}
Example of a secure pattern for the same weakness (reference only, do not copy blindly):
```python
{safe}
```
Code to fix:
```python
{code}
```
{feedback}Rewrite the code to remove the vulnerability with MINIMAL changes, keeping the same functionality, imports
and function names. Return only the complete corrected code in a single ```python code block."""


def fix_prompt(tok, key, r, code, feedback=""):
    if S.MODELS[key]["fmt"] == "completion":
        return (f"# Secure reference example ({r['cwe']}):\n{r['safe_example']}\n\n"
                f"# --- Vulnerable version ({r['cwe']}: {r['explanation'][:150]}) ---\n{code}\n\n"
                f"# --- Fixed version (minimal changes, same function names) ---\n")
    fb = f"Previous attempt was still rejected: {feedback}\n" if feedback else ""
    return S.format_prompt(tok, key, FIX_INSTR.format(cwe=r["cwe"], expl=r["explanation"][:300],
                                                       bandit=r["bandit_text"] or "none", safe=r["safe_example"],
                                                       code=code, feedback=fb))


def validator_for(fixer, generator):
    """Détecteur LoRA+RAG d'un AUTRE modèle que le correcteur (et si possible que le générateur)."""
    i = S.MODEL_KEYS.index(fixer)
    order = S.MODEL_KEYS[i + 1:] + S.MODEL_KEYS[:i]
    cands = [k for k in order if k in VALIDATORS and k != generator] or [k for k in order if k in VALIDATORS]
    return cands[0] if cands else None

# %% [markdown]
# ## Garde-fous contre les faux succès

# %%
from pyflakes.api import check as _pf_check
from pyflakes.reporter import Reporter

MIN_SIM = 0.30                                            # en dessous : fichier réécrit, pas une correction minimale
_STD = set(getattr(sys, "stdlib_module_names", ()))


def _sigs(code):
    """(nom de fonction, arguments) de chaque fonction ; None si le code ne parse pas."""
    try:
        t = ast.parse(str(code))
    except Exception:
        return None
    return {(n.name, tuple(a.arg for a in n.args.args))
            for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _ast_same(a, b):
    """Vrai si les deux codes ont le même AST (seuls des espaces/commentaires diffèrent)."""
    try:
        return ast.dump(ast.parse(str(a))) == ast.dump(ast.parse(str(b)))
    except Exception:
        return False


def _undefined(code):
    """Noms non définis signalés par pyflakes (ex. io utilisé sans import)."""
    out = io.StringIO()
    try:
        _pf_check(str(code), "f.py", Reporter(out, out))
    except Exception:
        return set()
    return set(re.findall(r"undefined name '(\w+)'", out.getvalue()))


def _resolve(path):
    for i in range(len(path), 0, -1):
        try:
            obj = importlib.import_module(".".join(path[:i]))
            break
        except ImportError:
            continue
    else:
        raise ImportError(path[0])
    for p in path[i:]:
        obj = getattr(obj, p)
    return obj


def _bad_calls(code):
    """Appels stdlib incompatibles avec leur signature (ex. secrets.choice(..., k=16))."""
    try:
        tree = ast.parse(str(code))
    except Exception:
        return set()
    alias = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            for a in n.names:
                alias[a.asname or a.name] = f"{n.module}.{a.name}"
    bad = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or any(isinstance(a, ast.Starred) for a in n.args) \
                or any(k.arg is None for k in n.keywords):
            continue
        parts, f = [], n.func
        while isinstance(f, ast.Attribute):
            parts.insert(0, f.attr)
            f = f.value
        if not isinstance(f, ast.Name) or f.id not in alias:
            continue
        path = alias[f.id].split(".") + parts
        if path[0] not in _STD:
            continue
        try:
            inspect.signature(_resolve(path)).bind(*n.args, **{k.arg: None for k in n.keywords})
        except AttributeError:
            bad.add(".".join(path) + " (inexistant)")
        except TypeError:
            bad.add(".".join(path) + "()")
        except (ValueError, ImportError):
            pass
    return bad

# %% [markdown]
# ## Étapes : génération (GPU), vérifications statiques (CPU), validation croisée (GPU)

# %%
def ckpt(it, kind):
    """Itération 1 : fichiers d'origine. Itération 2 : fichiers _v2 (feedback enrichi)."""
    return S.D["fix"] / f"iter{it}_{kind}{'' if it == 1 else '_v2'}.jsonl"


def stage_generate(it, tasks):
    """Génère les corrections manquantes (un correcteur chargé à la fois) ; saute celles déjà en checkpoint."""
    path = ckpt(it, "gen")
    done = {(x["id"], x["fixer"]) for x in S.read_jsonl(path)}
    for key in FIXERS:
        todo = [t for t in tasks if t["fixer"] == key and (t["id"], key) not in done]
        if not todo:
            continue
        S.log(f"Correction it{it} par {key} : {len(todo)} codes")
        stops = ["\n# ---", "\n### ", "\n```"] if S.MODELS[key]["fmt"] == "completion" else S.gen_stops(key)
        with S.loaded(key, mode="fp16") as h:
            for t in todo:
                r = by_id.loc[t["id"]]
                S.set_seed(S.SEED + it)
                outs, st = S.generate_text(h.model, h.tok, [fix_prompt(h.tok, key, r, t["code_in"], t["feedback"])],
                                           S.gen_kwargs(key), stop_strings=stops)
                code, ok, why, _ = S.extract_code(outs[0], S.MODELS[key]["fmt"], ref=r["code"])
                S.append_jsonl(path, dict(id=t["id"], fixer=key, iteration=it, fixed_code=code, extraction_ok=ok,
                                          extraction_reason=why, latency_s=st["latency_s"], raw=outs[0][:3000]))
    return pd.DataFrame(S.read_jsonl(path))


def stage_static(g):
    """ast.parse, Bandit, similarité et tous les garde-fous."""
    rows = []
    for r in g.to_dict("records"):
        o = by_id.loc[r["id"]]
        code = str(r["fixed_code"] or "")
        parse_ok = bool(r["extraction_ok"]) and S.parses(code)
        f, _ = S.run_bandit(code) if parse_ok else ([], None)
        r1 = {x["rule"] for x in f if not x["informational"] and S.SEV[x["severity"]] >= 2}
        r0 = set(filter(None, str(o["bandit_orig"]).split(";")))
        sim = S.diff_ratio(o["code"], code)
        s0, s1 = _sigs(o["code"]), _sigs(code)
        undef = ";".join(sorted(_undefined(code) - _undefined(o["code"])))
        bad = ";".join(sorted(_bad_calls(code) - _bad_calls(o["code"])))
        rows.append(dict(r, generator=o["generator"], cwe_expected=o["cwe_expected"], cwe=o["cwe"],
                         parse_ok=parse_ok, orig_alert_gone=parse_ok and not (r0 & r1), new_vuln=bool(r1 - r0),
                         bandit_ok=parse_ok and not r1, bandit_after=";".join(sorted(r1)), similarity=sim,
                         modifie=not _ast_same(o["code"], code),
                         api_conservee=bool(s0 is None or (s1 is not None and s0 <= s1)),
                         minimal=bool(sim >= MIN_SIM), undef_new=undef, noms_ok=not undef,
                         bad_calls=bad, appels_ok=not bad))
    return pd.DataFrame(rows)


def stage_validate(it, st):
    """Détecteur LoRA+RAG d'un autre modèle, puis succès brut et succès strict."""
    path = ckpt(it, "valid")
    done = {(x["id"], x["fixer"]) for x in S.read_jsonl(path)}
    st = st.copy()
    st["validator"] = [validator_for(f, g) for f, g in zip(st["fixer"], st["generator"])]
    need = [bool(p) and v is not None and (i, f) not in done
            for p, v, i, f in zip(st["parse_ok"], st["validator"], st["id"], st["fixer"])]
    todo = st[need]
    if len(todo):
        rag = S.RAG.load()
        ctx = {(r.id, r.fixer): rag.context(r.fixed_code) for r in todo.itertuples()}
        rag = None
        S.free_vram()
        for v, g in todo.groupby("validator"):
            with S.loaded(v, mode="4bit", adapter=S.D["adapters"] / v) as h:
                outs = S.detect_batch(h, list(g["fixed_code"]), [ctx[(r.id, r.fixer)] for r in g.itertuples()])
            for r, o in zip(g.itertuples(), outs):
                S.append_jsonl(path, dict(id=r.id, fixer=r.fixer, validator=v, validator_vulnerable=o["pred"],
                                          validator_cwe=o["cwe_pred"], validator_expl=o["explanation"]))
    val = pd.DataFrame(S.read_jsonl(path), columns=["id", "fixer", "validator", "validator_vulnerable",
                                                     "validator_cwe", "validator_expl"])
    val = val.drop_duplicates(["id", "fixer"], keep="last")
    st = st.drop(columns=["validator"]).merge(val, on=["id", "fixer"], how="left")
    st["validator_safe"] = st["validator_vulnerable"].astype(str).str.lower().eq("false")
    st["success_brut"] = st["parse_ok"] & st["bandit_ok"] & st["validator_safe"]
    st["success"] = (st["success_brut"] & st["modifie"] & st["api_conservee"] & st["minimal"]
                     & st["noms_ok"] & st["appels_ok"])
    return st


def feedback_for(r):
    why = []
    if not r["parse_ok"]:
        why.append("the code did not parse")
    if r["bandit_after"]:
        why.append(f"Bandit still reports {r['bandit_after']}")
    if r["parse_ok"] and not bool(r["validator_safe"]):
        why.append(f"an auditor still flags {r['validator_cwe']}: {r['validator_expl']}")
    if not r["modifie"]:
        why.append("the code was returned UNCHANGED; you must actually modify the vulnerable lines")
    if not r["api_conservee"]:
        why.append("you removed or renamed original functions; keep every original function name and argument list")
    if not r["minimal"]:
        why.append("you rewrote almost the whole file; change only the lines needed")
    if r["undef_new"]:
        why.append(f"undefined names {r['undef_new']}: add the missing imports")
    if r["bad_calls"]:
        why.append(f"invalid calls {r['bad_calls']}: check the function signatures")
    return "; ".join(why)

# %%
# Boucle des itérations (reprend les checkpoints : ne régénère que ce qui manque)
results = []
tasks = [dict(id=i, fixer=k, code_in=c, feedback="") for i, c in zip(inp["id"], inp["code"]) for k in FIXERS]
for it in range(1, S.MAX_FIX_ITERS + 1):
    if not tasks:
        break
    g = stage_generate(it, tasks)
    want = {(t["id"], t["fixer"]) for t in tasks}
    if len(g):
        g = g[[(i, f) in want for i, f in zip(g["id"], g["fixer"])]].drop_duplicates(["id", "fixer"], keep="last")
    if not len(g):
        break
    st = stage_validate(it, stage_static(g))
    results.append(st)
    S.save_csv(st.drop(columns=["raw"]), S.D["fix"] / f"iter{it}_results.csv")
    print(f"Itération {it} : succès strict {st['success'].mean():.0%} "
          f"(brut {st['success_brut'].mean():.0%}) sur {len(st)} corrections")
    tasks = [dict(id=r["id"], fixer=r["fixer"], feedback=feedback_for(r),
                  code_in=r["fixed_code"] if (r["parse_ok"] and r["modifie"] and r["minimal"]) else by_id.loc[r["id"], "code"])
             for r in st[~st["success"]].to_dict("records")]

# %% [markdown]
# ## Résultats automatiques

# %%
allr = pd.concat(results, ignore_index=True)
final = allr.sort_values("iteration").groupby(["id", "fixer"]).tail(1).copy()
final["self_fix"] = final["fixer"] == final["generator"]
it1 = results[0].set_index(["id", "fixer"])["success"]
final["success_it1"] = [bool(it1.get((i, f), False)) for i, f in zip(final["id"], final["fixer"])]
S.save_csv(final.drop(columns=["raw"]), S.D["results"] / "fix_details.csv")


def summarize(d, by):
    return d.groupby(by).agg(n=("id", "count"),
                             taux_correction_strict=("success", "mean"),
                             taux_succes_brut=("success_brut", "mean"),
                             taux_correction_it1=("success_it1", "mean"),
                             code_modifie=("modifie", "mean"),
                             api_conservee=("api_conservee", "mean"),
                             parse_ok=("parse_ok", "mean"),
                             bandit_ok=("bandit_ok", "mean"),
                             validateur_sur=("validator_safe", "mean"),
                             nouvelles_vulns=("new_vuln", "mean"),
                             noms_ok=("noms_ok", "mean"),
                             appels_ok=("appels_ok", "mean"),
                             similarite_diff=("similarity", "mean"),
                             iterations=("iteration", "mean")).reset_index()


fs = summarize(final, "fixer")
fsc = summarize(final, "self_fix")
fbc = summarize(final, ["cwe_expected", "fixer"])
for d, n in [(fs, "fix_summary.csv"), (fsc, "fix_self_vs_cross.csv"), (fbc, "fix_by_cwe.csv")]:
    S.save_csv(d, S.D["results"] / n)
print(fs.round(3).to_string(index=False))
print()
print(fsc.round(3).to_string(index=False))
print(f"\nCodes rendus inchangés (AST identique) : {(~final['modifie']).mean():.0%}")

# %% [markdown]
# ## Revue humaine des succès stricts
# `REVUE` contient les annotations de l'équipe : `(id, correcteur): (1 = vraiment corrigé / 0 = non ou partiel, commentaire)`.
# Les annotations déjà enregistrées dans `revue_corrections.csv` sont conservées si le code corrigé n'a pas changé.
# S'il reste des corrections « à relire », leurs diffs s'affichent : ajouter les lignes dans `REVUE` puis relancer
# cette cellule.

# %%
REVUE = {
    ("qwen2.5-coder-1.5b|CWE-215_codeql_1.py", "qwen2.5-coder-3b"): (1, "debug=False"),
    ("qwen2.5-coder-3b|CWE-215_codeql_1.py", "qwen2.5-coder-3b"): (1, "debug=False"),
    ("qwen2.5-coder-1.5b|CWE-377_codeql_1.py", "stable-code-3b"): (1, "mktemp -> TemporaryFile"),
    ("qwen2.5-coder-3b|CWE-330_author_1.py", "stable-code-3b"): (1, "secrets sûr, format de sortie modifié"),
    ("qwen2.5-coder-1.5b|CWE-377_codeql_1.py", "starcoder2-3b"): (1, "NamedTemporaryFile sûr (fichier non refermé)"),
    ("qwen2.5-coder-1.5b|CWE-611_sonar_1.py", "tinyllama-1.1b"): (0, "remove_blank_text ne bloque pas XXE"),
    ("qwen2.5-coder-3b|CWE-611_sonar_1.py", "tinyllama-1.1b"): (0, "remove_blank_text ne bloque pas XXE"),
    ("qwen2.5-coder-1.5b|CWE-020_codeql_2.py", "starcoder2-3b"): (0, "liste noire pickle contournable (partielle)"),
    ("qwen2.5-coder-3b|CWE-020_codeql_2.py", "starcoder2-3b"): (0, "liste noire pickle contournable (partielle)"),
    ("starcoder2-3b|CWE-020_codeql_2.py", "starcoder2-3b"): (0, "partielle + TypeError (decode avant BytesIO)"),
    ("stable-code-3b|CWE-020_codeql_2.py", "starcoder2-3b"): (0, "TypeError + liste noire contournable"),
    ("tinyllama-1.1b|CWE-020_codeql_2.py", "starcoder2-3b"): (0, "liste noire pickle contournable (partielle)"),
    ("qwen2.5-coder-1.5b|CWE-377_codeql_1.py", "qwen2.5-coder-3b"): (0, "nom de fichier fixe et prévisible"),
    ("starcoder2-3b|CWE-215_codeql_1.py", "qwen2.5-coder-3b"): (0, "changement cosmétique de l'exception"),
    ("qwen2.5-coder-3b|CWE-113_sonar_2.py", "stable-code-3b"): (0, "Content-Type toujours contrôlé par l'utilisateur"),
    ("qwen2.5-coder-1.5b|CWE-113_sonar_2.py", "stable-code-3b"): (0, "Content-Type toujours contrôlé par l'utilisateur"),
    ("qwen2.5-coder-1.5b|CWE-259_author_2.py", "starcoder2-3b"): (0, "mot de passe supprimé, fonctionnalité cassée"),
}

rv_path = S.D["results"] / "revue_corrections.csv"
cur = final[final["success"]][["id", "fixer", "generator", "cwe", "similarity", "fixed_code"]].copy()
cur["fixed_code"] = cur["fixed_code"].astype(str).str.strip()
cur["diff"] = ["\n".join(difflib.unified_diff(by_id.loc[i, "code"].splitlines(), c.splitlines(),
               "avant", "après", lineterm="", n=1)) for i, c in zip(cur["id"], cur["fixed_code"])]
if rv_path.exists():
    old = S.read_csv(rv_path)
    old = old[["id", "fixer", "fixed_code", "correction_valide", "commentaire"]].copy()
    old["fixed_code"] = old["fixed_code"].astype(str).str.strip()
    rv = cur.merge(old, on=["id", "fixer", "fixed_code"], how="left")
else:
    rv = cur.assign(correction_valide=np.nan, commentaire="")
rv["correction_valide"] = pd.to_numeric(rv["correction_valide"], errors="coerce")
rv["commentaire"] = rv["commentaire"].astype(object)
for k, (lab, com) in REVUE.items():
    m = (rv["id"] == k[0]) & (rv["fixer"] == k[1]) & rv["correction_valide"].isna()
    rv.loc[m, "correction_valide"], rv.loc[m, "commentaire"] = lab, com
S.save_csv(rv, rv_path)

todo = rv[rv["correction_valide"].isna()]
print(f"{len(rv)} succès stricts | {len(rv) - len(todo)} annotés | {len(todo)} à relire")
for r in todo.itertuples():
    print("\n" + "=" * 70, f"\n{r.fixer} | {r.id} | {r.cwe}\n{r.diff}")

tot = final.groupby("fixer").size().rename("n")
hum = rv.groupby("fixer")["correction_valide"].sum().reindex(tot.index, fill_value=0)
out = pd.DataFrame({"n": tot, "succes_strict": final.groupby("fixer")["success"].sum(),
                    "valides_humain": hum, "taux_correction_humain": hum / tot}).reset_index()
if len(todo) == 0:
    S.save_csv(out, S.D["results"] / "fix_human.csv")
    print(out.round(3).to_string(index=False))
    print(f"\nTOTAL : {int(hum.sum())} corrections valides / {int(out['succes_strict'].sum())} succès stricts "
          f"/ {int(tot.sum())} tentatives ({hum.sum() / tot.sum():.1%}) | précision de la validation automatique : "
          f"{hum.sum() / max(1, out['succes_strict'].sum()):.0%}")
else:
    print("\n⚠ fix_human.csv non écrit : terminer la revue d'abord.")

# %%
# Exemple de vraie correction (validée par la revue)
okv = rv[rv["correction_valide"] == 1].sort_values("similarity", ascending=False)
if len(okv):
    r = okv.iloc[0]
    print(f"{r['id']} corrigé par {r['fixer']} (similarité {r['similarity']:.2f})\n{r['diff']}")

# %%
# Rapport final (la section 8.1 « Revue humaine » nécessite la version à jour de slmsec.py sur Drive)
if "fix_human.csv" not in open(S.__file__, encoding="utf-8").read():
    print("⚠ slmsec.py sur Drive est l'ancienne version : la revue humaine n'apparaîtra pas dans le rapport.\n"
          "  Remplacer MyDrive/slm-security/slmsec.py par la version du projet, puis relancer cette cellule.")
print("Rapport :", S.build_report())
print("Phase P5 terminée.")
