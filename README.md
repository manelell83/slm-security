# SLM·Sec — Détection, analyse et correction des vulnérabilités du code généré par des SLMs

Projet du cours *Système intelligent pour la sécurité* — INPT, 2026–2027.
Équipe : Abderrahim Attou, Aymane El Farme, Manal Chemlali, Youssef Miftah — encadrante : Mme Meryem Ayache.

Cinq *Small Language Models* open source (Qwen2.5-Coder 1.5B et 3B, StarCoder2-3B, Stable-Code-3B, TinyLlama-1.1B)
sont évalués dans trois rôles : **générateur** de code, **détecteur** de vulnérabilités (Bandit vs SLM affiné par QLoRA,
avec ou sans RAG) et **correcteur**. Tout tourne sur **Google Colab, GPU T4** (fp16, pas de bf16), avec sauvegarde et
reprise sur Google Drive.

## Résultats principaux

| Question | Résultat |
|---|---|
| Le code généré est-il sûr ? | **22 / 74 codes (29,7 %)** contiennent une vulnérabilité réelle (Bandit, MEDIUM+) |
| Un SLM peut-il détecter ? | Base : F1 ≈ 0 ; **LoRA : F1 0,67 – 0,81**, au-dessus de Bandit (0,64) ; le RAG, non vu à l'entraînement, dégrade la plupart des détecteurs |
| Un SLM peut-il corriger ? | 105 tentatives → 35 succès bruts → 17 succès stricts → **5 validés par relecture humaine (4,8 %)** |
| Taille / pass@1 et sécurité | Aucune corrélation significative (4 à 5 modèles) |

Détails : [`RAPPORT_FINAL.md`](RAPPORT_FINAL.md) et le rapport LaTeX [`rapport/main.tex`](rapport/main.tex).

## Arborescence

```
slmsec.py        bibliothèque commune (config, VRAM, extraction, Bandit, détecteur, RAG, métriques, rapport)
notebooks/       00 à 06 — une phase par notebook Colab
notebooks_src/   sources des notebooks (cellules # %%) ; tools/build_notebooks.py régénère les .ipynb
results/         CSV et figures réels produits par les notebooks
rapport/         rapport LaTeX (main.tex + figures/) — compiler avec pdfLaTeX (Overleaf)
presentation/    soutenance HTML (index.html), mode présentateur (presenter.html), notes, captures
tools/           scripts de génération (notebooks, script de soutenance, présentation autonome)
```

Présentation : ouvrir `presentation/index.html` dans un navigateur (touche P = mode présentateur, R = répétition).
Version autonome en un seul fichier : `python tools/build_standalone.py` → `Presentation_SLM-Sec.html`.

## Contenu

| Fichier | Rôle |
|---|---|
| `slmsec.py` | Utilitaires communs (config, chargement/libération VRAM, extraction, Bandit, détecteur, RAG, métriques, rapport) |
| `notebooks/00_setup.ipynb` | Drive, arborescence, tests de l'extraction, sélection figée des prompts |
| `notebooks/01_generation.ipynb` | P1 — génération par les 5 SLMs (GPU) |
| `notebooks/02_bandit.ipynb` | P2 — approche A : Bandit (+ Semgrep optionnel) (CPU) |
| `notebooks/03_detecteur_lora_rag.ipynb` | P3 — jeu étiqueté, base RAG, 5 adaptateurs QLoRA (GPU) |
| `notebooks/04_benchmark.ipynb` | P4 — inférence des 4 configurations + métriques, matrice croisée, vérité terrain, lien avec l'article |
| `notebooks/05_correction.ipynb` | P5 — correction automatique et vérification |
| `notebooks/06_extras.ipynb` | P6 (optionnel) — localisation, profils de compétences, FP/FN |
| `notebooks_src/*.py` + `tools/build_notebooks.py` | Sources des notebooks (cellules `# %%`) ; `python tools/build_notebooks.py` régénère et valide les `.ipynb` |
| `RAPPORT_FINAL.md` | Rapport rédigé avec les résultats réels ; `ANNEXE_RESULTATS_AUTO.md` = annexe générée par `slmsec.build_report()` |
| `PROGRESS.md` | Fait / reste à faire / décisions, pour reprendre dans une autre session |

## Ordre d'exécution

1. Copier `slmsec.py` dans `MyDrive/slm-security/` (ou le téléverser quand `00_setup` le demande).
2. `00_setup` (une fois, CPU suffit) → `data/prompts_selected.csv`.
3. `01_generation` (GPU T4, ~5 × 15 générations) → `results/generations.csv`, `generation_summary.csv`.
4. `02_bandit` (CPU) → `results/detections_bandit.csv`, `bandit_summary.csv`, `bandit_findings_real.csv`, `observations.csv`.
5. `03_detecteur_lora_rag` (GPU, le plus long) → `data/det_*.csv`, `rag/`, `adapters/<modele>/`.
   Une session peut ne pas suffire : relancer, l'entraînement reprend au dernier checkpoint et les modèles finis sont sautés.
   `MODELS_TO_TRAIN = [...]` permet d'en entraîner un seul par session.
6. `04_benchmark` (GPU puis CPU) → `preds/`, `results/det_metrics_test.csv`, `mcnemar.csv`, `cross_matrix.*`, `kappa_*`,
   `annotation_humaine.csv`, `truth.csv`, `size_security.*`.
7. *(Facultatif)* remplir `results/annotation_humaine.csv` (`label_humain` : 1 = vulnérable, 0 = sûr) puis relancer la
   partie CPU de `04` : la vérité devient « humaine » (ou « mixte »).
8. `05_correction` (GPU) → `results/fix_summary.csv`, `fix_self_vs_cross.csv`, `fix_by_cwe.csv`, `fix_details.csv`.
9. `06_extras` (optionnel).

Chaque notebook remonte Drive, réinstalle ses dépendances et **saute ce qui existe déjà** (supprimer un fichier
pour forcer le recalcul). Un seul modèle est en VRAM à la fois (`with S.loaded(...)` libère la mémoire à la sortie).

Variables d'environnement optionnelles (avant `import slmsec`) : `SLM_N_PROMPTS` (15), `SLM_MAX_TRAIN` (3000),
`SLM_TEST_EVAL_N` (200). Changer `N_PROMPTS` après P1 implique de supprimer `data/prompts_selected.csv` et `gen/`.

## Correction des bugs de l'étude initiale

| # | Problème | Correction |
|---|---|---|
| 1 | Qwen-3B : phrase « Here's the implementation… » comptée saine | `extract_code` exige `ast.parse` + vraie instruction ; colonne `extraction_ok` + raison ; 2 régénérations max ; codes non extraits exclus des taux et taux d'échec reporté |
| 2 | Stable-Code-3B boucle sur `### Instruction/### Response` | Mode **complétion** (le squelette SecurityEval est complété), stop strings, `repetition_penalty=1.1`, coupe à la première répétition de bloc, retrait des balises |
| 3 | Ligne = 1 et extrait d'import pour toutes les alertes | Ligne = `line_number` de Bandit, extrait = cette ligne du code analysé ; dédup (règle, ligne) |
| 4 | B403/B405 comptées comme failles | B401–B413 = informatives, séparées (`n_info`, `bandit_findings_info.csv`) ; vulnérable = ≥ 1 alerte réelle MEDIUM+ |
| 5 | Observations identiques | `make_observations()` à partir des chiffres de chaque modèle |
| 6 | 3 CWE seulement, 5 prompts × 3 | 15 prompts, 1 par CWE distinct (CWE-502/611/020 forcés + tirage graine 42), 1 échantillon, mêmes prompts ; temp 0.2, top-p 0.95, 512 tokens ; VRAM + latence |
| 7 | Encodage cassé (« Scurit ») | Toutes les écritures en UTF-8 (`save_csv`, `write_text`, `append_jsonl`, Bandit lu en UTF-8) |

## Choix d'implémentation (décidés sans questions, à discuter dans le rapport)

- **Format des prompts** : Qwen/TinyLlama → chat template ; StarCoder2-instruct → `### Instruction/### Response`
  (format d'origine) ; Stable-Code-3B → complétion (pas de chat template, c'est un modèle de base).
- `top_k=0` et `repetition_penalty=1.0` explicites pour neutraliser les `generation_config` propres à chaque modèle
  (sauf Stable-Code : 1.1) ; seule différence de décodage entre modèles, documentée.
- Les imports du prompt réellement utilisés mais omis par le modèle sont réinjectés (le modèle ne renvoie souvent
  que la fonction) ; sans cela Bandit manque des appels (ex. `pickle.loads`).
- **Seuil « vulnérable »** Bandit : alerte réelle MEDIUM ou HIGH ; `pred_any` (toute sévérité) est aussi conservé.
- **Jeu étiqueté** : CyberNative DPO filtré `lang == python` (vérifié au chargement : colonnes, nombre de lignes).
  La CWE est inférée de la description par mots-clés (`CWE-Other` sinon). Le split se fait **par paire**
  (chosen/rejected d'une même question dans le même split) pour éviter une fuite quasi-doublon. Filtre anti-fuite :
  toute paire dont le code a une similarité de Jaccard ≥ 0.7 avec un code/prompt SecurityEval est retirée.
  Le repli CVEfixes n'a pas pu être vérifié ici (adaptation automatique des colonnes).
- **Cible JSON** : `{"vulnerable": bool, "cwe": "CWE-xxx" | "none", "explanation": "≤ 30 mots"}` ; le prompt est
  pré-rempli par `{"vulnerable": ` (même préfixe à l'entraînement et à l'inférence) ; la perte n'est calculée que sur
  la réponse. JSON invalide → repli tolérant sur `true/false`, compté dans `json_invalid_rate`.
- **Détecteurs base et LoRA en 4-bit** (même modèle de base quantifié : comparaison équitable) ; génération et
  correction en fp16.
- **LoRA entraînée sans contexte RAG** (max_len 768 incompatible avec 1200 tokens de contexte) ; le RAG est
  ajouté à l'inférence. Contexte RAG calculé une fois par code avec un budget en caractères (≈ 4 car./token),
  identique pour tous les SLMs.
- **Meilleure configuration** = F1 moyen maximal sur les 5 SLMs (départage MCC), utilisée pour la matrice croisée.
- **Sous-échantillon de test** : `TEST_EVAL_N = 200` (stratifié, figé) pour tenir le budget GPU.
- **Correction** : explication fournie par le détecteur de référence (meilleur F1 dans la meilleure config), sinon
  Bandit, sinon la CWE du prompt (signalé dans `info_source`). Validateur = LoRA+RAG du modèle suivant dans la liste
  (≠ correcteur, et ≠ générateur si possible). Succès = parse OK ∧ aucune alerte Bandit réelle MEDIUM+ ∧ validateur « sûr ».
- La **pseudo-vérité** (vote ≥ 3/6) est toujours signalée comme telle (`truth_source.csv`, titres des figures, rapport).

## Durées observées (T4)

Entraînement QLoRA : 2,9 à 5,8 min par modèle (pic VRAM 5,8 à 8,3 Go, 594 exemples). Génération : 3,9 à 9,8 s par code.

## Validation

`python tools/build_notebooks.py` : `nbformat.validate` + compilation de chaque cellule + `py_compile slmsec.py`.
Les notebooks ont été exécutés sur Colab (T4) et leurs résultats sont dans `results/`. Ils sont versionnés sans sorties.
