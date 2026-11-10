# PROGRESS

_Mis à jour le 2026-11-10._

## Fait (code écrit et validé hors GPU)
- [x] `slmsec.py` : config, VRAM (`loaded()` / `free_vram()`), extraction robuste, Bandit corrigé, détecteur
      (prompts, cibles, parsing JSON), RAG, métriques (bootstrap, McNemar), `build_report()`.
- [x] Bugs 1–7 corrigés (voir README) ; tests unitaires locaux OK sur les cas réels (Qwen-3B prose, boucle Stable-Code,
      B301 à la bonne ligne, B403 informatif).
- [x] Notebooks 00 → 06 générés depuis `notebooks_src/`, validés (nbformat + compilation des cellules + py_compile).
- [x] README (ordre d'exécution + choix), squelette `RAPPORT_FINAL.md`.

## Reste à faire (exécution sur Colab)
- [x] P0 `00_setup` — copier `slmsec.py` sur Drive, figer les prompts.
- [x] P1 `01_generation` — vérifier le taux `extraction_ok` (cible > 90 %) et l'absence de `###` dans Stable-Code.
- [x] P2 `02_bandit`.
- [x] P3 `03_detecteur_lora_rag` — vérifier au chargement le nombre de paires Python CyberNative et la répartition CWE.
- [x] P4 `04_benchmark`.
- [ ] Annotation humaine de `results/annotation_humaine.csv` (non faite : la vérité sur les codes générés reste la pseudo-vérité).
- [x] P5 `05_correction` (2026-11-02) : 21 codes × 5 correcteurs ; garde-fous ajoutés sur Colab (AST identique,
      noms non définis via pyflakes, signatures stdlib) ; revue humaine : 5 corrections valides / 17 succès stricts / 105.
      Notebook 05 réécrit (2026-11-03) avec tous ces correctifs et la revue intégrée ; il réutilise les checkpoints.
- [x] P6 `06_extras` (localisation, profils, FP/FN).
- [x] `RAPPORT_FINAL.md` rédigé avec les chiffres réels (2026-11-03) ; tableaux auto dans `ANNEXE_RESULTATS_AUTO.md`.
- [x] Présentation HTML `presentation/index.html` (30 slides, notes, captures intégrées) et rapport LaTeX `rapport/` (PDF compilé).

## Points à surveiller au premier lancement
- `stop_strings` dans `generate` nécessite transformers ≥ 4.39 (installé en `-U`).
- Si `CyberNative` change de schéma, `load_vuln_dataset()` bascule sur le repli CVEfixes (non vérifié).
- Si l'entraînement fp16 diverge (loss NaN) sur un modèle : baisser lr à 1e-4 pour ce modèle.

## Décisions
Voir README, section « Choix d'implémentation ».
