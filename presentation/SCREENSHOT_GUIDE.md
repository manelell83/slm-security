# Guide de collecte des captures d'écran

Ce guide décrit **exactement** les captures à prendre pour la soutenance. Elles prouvent toutes un élément réellement
implémenté dans le projet (notebooks Colab `00` à `06`, bibliothèque `slmsec.py`, fichiers de `results/`).
Aucune capture n'est demandée pour la criminalistique numérique, le hachage SHA-256 ou la blockchain : **ces
fonctionnalités n'existent pas dans le projet**.

Il y a **9 captures à faire** (CAP-01 à CAP-09). La capture CAP-00 (le cerveau de la couverture) est déjà en place.

> **Mise à jour :** la slide 27 (« Un code, de bout en bout ») a été supprimée à la demande de l'équipe. La présentation compte désormais 30 slides ; `06_demo.png` n'est plus affichée et CAP-06 à CAP-09 ne sont plus nécessaires.

---

## 1. Où enregistrer et comment nommer

```
presentation/
└── captures/
    ├── cerveau.png              ← CAP-00, déjà présent
    ├── 01_generation.png        ← CAP-01
    ├── 02_bandit.png            ← CAP-02
    ├── 03_cwe.png               ← CAP-03
    ├── 04_lora.png              ← CAP-04
    ├── 05_correction.png        ← CAP-05
    ├── 06_demo.png              ← CAP-06
    ├── 07_demo_generation.png   ← CAP-07
    ├── 08_demo_detection.png    ← CAP-08
    └── 09_demo_fix.png          ← CAP-09
```

- Format **PNG**, nom **exactement** comme ci-dessus : minuscules, sans espace ni accent.
- Dès qu'un fichier existe, il remplace automatiquement son cadre pointillé dans la présentation, avec sa légende,
  sans déformation (l'image est ajustée sans être étirée). Rechargez `index.html` (F5) pour vérifier.
- Une capture absente laisse le cadre pointillé en place : la présentation reste utilisable.

## 2. Préparer une capture propre (pour toutes les captures)

1. **Colab** : ouvrez le notebook indiqué depuis `MyDrive/slm-security`, avec le thème clair (celui par défaut),
   qui correspond au design de la présentation.
2. **Fermez le panneau de gauche** (icône dossier ou table des matières) et le panneau Gemini s'il est ouvert.
3. **Zoom du navigateur à 110–125 %** (Ctrl + molette) : le texte doit rester lisible une fois réduit dans la slide.
4. **Ne montrez jamais** :
   - le contenu de votre Google Drive en dehors de `slm-security` (CV, NDA, documents personnels visibles à la racine) ;
   - votre photo ou votre adresse Google (en haut à droite) ;
   - les autres onglets, les favoris, la barre des tâches et les notifications ;
   - les jetons d'accès (Hugging Face, etc.) ou les cellules qui les contiennent ;
   - les messages d'erreur sans rapport avec la capture.
5. **Capture** : touches **Windows + Maj + S**, mode **Rectangle**, puis cadrez uniquement la cellule et sa sortie.
   Cliquez sur la notification, puis **Enregistrer sous** dans `presentation/captures/` avec le nom indiqué.
6. **Vérification** : ouvrez `index.html`, allez à la slide concernée (numéro + Entrée) et contrôlez que les chiffres
   se lisent.

### Cellule de préparation (à exécuter une fois en haut d'un notebook)

Pour les captures CAP-01 à CAP-04 et CAP-07 à CAP-09, il suffit de relire les résultats déjà sur Drive : rien n'est
recalculé et aucun GPU n'est nécessaire.

```python
# Préparation : accès aux résultats du projet (aucun calcul)
from google.colab import drive
drive.mount("/content/drive")
import os, sys, json
BASE = "/content/drive/MyDrive/slm-security"
os.environ["SLM_BASE"] = BASE
sys.path.insert(0, BASE)
import slmsec as S, pandas as pd
pd.set_option("display.width", 200); pd.set_option("display.max_colwidth", 60)
ID = "qwen2.5-coder-1.5b|CWE-215_codeql_1.py"   # le code suivi dans la démonstration (slide 27)
```

---

## 3. Fiches des captures

### CAP-01 — Synthèse de la génération · `01_generation.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 14 — « Générer, puis extraire le vrai code » (intervenant·e 03) |
| **Où** | Notebook `01_generation.ipynb` (ou tout notebook après la cellule de préparation) |
| **Action** | Exécuter : `S.read_csv(S.D["results"] / "generation_summary.csv")[["model", "generated", "extraction_ok_rate", "extraction_fail_final", "latency_mean_s", "tok_per_s", "peak_vram_gb"]].round(2)` |
| **Doit être visible** | Les 5 modèles ; `extraction_ok_rate` (1,0 pour quatre modèles, 0,93 pour stable-code-3b) ; latence moyenne (3,9 à 9,8 s) ; pic de VRAM (2,2 à 6,2 Go) |
| **À éviter** | Le panneau de fichiers, les sorties des autres cellules |
| **Format** | Proche du carré (1:1 à 4:3), au moins 1200 px de large |
| **Prouve** | L'extraction robuste (74 codes exploitables sur 75) et le coût réel de chaque modèle sur un T4 |

### CAP-02 — Alertes Bandit réelles · `02_bandit.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 15 — « Bandit, correctement lu » (intervenant·e 03) |
| **Où** | Notebook `02_bandit.ipynb` (ou après la cellule de préparation) |
| **Action** | Exécuter : `S.read_csv(S.D["results"] / "bandit_findings_real.csv")[["model", "prompt_id", "rule", "severity", "line", "snippet", "cwe"]].head(12)` |
| **Doit être visible** | La 1ʳᵉ ligne : `qwen2.5-coder-1.5b · CWE-020_codeql_2.py · B301 · MEDIUM · 15 · profile_data = pickle.loads(decoded_data) · CWE-502`, ainsi que plusieurs règles différentes (B301, B311, B202…) et la colonne `line` |
| **À éviter** | Les alertes informatives B4xx (elles ne sont pas dans ce fichier, c'est voulu) |
| **Format** | Proche du carré, au moins 1200 px de large ; réduire à 8 lignes si le texte est trop petit |
| **Prouve** | La correction du défaut initial : ligne réelle et extrait exact de chaque alerte, au lieu de « ligne 1 » |

### CAP-03 — Métriques de détection et justesse de la CWE · `03_cwe.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 16 — « De l'alerte à la CWE » (intervenant·e 03) |
| **Où** | Notebook `04_benchmark.ipynb` (ou après la cellule de préparation) |
| **Action** | Exécuter : `m = S.read_csv(S.D["results"] / "det_metrics_test.csv"); m[m.config.isin(["lora", "static"])][["detector", "config", "f1", "mcc", "f1_ci95", "cwe_acc_tp", "json_invalid_rate"]].round(3)` |
| **Doit être visible** | Les 5 détecteurs en configuration `lora` et la ligne `bandit / static` ; la colonne `cwe_acc_tp` (0,759 à 1,0 pour LoRA, 0,407 pour Bandit) ; le F1 (0,667 à 0,815 contre 0,635) |
| **À éviter** | Les configurations `base`, qui alourdissent le tableau |
| **Format** | Proche du carré ou 4:3, au moins 1200 px de large |
| **Prouve** | La classification CWE des détecteurs LoRA est bien plus juste que celle de Bandit, sur le même test de 76 exemples |

### CAP-04 — Journal d'entraînement QLoRA · `04_lora.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 17 — « Entraîné en quelques minutes » (intervenant·e 03) |
| **Où** | Notebook `03_detecteur_lora_rag.ipynb` (ou après la cellule de préparation) |
| **Action** | Exécuter : `S.read_csv(S.D["results"] / "train_log.csv").round(3)`, puis éventuellement `S.read_csv(S.D["results"] / "dataset_stats.csv")` dans une seconde cellule |
| **Doit être visible** | Les 5 modèles ; `n_train` = 594 ; `steps` = 38 ; `minutes` (2,9 à 5,8) ; `peak_vram_gb` (5,76 à 8,34) ; et si possible les 372 paires gardées sur 424 |
| **À éviter** | Ne relancez pas l'entraînement : les adaptateurs existent déjà (la cellule les saute) |
| **Format** | Paysage 4:3 ou carré, au moins 1200 px de large |
| **Prouve** | L'affinage QLoRA a réellement été fait sur un T4 gratuit, en quelques minutes par modèle |

### CAP-05 — Résultats des deux itérations de correction · `05_correction.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 18 — « Corriger, vérifier, recommencer » (intervenant·e 03) |
| **Où** | Notebook `05_correction.ipynb` (version finale), **Exécution → Tout exécuter** (les checkpoints sont réutilisés, aucun GPU nécessaire) |
| **Action** | Attendre la fin de la cellule « Boucle des itérations », puis de la cellule « Résultats automatiques » |
| **Doit être visible** | Les deux lignes « Itération 1 : succès strict 7 % (brut 40 %) sur 105 corrections » et « Itération 2 : succès strict 10 % (brut 29 %) sur 98 corrections », puis le haut du tableau par correcteur (`taux_correction_strict`, `taux_succes_brut`) |
| **À éviter** | Le code source des cellules (repliez-le), la cellule de montage Drive |
| **Format** | Proche du carré, au moins 1200 px de large ; si tout ne tient pas, privilégier les deux lignes « Itération » |
| **Prouve** | La boucle de correction en deux itérations avec contrôles automatiques a bien été exécutée |

### CAP-06 — Revue humaine des corrections · `06_demo.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 27 — « Un code, de bout en bout », grande zone (intervenant·e 04) |
| **Où** | Notebook `05_correction.ipynb`, cellule « Revue humaine des succès stricts » (après Tout exécuter) |
| **Action** | Faire défiler jusqu'à la sortie de la cellule |
| **Doit être visible** | « 17 succès stricts \| 17 annotés \| 0 à relire », le tableau par correcteur (`valides_humain`, `taux_correction_humain`) et la ligne « TOTAL : 5 corrections valides / 17 succès stricts / 105 tentatives (4.8%) \| précision de la validation automatique : 29% » |
| **À éviter** | Le dictionnaire `REVUE` (code de la cellule : repliez-le) |
| **Format** | **16:9** (large), au moins 1600 × 900 px |
| **Prouve** | Le chiffre clé de la correction (5 valides sur 105) repose sur une relecture humaine documentée |

### CAP-07 — Le code généré suivi dans la démo · `07_demo_generation.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 27 — petite zone « Étape 1 » (intervenant·e 04) |
| **Où** | N'importe quel notebook, après la cellule de préparation |
| **Action** | `g = S.read_csv(S.D["results"] / "generations.csv"); g["id"] = g.model + "\|" + g.prompt_id; print(ID); print(g.set_index("id").loc[ID, "code"])` |
| **Doit être visible** | L'identifiant `qwen2.5-coder-1.5b\|CWE-215_codeql_1.py` et les 10 lignes du code, jusqu'à `app.run(debug=True)` |
| **À éviter** | Les lignes vides inutiles autour de la sortie : cadrer serré |
| **Format** | **Bandeau large ≈ 3:1** (par exemple 1200 × 400 px) |
| **Prouve** | Un code réellement produit par un SLM contient une faille (mode debug, Bandit B201, sévérité HIGH) |

### CAP-08 — Le verdict JSON d'un détecteur · `08_demo_detection.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 27 — petite zone « Étape 2 » (intervenant·e 04) |
| **Où** | N'importe quel notebook, après la cellule de préparation |
| **Action** | Exécuter :<br>`for k in S.MODEL_KEYS:`<br>`    d = S.read_csv(S.D["preds"] / f"gen_{k}_lora.csv").set_index("id")`<br>`    if ID in d.index: print(k, json.dumps(d.loc[ID, ["pred", "cwe_pred", "explanation"]].to_dict(), ensure_ascii=False))` |
| **Doit être visible** | Au moins une ligne où `pred` vaut `true`, avec sa CWE et son explication. Si plusieurs détecteurs répondent `true`, recadrez sur un ou deux d'entre eux |
| **À éviter** | Inventer ou retoucher un verdict. Si aucun détecteur ne répond `true` pour ce code, montrez la sortie telle quelle et prévenez Youssef pour qu'il adapte la phrase de la slide 27 |
| **Format** | **Bandeau large ≈ 3:1** |
| **Prouve** | Le détecteur LoRA rend un verdict structuré (vulnérable, CWE, explication) sur du code généré |

### CAP-09 — La correction validée · `09_demo_fix.png` · **obligatoire**
| | |
|---|---|
| **Slide** | 27 — petite zone « Étape 3 » (intervenant·e 04) |
| **Où** | N'importe quel notebook, après la cellule de préparation |
| **Action** | `rv = S.read_csv(S.D["results"] / "revue_corrections.csv"); r = rv[(rv.id == ID) & (rv.fixer == "qwen2.5-coder-3b")].iloc[0]; print(r["diff"]); print("revue humaine :", int(r["correction_valide"]), "·", r["commentaire"])` |
| **Doit être visible** | Le diff `- app.run(debug=True)` / `+ app.run(debug=False)` et la ligne « revue humaine : 1 · debug=False » |
| **À éviter** | Les autres corrections du fichier |
| **Format** | **Bandeau large ≈ 3:1** |
| **Prouve** | Une correction minimale et réellement valide, confirmée par les contrôles puis par la relecture humaine |

### CAP-00 — Cerveau de la couverture · `cerveau.png` · **fait**
Slide 1. Le fichier est déjà en place ; vérifiez seulement l'affichage de la couverture.

---

## 4. Liste de contrôle par intervenant·e

| Intervenant·e | Captures à faire | Vérification finale |
|---|---|---|
| 01 · Abderrahim Attou | — (CAP-00 déjà en place) | Couverture (slide 1) : cerveau, noms, encadrante |
| 02 · Aymane El Farme | ☐ CAP-03 `03_cwe.png` · ☐ CAP-04 `04_lora.png` | Slides 16–17 lisibles |
| 03 · Manal Chemlali | ☐ CAP-01 `01_generation.png` · ☐ CAP-02 `02_bandit.png` · ☐ CAP-05 `05_correction.png` | Slides 14, 15, 18 lisibles |
| 04 · Youssef Miftah | ☐ CAP-06 `06_demo.png` · ☐ CAP-07 · ☐ CAP-08 · ☐ CAP-09 | Slide 27 : le même code suivi sur les trois étapes |

Aymane fait CAP-03 et CAP-04 pour équilibrer la charge ; elles illustrent les slides présentées par Manal.

## 5. Éléments manquants à ce jour

| Élément | État | Conséquence |
|---|---|---|
| CAP-01 à CAP-06 | ✅ **Intégrées** | CAP-02 montre le graphique « réelles / informatives », CAP-03 le F1 par configuration, CAP-04 le code de configuration QLoRA (légendes et script adaptés). CAP-06 est recadrée sur la sortie de la revue humaine (original : `06_demo_complet.png`) |
| CAP-07, CAP-08, CAP-09 | **Retirées** (décision de l'équipe) | Slide 27 : les trois petits cadres ont été supprimés ; la revue humaine occupe toute la largeur et l'exemple CWE-215 est résumé en texte sous la capture. Les fiches restent dans ce guide si vous voulez les ajouter plus tard |
| `10_cross_matrix.png`, `11_size_security.png` | Enregistrées, non utilisées | Les slides 24 et 28 affichent déjà ces mêmes données en graphiques natifs ; images gardées en réserve pour les questions du jury |
| Annotation humaine des 74 codes générés (`results/annotation_humaine.csv`, colonne `label_humain`) | **Vide** | La vérité terrain des codes générés reste un vote majoritaire (dit à l'oral, slides 21 et 29) |
| Tests fonctionnels des corrections | Non réalisés | Limite présentée slide 29 |
| Criminalistique, SHA-256, blockchain | **Non implémentés** | Aucune capture ni aucun discours à ce sujet |
