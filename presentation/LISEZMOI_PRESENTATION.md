# Présentation de soutenance — mode d'emploi

> **Documents de soutenance** : `SCRIPT_SOUTENANCE.md` contient le script complet, les durées par slide et le plan de
> répétition ; `SCREENSHOT_GUIDE.md` donne la procédure exacte des 9 captures, répartie par intervenant·e.

## Lancer la présentation
1. Ouvrir `presentation/index.html` dans **Chrome** ou **Edge** (double-clic). Aucune installation.
   Avec une connexion internet, les polices Space Grotesk, Inter et IBM Plex Mono se chargent ; sans internet, la police
   système les remplace et la mise en page reste correcte.
2. Appuyer sur **F** pour le plein écran.

| Touche | Action |
|---|---|
| → · Espace · PgDn | Slide suivante |
| ← · PgUp | Slide précédente |
| Début · Fin | Première · dernière slide |
| `12` puis Entrée | Aller à la slide 12 |
| **N** | Afficher / masquer les notes de l'orateur (mode simple, un seul écran) |
| **P** | Lancer le mode présentateur (deux fenêtres) |
| ? | Aide |

On peut aussi ouvrir une slide précise avec `index.html#23`. Une télécommande de présentation (qui envoie PgUp / PgDn) fonctionne.

## Soutenance de 20 minutes : script, chronomètres et répétition
- **Profils et script oral** : `presentation/notes.js`. `PROFILES` contient les 4 noms, et chaque nom modifié là se met à jour partout. `SCRIPT` contient la note orale de chacune des 31 slides avec son intervenant·e. Version lisible ou imprimable : `presentation/SCRIPT_SOUTENANCE.md`.
- **Répartition** :

  | Intervenant·e | Slides | Créneau |
  |---|---|---|
  | 01 · Abderrahim Attou | 1–6 | 00:00 → 05:00 |
  | 02 · Aymane El Farme | 7–12 | 05:00 → 10:00 |
  | 03 · Manal Chemlali | 13–20 | 10:00 → 15:00 |
  | 04 · Youssef Miftah | 21–30 | 15:00 → 20:00 |

  La slide 31 (questions) est hors chronomètre. Le script complet est estimé à environ 17 min à 110 mots/min, ce qui laisse de la marge pour les pauses et la démo.
- **Tableau de bord** :
  - un compte à rebours de 20 min pour la soutenance et un de 5 min par intervenant·e, identifié automatiquement d'après la slide en cours ;
  - le temps passé sur la slide comparé à sa cible ;
  - la couleur du compteur : **vert** (temps suffisant), **orange** (moins d'une minute), **rouge** (dépassé), avec une alerte en clair ;
  - les commandes : bouton pause / reprise (ou touche **T**), ↺ pour la remise à zéro, **bilan** (ou touche **B**).

  Les slides ne changent jamais toutes seules, et rien de tout cela ne s'affiche sur le vidéoprojecteur.
- **Mode répétition** : touche **R** dans `index.html`, ou ouvrir `presenter.html?repetition=1`. On a le tableau de bord complet sans vidéoprojecteur ; faites la répétition à quatre, puis ouvrez le **bilan** : temps réel comparé aux 5 min de chacun·e, total comparé aux 20 min, et temps passé sur chaque slide.
- Les scripts modifiés dans le tableau de bord sont enregistrés dans le navigateur de cet ordinateur. Pour les rendre définitifs, recopiez-les dans `notes.js`.

## Mode présentateur (deux écrans)
1. Brancher le vidéoprojecteur en mode **« Étendre »** (Windows + P → Étendre).
2. Ouvrir `index.html` dans **Chrome ou Edge** sur l'ordinateur, puis cliquer **« présentateur »** (en bas à droite) ou appuyer sur **P**.
   - une **fenêtre publique** s'ouvre (`index.html?mode=public`) : glissez-la sur le vidéoprojecteur, puis **cliquez dedans** pour
     passer en plein écran (le navigateur exige un clic dans cette fenêtre ; sinon F11) ;
   - la fenêtre d'origine devient le **tableau de bord privé** (`presenter.html`).
3. Le tableau de bord affiche : la slide actuelle, la slide suivante, les notes de la slide (modifiables), l'intervenant·e
   en cours, le chronomètre (démarre à la première navigation ; **T** = pause), l'heure, la progression par intervenant·e
   et l'état de la synchronisation (point vert = fenêtre publique synchronisée).
4. Navigation : flèches, Espace, **PgUp / PgDn** (télécommandes, actifs même pendant l'édition des notes), numéro + Entrée,
   clic sur la barre de progression. La navigation dans la fenêtre publique met aussi à jour le tableau de bord.

**Fenêtre pop-up bloquée ?** Le tableau de bord affiche un bandeau : autorisez les pop-ups (icône dans la barre d'adresse)
puis cliquez « Ouvrir la fenêtre publique ». **« Placer sur le 2ᵉ écran »** demande l'autorisation « gestion des fenêtres »
(Chrome/Edge) et ouvre directement la fenêtre publique sur le vidéoprojecteur ; une fois accordée, le bouton « présentateur »
l'utilise automatiquement.

**Notes privées :** les notes d'origine viennent de chaque slide ; vos modifications sont enregistrées dans ce navigateur
uniquement (« note d'origine » pour revenir au texte initial). La fenêtre publique n'affiche jamais les notes, les boutons ni
le chronomètre. Synchronisation : BroadcastChannel, avec repli par messages directs entre les deux fenêtres.

## Partager avec WhatsApp
1. Envoyer `Presentation_SLM-Sec.zip` comme **document** dans WhatsApp. Cette archive contient les deux fenêtres du mode
   présentateur, les scripts et les captures ; ne partager pas seulement `Presentation_SLM-Sec.html`, qui est la version
   autonome sans tableau de bord présentateur.
2. Chaque destinataire télécharge puis extrait le ZIP (clic droit → **Extraire tout**) et ouvre
   `Presentation_SLM-Sec/index.html` dans Chrome ou Edge. Les fichiers doivent rester ensemble dans le même dossier.
3. Pour répéter ou présenter avec les notes, cliquer sur **présentateur** ou appuyer sur **P**. Le script de la slide
   s'affiche dans la fenêtre privée ; la fenêtre publique n'affiche que les slides. Le rôle se met à jour selon la slide :
   Abderrahim 1–6, Aymane 7–12, Manal 13–20, Youssef 21–30.
4. En soutenance à plusieurs, utilisez un seul ordinateur connecté au projecteur : le tableau de bord et ses notes restent
   sur l'écran privé, et chacun prend la parole au passage de sa partie. Chaque ami peut aussi ouvrir sa propre copie pour
   répéter ; les fenêtres ne se synchronisent pas entre ordinateurs via WhatsApp.

Conseil : faites une répétition avec les deux écrans branchés la veille ; la première ouverture peut demander d'autoriser les
pop-ups pour ce fichier.

## À compléter avant la soutenance (2 minutes)
En haut du `<script>` de `index.html` :

```js
const CONFIG = {
  team: ["[NOM COMPLET 1]", "[NOM COMPLET 2]", "[NOM COMPLET 3]", "[NOM COMPLET 4]"],
  prof: "[NOM DE L'ENCADRANT·E]",
  year: "2026 – 2027",
};
```

Les noms apparaissent automatiquement sur la couverture, en haut de chaque slide, sur la première slide de chaque
intervenant·e et sur la slide de questions.

## Captures d'écran à fournir
Enregistrer chaque capture dans `presentation/captures/` **avec exactement ce nom de fichier** : elle remplace le
cadre pointillé automatiquement (il suffit de recharger la page). Format conseillé : PNG, 16:10 ou proche.

| Fichier | Slide | Quoi capturer |
|---|---|---|
| `cerveau.png` | 1 | Visuel central de la couverture (le cerveau) — fond blanc ou transparent |
| `01_generation.png` | 14 | Notebook 01 : sortie de la boucle de génération (ok=True, essais, latence, VRAM) ou un code généré |
| `02_bandit.png` | 15 | Notebook 02 : tableau `bandit_summary` ou extrait de `bandit_findings_real.csv` |
| `03_cwe.png` | 16 | Notebook 04 : tableau `det_metrics_test` (colonne `cwe_acc_tp`) ou une réponse JSON du détecteur |
| `04_lora.png` | 17 | Notebook 03 : barre de progression de l'entraînement ou tableau `train_log` |
| `05_correction.png` | 18 | Notebook 05 : « Itération 1 / 2 » + « TOTAL : 5 valides / 17 / 105 », ou un diff avant/après |
| `06_demo.png` | 27 | Vue principale de la démo : notebook 05 en cours d'exécution ou RAPPORT_FINAL.md ouvert |
| `07_demo_generation.png` | 27 | Un code généré avec sa ligne vulnérable |
| `08_demo_detection.png` | 27 | La réponse JSON d'un détecteur LoRA |
| `09_demo_fix.png` | 27 | Le diff avant / après d'une correction validée (ex. `debug=True → debug=False`) |

Une capture absente laisse le cadre pointillé avec son libellé : la présentation reste utilisable.

## Répartition des intervenant·es (≈ 30 min au total)

| Intervenant·e | Slides | Contenu | Durée indicative |
|---|---|---|---|
| 01 — Contexte et problème | 1 – 6 | Couverture, constat (29,7 %), contexte, problématique, questions de recherche, périmètre | ≈ 6 min |
| 02 — Fondements et méthodologie | 7 – 12 | Les 5 SLMs, CWE, approches de détection, QLoRA & RAG, traçabilité, pipeline | ≈ 6 min |
| 03 — Architecture et implémentation | 13 – 20 | Architecture, génération, Bandit, classification CWE, détecteur LoRA, correction, défauts corrigés, technologies | ≈ 8 min |
| 04 — Résultats et conclusion | 21 – 31 | Protocole, résultats Q1 à Q4, rôles échangés, correction, analyse, démo, discussion, limites, conclusion, questions | ≈ 10 min |

La partie 4 est la plus longue : si besoin, l'intervenant·e 03 peut aussi présenter la slide 21 (protocole).
Chaque slide contient des notes (touche **N**) : quoi dire, transitions, points à souligner et durée.

## Choix de contenu
- Tous les chiffres viennent de `results/*.csv` et de `RAPPORT_FINAL.md` ; aucune valeur n'est inventée.
- Le brief initial mentionnait la criminalistique numérique, le hachage SHA-256 et la blockchain : **ces éléments ne
  font pas partie du projet**. Ils ont été remplacés par ce que le projet contient réellement : la **traçabilité des
  résultats** (slide 11 : checkpoints, graine fixe, configuration figée, revue humaine archivée), le détecteur
  LoRA + RAG et la correction automatique.
- Style : d'après la référence Valarian Technologies (Insposec) — fond clair #F2F2EE, grotesque noire, accent bleu
  #042DF5, libellés mono, numéros encadrés, fiches techniques à coins bleus, visuels tramés générés en code.
  `couvertures.html` garde les 3 variantes de couverture proposées (A retenue).
- Les graphiques sont dessinés en HTML à partir des données (survol = infobulle avec la valeur exacte). Palette
  vérifiée pour le daltonisme sur fond clair (cuivre / bleu / vert).
