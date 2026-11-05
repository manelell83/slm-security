# Script oral de la soutenance — 20 minutes

_Source : presentation/notes.js (à modifier là-bas). Estimation à 110 mots/min, débit posé. Les [crochets] sont des indications, pas du texte à dire. Tous les chiffres viennent de results/*.csv._

## 1. Répartition et durées

| Intervenant·e | Partie | Slides | Créneau | Script estimé | Marge |
|---|---|---|---|---|---|
| 01 · Abderrahim Attou | Introduction et problématique | 1–6 | 00:00 → 05:00 | ≈ 4:26 | 0:34 |
| 02 · Aymane El Farme | Fondements et méthodologie | 7–12 | 05:00 → 10:00 | ≈ 3:56 | 1:04 |
| 03 · Manal Chemlali | Architecture et implémentation | 13–20 | 10:00 → 15:00 | ≈ 5:04 | -1:-4 |
| 04 · Youssef Miftah | Résultats et conclusion | 21–29 | 15:00 → 20:00 | ≈ 4:23 | 0:37 |
| **Total** | | 1–30 (+31 questions) | **20:00** | **≈ 17:48** | 2:12 |

La marge sert aux pauses, aux changements d'intervenant·e et au commentaire des captures. La slide 31 (questions) est hors chronomètre.

## 2. Plan de répétition (20 minutes)

1. **Préparer** : ouvrir `presentation/index.html` dans Chrome, appuyer sur **R** (mode répétition). Chacun·e a son script sous les yeux.
2. **Première répétition complète**, sans s'arrêter : le chronomètre démarre à la première navigation. Respecter les passages de parole écrits en fin de partie.
3. **Bilan** (bouton « bilan » ou touche **B**) : temps réel par intervenant·e comparé aux 5:00, et temps par slide.
   - Une partie en **rouge** : couper dans ses slides les plus longues (tableau de la section 3), dans le tableau de bord ou dans `notes.js`.
   - Une partie très en avance : ne rien ajouter, la marge servira le jour J.
4. **Deuxième répétition** en conditions réelles : deux écrans en mode « Étendre », touche **P**, fenêtre publique en plein écran sur le second écran.
5. **Repères de temps** à surveiller dans le tableau de bord :

| Repère | Slide attendue | Si en retard |
|---|---|---|
| 00:00 | 1 · début de Abderrahim Attou | raccourcir la partie suivante |
| 05:00 | 7 · début de Aymane El Farme | raccourcir la partie suivante |
| 10:00 | 13 · début de Manal Chemlali | raccourcir la partie suivante |
| 15:00 | 21 · début de Youssef Miftah | raccourcir la partie suivante |
| 20:00 | 30 · conclusion terminée | conclure immédiatement |

## 3. Durée estimée slide par slide

| Slide | Intervenant·e | Titre | Mots | Durée | Capture(s) |
|---|---|---|---|---|---|
| 1 | Abderrahim Attou | Code généré, failles cachées. | 81 | 0:44 | ✅ cerveau.png |
| 2 | Abderrahim Attou | des codes générés contiennent une vulnérabilité réelle. | 83 | 0:45 |  |
| 3 | Abderrahim Attou | Des assistants de code locaux. | 85 | 0:46 |  |
| 4 | Abderrahim Attou | Un code qui fonctionne n'est pas un code sûr. | 82 | 0:45 |  |
| 5 | Abderrahim Attou | Un modèle, trois rôles. | 79 | 0:43 |  |
| 6 | Abderrahim Attou | Ce que nous avons mesuré. | 77 | 0:42 |  |
| 7 | Aymane El Farme | Cinq petits modèles de code. | 81 | 0:44 |  |
| 8 | Aymane El Farme | Chaque faille a un nom. | 81 | 0:44 |  |
| 9 | Aymane El Farme | Deux façons de lire le code. | 80 | 0:44 |  |
| 10 | Aymane El Farme | Spécialiser un SLM sans le réentraîner. | 79 | 0:43 |  |
| 11 | Aymane El Farme | Chaque chiffre a une trace. | 63 | 0:34 |  |
| 12 | Aymane El Farme | Sept phases, sept notebooks. | 48 | 0:26 |  |
| 13 | Manal Chemlali | Architecture du système. | 92 | 0:50 |  |
| 14 | Manal Chemlali | Générer, puis extraire le vrai code. | 80 | 0:44 | ✅ 01_generation.png |
| 15 | Manal Chemlali | Bandit, correctement lu. | 77 | 0:42 | ✅ 02_bandit.png |
| 16 | Manal Chemlali | De l'alerte à la CWE. | 73 | 0:40 | ✅ 03_cwe.png |
| 17 | Manal Chemlali | Entraîné en quelques minutes. | 69 | 0:38 | ✅ 04_lora.png |
| 18 | Manal Chemlali | Corriger, vérifier, recommencer. | 85 | 0:46 | ✅ 05_correction.png |
| 19 | Manal Chemlali | Nous avons d'abord audité notre propre étude. | 46 | 0:25 |  |
| 20 | Manal Chemlali | Une pile entièrement open source. | 35 | 0:19 |  |
| 21 | Youssef Miftah | Protocole expérimental. | 53 | 0:29 |  |
| 22 | Youssef Miftah | Tous les modèles génèrent des failles, Qwen‑3B le plus. | 57 | 0:31 |  |
| 23 | Youssef Miftah | La LoRA fait d'un SLM un détecteur. | 66 | 0:36 |  |
| 24 | Youssef Miftah | Chaque détecteur juge le code de chaque générateur. | 47 | 0:26 |  |
| 25 | Youssef Miftah | Les outils valident 17 corrections. 5 sont vraies. | 64 | 0:35 |  |
| 26 | Youssef Miftah | Les détecteurs lisent des mots, pas des flux. | 49 | 0:27 |  |
| 27 | Youssef Miftah | Plus gros, plus performant… pas plus sûr. | 46 | 0:25 |  |
| 28 | Youssef Miftah | Ce que nos chiffres ne disent pas. | 41 | 0:22 |  |
| 29 | Youssef Miftah | Un SLM peut surveiller le code. Pas encore le réparer. | 59 | 0:32 |  |
| 30 | Youssef Miftah | Des questions? | — | hors chrono |  |

## 4. Script complet

---

### Intervenant·e 01 — Abderrahim Attou · Introduction et problématique · 00:00 → 05:00 · ≈ 4:26

#### Slide 1 — Code généré, failles cachées. · ≈ 0:44

Bonjour à toutes et à tous. Je suis Abderrahim Attou, et je vous présente, avec Aymane El Farme, Manal Chemlali et Youssef Miftah, notre projet encadré par Madame Meryem Ayache.

Notre question est simple : le code écrit par les petits modèles de langage, les SLMs, est-il sûr ? Nous avons évalué cinq SLMs dans trois rôles : produire du code, y détecter des vulnérabilités, puis les corriger. Les trois fiches autour du visuel résument les résultats que nous allons démontrer.

#### Slide 2 — des codes générés contiennent une vulnérabilité réelle. · ≈ 0:45

Premier constat : sur les 74 codes générés que nous avons pu analyser, 22 contiennent une vulnérabilité réelle, soit 29,7 %.

Nous ne retenons que les alertes de sévérité moyenne ou haute ; un simple import de module n'est pas compté. Les trois familles les plus fréquentes figurent à droite : la désérialisation avec pickle, le mode debug laissé actif sur un serveur, et un aléa ou un mot de passe trop faibles. Près d'un code sur trois serait donc dangereux en production.

#### Slide 3 — Des assistants de code locaux. · ≈ 0:46

Pourquoi ce sujet est-il important ? Les assistants de code sont devenus courants, et le code qu'ils produisent est souvent intégré sans relecture de sécurité.

Les SLMs, avec un à trois milliards de paramètres, s'exécutent sur un simple GPU : le code ne quitte pas la machine, ce qui préserve sa confidentialité. Or l'article de référence de Hasan et al. les compare uniquement sur leur capacité à réussir des tests fonctionnels. La sécurité n'y est pas mesurée : c'est cet angle mort que nous étudions.

#### Slide 4 — Un code qui fonctionne n'est pas un code sûr. · ≈ 0:45

D'où notre problématique : un code qui fonctionne n'est pas nécessairement un code sûr.

L'exemple à droite a été généré par Qwen2.5-Coder-3B. Le serveur démarre et répond correctement, mais la ligne 10 active le mode debug, qui expose la trace des erreurs et une console interactive ; Bandit la classe en sévérité haute. Ce modèle obtient le meilleur score fonctionnel de l'article, 0,59 en pass@1, et c'est pourtant lui qui produit le plus de code vulnérable dans notre étude : 40 %.

#### Slide 5 — Un modèle, trois rôles. · ≈ 0:43

Nous avons donc formulé quatre questions de recherche.

Premièrement, les SLMs génèrent-ils du code vulnérable, et dans quelles catégories ? Deuxièmement, un SLM peut-il servir de détecteur, et l'affinage LoRA ou la recherche documentaire RAG l'améliorent-ils face à l'outil Bandit ? Troisièmement, savent-ils corriger leur propre code et celui des autres ? Enfin, la taille ou la performance fonctionnelle rendent-elles le code plus sûr ?

Notre contribution est un pipeline reproductible qui évalue chaque modèle dans ces trois rôles.

#### Slide 6 — Ce que nous avons mesuré. · ≈ 0:42

Pour garantir la rigueur de l'étude, nous avons fixé un périmètre précis : le langage Python, avec les prompts du jeu SecurityEval ; cinq modèles ; quinze prompts couvrant quinze catégories de failles ; et un GPU T4 gratuit de Google Colab. Nous n'avons en revanche ni testé d'autres langages, ni exécuté le code produit, ni recherché les failles purement logiques.

[Transition] Je laisse maintenant la parole à Aymane, qui va présenter les fondements scientifiques et la méthode.

---

### Intervenant·e 02 — Aymane El Farme · Fondements et méthodologie · 05:00 → 10:00 · ≈ 3:56

#### Slide 7 — Cinq petits modèles de code. · ≈ 0:44

Merci Abderrahim. Ma partie présente les notions et la méthode sur lesquelles repose notre étude.

Un SLM est un modèle de langage suffisamment petit pour fonctionner sur un ordinateur ordinaire. Nous en avons retenu cinq, de 1,1 à 3,1 milliards de paramètres : deux Qwen2.5-Coder, StarCoder2, Stable-Code et TinyLlama. Chacun reçoit son format de prompt : conversation, instruction, ou simple complétion pour Stable-Code, qui est un modèle de base. Le pass@1 provient de l'article de référence ; TinyLlama n'y figure pas.

#### Slide 8 — Chaque faille a un nom. · ≈ 0:44

Pour nommer les failles, nous utilisons le référentiel CWE, maintenu par le MITRE, qui attribue un identifiant à chaque type de faiblesse logicielle.

Cette slide présente les huit familles rencontrées dans nos résultats, avec le motif de code typique et la règle Bandit associée. Par exemple, CWE-502 désigne la désérialisation de données non fiables avec pickle, et CWE-330 l'usage du module random là où un aléa cryptographique est nécessaire. Chaque verdict de nos détecteurs est rattaché à l'une de ces catégories.

#### Slide 9 — Deux façons de lire le code. · ≈ 0:44

Nous comparons deux approches de détection.

À gauche, l'analyse statique avec Bandit : l'outil recherche des appels dangereux connus dans le code. Il est rapide et indique la ligne exacte, mais il ne comprend pas le contexte. À droite, le SLM détecteur : le modèle lit le code et rend un verdict au format JSON, avec la catégorie CWE et une courte explication. Nous évaluons quatre configurations : le modèle seul, avec RAG, affiné par LoRA, et LoRA avec RAG.

#### Slide 10 — Spécialiser un SLM sans le réentraîner. · ≈ 0:43

Deux techniques permettent de spécialiser un SLM sans le réentraîner entièrement.

La première, QLoRA, compresse le modèle en 4 bits et le fige ; on n'entraîne que de petites matrices ajoutées à ses couches, ce qui rend l'entraînement possible sur un GPU gratuit. La seconde, le RAG, fournit au détecteur, avant sa réponse, les trois documents les plus proches du code analysé, trouvés par recherche sémantique. Cette base documentaire ne contient que des données d'entraînement, jamais celles de l'évaluation.

#### Slide 11 — Chaque chiffre a une trace. · ≈ 0:34

Les sessions Colab s'interrompent régulièrement. Chaque étape écrit donc ses résultats dans un fichier sur Google Drive : prompts, codes générés, alertes, verdicts, corrections et revue humaine.

Chaque chiffre de cette présentation peut ainsi être retrouvé dans un fichier précis. Nous utilisons également une graine aléatoire fixe, une configuration figée, et un filtre qui exclut tout exemple d'entraînement trop proche du jeu d'évaluation.

#### Slide 12 — Sept phases, sept notebooks. · ≈ 0:26

L'ensemble du projet suit sept phases, une par notebook : configuration, génération, analyse Bandit, entraînement des détecteurs, évaluation, correction, puis analyses complémentaires. Tous les notebooks s'appuient sur une bibliothèque commune, slmsec.py, qui regroupe le code partagé.

[Transition] Manal va maintenant vous montrer comment ce système a été construit concrètement.

---

### Intervenant·e 03 — Manal Chemlali · Architecture et implémentation · 10:00 → 15:00 · ≈ 5:04

#### Slide 13 — Architecture du système. · ≈ 0:50

À DIRE
Merci Aymane. Je vais vous montrer comment nous avons construit le système, étape par étape.

Le schéma se lit de gauche à droite. À gauche, nos sources, téléchargées depuis Hugging Face : les cinq modèles et les deux jeux de données. Au centre, le calcul, dans Google Colab sur un GPU T4 : sept notebooks, un par étape, qui partagent la même bibliothèque, slmsec.py. À droite, Google Drive, où chaque étape enregistre ses résultats. Le GPU n'a que 16 Go : nous chargeons donc un seul modèle à la fois.

[DÉTAILS À SAVOIR
• Hugging Face : les 5 modèles, SecurityEval (prompts de test), CyberNative (données d'entraînement), bge-small-en-v1.5 (modèle de recherche du RAG).
• Colab : GPU T4 de 16 Go, calcul en fp16 (le T4 ne gère pas le bf16). Notebooks 00 à 06, un par phase.
• slmsec.py regroupe le code commun : chargement et libération des modèles, extraction du code, Bandit, détecteur, RAG, métriques, rapport.
• Drive : gen/ (codes générés), preds/ (verdicts), fix/ (corrections), adapters/ (modules LoRA), rag/ (index), results/ (tableaux et figures).
• Mémoire : un modèle de 3 milliards de paramètres prend environ 6 Go en génération et jusqu'à 8,3 Go en entraînement. On le charge, on l'utilise, puis on le libère.
• Reprise : les sessions Colab se coupent ; chaque étape saute ce qui existe déjà sur Drive.]

#### Slide 14 — Générer, puis extraire le vrai code. · ≈ 0:44

À DIRE
Première étape : faire écrire le code. Chaque modèle reçoit les 15 prompts et écrit une réponse par prompt, avec les mêmes réglages que l'article, pour rester comparables.

Le piège : un modèle répond parfois par une phrase au lieu du code. Nous vérifions donc que la réponse est du vrai Python ; sinon, nous lui redemandons, deux fois au maximum. Le tableau le confirme : 74 codes valides sur 75, et le seul échec vient de Stable-Code.

[DÉTAILS À SAVOIR
• 15 prompts × 5 modèles = 75 réponses, une seule réponse par prompt, graine aléatoire fixe.
• Réglages (slmsec.py, GEN_CFG) : température 0,2 = peu de hasard ; top-p 0,95 = le modèle choisit seulement parmi les mots les plus probables ; 512 tokens = longueur maximale, environ une page. Mêmes valeurs que Hasan et al.
• Format du prompt : conversation pour Qwen et TinyLlama, « ### Instruction » pour StarCoder2, complétion pour Stable-Code. Stable-Code est un modèle de base : on lui donne le début du code SecurityEval et il écrit la suite, avec des mots d'arrêt et une pénalité de répétition de 1,1 pour l'empêcher de tourner en boucle.
• Extraction : on prend le bloc de code, puis on vérifie avec ast.parse qu'il s'agit de Python valide contenant de vraies instructions. Sinon : nouvel essai avec une autre graine, deux au maximum.
• On ne redemande jamais parce qu'un code est vulnérable, uniquement quand il n'y a pas de code.
• Tableau : extraction_ok_rate = 1,0 pour 4 modèles et 0,933 pour Stable-Code (14 sur 15) ; mean_attempts = 1,133 pour Stable-Code ; latence moyenne de 3,9 s (Qwen-1.5B) à 9,8 s (StarCoder2).
• Dans l'étude initiale, la phrase « Here's the implementation… » de Qwen-3B était comptée comme un code sûr.]

#### Slide 15 — Bandit, correctement lu. · ≈ 0:42

À DIRE
Deuxième étape : chercher les failles avec Bandit. Nous avons corrigé deux erreurs de l'étude initiale.

D'abord, un simple import, comme « import pickle », était compté comme une faille ; il est désormais mis à part. Seule compte une utilisation dangereuse, par exemple « pickle.loads » sur des données reçues. Ensuite, chaque alerte indique maintenant sa vraie ligne. Sur le graphique : en bleu, les codes réellement vulnérables ; en orange, les simples imports.

[DÉTAILS À SAVOIR
• Bandit est un analyseur statique : il lit le code sans l'exécuter et produit un rapport JSON (règle, sévérité, ligne).
• Alertes informatives = règles B401 à B413, déclenchées par un simple import (B403 import pickle, B404 import subprocess, B405 import xml…). Importer n'est pas dangereux : elles sont comptées à part.
• Un code est vulnérable s'il a au moins une alerte réelle de sévérité MEDIUM ou HIGH. Les alertes LOW, comme assert, sont trop bruitées.
• Exemple réel (Qwen-1.5B, prompt CWE-020) : ligne 2, import pickle → B403, informative ; ligne 15, pickle.loads(decoded_data) → B301, MEDIUM, CWE-502, réelle.
• La ligne vient du champ line_number de Bandit ; les doublons (même règle, même ligne) sont supprimés.
• Résultat : 22 codes vulnérables sur 74, soit 29,7 % ; de 26,7 % à 40 % selon le modèle (Qwen-3B le plus haut).
• Graphique : barres bleues = % de codes vulnérables ; barres orange = nombre d'alertes d'import.]

#### Slide 16 — De l'alerte à la CWE. · ≈ 0:40

À DIRE
Troisième étape : nommer la faille. Bandit donne un code de règle, que nous traduisons en catégorie CWE ; par exemple, B301 devient CWE-502.

Nous vérifions ensuite, sur notre jeu de test, si la catégorie donnée est la bonne : nos détecteurs entraînés la trouvent dans 76 à 100 % des cas, contre 41 % pour Bandit. Le graphique montre le score F1 de chaque configuration : LoRA est la meilleure.

[DÉTAILS À SAVOIR
• CWE = catalogue du MITRE qui donne un numéro à chaque type de faille (CWE-502 désérialisation, CWE-330 aléa faible, CWE-259 mot de passe en dur…).
• Bandit : la CWE vient du champ issue_cwe de son rapport ; à défaut, de notre table (B301 → CWE-502, B201 → CWE-94, B105/B106 → CWE-259, B311 → CWE-330, B108 → CWE-377, B202 → CWE-22). Si un code a plusieurs alertes, on garde celle de l'alerte la plus grave.
• Détecteur SLM : la CWE est écrite directement dans sa réponse JSON.
• Vérification sur les 76 codes de test : parmi les failles bien détectées, on compare la CWE donnée à la CWE attendue. Celle-ci est déduite par mots-clés de la description CyberNative ; les cas « CWE-Other » sont exclus.
• Bonne catégorie : Qwen-1.5B 100 %, Qwen-3B 88 %, Stable-Code 85 %, StarCoder2 79 %, TinyLlama 76 % ; Bandit 41 %.
• F1 = note de 0 à 1 qui combine deux qualités : trouver les failles, et ne pas crier au loup. Modèles de base ≈ 0 ; Bandit 0,64 ; LoRA de 0,67 à 0,82.
• Limite : la CWE attendue est approximative, et la comparaison est stricte (deux catégories proches comptent comme une erreur).]

#### Slide 17 — Entraîné en quelques minutes. · ≈ 0:38

À DIRE
Quatrième étape : entraîner les détecteurs. Nous leur montrons des paires d'exemples : le même programme en version vulnérable et en version corrigée. Après nettoyage, il en reste 372.

Chaque paire reste toujours dans le même groupe, entraînement ou test, pour que le test soit honnête. La capture montre les réglages réels de l'entraînement QLoRA présenté par Aymane : chaque modèle s'entraîne en 3 à 6 minutes.

[DÉTAILS À SAVOIR
• CyberNative : paires « même programme, version vulnérable et version corrigée ».
• Nettoyage : 424 paires Python au départ ; 52 doublons retirés (même code présent plusieurs fois, ou versions vulnérable et sûre identiques) ; il en reste 372. Les vérifications de longueur et d'anti-fuite avec SecurityEval n'ont retiré aucune paire.
• Découpage par paire : 297 / 37 / 38 paires, soit 594 / 74 / 76 codes (entraînement / validation / test), moitié vulnérables.
• Pourquoi par paire : les deux versions se ressemblent beaucoup ; si elles étaient séparées, le modèle aurait presque vu la réponse du test.
• Réglages QLoRA (capture) : modèle en 4 bits (nf4), rang r = 16, alpha = 32, dropout 0,05, toutes les couches linéaires, taux d'apprentissage 2e-4, un seul passage, lots de 2 × 8, calcul en fp16, optimiseur paged AdamW 8 bits.
• Le modèle n'apprend que la réponse JSON, pas le code. 38 pas d'entraînement, 2,9 à 5,8 minutes et 5,8 à 8,3 Go de mémoire selon le modèle.
• Un module LoRA par modèle, enregistré sur Drive et rechargé pour la détection.]

#### Slide 18 — Corriger, vérifier, recommencer. · ≈ 0:46

À DIRE
Cinquième étape : corriger. Les cinq modèles corrigent chacun les 21 codes vulnérables, soit 105 tentatives. Chacun reçoit le code, le type de faille et un exemple corrigé similaire, retrouvé par le RAG.

La correction est acceptée si le code reste valide, si Bandit ne signale plus rien et si un autre modèle le juge sûr ; sinon, on retente une fois. Nous avons aussi ajouté des garde-fous, par exemple pour refuser un code rendu inchangé. Le tableau donne le bilan par correcteur.

[DÉTAILS À SAVOIR
• Les 21 codes vulnérables : ceux signalés par au moins 3 détecteurs sur 6 (Bandit + 5 détecteurs LoRA).
• 21 × 5 = 105 tentatives : 21 auto-corrections (un modèle corrige son propre code) et 84 corrections croisées. Les correcteurs sont les modèles d'origine, non entraînés.
• Dossier du correcteur : le code ; la CWE et l'explication du meilleur détecteur (Qwen-3B LoRA) ; l'alerte Bandit avec sa ligne ; un exemple corrigé retrouvé par le RAG, de la même CWE si possible.
• Contrôles : 1) Python valide (ast.parse) ; 2) aucune alerte Bandit MEDIUM ou HIGH ; 3) le détecteur LoRA + RAG d'un autre modèle juge le code sûr, car un modèle est indulgent avec son propre code.
• Échec : deuxième tentative, avec le motif du rejet transmis au correcteur.
• Garde-fous : code réellement modifié (structure différente) ; mêmes fonctions et arguments ; au moins 30 % de ressemblance avec l'original ; aucun nom non défini (pyflakes) ; appels de fonctions valides.
• Vrais faux succès qui les ont motivés : une ligne vide supprimée ; io utilisé sans import ; secrets.choice(…, k=16).
• Bilan : 35 succès bruts, 17 après les garde-fous, 5 validés par la relecture humaine (Youssef présente ce résultat).]

#### Slide 19 — Nous avons d'abord audité notre propre étude. · ≈ 0:25

À DIRE
Avant tout cela, nous avons vérifié notre propre étude de départ et corrigé les sept erreurs listées ici.

La plus parlante : Qwen-3B semblait n'avoir aucune faille, uniquement parce que son code n'était pas extrait. Une fois l'extraction corrigée, il en a 40 %.

[DÉTAILS À SAVOIR — les 7 défauts corrigés
1. Une phrase sans code comptée comme code sain → vérification avec ast.parse.
2. Stable-Code tournait en boucle sur « ### Instruction » → mode complétion.
3. Toutes les alertes placées ligne 1 → ligne réelle donnée par Bandit.
4. Les imports comptés comme failles → alertes B401 à B413 mises à part.
5. Des observations identiques pour tous les modèles → générées à partir des vraies données.
6. Seulement 3 types de failles testés → 15 prompts couvrant 15 CWE.
7. Les accents cassés dans les fichiers → tout est écrit en UTF-8.
• Effet le plus visible : Qwen-3B passe de 0 % à 40 % de codes vulnérables.]

#### Slide 20 — Une pile entièrement open source. · ≈ 0:19

À DIRE
Tous nos outils sont gratuits et open source : Transformers pour les modèles, FAISS pour la recherche d'exemples, Bandit pour l'analyse, Colab et Drive pour l'infrastructure.

[Transition] Youssef va maintenant vous présenter les résultats.

[DÉTAILS À SAVOIR
• Transformers : charger les modèles, les faire générer, lancer l'entraînement.
• PEFT : ajouter, entraîner et recharger les modules LoRA.
• bitsandbytes : compression des modèles en 4 bits et optimiseur AdamW 8 bits.
• sentence-transformers + FAISS : transformer le code en vecteurs et trouver les exemples les plus proches pour le RAG.
• Bandit + pyflakes : analyse statique et détection des noms non définis.
• datasets + pandas : chargement et manipulation des données.
• scikit-learn + statsmodels + SciPy : F1, MCC, McNemar, kappa, corrélations.
• matplotlib : graphiques.
• Colab + Drive : GPU gratuit et stockage avec reprise.
• Tout est gratuit : n'importe qui peut reproduire l'étude.]

---

### Intervenant·e 04 — Youssef Miftah · Résultats et conclusion · 15:00 → 20:00 · ≈ 4:23

#### Slide 21 — Protocole expérimental. · ≈ 0:29

Merci Manal. Je réponds maintenant à nos quatre questions.

L'expérience porte sur cinq modèles, 75 codes générés, 76 exemples de test étiquetés, vingt configurations de détecteurs et 105 tentatives de correction. Précision importante : sans annotation humaine complète des codes générés, la référence est un vote majoritaire entre Bandit et les cinq détecteurs.

#### Slide 22 — Tous les modèles génèrent des failles, Qwen‑3B le plus. · ≈ 0:31

Première question : tous les modèles génèrent des failles, dans 27 à 40 % des cas, et Qwen-3B est le plus concerné. Il s'agit surtout de réflexes d'API : pickle, random, mode debug, mots de passe écrits en dur.

Prudence toutefois : avec 15 codes par modèle, un seul code de différence représente près de 7 points.

#### Slide 23 — La LoRA fait d'un SLM un détecteur. · ≈ 0:36

Deuxième question, la détection. Les modèles de base répondent presque toujours « sûr » : leur score F1 est proche de zéro. Après affinage LoRA, il atteint 0,67 à 0,82, au-dessus de Bandit à 0,64, écart significatif pour quatre modèles sur cinq.

Le meilleur est Qwen-3B avec LoRA. Le RAG, lui, n'améliore qu'un modèle et dégrade les autres, probablement parce qu'il n'était pas présent pendant l'entraînement.

#### Slide 24 — Chaque détecteur juge le code de chaque générateur. · ≈ 0:26

Cette matrice croise chaque détecteur avec chaque générateur. L'accord entre détecteurs est modéré, avec un kappa de Fleiss de 0,36 : ils ne repèrent pas les mêmes failles.

Nous observons aussi une forme d'indulgence : trois détecteurs signalent nettement moins leur propre code que celui des autres.

#### Slide 25 — Les outils valident 17 corrections. 5 sont vraies. · ≈ 0:35

Troisième question, la correction. Sur 105 tentatives, les contrôles automatiques en valident 35, puis 17 après nos garde-fous. En relisant ces 17 corrections une à une, nous n'en avons retenu que 5 réellement valides, soit 4,8 %.

Les corrections réussies sont simples, comme désactiver le mode debug. Les autres passent tous les tests automatiques sans corriger la faille : une relecture humaine reste indispensable.

#### Slide 26 — Les détecteurs lisent des mots, pas des flux. · ≈ 0:27

L'analyse des erreurs va dans le même sens. Le mot subprocess apparaît dans 65 % des faux positifs, contre 10 % des prédictions correctes : les détecteurs réagissent au vocabulaire plutôt qu'à l'usage. À l'inverse, ils manquent les failles qui dépendent du flux des données, comme les injections SQL.

#### Slide 27 — Plus gros, plus performant… pas plus sûr. · ≈ 0:25

Quatrième question : le lien entre taille, performance fonctionnelle et sécurité. Avec quatre ou cinq modèles, aucune corrélation n'est significative.

Rien n'indique cependant qu'un modèle plus grand soit plus sûr : TinyLlama, une fois affiné, détecte aussi bien que les modèles de 3 milliards de paramètres.

#### Slide 28 — Ce que nos chiffres ne disent pas. · ≈ 0:22

Nos résultats comportent des limites, chacune associée ici à une piste d'amélioration : un nombre réduit de prompts, une référence construite par vote, un jeu d'entraînement synthétique et l'absence de tests fonctionnels. La priorité serait d'annoter manuellement les 74 codes générés.

#### Slide 29 — Un SLM peut surveiller le code. Pas encore le réparer. · ≈ 0:32

En conclusion : près d'un code sur trois est vulnérable ; un SLM affiné en quelques minutes détecte mieux que Bandit ; mais seules 4,8 % des corrections sont réellement valides. Un SLM peut donc surveiller le code, mais pas encore le réparer seul.

Nous vous remercions de votre attention et nous sommes prêts à répondre à vos questions.

---

### Questions du jury (hors chronomètre)

#### Slide 30 — Des questions?

[Questions du jury — hors chronomètre. Chacun·e répond sur sa partie.]

Pourquoi un vote majoritaire ? → Faute de temps pour annoter les 74 codes ; le fichier d'annotation est prêt.
Pourquoi le RAG dégrade-t-il la détection ? → Il n'a pas été vu pendant l'entraînement LoRA.
Le jeu de test est-il représentatif ? → Non, il est synthétique : c'est une limite assumée.
Pourquoi ces cinq modèles ? → Au plus 3 milliards de paramètres, exécutables sur un T4, et présents dans l'article, sauf TinyLlama.
Comment avez-vous validé les corrections ? → Contrôles automatiques puis relecture des 17 succès stricts ; 5 confirmées.

---

## 5. Captures et éléments manquants

Voir `SCREENSHOT_GUIDE.md`. Toutes les captures sont en place. Élément de fond manquant : l'annotation humaine des 74 codes générés (vérité terrain par vote majoritaire, dite à l'oral).
