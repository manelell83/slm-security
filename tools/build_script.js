// Régénère presentation/SCRIPT_SOUTENANCE.md depuis presentation/notes.js.
// Usage : node tools/build_script.js
const fs = require("fs"), path = require("path");
const PRES = path.join(__dirname, "..", "presentation");
global.window = {};
eval(fs.readFileSync(path.join(PRES, "notes.js"), "utf8"));
const S = window.SCRIPT, P = window.PROFILES, D = window.DEFENSE;
const html = fs.readFileSync(path.join(PRES, "index.html"), "utf8");
const titles = [...html.matchAll(/<section class="slide"[\s\S]*?<(h1|h2)[^>]*>([\s\S]*?)<\/\1>/g)]
  .map(m => m[2].replace(/<br>/g, " ").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim());
const words = t => t.replace(/\[[^\]]*\]/g, " ").split(/\s+/).filter(Boolean).length;
const sec = t => words(t) / D.wordsPerMinute * 60;
const mm = s => Math.floor(s / 60) + ":" + String(Math.round(s % 60)).padStart(2, "0");
const pad = n => String(n).padStart(2, "0");
const capDir = path.join(PRES, "captures");
const has = f => fs.existsSync(path.join(capDir, f));
const SHOTS = { 1: ["cerveau.png"], 14: ["01_generation.png"], 15: ["02_bandit.png"], 16: ["03_cwe.png"], 17: ["04_lora.png"],
  18: ["05_correction.png"] };
const shotCell = i => (SHOTS[i] || []).map(f => (has(f) ? "✅ " : "⬜ ") + f).join("<br>");

let o = "# Script oral de la soutenance — 20 minutes\n\n_Source : presentation/notes.js (à modifier là-bas). Estimation à " + D.wordsPerMinute +
  " mots/min, débit posé. Les [crochets] sont des indications, pas du texte à dire. Tous les chiffres viennent de results/*.csv._\n\n";
o += "## 1. Répartition et durées\n\n| Intervenant·e | Partie | Slides | Créneau | Script estimé | Marge |\n|---|---|---|---|---|---|\n";
let t0 = 0, tot = 0; const sect = [];
P.forEach((pr, p) => {
  const sl = S.map((s, i) => ({ s, i })).filter(x => x.s.p === p && !x.s.untimed);
  const d = sl.reduce((a, x) => a + sec(x.s.text), 0); tot += d; sect.push({ pr, sl, d, start: t0 });
  o += `| 0${p + 1} · ${pr.name} | ${pr.section} | ${sl[0].i + 1}–${sl.at(-1).i + 1} | ${pad(t0)}:00 → ${pad(t0 + pr.minutes)}:00 | ≈ ${mm(d)} | ${mm(pr.minutes * 60 - d)} |\n`;
  t0 += pr.minutes;
});
o += `| **Total** | | 1–30 (+31 questions) | **20:00** | **≈ ${mm(tot)}** | ${mm(D.totalMinutes * 60 - tot)} |\n\nLa marge sert aux pauses, aux changements d'intervenant·e et au commentaire des captures. La slide 31 (questions) est hors chronomètre.\n`;
o += "\n## 2. Plan de répétition (20 minutes)\n\n1. **Préparer** : ouvrir `presentation/index.html` dans Chrome, appuyer sur **R** (mode répétition). Chacun·e a son script sous les yeux.\n" +
  "2. **Première répétition complète**, sans s'arrêter : le chronomètre démarre à la première navigation. Respecter les passages de parole écrits en fin de partie.\n" +
  "3. **Bilan** (bouton « bilan » ou touche **B**) : temps réel par intervenant·e comparé aux 5:00, et temps par slide.\n" +
  "   - Une partie en **rouge** : couper dans ses slides les plus longues (tableau de la section 3), dans le tableau de bord ou dans `notes.js`.\n" +
  "   - Une partie très en avance : ne rien ajouter, la marge servira le jour J.\n" +
  "4. **Deuxième répétition** en conditions réelles : deux écrans en mode « Étendre », touche **P**, fenêtre publique en plein écran sur le second écran.\n" +
  "5. **Repères de temps** à surveiller dans le tableau de bord :\n\n| Repère | Slide attendue | Si en retard |\n|---|---|---|\n";
sect.forEach(x => { o += `| ${pad(x.start)}:00 | ${x.sl[0].i + 1} · début de ${x.pr.name} | raccourcir la partie suivante |\n`; });
o += "| 20:00 | 30 · conclusion terminée | conclure immédiatement |\n";
o += "\n## 3. Durée estimée slide par slide\n\n| Slide | Intervenant·e | Titre | Mots | Durée | Capture(s) |\n|---|---|---|---|---|---|\n";
S.forEach((s, i) => { o += `| ${i + 1} | ${P[s.p].name} | ${titles[i] || ""} | ${s.untimed ? "—" : words(s.text)} | ${s.untimed ? "hors chrono" : mm(sec(s.text))} | ${shotCell(i + 1)} |\n`; });
o += "\n## 4. Script complet\n";
let last = -1;
S.forEach((s, i) => {
  if (!s.untimed && s.p !== last) { const x = sect[s.p]; o += `\n---\n\n### Intervenant·e 0${s.p + 1} — ${P[s.p].name} · ${P[s.p].section} · ${pad(x.start)}:00 → ${pad(x.start + 5)}:00 · ≈ ${mm(x.d)}\n`; last = s.p; }
  if (s.untimed) o += "\n---\n\n### Questions du jury (hors chronomètre)\n";
  o += `\n#### Slide ${i + 1} — ${titles[i] || ""}${s.untimed ? "" : " · ≈ " + mm(sec(s.text))}\n\n${s.text}\n`;
});
const missing = Object.values(SHOTS).flat().filter(f => !has(f));
o += "\n---\n\n## 5. Captures et éléments manquants\n\nVoir `SCREENSHOT_GUIDE.md`. " +
  (missing.length ? "Captures encore manquantes : " + missing.map(f => "`" + f + "`").join(", ") + "." : "Toutes les captures sont en place.") +
  " Élément de fond manquant : l'annotation humaine des 74 codes générés (vérité terrain par vote majoritaire, dite à l'oral).\n";
fs.writeFileSync(path.join(PRES, "SCRIPT_SOUTENANCE.md"), o, "utf8");
console.log("SCRIPT_SOUTENANCE.md · total ≈ " + mm(tot) + " · captures manquantes : " + (missing.join(", ") || "aucune"));
