# -*- coding: utf-8 -*-
"""Construit un fichier HTML unique et autonome à partager (WhatsApp, e-mail…).

- intègre presentation/notes.js (script oral, noms) directement dans la page ;
- intègre les captures présentes dans presentation/captures/ (images en base64) ;
- masque le bouton « présentateur », qui nécessite presenter.html à côté du fichier.
Usage : python tools/build_standalone.py  →  Presentation_SLM-Sec.html à la racine du projet
"""
import base64
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRES = ROOT / "presentation"
html = (PRES / "index.html").read_text(encoding="utf-8")
notes = (PRES / "notes.js").read_text(encoding="utf-8")

# 1. notes.js en ligne + drapeau « autonome »
html = html.replace('<script src="notes.js"></script>',
                    "<script>\nwindow.STANDALONE = true;\n" + notes.replace("</script", "<\\/script") + "\n</script>", 1)

# 2. captures disponibles intégrées en base64 (les autres gardent leur cadre pointillé)
def embed(m):
    path = PRES / m.group(1)
    if not path.exists():
        return m.group(0)
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f'"data:image/png;base64,{data}"'

html = re.sub(r'"(captures/[\w.-]+\.png)"', embed, html)

out = ROOT / "Presentation_SLM-Sec.html"
out.write_text(html, encoding="utf-8")
n = html.count("data:image/png;base64,")
print(f"{out} · {out.stat().st_size // 1024} Ko · {n} image(s) intégrée(s)")
