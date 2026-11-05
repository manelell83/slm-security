# -*- coding: utf-8 -*-
"""Convertit notebooks_src/*.py (cellules séparées par `# %%`) en notebooks/*.ipynb,
puis valide : nbformat.validate + compilation de chaque cellule de code + py_compile de slmsec.py.
Usage : python tools/build_notebooks.py"""
import py_compile
import sys
from pathlib import Path

import nbformat

ROOT = Path(__file__).resolve().parents[1]
SRC, OUT = ROOT / "notebooks_src", ROOT / "notebooks"


def convert(src):
    cells, cur, kind = [], [], "code"

    def flush():
        text = "\n".join(cur).strip("\n")
        if text:
            if kind == "markdown":
                text = "\n".join(l[2:] if l.startswith("# ") else l.lstrip("#") for l in text.split("\n"))
                cells.append(nbformat.v4.new_markdown_cell(text))
            else:
                cells.append(nbformat.v4.new_code_cell(text))

    for line in src.read_text(encoding="utf-8").split("\n"):
        if line.startswith("# %%"):
            flush()
            cur, kind = [], ("markdown" if "[markdown]" in line else "code")
        else:
            cur.append(line)
    flush()
    nb = nbformat.v4.new_notebook(cells=cells)
    nb.metadata.update({"kernelspec": {"name": "python3", "display_name": "Python 3"},
                        "language_info": {"name": "python"}, "accelerator": "GPU",
                        "colab": {"provenance": [], "gpuType": "T4"}})
    return nb


def main():
    OUT.mkdir(exist_ok=True)
    py_compile.compile(str(ROOT / "slmsec.py"), doraise=True)
    ok = True
    for src in sorted(SRC.glob("*.py")):
        nb = convert(src)
        nbformat.validate(nb)
        for i, c in enumerate(nb.cells):
            if c.cell_type == "code":
                try:
                    compile(c.source, f"{src.name}[cell {i}]", "exec")
                except SyntaxError as e:
                    ok = False
                    print("ERREUR", e)
        dst = OUT / (src.stem + ".ipynb")
        nbformat.write(nb, str(dst))
        print(f"{dst.name}: {len(nb.cells)} cellules OK")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
