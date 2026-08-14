"""Execute notebooks in-process when sandboxed environments cannot open kernel sockets."""

from __future__ import annotations

import ast
import base64
import contextlib
import io
import os
import sys
import traceback
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import nbformat  # noqa: E402
from nbformat.v4 import new_output  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def execute_source(source: str, namespace: dict[str, object]) -> object | None:
    tree = ast.parse(source, mode="exec")
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
        if prefix.body:
            exec(compile(prefix, "<notebook>", "exec"), namespace)
        expression = ast.Expression(tree.body[-1].value)
        return eval(compile(expression, "<notebook>", "eval"), namespace)
    exec(compile(tree, "<notebook>", "exec"), namespace)
    return None


def result_output(value: object, execution_count: int):
    data = {"text/plain": repr(value)}
    html = getattr(value, "_repr_html_", None)
    if callable(html):
        rendered = html()
        if rendered:
            data["text/html"] = rendered
    return new_output("execute_result", data=data, execution_count=execution_count)


def figure_outputs(existing: set[int]) -> list:
    outputs = []
    for number in sorted(set(plt.get_fignums()) - existing):
        figure = plt.figure(number)
        buffer = io.BytesIO()
        figure.savefig(buffer, format="png", dpi=135, bbox_inches="tight", facecolor="white")
        outputs.append(
            new_output(
                "display_data",
                data={"image/png": base64.b64encode(buffer.getvalue()).decode("ascii")},
                metadata={"image/png": {"width": int(figure.get_figwidth() * 110)}},
            )
        )
        plt.close(figure)
    return outputs


def execute_notebook(path: Path) -> None:
    document = nbformat.read(path, as_version=4)
    namespace: dict[str, object] = {"__name__": "__main__"}
    execution_count = 0
    for cell in document.cells:
        if cell.cell_type != "code":
            continue
        execution_count += 1
        cell.execution_count = execution_count
        cell.outputs = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        existing_figures = set(plt.get_fignums())
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                value = execute_source(cell.source, namespace)
            if stdout.getvalue():
                cell.outputs.append(new_output("stream", name="stdout", text=stdout.getvalue()))
            if stderr.getvalue():
                cell.outputs.append(new_output("stream", name="stderr", text=stderr.getvalue()))
            if value is not None:
                cell.outputs.append(result_output(value, execution_count))
            cell.outputs.extend(figure_outputs(existing_figures))
        except Exception as exc:
            trace = traceback.format_exc().splitlines()
            cell.outputs.append(
                new_output(
                    "error",
                    ename=exc.__class__.__name__,
                    evalue=str(exc),
                    traceback=trace,
                )
            )
            nbformat.write(document, path)
            raise RuntimeError(f"Execution failed in {path.name}, cell {execution_count}: {exc}") from exc
    document.metadata["guardian_execution"] = {
        "mode": "in-process top-to-bottom",
        "reason": "portable execution without a Jupyter kernel socket",
        "python": sys.version.split()[0],
    }
    nbformat.write(document, path)
    print(f"executed {path.relative_to(ROOT)} ({execution_count} code cells)")


def main() -> None:
    os.chdir(ROOT)
    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        execute_notebook(path)


if __name__ == "__main__":
    main()

