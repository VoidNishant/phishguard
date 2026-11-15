"""Apply a local workaround when Windows Smart App Control blocks the
compiled scikit-learn ``histogram`` extension.

The blocked extension is only required by HistGradientBoosting, which
PhishGuard never uses. Renaming the .pyd and dropping in a pure-Python
stub keeps ``sklearn.ensemble`` importable so RandomForest models load.

Run with the project virtual environment's Python:
    .venv\\Scripts\\python.exe fix_sklearn_dll.py
"""

import sys
import textwrap
from pathlib import Path

STUB = textwrap.dedent(
    '''\
    """Pure-Python stub for the compiled HistogramBuilder extension.

    Installed by fix_sklearn_dll.py when Windows Smart App Control blocks
    the histogram .pyd. HistogramBuilder is only needed by
    HistGradientBoosting, which PhishGuard does not use.
    """


    class HistogramBuilder:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError(
                "HistGradientBoosting is unavailable because Windows Smart "
                "App Control blocked the compiled histogram extension."
            )
    '''
)


def main() -> int:
    site_packages = Path(sys.executable).resolve().parent.parent / "Lib" / "site-packages"
    folder = site_packages / "sklearn" / "ensemble" / "_hist_gradient_boosting"

    if not folder.is_dir():
        print(f"scikit-learn folder not found: {folder}")
        return 1

    renamed = 0
    for pyd in sorted(folder.glob("histogram*.pyd")):
        target = pyd.with_name(pyd.name + ".disabled")
        pyd.rename(target)
        renamed += 1
        print(f"Disabled blocked module: {pyd.name}")

    stub_path = folder / "histogram.py"
    stub_path.write_text(STUB, encoding="utf-8")
    print(f"Installed stub: {stub_path}")

    if renamed == 0:
        print("Note: no compiled histogram module was present; stub still installed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
