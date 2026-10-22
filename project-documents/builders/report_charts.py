"""Result charts for the final report, drawn with matplotlib from the JSON result snapshots.

Only the three essential results are charted (live overhead, attack
detection, throughput); everything else is in the report's tables and text.

Visual rules: one quiet chrome (hairline grid, muted axes, text in ink tokens),
thin bars with a rounded data end and a square baseline, values labeled at the
bar tip, a legend only when two or more series share a chart, and categorical
colors in a fixed, validated order (blue, orange; checked for colour-vision
deficiency against a white page).
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import PathPatch, Patch  # noqa: E402
from matplotlib.path import Path as MplPath  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, NEUTRAL = "#e1e0d9", "#c3c2b7", "#d9d8d2"
DPI = 220
WIDTH = 6.3  # inches, the report's text width


def _setup_fonts() -> None:
    for folder in (Path("/fonts"), Path("/mnt/c/Windows/Fonts"), Path(r"C:\Windows\Fonts")):
        for name in ("arial.ttf", "arialbd.ttf"):
            if (folder / name).exists():
                font_manager.fontManager.addfont(str(folder / name))
    family = "Arial" if any(font.name == "Arial" for font in font_manager.fontManager.ttflist) else "DejaVu Sans"
    plt.rcParams.update({
        "font.family": family, "font.size": 8.5, "axes.titlesize": 9.5, "axes.titleweight": "bold",
        "axes.titlelocation": "left", "axes.titlepad": 8, "axes.edgecolor": AXIS, "axes.labelcolor": INK_2,
        "xtick.color": MUTED, "ytick.color": INK_2, "xtick.labelsize": 8, "ytick.labelsize": 8,
        "axes.spines.top": False, "axes.spines.right": False, "figure.facecolor": "white", "axes.facecolor": "white",
        "legend.frameon": False, "legend.fontsize": 8,
    })


_setup_fonts()


# ------------------------------------------------------------------ marks

def _rounded_bar(ax, start: float, end: float, center: float, thickness: float, color: str, horizontal: bool, radius_pt: float = 2.2) -> None:
    """A bar with a rounded data end and a square baseline end."""
    ax.figure.canvas.draw_idle()
    bbox = ax.get_window_extent()
    (x0, x1), (y0, y1) = ax.get_xlim(), ax.get_ylim()
    px_x, px_y = bbox.width / abs(x1 - x0), bbox.height / abs(y1 - y0)
    radius_px = radius_pt * ax.figure.dpi / 72
    k = 0.5523
    low, high = center - thickness / 2, center + thickness / 2
    if horizontal:
        rx = min(radius_px / px_x, abs(end - start) / 2)
        ry = min(radius_px / px_y, thickness / 2)
        e = end - rx
        vertices = [(start, low), (e, low), (e + k * rx, low), (end, low + ry - k * ry), (end, low + ry),
                    (end, high - ry), (end, high - ry + k * ry), (e + k * rx, high), (e, high), (start, high), (start, low)]
    else:
        rx = min(radius_px / px_x, thickness / 2)
        ry = min(radius_px / px_y, abs(end - start) / 2)
        e = end - ry
        vertices = [(low, start), (low, e), (low, e + k * ry), (low + rx - k * rx, end), (low + rx, end),
                    (high - rx, end), (high - rx + k * rx, end), (high, e + k * ry), (high, e), (high, start), (low, start)]
    codes = [MplPath.MOVETO, MplPath.LINETO, MplPath.CURVE4, MplPath.CURVE4, MplPath.CURVE4,
             MplPath.LINETO, MplPath.CURVE4, MplPath.CURVE4, MplPath.CURVE4, MplPath.LINETO, MplPath.CLOSEPOLY]
    ax.add_patch(PathPatch(MplPath(vertices, codes), facecolor=color, edgecolor="none", zorder=3))


def _hbars(ax, labels, values, colors, fmt, xmax=None, thickness=0.56):
    positions = list(range(len(labels)))[::-1]
    xmax = xmax or max(values) * 1.18
    ax.set_xlim(0, xmax)
    ax.set_ylim(-0.6, len(labels) - 0.4)
    ax.set_yticks(positions, labels)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8, zorder=0)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    for position, value, color in zip(positions, values, colors):
        _rounded_bar(ax, 0, value, position, thickness, color, horizontal=True)
        ax.text(value + xmax * 0.012, position, fmt(value), va="center", ha="left", color=INK, fontsize=8, zorder=4)


def _vbars(ax, labels, values, colors, fmt, ymax=None, thickness=0.5):
    positions = list(range(len(labels)))
    ymax = ymax or max(values) * 1.2
    ax.set_ylim(0, ymax)
    ax.set_xlim(-0.6, len(labels) - 0.4)
    ax.set_xticks(positions, labels)
    ax.tick_params(axis="x", length=0, colors=INK_2)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    for position, value, color in zip(positions, values, colors):
        _rounded_bar(ax, 0, value, position, thickness, color, horizontal=False)
        ax.text(position, value + ymax * 0.015, fmt(value), ha="center", va="bottom", color=INK, fontsize=8, zorder=4)


def _save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def _compact(value: float) -> str:
    return f"{value / 1000:.1f}K" if value >= 1000 else f"{value:,.0f}"


# ------------------------------------------------------------------ charts

def live_overhead(live: dict, out: Path) -> Path:
    phases = ["baseline", "tracing only", "B-SCAF"]
    names = ["No tracing", "eBPF tracing only", "B-SCAF capture\n+ 3 witnesses"]
    overview = live["overview"]
    medians = [overview[phase]["workload_seconds"] for phase in phases]
    fig, ax = plt.subplots(figsize=(WIDTH, 2.5))
    _vbars(ax, names, medians, [BLUE] * 3, lambda v: "", ymax=max(medians) * 1.35, thickness=0.42)
    for index, phase in enumerate(phases):
        runs = [run["seconds"] for run in live["phases"][phase]]
        offsets = [-0.07, 0.0, 0.07][: len(runs)]
        ax.scatter([index + offset for offset in offsets], runs, s=16, color=INK, edgecolor="white", linewidth=1.2, zorder=5)
        slowdown = overview[phase]["slowdown_percent"]
        label = f"{medians[index]:.2f} s" + ("" if phase == "baseline" else f"  ({slowdown:+.0f}%)")
        ax.text(index, max(runs) + max(medians) * 0.04, label, ha="center", va="bottom", color=INK, fontsize=8)
    ax.set_ylabel("Workload time (s)")
    ax.set_title(f"Live workload time ({live['iterations']:,} iterations): median bar, individual runs as dots")
    return _save(fig, out)


LABELS = {"plain log": "Plain log", "hash chain only": "Hash chain only", "plain log + fsync/100": "Plain log + fsync per 100"}


def _bench(real: dict) -> list[dict]:
    return [{**row, "label": LABELS.get(row["label"], row["label"])} for row in real.get("bench", {}).get("results", [])]


def _is_baseline(row: dict) -> bool:
    return row["mode"] != "bscaf"


def replay_throughput(real: dict, out: Path) -> Path:
    rows = _bench(real)
    fig, ax = plt.subplots(figsize=(WIDTH, 0.34 * len(rows) + 1.0))
    _hbars(ax, [row["label"] for row in rows], [row["events_per_second"] for row in rows],
           [ORANGE if _is_baseline(row) else BLUE for row in rows], lambda v: f"{v:,.0f}")
    ax.xaxis.set_major_formatter(lambda value, _: _compact(value))
    ax.set_xlabel("Events per second (one core)")
    ax.set_title(f"Ingest throughput, {real['bench']['events']:,} replayed events")
    ax.legend(handles=[Patch(color=ORANGE, label="Baseline logging"), Patch(color=BLUE, label="B-SCAF")], loc="lower right")
    return _save(fig, out)


def attack_grid(real: dict, out: Path) -> Path:
    rows = real["attacks"]
    fig, ax = plt.subplots(figsize=(WIDTH, 0.3 * len(rows) + 1.1))
    columns = ["Local verification", "With 3 witnesses"]
    fills = {"fail": BLUE, "pass": NEUTRAL, "partial": ORANGE}
    words = {"fail": "Detected", "pass": "Pass", "partial": "Partial"}
    for row_index, row in enumerate(rows):
        y = len(rows) - 1 - row_index
        for column_index, key in enumerate(("local_verdict", "witness_verdict")):
            verdict = row[key]
            ax.add_patch(plt.Rectangle((column_index + 0.04, y - 0.42), 0.92, 0.84, facecolor=fills[verdict], edgecolor="white", linewidth=2))
            ax.text(column_index + 0.5, y, words[verdict], ha="center", va="center", fontsize=8,
                    color="white" if verdict == "fail" else INK, fontweight="bold" if verdict == "fail" else "normal")
        ax.text(2.12, y, "as designed" if row["as_expected"] else "UNEXPECTED", va="center", fontsize=8, color=INK_2)
    ax.set_xlim(0, 2.75)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_yticks(range(len(rows)), [row["description"] for row in rows][::-1])
    ax.set_xticks([0.5, 1.5], columns)
    ax.xaxis.tick_top()
    ax.tick_params(length=0)
    for side in ("left", "bottom", "top"):
        ax.spines[side].set_visible(False)
    ax.set_title("Attack scenarios: verdict without and with witnesses", pad=24)
    ax.legend(handles=[Patch(color=BLUE, label="Detected (verdict fail)"), Patch(color=NEUTRAL, label="Pass"), Patch(color=ORANGE, label="Partial evidence")],
              loc="upper center", bbox_to_anchor=(0.45, -0.02), ncol=3)
    return _save(fig, out)


def build_all(real: dict, live: dict, out_dir: Path) -> dict[str, Path]:
    """The three essential result charts: live overhead, attack detection and throughput."""
    return {
        "live_overhead": live_overhead(live, out_dir / "chart-live-overhead.png"),
        "attacks": attack_grid(real, out_dir / "chart-attacks.png"),
        "throughput": replay_throughput(real, out_dir / "chart-throughput.png"),
    }
