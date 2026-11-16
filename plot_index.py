"""2D Index -- Contribution vs Security.

Static rendering of the scatter chart shown at https://cybersimplifier.com/index:
X is the Contribution & Usage score, Y the Security & Issues score, and the
colour marks one of the three clusters of similar projects.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.text import Text  # noqa: E402

from omsindex_math import CLUSTER_KEYS, CLUSTER_LABELS, INDEX_VERSION  # noqa: E402

CLUSTER_COLORS = {
    "needs-attention": "#fb923c",
    "promising": "#22d3ee",
    "mature": "#84cc16",
}
BACKGROUND = "#0b1220"
PANEL = "#0f172a"
GRID = "#1e293b"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"

# Candidate label offsets in points; the first one without a collision wins.
_OFFSETS = (
    (7, 5, "left", "bottom"), (7, -5, "left", "top"), (-7, 5, "right", "bottom"), (-7, -5, "right", "top"),
    (0, 9, "center", "bottom"), (0, -9, "center", "top"), (12, 0, "left", "center"), (-12, 0, "right", "center"),
    (12, 14, "left", "bottom"), (12, -14, "left", "top"), (-12, 14, "right", "bottom"), (-12, -14, "right", "top"),
    (0, 20, "center", "bottom"), (0, -20, "center", "top"),
    (24, 22, "left", "bottom"), (-24, -22, "right", "top"), (24, -22, "left", "top"), (-24, 22, "right", "bottom"),
    (0, 32, "center", "bottom"), (0, -32, "center", "top"),
    (36, 34, "left", "bottom"), (-36, -34, "right", "top"), (36, -34, "left", "top"), (-36, 34, "right", "bottom"),
    (0, 46, "center", "bottom"), (0, -46, "center", "top"),
    (50, 48, "left", "bottom"), (-50, -48, "right", "top"), (50, -48, "left", "top"), (-50, 48, "right", "bottom"),
)


def _axis_range(values: Sequence[float]) -> tuple:
    """Fit the axis to the data with padding, clamped to the 0-100 score range."""
    low, high = min(values), max(values)
    padding = max(4.0, (high - low) * 0.08)
    return max(0.0, low - padding), min(100.0, high + padding)


def _place_labels(ax, fig, projects: List[dict]) -> None:
    """Greedy label placement: best-ranked projects pick their spot first."""
    renderer = fig.canvas.get_renderer()
    axes_box = ax.get_window_extent(renderer)
    marker_half = 5 * fig.dpi / 72
    markers = [tuple(ax.transData.transform((p["indexPart1"], p["indexPart2"]))) for p in projects]
    placed = []

    def annotate(project, dx, dy, ha, va):
        far = abs(dx) > 12 or abs(dy) > 12
        return ax.annotate(
            project["name"],
            (project["indexPart1"], project["indexPart2"]),
            xytext=(dx, dy), textcoords="offset points", ha=ha, va=va,
            fontsize=7.5, color=TEXT, zorder=4,
            arrowprops={"arrowstyle": "-", "color": MUTED, "lw": 0.5, "shrinkA": 0, "shrinkB": 4} if far else None,
        )

    def text_box(annotation):
        # Text extent only (the annotation extent would include the leader line).
        annotation.update_positions(renderer)
        return Text.get_window_extent(annotation, renderer).expanded(1.04, 1.15)

    for project, own in sorted(zip(projects, markers), key=lambda item: item[0]["rank"]):
        best = None
        for candidate in _OFFSETS:
            annotation = annotate(project, *candidate)
            box = text_box(annotation)
            annotation.remove()
            outside = not (
                box.x0 >= axes_box.x0 and box.x1 <= axes_box.x1
                and box.y0 >= axes_box.y0 and box.y1 <= axes_box.y1
            )
            penalty = (
                20 * outside
                + 10 * sum(1 for other in placed if box.overlaps(other))
                + 4 * sum(
                    1 for mx, my in markers
                    if (mx, my) != own
                    and box.x0 - marker_half < mx < box.x1 + marker_half
                    and box.y0 - marker_half < my < box.y1 + marker_half
                )
            )
            if best is None or penalty < best[0]:
                best = (penalty, candidate)
            if penalty == 0:
                break
        placed.append(text_box(annotate(project, *best[1])))


def plot_2d_index(projects: List[dict], path, date: Optional[str] = None) -> Path:
    """Render the Contribution vs Security scatter chart to ``path`` (PNG)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(13, 8.2), dpi=160)
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(PANEL)

    xs = [p["indexPart1"] for p in projects]
    ys = [p["indexPart2"] for p in projects]
    ax.set_xlim(*_axis_range(xs))
    ax.set_ylim(*_axis_range(ys))

    ax.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)

    ax.scatter(
        xs, ys, s=95,
        c=[CLUSTER_COLORS.get(p.get("clusterKey"), MUTED) for p in projects],
        edgecolors=BACKGROUND, linewidths=1.2, alpha=0.95, zorder=3,
    )

    ax.set_xlabel("Contribution & Usage Score", color=TEXT, fontsize=11, labelpad=10)
    ax.set_ylabel("Security & Issues Score", color=TEXT, fontsize=11, labelpad=10)
    fig.suptitle(
        "2D Index — Contribution vs Security",
        color=TEXT, fontsize=17, fontweight="bold", x=0.065, y=0.965, ha="left",
    )
    subtitle = f"OMSIndex v{INDEX_VERSION} · {len(projects)} open-source security projects"
    if date:
        subtitle += f" · {date}"
    fig.text(0.065, 0.905, subtitle, color=MUTED, fontsize=10, ha="left")
    fig.text(0.985, 0.012, "cybersimplifier.com/index", color=MUTED, fontsize=8.5, ha="right")

    present = [key for key in CLUSTER_KEYS if any(p.get("clusterKey") == key for p in projects)]
    legend = ax.legend(
        handles=[
            Line2D([], [], marker="o", linestyle="", markersize=8, markerfacecolor=CLUSTER_COLORS[key],
                   markeredgecolor=BACKGROUND, label=CLUSTER_LABELS[key])
            for key in present
        ],
        title="Three clusters of similar projects",
        loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=len(present) or 1,
        frameon=False, fontsize=9.5, title_fontsize=9.5, labelcolor=TEXT, handletextpad=0.3, columnspacing=2.2,
    )
    legend.get_title().set_color(MUTED)

    fig.subplots_adjust(left=0.065, right=0.985, top=0.875, bottom=0.17)
    fig.canvas.draw()
    _place_labels(ax, fig, projects)

    fig.savefig(path, facecolor=fig.get_facecolor())
    plt.close(fig)
    return path
