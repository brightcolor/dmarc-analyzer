"""
Geometry for server-rendered SVG charts; the templates only draw what is computed here.
"""
import math
from dataclasses import dataclass
from datetime import date, timedelta

# Drawing constants of the chart layout (pixels in the SVG viewBox)
WIDTH = 720
HEIGHT = 220
LEFT = 44          # room for y-axis labels
RIGHT = 8
TOP = 12
BOTTOM = 28        # room for x-axis labels
BAR_GAP = 2        # surface gap between bars and between stacked segments
CORNER = 4         # rounded data end
X_LABEL_EVERY = 7  # label every n-th day


@dataclass
class Segment:
    path: str
    value: int


@dataclass
class DayBar:
    day: date
    x: float
    width: float
    passed: Segment | None
    failed: Segment | None
    total: int


@dataclass
class Tick:
    y: float
    label: str


@dataclass
class XLabel:
    x: float
    label: str


@dataclass
class DayChart:
    width: int
    height: int
    left: int
    right_edge: int
    baseline: float
    bars: list[DayBar]
    ticks: list[Tick]
    x_labels: list[XLabel]
    total_pass: int
    total_fail: int


def _nice_ceiling(value: int) -> int:
    """Round up to 1, 2 or 5 times a power of ten, so axis labels stay readable."""
    if value <= 0:
        return 1
    power = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 5, 10):
        if value <= step * power:
            return step * power
    return 10 * power


def _bar_path(x: float, y_top: float, width: float, height: float, rounded: bool) -> str:
    """Rectangle anchored at the bottom; only the top corners are rounded."""
    bottom = y_top + height
    r = min(CORNER, width / 2, height) if rounded else 0
    if r <= 0:
        return f"M{x:.1f} {bottom:.1f}V{y_top:.1f}H{x + width:.1f}V{bottom:.1f}Z"
    return (
        f"M{x:.1f} {bottom:.1f}V{y_top + r:.1f}Q{x:.1f} {y_top:.1f} {x + r:.1f} {y_top:.1f}"
        f"H{x + width - r:.1f}Q{x + width:.1f} {y_top:.1f} {x + width:.1f} {y_top + r:.1f}V{bottom:.1f}Z"
    )


def _format_count(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def day_chart(rows: list[dict], days: int, today: date) -> DayChart | None:
    """
    Stacked daily bars (passed at the baseline, failed on top) for the last `days` days.
    rows: [{"date": "YYYY-MM-DD", "pass": int, "fail": int}]; missing days count as zero.
    Returns None when there is nothing to draw.
    """
    by_day = {row["date"]: row for row in rows}
    first = today - timedelta(days=days - 1)
    series = []
    for offset in range(days):
        day = first + timedelta(days=offset)
        row = by_day.get(day.isoformat(), {})
        series.append((day, int(row.get("pass", 0) or 0), int(row.get("fail", 0) or 0)))

    total_pass = sum(p for _, p, _ in series)
    total_fail = sum(f for _, _, f in series)
    if total_pass + total_fail == 0:
        return None

    top_value = _nice_ceiling(max(p + f for _, p, f in series))
    plot_height = HEIGHT - TOP - BOTTOM
    baseline = TOP + plot_height
    slot = (WIDTH - LEFT - RIGHT) / days
    bar_width = max(slot - BAR_GAP, 1)

    def height_of(value: int) -> float:
        return value / top_value * plot_height

    bars = []
    for index, (day, passed, failed) in enumerate(series):
        x = LEFT + index * slot + BAR_GAP / 2
        pass_h = height_of(passed)
        fail_h = height_of(failed)
        pass_segment = fail_segment = None
        if passed:
            pass_segment = Segment(_bar_path(x, baseline - pass_h, bar_width, pass_h, rounded=not failed), passed)
        if failed:
            gap = BAR_GAP if passed else 0
            fail_top = baseline - pass_h - gap - fail_h
            fail_segment = Segment(_bar_path(x, fail_top, bar_width, fail_h, rounded=True), failed)
        bars.append(DayBar(day, x, bar_width, pass_segment, fail_segment, passed + failed))

    ticks = [Tick(baseline - height_of(v), _format_count(v)) for v in sorted({0, top_value // 2, top_value})]
    x_labels = [
        XLabel(bars[i].x + bar_width / 2, bars[i].day.strftime("%d.%m."))
        for i in range(len(bars) - 1, -1, -X_LABEL_EVERY)
    ]
    return DayChart(
        width=WIDTH, height=HEIGHT, left=LEFT, right_edge=WIDTH - RIGHT, baseline=baseline,
        bars=bars, ticks=ticks, x_labels=x_labels, total_pass=total_pass, total_fail=total_fail,
    )
