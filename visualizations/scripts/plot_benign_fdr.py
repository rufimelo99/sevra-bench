import glob, json, re, zipfile
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = ROOT / "benign_top10cvss_evals"
OUT = ROOT / "visualizations"

NAMES = {"claude-opus-4-7": "Opus 4.7", "gpt-5.5": "GPT-5.5", "glm-5": "GLM-5", "haiku": "Haiku 4.5",
         "gpt-5.4-nano": "GPT-5.4-nano", "grok": "Grok Code Fast", "DeepSeek": "DeepSeek", "kimi": "Kimi K2.5"}
CWE_NAME = {"cwe79": "CWE-79 (XSS)", "cwe89": "CWE-89 (SQL injection)", "cwe352": "CWE-352 (CSRF)",
            "cwe862": "CWE-862 (missing authorization)", "cwe787": "CWE-787 (out-of-bounds write)",
            "cwe22": "CWE-22 (path traversal)", "cwe416": "CWE-416 (use-after-free)",
            "cwe125": "CWE-125 (out-of-bounds read)", "cwe78": "CWE-78 (OS command injection)",
            "cwe94": "CWE-94 (code injection)"}
C = "#1F77B4"


def wilson_ci(p_pct, n, z=1.645):
    p = p_pct / 100
    d = 1 + z**2 / n
    c = (p + z**2 / (2 * n)) / d
    m = z * ((p * (1 - p) / n + z**2 / (4 * n**2)) ** 0.5) / d
    return (max(0, p_pct - max(0, c - m) * 100), max(0, min(1, c + m) * 100 - p_pct))


by_model, by_cwe = {}, {}
for f in sorted(glob.glob(str(EVAL_DIR / "*.eval"))):
    name = next(n for k, n in NAMES.items() if k in Path(f).name)
    cwe = re.search(r"_(cwe\d+)\.eval", f).group(1)
    z = zipfile.ZipFile(f)
    for member in z.namelist():
        if member.startswith("samples/") and member.endswith(".json"):
            sc = next(iter((json.loads(z.read(member)).get("scores") or {}).values()), {})
            declined = int(sc.get("value") == 0.0)
            for d, k in ((by_model, name), (by_cwe, cwe)):
                c = d.setdefault(k, [0, 0])
                c[0] += 1
                c[1] += declined


def rows(d, label):
    return sorted(((label(k), 100 * dec / n, n) for k, (n, dec) in d.items()), key=lambda r: r[1])


fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(24, 7.4), gridspec_kw={"wspace": 0.55, "width_ratios": [10, 12]})
for ax, R, title in ((ax1, rows(by_model, lambda k: k), "(a) By review agent"),
                     (ax2, rows(by_cwe, lambda k: CWE_NAME[k]), "(b) By vulnerability class")):
    y = np.arange(len(R))
    vals = [r[1] for r in R]
    ci = np.array([wilson_ci(r[1], r[2]) for r in R]).T
    ax.barh(y, vals, 0.65, xerr=ci, color=C, edgecolor="black", linewidth=0.8, zorder=3, capsize=3,
            error_kw={"linewidth": 1.2, "capthick": 1.2})
    for yi, v, up in zip(y, vals, ci[1]):
        ax.text(v + up + 1.0, yi, f"{v:.0f}", va="center", fontsize=14, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels([r[0] for r in R], fontsize=15, fontweight="bold")
    ax.set_xlim(0, 50)
    ax.grid(True, axis="x", alpha=0.3, zorder=0)
    ax.set_facecolor("white")
    ax.spines["left"].set_linewidth(2.0)
    ax.spines["bottom"].set_linewidth(2.0)
    ax.spines["left"].set_color("black")
    ax.spines["bottom"].set_color("black")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(width=1.5, length=5, labelsize=17)
    for l in ax.get_xticklabels():
        l.set_fontweight("bold")
    ax.set_xlabel("False-Decline Rate (%)", fontsize=18, fontweight="bold")
    ax.set_title(title, fontsize=22, fontweight="bold")

plt.savefig(OUT / "24_benign_false_decline_rate.png", dpi=300, bbox_inches="tight", facecolor="white")
plt.savefig(OUT / "24_benign_false_decline_rate.pdf", bbox_inches="tight", facecolor="white")
for label, d in (("model", by_model), ("cwe", by_cwe)):
    print(label, {k: f"{100*v[1]/v[0]:.1f}% (n={v[0]})" for k, v in d.items()})
