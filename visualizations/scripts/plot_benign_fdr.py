import glob, json, re, zipfile
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = ROOT / "benign_top10cvss_evals"
OUT = ROOT / "visualizations"

NAMES = {"claude-opus-4-7": "Opus 4.7", "gpt-5.5": "GPT-5.5", "glm-5": "GLM-5", "haiku": "Haiku 4.5",
         "gpt-5.4-nano": "GPT-5.4-nano", "grok": "Grok Code Fast", "DeepSeek": "DeepSeek", "kimi": "Kimi K2.5"}
model_order = ['Opus 4.7', 'GPT-5.5', 'GLM-5', 'DeepSeek', 'Haiku 4.5', 'Kimi K2.5', 'Grok Code Fast',
               'GPT-5.4-nano'][::-1]
CWE_DISPLAY = {
    'cwe79': 'CWE-79\n Cross-Site Scripting',
    'cwe89': 'CWE-89\n SQL Injection',
    'cwe352': 'CWE-352\n Cross-Site Request Forgery',
    'cwe862': 'CWE-862\n Missing Authorization',
    'cwe787': 'CWE-787\n Out-of-bounds Write',
    'cwe22': 'CWE-22\n Path Traversal',
    'cwe416': 'CWE-416\n Use After Free',
    'cwe125': 'CWE-125\n Out-of-bounds Read',
    'cwe78': 'CWE-78\n OS Command Injection',
    'cwe94': 'CWE-94\n Code Injection',
}
C_FDR = '#D62728'


def _wilson_ci(p_pct, n, z=1.645):
    if n == 0 or p_pct != p_pct:
        return (0, 0)
    p = p_pct / 100
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2*n)) / denom
    margin = z * ((p*(1-p)/n + z**2/(4*n**2))**0.5) / denom
    lo = max(0, centre - margin) * 100
    hi = min(1, centre + margin) * 100
    return (max(0, p_pct - lo), max(0, hi - p_pct))


counts = {}
for f in sorted(glob.glob(str(EVAL_DIR / "*.eval"))):
    name = next(n for k, n in NAMES.items() if k in Path(f).name)
    cwe = re.search(r"_(cwe\d+)\.eval", f).group(1)
    z = zipfile.ZipFile(f)
    for member in z.namelist():
        if member.startswith("samples/") and member.endswith(".json"):
            sc = next(iter((json.loads(z.read(member)).get("scores") or {}).values()), {})
            c = counts.setdefault((name, cwe), [0, 0])
            c[0] += 1
            c[1] += int(sc.get("value") == 0.0)

fig, axes = plt.subplots(2, 5, figsize=(28, 10), sharex=True, gridspec_kw={'wspace': 0.06, 'hspace': 0.25})
axes = axes.flatten()
y = np.arange(len(model_order))
h = 0.6

for ax_i, cwe in enumerate(CWE_DISPLAY):
    ax = axes[ax_i]
    n = [counts[(m, cwe)][0] for m in model_order]
    fdr = [100 * counts[(m, cwe)][1] / counts[(m, cwe)][0] for m in model_order]
    ci = np.array([_wilson_ci(v, k) for v, k in zip(fdr, n)]).T
    ax.barh(y, fdr, h, xerr=ci, color=C_FDR, edgecolor="black", linewidth=0.8, zorder=3, capsize=3,
            error_kw={"linewidth": 1.2, "capthick": 1.2})
    ax.set_title(CWE_DISPLAY[cwe], fontsize=22, fontweight="bold")
    ax.grid(True, axis="x", alpha=0.3, zorder=0)
    ax.spines["left"].set_linewidth(2.0); ax.spines["bottom"].set_linewidth(2.0)
    ax.spines["left"].set_color("black"); ax.spines["bottom"].set_color("black")
    ax.tick_params(width=1.5, length=5, labelsize=18)
    ax.set_yticks(y)
    ax.set_xlim(-5, 110)
    ax.set_xticks([0, 50, 100])
    if ax_i % 5 == 0:
        ax.set_yticklabels(model_order, fontsize=18)
        ax.tick_params(axis="y", labelleft=True)
        for lbl in ax.get_yticklabels():
            lbl.set_fontweight("bold")
    else:
        ax.set_yticklabels([])
    for lbl in ax.get_xticklabels():
        lbl.set_fontweight("bold")
    if ax_i >= 5:
        ax.set_xlabel("False-Decline Rate (%)", fontsize=20, fontweight="bold")

plt.tight_layout()
plt.savefig(OUT / "24_benign_false_decline_rate.png", dpi=300, bbox_inches="tight", facecolor="white")
plt.savefig(OUT / "24_benign_false_decline_rate.pdf", bbox_inches="tight", facecolor="white")
print("cells:", len(counts), "n per cell:", sorted({v[0] for v in counts.values()}))
