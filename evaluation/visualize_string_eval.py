import os
import sys
import json
import math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = os.path.join(SCRIPT_DIR, "out")

# Optional: map raw binary names to prettier labels in titles.
# Edit this dictionary to customize display names.
BINARY_LABEL_MAP = {
    "frpc": "frpc",
    "css": "Countle Secured Storage (TISC)",
    "syntra": "Syntra Server (TISC)",
    "checksum.exe": "Checksum (Flare-On 11)"
}


def _compute_rate(key: str, version: str, payload: dict) -> float:
    data = payload.get(f"{version}totals") or {}
    if data and data.get("total", 0):
        return 100.0 * float(data.get(key, 0.0)) / float(data.get("total", 1))


def main():
    # Parse args: support single-binary mode and an 'all' mode (default if no args)
    # Usage:
    #   python visualize_string_eval.py <test_binary> [output_dir]
    #   python visualize_string_eval.py all [output_dir]
    #   python visualize_string_eval.py            -> defaults to 'all' mode with DEFAULT_OUT_DIR

    # Labels (configurable via env). Support three labels for: 9.1 initial, 9.2 initial, 9.2 plugin (final)
    default_labels = ["IDA 9.1", "IDA 9.2", "IDA 9.2 with\nAGAR plugin"]
    labels_env = os.environ.get("EVAL_BAR_LABELS")
    if labels_env:
        parts = [p.strip() for p in labels_env.split(",") if p.strip()]
        if len(parts) >= 3:
            labels_cfg = parts[:3]
        elif len(parts) == 2:
            labels_cfg = [default_labels[0], parts[0], parts[1]]
        else:
            labels_cfg = default_labels
    else:
        labels_cfg = default_labels
    label_91, label_92_init, label_92_final = labels_cfg[0], labels_cfg[1], labels_cfg[2]
    colors = ["#9467bd", "#1f77b4", "#2ca02c"]  # 9.1, 9.2, 9.2+plugin

    # Determine mode
    combined_mode = False
    test_binary = None
    if len(sys.argv) == 1:
        combined_mode = True
        output_dir = DEFAULT_OUT_DIR
    else:
        arg1 = sys.argv[1].strip().lower()
        if arg1 in ("all", "*", "--all"):
            combined_mode = True
            output_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT_DIR
        else:
            test_binary = sys.argv[1]
            output_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT_DIR

    os.makedirs(output_dir, exist_ok=True)


    # Load rates from each JSON
    entries = []
    for jf in ["frpc", "css", "syntra", "checksum.exe"]:
        jf = f"{jf}_string_eval_results.json"
        path = os.path.join(output_dir, jf)
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            rate_92_initial = _compute_rate("initial", "", payload)
            rate_92_final = _compute_rate("final", "", payload)
            rate_91_initial = _compute_rate("initial", "ida_91_", payload)
            # Derive test name from filename
            name = jf.replace("_string_eval_results.json", "")
            entries.append({
                "name": name,
                "rate_91": rate_91_initial,
                "rate_92_init": rate_92_initial,
                "rate_92_final": rate_92_final,
            })
            print(entries)
        except Exception as e:
            print(f"Failed to load {path}: {e}")

    n = len(entries)
    # Prefer a 2x2 layout for visual compactness. If there are more than 4
    # entries, fall back to additional rows while keeping 2 columns.
    cols = 2
    rows = 2
    if n > cols * rows:
        rows = math.ceil(n / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 4.0, rows * 3.5), squeeze=False)
    for idx, entry in enumerate(entries):
        r = idx // cols
        c = idx % cols
        ax = axes[r][c]
        vals = [entry["rate_91"], entry["rate_92_init"], entry["rate_92_final"]]
        positions = [-0.3, 0.0, 0.3]
        bars = ax.bar(positions, vals, color=colors, width=0.22)
        ax.set_xticks(positions)
        # Hide repeated category labels; use a single legend instead
        ax.set_xticklabels([])
        ax.tick_params(axis='x', labelbottom=False)
        ax.set_ylim(0, 100)
        # Restore y-axis only for leftmost subplot; hide otherwise
        if c == 0:
            ax.set_ylabel("Success rate (%)")
            ax.tick_params(axis='y', left=True, labelleft=True)
            ax.spines['left'].set_visible(True)
        else:
            ax.tick_params(axis='y', left=False, labelleft=False)
            ax.spines['left'].set_visible(False)
        # Show bottom border and x-axis ticks
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(True)
        ax.spines['bottom'].set_linewidth(1.0)
        ax.xaxis.set_ticks_position('bottom')
        # No label rotation
        ax.tick_params(axis='x', labelrotation=0)
        # Title moved to bottom (use xlabel) with optional mapping
        title_name = BINARY_LABEL_MAP.get(entry["name"], entry["name"])
        ax.set_xlabel(title_name, fontsize=10, labelpad=8)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, val + 1, f"{val:.1f}%", ha="center", va="bottom", fontsize=8)

    # Hide any unused subplots
    for j in range(n, rows * cols):
        r = j // cols
        c = j % cols
        axes[r][c].axis('off')

    # Add a single legend for all subplots (vertical right)
    legend_handles = [
        Patch(color=colors[0], label=label_91),
        Patch(color=colors[1], label=label_92_init),
        Patch(color=colors[2], label=label_92_final),
    ]
    fig.legend(handles=legend_handles, loc='center left', bbox_to_anchor=(0.77, 0.5), frameon=False, ncol=1)

    # Make horizontally compact and bottom borders appear continuous
    fig.subplots_adjust(wspace=0.12, hspace=0.35)
    fig.suptitle("String detection success rates", fontsize=12)
    # Leave space on the right for the legend
    fig.tight_layout(rect=[0.05, 0.03, 0.77, 0.97])
    out_path_all = os.path.join(output_dir, "string_eval_all.png")
    fig.savefig(out_path_all)
    print(f"Saved combined bar charts to: {out_path_all}")
    return


if __name__ == "__main__":
    main()
