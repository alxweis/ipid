import os
import pickle
import random
import unittest
from collections import defaultdict
from enum import Enum

import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from matplotlib.transforms import Bbox

from core import TEST_RESULTS
from core.classifier import IPIDSequence, get_pattern, Pattern, pattern_generation_map

FORCE_CREATE_DATASET = False


class Dataset(Enum):
    IDEAL = "Ideal"
    LOSSY = "Lossy"
    REORDER = "Reorder"


def create_dataset(dataset: Dataset, sequence_length: int, sequence_count_per_pattern: int):
    if dataset == Dataset.IDEAL:
        create_ideal_dataset(sequence_length, sequence_count_per_pattern)
    elif dataset == Dataset.LOSSY:
        create_lossy_dataset(sequence_length, sequence_count_per_pattern)
    elif dataset == Dataset.REORDER:
        create_reorder_dataset(sequence_length, sequence_count_per_pattern)


def create_ideal_dataset(sequence_length: int, sequence_count_per_pattern: int):
    data = defaultdict(list)

    for true_pattern, generator in pattern_generation_map.items():
        if generator is None:
            continue

        for _ in range(sequence_count_per_pattern):
            seq = generator(sequence_length)
            data[true_pattern].append(seq)

    os.makedirs(TEST_RESULTS, exist_ok=True)
    with open(os.path.join(TEST_RESULTS, f"ideal_cm_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_lossy_dataset(sequence_length: int, sequence_count_per_pattern: int):
    data = defaultdict(list)

    for true_pattern, generator in pattern_generation_map.items():
        if generator is None:
            continue

        for _ in range(sequence_count_per_pattern):
            seq = generator(sequence_length).s.sequence.tolist()

            # Remove 20% of sequence
            k = int(len(seq) * 0.2)
            indices_to_remove = set(random.sample(range(len(seq)), k))
            lossy_seq = [x for i, x in enumerate(seq) if i not in indices_to_remove]

            data[true_pattern].append(IPIDSequence(lossy_seq))

    os.makedirs(TEST_RESULTS, exist_ok=True)
    with open(os.path.join(TEST_RESULTS, f"lossy_cm_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_reorder_dataset(sequence_length: int, sequence_count_per_pattern: int):
    data = defaultdict(list)

    for true_pattern, generator in pattern_generation_map.items():
        if generator is None:
            continue

        for _ in range(sequence_count_per_pattern):
            seq = generator(sequence_length).s.sequence.tolist()

            # Reorder 20% of sequence
            reorder_seq = seq.copy()
            k = int(len(reorder_seq) * 0.2)
            reorder_indices = random.sample(range(len(reorder_seq)), k)

            values = [reorder_seq[i] for i in reorder_indices]
            if k == 2:
                values = [values[1], values[0]]
            else:
                random.shuffle(values)

            for i, idx in enumerate(reorder_indices):
                reorder_seq[idx] = values[i]

            data[true_pattern].append(IPIDSequence(reorder_seq))

    os.makedirs(TEST_RESULTS, exist_ok=True)
    with open(os.path.join(TEST_RESULTS, f"reorder_cm_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_confusion_matrix(
        dataset: Dataset,
        sequence_length: int,
        sequence_count_per_pattern: int,
) -> bool:
    # --- Pfade ---
    base_name = f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}"
    dataset_fp = os.path.join(TEST_RESULTS, f"{base_name}.pkl")
    info_fp = os.path.join(TEST_RESULTS, f"{base_name}_info.txt")
    heatmap_fp = os.path.join(TEST_RESULTS, f"{base_name}_heatmap.pkl")
    plot_fp = os.path.join(TEST_RESULTS, f"{base_name}_acm.pdf")

    # info.txt leeren
    open(info_fp, "w").close()

    def log(msg: str = ""):
        print(msg)
        with open(info_fp, "a") as f:
            f.write(msg + "\n")

    # --- Klassen-Mapping (Reihenfolge = Achsen-Reihenfolge der Heatmap) ---
    # raw_name -> display_name
    display_map = {
        "Mirror": "Reflection",
        "Constant": "Constant",
        "Single": "Single",
        "Per-Con": "Per-Connection",
        "Per-Dst": "Per-Destination",
        "Per-Bucket": "Per-Bucket",
        "Per-CPU": "Multi",
        "Random": "Random",
        "Fallback": "Unclassified",
    }
    order_index = {k: i for i, k in enumerate(display_map)}

    # --- Cache: wenn Heatmap-Daten existieren und nicht FORCE -> direkt plotten ---
    if os.path.exists(heatmap_fp) and not FORCE_CREATE_DATASET:
        log(f"Loading cached heatmap data from {heatmap_fp}")
        with open(heatmap_fp, "rb") as f:
            cache = pickle.load(f)
        df_rel = cache["df_rel"]
        metrics = cache["metrics"]
        log(f"Accuracy:        {metrics['accuracy']:.4%}")
        log(f"Macro Precision: {metrics['macro_precision']:.4%}")
        log(f"Macro Recall:    {metrics['macro_recall']:.4%}")
        log(f"Macro F1:        {metrics['macro_f1']:.4%}")
        _plot_confusion_matrix(df_rel, plot_fp)
        return True

    # --- Dataset laden (ggf. erzeugen) ---
    if not os.path.exists(dataset_fp) or FORCE_CREATE_DATASET:
        log("Creating dataset...")
        create_dataset(dataset, sequence_length, sequence_count_per_pattern)

    with open(dataset_fp, "rb") as f:
        data = pickle.load(f)

    log(f"### {dataset.value.upper()} DATASET ###\n")

    # --- Confusion-Matrix aufbauen ---
    is_mass_scan = sequence_length >= 80
    confusion_matrix = defaultdict(lambda: defaultdict(int))

    for true_pattern, ip_id_sequences in data.items():
        correct = 0
        total = len(ip_id_sequences)
        misclassified = defaultdict(int)

        for seq in ip_id_sequences:
            predicted_pattern = get_pattern(seq, is_mass_scan)
            if true_pattern.value == predicted_pattern.value:
                correct += 1
            else:
                misclassified[predicted_pattern.value] += 1

        log(
            f"{true_pattern.value}: total={total} "
            f"correct={correct} incorrect={total - correct} "
            f"recall={correct / total:.4f}"
        )
        log(f"Misclassification breakdown: {dict(misclassified)}")

        confusion_matrix[true_pattern.value][true_pattern.value] += correct
        for predicted, count in misclassified.items():
            confusion_matrix[true_pattern.value][predicted] += count

    # --- Metriken berechnen ---
    precisions, recalls, f1s = [], [], []
    overall_correct = overall_total = 0

    log("\n=== Overall Evaluation ===")
    for true_label, inner_dict in confusion_matrix.items():
        # Spezialfall: Per-CPU und Random bei non-mass-scan -> als Fallback gezählt
        if not is_mass_scan and true_label in (Pattern.PER_CPU.value, Pattern.RANDOM.value):
            tp = confusion_matrix[true_label][Pattern.FALLBACK.value]
            fp = sum(
                confusion_matrix[other][true_label]
                for other in confusion_matrix
                if other != Pattern.FALLBACK.value
            )
        else:
            tp = confusion_matrix[true_label][true_label]
            fp = sum(
                confusion_matrix[other][true_label]
                for other in confusion_matrix
                if other != true_label
            )
        fn = sum(confusion_matrix[true_label].values()) - tp

        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0

        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

        overall_correct += tp
        overall_total += tp + fn

    accuracy = overall_correct / overall_total
    macro_precision = sum(precisions) / len(precisions)
    macro_recall = sum(recalls) / len(recalls)
    macro_f1 = sum(f1s) / len(f1s)

    log()
    log(f"Accuracy:        {accuracy:.4%}")
    log(f"Macro Precision: {macro_precision:.4%}")
    log(f"Macro Recall:    {macro_recall:.4%}")
    log(f"Macro F1:        {macro_f1:.4%}")
    log()

    # --- DataFrame mit relativen Werten aufbauen ---
    true_labels = sorted(confusion_matrix.keys(), key=lambda c: order_index.get(c, 999))
    predicted_labels = sorted(
        {p for inner in confusion_matrix.values() for p in inner},
        key=lambda c: order_index.get(c, 999),
    )

    cm = np.array([
        [confusion_matrix[t][p] for p in predicted_labels]
        for t in true_labels
    ], dtype=float)
    cm_rel = cm / cm.sum(axis=1, keepdims=True) * 100

    df_rel = pd.DataFrame(
        cm_rel,
        index=[display_map.get(l, l) for l in true_labels],
        columns=[display_map.get(l, l) for l in predicted_labels],
    )

    # --- Heatmap-Daten cachen ---
    metrics = {
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
    }
    with open(heatmap_fp, "wb") as f:
        pickle.dump({"df_rel": df_rel, "metrics": metrics}, f)
    log(f"Heatmap data saved to {heatmap_fp}")

    # --- Plot ---
    _plot_confusion_matrix(df_rel, plot_fp)
    return True


def _plot_confusion_matrix(df_rel: pd.DataFrame, out_path: str):
    """Zeichnet die Confusion-Matrix als ACM-Style Heatmap."""
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman", "Times New Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "pdf.fonttype": 42,
    })

    annot_matrix = df_rel.map(lambda v: "-" if v < 0.05 else f"{v:.1f}")

    fig, ax = plt.subplots(figsize=(5.2, 2.5))
    sns.heatmap(
        df_rel,
        ax=ax,
        annot=annot_matrix,
        fmt="",
        cmap="Blues",
        vmin=0, vmax=100,
        linewidths=0.4,
        linecolor="white",
        cbar_kws={"label": "Percentage [%]"},
    )

    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color("black")

    cbar = ax.collections[0].colorbar
    cbar.outline.set_linewidth(0.5)
    cbar.outline.set_edgecolor("black")
    cbar.ax.tick_params(width=0.5)

    ax.set_xlabel("Detected IP-ID\nSelection Strategy", labelpad=4)
    ax.set_ylabel("Generating IP-ID\nSelection Strategy", labelpad=4, y=0.5)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=30, ha="right")

    plt.tight_layout(pad=0.4)

    # Figure rendern, damit get_tightbbox korrekt arbeitet
    # fig.canvas.draw()
    # renderer = fig.canvas.get_renderer()
    # tight_bbox = fig.get_tightbbox(renderer)
    #
    # # Ränder manuell erweitern (in Zoll)
    # pad_top, pad_right, pad_bottom, pad_left = 0.25, 0.03, 0.03, 0.03
    # bbox_padded = Bbox.from_extents(
    #     tight_bbox.x0 - pad_left,
    #     tight_bbox.y0 - pad_bottom,
    #     tight_bbox.x1 + pad_right,
    #     tight_bbox.y1 + pad_top,
    #     )

    # plt.savefig(out_path, bbox_inches=bbox_padded, dpi=300)
    plt.savefig(out_path, bbox_inches="tight", pad_inches=0.05, dpi=300)
    plt.close(fig)


class ClassifierTests(unittest.TestCase):
    def test_classifier(self):
        # raw_seq = [5792, 44723, 18963, 20717, 58444, 13978, 19507, 55507, 58988, 7239, 32934, 48768, 6880, 24762, 46105,
        #            756, 20051, 42029, 59532, 18023, 33478, 59552, 7168, 35546, 20595, 11284, 60076, 22068, 47193, 39591,
        #            60620, 15585, 34310, 56858, 8256, 50375, 21683, 26113, 61164, 43636, 8800, 19630, 48281, 36897,
        #            22227, 12891, 61452, 54420, 35398, 6152, 48825, 65204, 22771, 41198, 35942, 10453, 49369, 27720,
        #            62540, 45243, 36486, 38504, 10432, 49288, 23603, 1276, 37030, 18543, 50201, 29327, 24147, 46594,
        #            50745, 16105, 38118, 57378, 11808, 50895, 64716, 37417, 12352, 6672, 25779, 58985, 12896, 52246, 13,
        #            45763, 52921, 15018, 40038, 8279, 27155, 43069, 40582, 60592, 54009, 53853, 1645, 64637]
        # seq = IPIDSequence(raw_seq)
        #
        # print(f"Even Inc: {chi2_test(seq.even.increments)}")
        # print(f"Odd Inc: {chi2_test(seq.odd.increments)}")
        # clusters: list[dict[int, np.int32]] = get_clusters(seq.full.sequence, max_diff=MULTI_GLOBAL_CLUSTER_MAX_INC)
        # for i, cluster in enumerate(clusters):
        #     if len(cluster) < 20:
        #         continue
        #     cluster_sequence = np.array(list(cluster.values()))
        #     print(f"Cluster {i}: {chi2_test(cluster_sequence)}")

        # print(get_pattern(seq, is_mass_scan=True).value)
        # seq_raw = "[  233 26180  6417 56642 48544 46343 33530 24928 24847 20023]"
        # seq_array = np.fromstring(seq_raw.strip("[]"), sep=" ")
        # seq = IPIDSequence(seq_array)
        # print(seq.full.sequence)
        # print(seq.full.increments)
        # print(p_value(values=seq.full.sequence, start_point=1, stop_point=MAX_IP_ID))
        # print(f"Increments: {seq.full.increments}")
        # print(f"Clusters: {len(get_clusters(seq.full.sequence))}")
        # print(seq.full.is_bounded_increasing(lower_inc_bound=1, upper_inc_bound=MAX_INC))
        # print(seq.even.is_bounded_increasing(lower_inc_bound=1, upper_inc_bound=MAX_INC))
        # print(seq.odd.is_bounded_increasing(lower_inc_bound=1, upper_inc_bound=MAX_INC))
        # print(seq.full.has_uniform_increments())
        # print(seq.even.has_uniform_increments())
        # print(seq.odd.has_uniform_increments())

        # total_sequences = 10000
        # sequence_length = 80
        # points = [(15, 300), (15, 500), (15, 700), (15, 900)]
        #
        # for max_clusters, max_inc in points:
        #     correct_count = 0
        #     for _ in range(total_sequences):
        #         sequence = multi_global_ip_id_sequence(sequence_length, max_clusters, max_inc)
        #         if is_multi_global(sequence, max_clusters, max_inc):
        #             correct_count += 1
        #     print(f"Precision (max_clusters={max_clusters}, max_inc={max_inc}): {correct_count/total_sequences}")

        # hist = [50, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # chi2, p_chi2 = chisquare(hist)
        # print(p_chi2)

        # seq = IPIDSequence(
        #     np.array([0, 0, 0, 0, 19908, 44119, 6203, 14284, 19909, 44120, 6204, 14285, 19910, 44121, 6205, 14286]))
        # print(get_pattern(seq, is_mass_scan=False, get_all=False))

        sequence_count_per_pattern = 100_000

        self.assertTrue(create_confusion_matrix(Dataset.IDEAL, 16, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.LOSSY, 16, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.REORDER, 16, sequence_count_per_pattern))

        self.assertTrue(create_confusion_matrix(Dataset.IDEAL, 80, sequence_count_per_pattern))
        self.assertTrue(create_confusion_matrix(Dataset.LOSSY, 80, sequence_count_per_pattern))
        self.assertTrue(create_confusion_matrix(Dataset.REORDER, 80, sequence_count_per_pattern))


# class ConfigTests(unittest.TestCase):
#


if __name__ == '__main__':
    unittest.main()
