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

from core import TEST_RESULTS
from core.classifier import IPIDSequence, get_pattern, Pattern, pattern_generation_map, is_reflection, \
    multi_global_ip_id_sequence, is_multi_global

FORCE_CREATE_DATASET = True


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
            seq = generator(sequence_length).full.sequence.tolist()

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
            seq = generator(sequence_length).full.sequence.tolist()

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


def create_confusion_matrix(dataset: Dataset, sequence_length: int, sequence_count_per_pattern: int) -> bool:
    dataset_fp = os.path.join(TEST_RESULTS,
                              f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}.pkl")
    if not os.path.exists(dataset_fp) or FORCE_CREATE_DATASET:
        print("Creating dataset...")
        create_dataset(dataset, sequence_length, sequence_count_per_pattern)

    with open(dataset_fp, "rb") as f:
        data = pickle.load(f)

    print(f"### {dataset.value.upper()} DATASET ###\n")

    is_mass_scan = sequence_length >= 80
    overall_correct = 0
    overall_total = 0
    confusion_matrix = defaultdict(lambda: defaultdict(int))

    for true_pattern, ip_id_sequences in data.items():
        correct_classifications = 0
        sequence_count_per_pattern = len(ip_id_sequences)
        misclassified_counts = defaultdict(int)

        for seq in ip_id_sequences:
            predicted_pattern = get_pattern(seq, is_mass_scan)

            if (true_pattern.value == predicted_pattern.value or
                    (not is_mass_scan and true_pattern in [Pattern.MULTI_GLOBAL, Pattern.RANDOM] and predicted_pattern == Pattern.FALLBACK)):
                correct_classifications += 1
            else:
                # print(f"'{",".join(map(str, seq.full.sequence.tolist()))}' is classified as {predicted_pattern} (real: {true_pattern})")
                misclassified_counts[predicted_pattern.value] += 1

            # if true_pattern == Pattern.RANDOM and predicted_pattern == Pattern.FALLBACK:
            #     print(
            #         f"{seq.full.sequence} should be {true_pattern.value} but is {predicted_pattern.value}")

        incorrect_classifications = sequence_count_per_pattern - correct_classifications
        print(
            f"{true_pattern.value}: total={sequence_count_per_pattern} "
            f"correct={correct_classifications} incorrect={incorrect_classifications} "
            f"recall={correct_classifications / sequence_count_per_pattern:.4f}"
        )
        print(f"Misclassification breakdown: {dict(misclassified_counts)}")

        overall_correct += correct_classifications
        overall_total += sequence_count_per_pattern

        # Update confusion matrix
        confusion_matrix[true_pattern.value][true_pattern.value] += correct_classifications
        for predicted, count in misclassified_counts.items():
            confusion_matrix[true_pattern.value][predicted] += count

    # Confusion matrix and evaluation
    true_labels = []
    predicted_labels = []

    precisions = []
    recalls = []
    f1s = []

    print(f"\n=== Overall Evaluation ===")

    for true_label, inner_dict in confusion_matrix.items():
        true_labels.append(true_label)

        tp = confusion_matrix[true_label][true_label]
        fn = sum(confusion_matrix[true_label].values()) - tp
        fp = sum(confusion_matrix[other][true_label] for other in confusion_matrix if other != true_label)
        precision = tp / (tp + fp) if tp + fp else 0
        precisions.append(precision)
        recall = tp / (tp + fn) if tp + fn else 0
        recalls.append(recall)
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        f1s.append(f1)
        print(f"{true_label}: Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}")

        for predicted_label, value in inner_dict.items():
            predicted_labels.append(predicted_label)

    print()

    accuracy = overall_correct / overall_total
    print(f"Accuracy: {accuracy:.4%}")
    macro_precision = sum(precisions) / len(precisions)
    print(f"Macro Precision: {macro_precision:.4%}")
    macro_recall = sum(recalls) / len(recalls)
    print(f"Macro Recall: {macro_recall:.4%}")
    macro_f1 = sum(f1s) / len(f1s)
    print(f"Macro F1: {macro_f1:.4%}")

    print()

    true_labels = sorted(set(true_labels), key=lambda x: list(Pattern).index(Pattern(x)))
    predicted_labels = sorted(set(predicted_labels), key=lambda x: list(Pattern).index(Pattern(x)))

    cm = np.array([[confusion_matrix[t][p] for p in predicted_labels] for t in true_labels])

    # ACM CCR Stil
    plt.rcParams.update({
        "font.family": "Times New Roman",
        "font.size": 11,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
    })

    cm_rel = cm / cm.sum(axis=1, keepdims=True) * 100
    df = pd.DataFrame(cm_rel, index=true_labels, columns=predicted_labels)

    plt.figure(figsize=(4.8, 2.8))
    ax = sns.heatmap(
        df,
        annot=True,
        fmt=".1f",
        cmap="Blues",
        cbar_kws={'label': 'Percentage [%]'},
        linewidths=0.4,
        linecolor='white'
    )

    ax.set_xlabel("Predicted Class", labelpad=4)
    ax.set_ylabel("True Class", labelpad=4)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=25, ha="center")

    # Schwarzer Rand
    for _, spine in ax.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.4)
    plt.savefig(
        os.path.join(TEST_RESULTS,
                     f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}_acm.pdf"),
        bbox_inches="tight", dpi=300
    )
    return True


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

        sequence_length = 10
        sequence_count_per_pattern = 100_000

        self.assertTrue(create_confusion_matrix(Dataset.IDEAL, sequence_length, sequence_count_per_pattern))
        self.assertTrue(create_confusion_matrix(Dataset.LOSSY, sequence_length, sequence_count_per_pattern))
        self.assertTrue(create_confusion_matrix(Dataset.REORDER, sequence_length, sequence_count_per_pattern))


# class ConfigTests(unittest.TestCase):
#


if __name__ == '__main__':
    unittest.main()
