import os
import pickle
import random
import unittest
from collections import defaultdict
from enum import Enum

import numpy as np
from matplotlib import pyplot as plt

from core import TEST_RESULTS
from core.classifier import IPIDSequence, get_pattern, Pattern, pattern_generation_map

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

    overall_correct = 0
    overall_total = 0
    confusion_matrix = defaultdict(lambda: defaultdict(int))

    for true_pattern, ip_id_sequences in data.items():
        correct_classifications = 0
        sequence_count_per_pattern = len(ip_id_sequences)
        misclassified_counts = defaultdict(int)

        for seq in ip_id_sequences:
            predicted_pattern = get_pattern(seq, is_mass_scan=sequence_length >= 80)

            if true_pattern.value == predicted_pattern.value:
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

    fig, ax = plt.subplots(figsize=(7, 5))

    ax.set_xticks(range(len(predicted_labels)), labels=predicted_labels, rotation=45, ha="right")
    ax.set_yticks(range(len(true_labels)), labels=true_labels)
    ax.set_xlabel("Predicted Class")
    ax.set_ylabel("True Class")

    row_sums = cm.sum(axis=1, keepdims=True)
    cm_rel = cm / row_sums

    im = ax.imshow(cm_rel * 100, cmap="Blues", vmin=0, vmax=100)
    cbar = ax.figure.colorbar(im, ax=ax)
    cbar.ax.set_ylabel("Percentage (%)", rotation=-90, va="bottom")

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm_rel[i, j] * 100
            ax.text(j, i, f"{val:.1f}", ha="center", va="center",
                    color="white" if val > 50 else "black")

    plt.tight_layout()
    plt.savefig(
        os.path.join(TEST_RESULTS, f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}.pdf"),
        dpi=300)
    return True


class ClassifierTests(unittest.TestCase):
    def test_classifier(self):
        # raw_seq = [49361, 58284, 55906, 63338, 31769, 58315, 58323, 55952, 49393, 55972, 55986, 31823, 49433, 55996,
        #            45652, 31871, 56009, 56023, 31893, 56044, 45678, 31929, 49522, 58455, 58465, 58483, 56074, 47116,
        #            31981, 47130, 49558, 47136, 56124, 32023, 47154, 56148, 58554, 32052, 49596, 32067, 47174, 61691,
        #            32090, 56190, 45734, 49687, 61722, 58615, 32141, 49712, 49734, 47235, 49747, 49757, 47262, 47266,
        #            61767, 32197, 61782, 32215, 32221, 47297, 45825, 32245, 61808, 49893, 49908, 63565, 47410, 32319,
        #            49949, 49961, 61881, 63587, 49988, 32351, 45891, 50033, 50041, 50063, 50088, 47495, 32411, 61939,
        #            45936, 47517, 32435, 61957, 50137, 63658, 61972, 63668, 47550, 63670, 47564, 50198, 61998, 47580,
        #            32536, 63692]
        # seq = IPIDSequence(raw_seq)
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

        sequence_length = 100
        sequence_count_per_pattern = 100000

        self.assertTrue(create_confusion_matrix(Dataset.IDEAL, sequence_length, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.LOSSY, sequence_length, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.REORDER, sequence_length, sequence_count_per_pattern))


# class ConfigTests(unittest.TestCase):
#


if __name__ == '__main__':
    unittest.main()
