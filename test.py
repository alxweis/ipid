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
from core.utils import config


def classify_reflection_ip_id_sequence() -> dict[str, list[Pattern]]:
    predicted_patterns: dict[str, list[Pattern]] = {}
    for method, request_count in [("SEQ", config.b2b_request_count), ("B2B", config.seq_request_count)]:
        seq = [config.reflection_send_ip_ids[i % len(config.reflection_send_ip_ids)] for i in range(request_count)]
        ip_id_sequence = IPIDSequence(seq)

        patterns: list[Pattern] = get_pattern(ip_id_sequence, get_all=True)
        print(
            f"{method}: {ip_id_sequence.full.sequence} => predicted [{", ".join([p.value for p in patterns])}]")
        predicted_patterns[method] = patterns

    return predicted_patterns


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
        for _ in range(sequence_count_per_pattern):
            seq = generator(sequence_length)
            data[true_pattern].append(seq)

    os.makedirs(TEST_RESULTS, exist_ok=True)
    with open(os.path.join(TEST_RESULTS, f"ideal_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_lossy_dataset(sequence_length: int, sequence_count_per_pattern: int):
    data = defaultdict(list)

    for true_pattern, generator in pattern_generation_map.items():
        for _ in range(sequence_count_per_pattern):
            seq = generator(sequence_length).full.sequence.tolist()

            # Remove 20% of sequence
            k = int(len(seq) * 0.2)
            indices_to_remove = set(random.sample(range(len(seq)), k))
            lossy_seq = [x for i, x in enumerate(seq) if i not in indices_to_remove]

            data[true_pattern].append(IPIDSequence(lossy_seq))

    os.makedirs(TEST_RESULTS, exist_ok=True)
    with open(os.path.join(TEST_RESULTS, f"lossy_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_reorder_dataset(sequence_length: int, sequence_count_per_pattern: int):
    data = defaultdict(list)

    for true_pattern, generator in pattern_generation_map.items():
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
    with open(os.path.join(TEST_RESULTS, f"reorder_{sequence_length}_{sequence_count_per_pattern}.pkl"), "wb") as f:
        pickle.dump(data, f)


def create_confusion_matrix(dataset: Dataset, sequence_length: int, sequence_count_per_pattern: int) -> bool:
    dataset_fp = os.path.join(TEST_RESULTS,
                              f"{dataset.value.lower()}_{sequence_length}_{sequence_count_per_pattern}.pkl")
    if not os.path.exists(dataset_fp):
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
            predicted_pattern = get_pattern(seq)

            if true_pattern.value == predicted_pattern.value:
                correct_classifications += 1
            else:
                misclassified_counts[predicted_pattern.value] += 1

            if true_pattern == Pattern.MULTI_GLOBAL and predicted_pattern != Pattern.MULTI_GLOBAL:
                print(f"{seq.full.sequence} should be {true_pattern.value} but is {predicted_pattern.value}")

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

    # Final evaluation
    accuracy = overall_correct / overall_total
    print(f"\n=== Overall Evaluation ===")
    print(f"Accuracy: {accuracy:.4%}")

    for label in confusion_matrix:
        tp = confusion_matrix[label][label]
        fn = sum(confusion_matrix[label].values()) - tp
        fp = sum(confusion_matrix[other][label] for other in confusion_matrix if other != label)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        print(f"{label}: precision={precision:.4f}, recall={recall:.4f}, f1={f1:.4f}")

    print()

    # Save confusion matrix
    labels = sorted(confusion_matrix.keys())
    cm = np.array([[confusion_matrix[t][p] for p in labels] for t in labels])

    fig, ax = plt.subplots(figsize=(6, 5))

    ax.set_xticks(range(len(labels)), labels=labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels=labels)
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")

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
        os.path.join(TEST_RESULTS, f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}.png"),
        dpi=300)
    return True


class ClassifierTests(unittest.TestCase):
    def test_classifier(self):
        seq = [23334, 30695, 30795, 3165, 31451, 11146, 31517, 3187, 23338, 11202]
        ip_id_seq = IPIDSequence(seq)


        # sequence_length = 10
        # sequence_count_per_pattern = 100_000
        #
        # self.assertTrue(create_confusion_matrix(Dataset.IDEAL, sequence_length, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.LOSSY, sequence_length, sequence_count_per_pattern))
        # self.assertTrue(create_confusion_matrix(Dataset.REORDER, sequence_length, sequence_count_per_pattern))


class ConfigTests(unittest.TestCase):
    def test_reflection_ip_id_sequence(self):
        if config.detect_reflected_ip_ids:
            predicted_patterns = {"B2B": [Pattern.REFLECTION, Pattern.FALLBACK],
                                  "SEQ": [Pattern.REFLECTION, Pattern.FALLBACK]}
            self.assertEqual(classify_reflection_ip_id_sequence(), predicted_patterns)
        else:
            predicted_patterns = {"B2B": Pattern.FALLBACK, "SEQ": Pattern.FALLBACK}
            self.assertEqual(classify_reflection_ip_id_sequence(), predicted_patterns)


if __name__ == '__main__':
    unittest.main()
