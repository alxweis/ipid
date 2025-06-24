import math
import os
import pickle
import random
from collections import defaultdict
from enum import Enum

import numpy as np
from matplotlib import pyplot as plt
from scipy.stats import chisquare

from core.utils import config

MAX_IP_ID = 65535
MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IP_ID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1


class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IP_ID + 1)

    def is_increasing(self) -> bool:
        return np.all((1 <= self.increments) & (self.increments <= MAX_INC))


class IPIDSequence:
    def __init__(self, sequence: list[int] | tuple[int, ...] | np.ndarray):
        arr = np.array(sequence, dtype=np.int32)
        self.full = IPIDSubsequence(arr)
        self.even = IPIDSubsequence(arr[0::2])
        self.odd = IPIDSubsequence(arr[1::2])

    def __len__(self):
        return len(self.full.sequence)


class Pattern(Enum):
    REFLECTION = "Reflection"
    CONSTANT = "Constant"
    GLOBAL = "Global"
    LOCAL_EQ1 = "Local (=1)"  # per-destination/ per-connection counter
    LOCAL_GE1 = "Local (≥1)"  # per-bucket counter
    MULTI_GLOBAL = "Multi Global"  # per-cpu counter when >1 cpu
    RANDOM = "Random"
    FALLBACK = "Fallback"
    NONE = "None"


# region Class Recognition
def nrm_entropy(values: np.ndarray) -> float:
    unique_values, counts = np.unique(values, return_counts=True)
    probabilities = counts / counts.sum()
    entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(unique_values))  # Max Entropy based on unique values
    return entropy / max_entropy


def get_clusters(values: np.ndarray):
    sorted_values = sorted(values)

    clusters = []
    current_cluster = [sorted_values[0]]

    for i in range(1, len(sorted_values)):
        # Check the difference to the previous number
        diff = sorted_values[i] - sorted_values[i - 1]

        if diff < 100:
            # Numbers belong to the same cluster
            current_cluster.append(sorted_values[i])
        else:
            # New cluster starts
            clusters.append(current_cluster)
            current_cluster = [sorted_values[i]]

    # Add the last cluster
    clusters.append(current_cluster)

    return clusters


def p_value(values: np.ndarray) -> float:
    intervals = len(values) // 2
    interval_edges = np.linspace(0, MAX_IP_ID + 1, intervals + 1)
    observed_frequencies, _ = np.histogram(values, bins=interval_edges)
    expected_frequencies = np.full(intervals, len(values) / intervals)

    chi2_stat, p = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
    return p


def is_uniform(values: np.ndarray, alpha: float) -> bool:
    return p_value(values) > alpha


def is_reflection(seq: IPIDSequence) -> bool:
    return all(ip_id == config.reflection_send_ip_ids[i % len(config.reflection_send_ip_ids)]
               for i, ip_id in enumerate(seq.full.sequence.tolist()))


def is_constant(seq: IPIDSequence) -> bool:
    return np.all(seq.full.increments == 0)


def is_local(seq: IPIDSequence) -> bool:
    return seq.even.is_increasing() and seq.odd.is_increasing()


def is_local_eq1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.even.increments == 1)
            and np.all(seq.odd.increments == 1))


def is_local_ge1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.even.increments >= 1)
            and np.all(seq.odd.increments >= 1))


def is_global(seq: IPIDSequence) -> bool:
    return seq.full.is_increasing()


def is_multi_global(seq: IPIDSequence) -> bool:
    clusters = get_clusters(seq.full.sequence)
    return np.all(seq.full.increments >= 1) and len(clusters) <= len(seq.full.sequence) // 2


def is_random(seq: IPIDSequence) -> bool:
    alpha = 0.01
    return np.all(seq.full.increments >= 1) and is_uniform(seq.full.increments, alpha)


def is_anomalous(seq: IPIDSequence) -> bool:
    return not has_pattern(seq)


def has_pattern(seq: IPIDSequence) -> bool:
    return (
            is_constant(seq)
            or is_local_eq1(seq)
            or is_local_ge1(seq)
            or is_global(seq)
            or is_multi_global(seq)
            or is_random(seq)
    )


def get_pattern(seq: IPIDSequence, get_all=False) -> list[Pattern] | Pattern:
    result = []
    if config.detect_reflected_ip_ids and is_reflection(seq):
        result.append(Pattern.REFLECTION)
    if is_constant(seq):
        result.append(Pattern.CONSTANT)
    if is_global(seq):
        result.append(Pattern.GLOBAL)
    if is_local_eq1(seq):
        result.append(Pattern.LOCAL_EQ1)
    if is_local_ge1(seq):
        result.append(Pattern.LOCAL_GE1)
    if is_multi_global(seq):
        result.append(Pattern.MULTI_GLOBAL)
    if is_random(seq):
        result.append(Pattern.RANDOM)
    if is_anomalous(seq):
        result.append(Pattern.FALLBACK)
    return result if get_all else result[0]


# endregion


# region Sequence Generation
def random_ip_id() -> int:
    return random.randint(0, MAX_IP_ID)


def clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def increment_ip_id(ip_id: int, inc: int) -> int:
    return (ip_id + inc) % (MAX_IP_ID + 1)


def constant_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    for i in range(length):
        seq.append(s)
    return IPIDSequence(seq)


def local_eq1_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    for i in range(length):
        if i % 2 == 0:
            a = increment_ip_id(a, 1)
            seq.append(a)
        else:
            b = increment_ip_id(b, 1)
            seq.append(b)
    return IPIDSequence(seq)


def local_ge1_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    max_inc = 2000  # 1 tick = 1ms => Max RTT of 2000ms = 2000 ticks
    for i in range(length):
        if i % 2 == 0:
            a = increment_ip_id(a, random.randint(1, max_inc))
            seq.append(a)
        else:
            b = increment_ip_id(b, random.randint(1, max_inc))
            seq.append(b)
    return IPIDSequence(seq)


def global_ip_id_sequence(length: int, max_inc: int = MAX_INC) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    avg_inc = random.randint(1, max_inc)  # correlated with avg pps of device
    dev = max(int(0.5 * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(length):
        s = increment_ip_id(s, clamp(avg_inc + random.randint(-dev, dev), 1, max_inc))
        seq.append(s)
    return IPIDSequence(seq)


def multi_global_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    cluster_count = random.randint(2, length // 2)

    sizes = [length // cluster_count] * cluster_count
    for i in range(length % cluster_count):
        sizes[i] += 1

    cluster_seqs = {
        i: global_ip_id_sequence(length=sizes[i], max_inc=100).full.sequence.astype(int).tolist()
        for i in range(cluster_count)
    }

    while any(cluster_seqs.values()):
        i = random.choice([k for k in cluster_seqs if cluster_seqs[k]])
        seq.append(cluster_seqs[i].pop(0))

    return IPIDSequence(seq)


def random_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    for _ in range(length):
        seq.append(random_ip_id())
    return IPIDSequence(seq)


pattern_generation_map = {
    Pattern.CONSTANT: constant_ip_id_sequence,
    Pattern.GLOBAL: global_ip_id_sequence,
    Pattern.LOCAL_EQ1: local_eq1_ip_id_sequence,
    Pattern.LOCAL_GE1: local_ge1_ip_id_sequence,
    Pattern.MULTI_GLOBAL: multi_global_ip_id_sequence,
    Pattern.RANDOM: random_ip_id_sequence
}


# endregion


# region Classifier Evaluation
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

    with open(f"ideal_{sequence_length}_{sequence_count_per_pattern}.pkl", "wb") as f:
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

    with open(f"lossy_{sequence_length}_{sequence_count_per_pattern}.pkl", "wb") as f:
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

    with open(f"reorder_{sequence_length}_{sequence_count_per_pattern}.pkl", "wb") as f:
        pickle.dump(data, f)


def test_classifier(dataset: Dataset, sequence_length: int, sequence_count_per_pattern: int):
    dataset_fp = f"{dataset.value.lower()}_{sequence_length}_{sequence_count_per_pattern}.pkl"
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
    plt.savefig(f"{dataset.value.lower()}_cm_{sequence_length}_{sequence_count_per_pattern}.png", dpi=300)


def test():
    sequence_length = 10
    sequence_count_per_pattern = 100_000

    test_classifier(Dataset.IDEAL, sequence_length, sequence_count_per_pattern)
    test_classifier(Dataset.LOSSY, sequence_length, sequence_count_per_pattern)
    test_classifier(Dataset.REORDER, sequence_length, sequence_count_per_pattern)


if __name__ == "__main__":
    test()

# endregion
