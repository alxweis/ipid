import csv
import unittest
from enum import Enum

import numpy as np
import seaborn as sns
from matplotlib import pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report, confusion_matrix, \
    ConfusionMatrixDisplay

import pandas as pd

from ipid_analysis.postprocessing import (
    get_pattern,
    is_mirror,
    has_pattern,
    IPIDParts,
    pattern_distribution_df,
)
from ipid_analysis.utils import (
    headline_str,
    MAX_IPID,
    MIRROR_IPIDS,
    create_logger,
    log_df,
    PROBE_COUNT, DETECT_MIRROR,
)

logger = create_logger(__name__)
PROBE_COUNT_PER_VP = int(PROBE_COUNT / 2)


def unit_probe(size, off, inc):
    if inc > 0:
        end = off + size * inc
    else:
        end = off + size * inc + inc

    return tuple(i % (MAX_IPID + 1) for i in range(off, end, inc))


def combine_probes(a, b):
    combined = ()
    for i in range(min(len(a), len(b))):
        combined += (a[i], b[i])
    return combined


class Patterns(Enum):
    MIRROR = "mirror"
    CONST = "const"
    GLOBAL = "global"
    LOCAL_EQ1 = "local_eq1"
    LOCAL_GE1 = "local_ge1"
    RANDOM = "random"
    ODD = "odd"


patterns = {pattern.value for pattern in Patterns}


def classify(probe, on_all_patterns):
    if on_all_patterns:
        return set(get_pattern(probe, get_all=on_all_patterns))
    else:
        return {get_pattern(probe, get_all=on_all_patterns)}


def evaluate(dir_name, true_labels, predicted_labels):
    accuracy = accuracy_score(true_labels, predicted_labels)
    precision = precision_score(true_labels, predicted_labels, average='macro')
    recall = recall_score(true_labels, predicted_labels, average='macro')

    print(f"Accuracy: {accuracy:.2f}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")

    print("\nClassification Report:")
    print(classification_report(true_labels, predicted_labels, zero_division=0))

    ordered_labels = ["Constant", "Global", "Local (=1)", "Local (≥1)", "Random", "Anomalous"]

    label_mapping = {
        "const": "Constant",
        "global": "Global",
        "local_eq1": "Local (=1)",
        "local_ge1": "Local (>=1)",
        "random": "Random",
        "odd": "Anomalous"
    }

    cm = confusion_matrix(true_labels, predicted_labels, labels=list(label_mapping.keys()))

    cm_safe = cm.astype('float')
    row_sums = cm_safe.sum(axis=1, keepdims=True)
    cm_percentage_safe = np.divide(cm_safe, row_sums, where=row_sums != 0) * 100
    cm_percentage_safe = np.round(cm_percentage_safe, 0).astype(int)

    disp = ConfusionMatrixDisplay(confusion_matrix=cm_percentage_safe, display_labels=ordered_labels)
    disp.plot(cmap='Blues', xticks_rotation=45, values_format='d')
    # plt.title("Confusion Matrix in %")

    plt.setp(disp.ax_.get_xticklabels(), fontsize=12)
    plt.setp(disp.ax_.get_yticklabels(), fontsize=12)

    disp.ax_.set_xlabel('Predicted Label', fontsize=14)
    disp.ax_.set_ylabel('True Label', fontsize=14)

    cbar = disp.im_.colorbar
    cbar.ax.tick_params(labelsize=12)

    plt.tight_layout()

    plt.savefig(f"confusion_matrix_{dir_name}.pdf", format="pdf")
    plt.show()

    return accuracy


class TestClassifier(unittest.TestCase):
    sample_set = "ideal"

    def assert_probe(self, probe, on_all_patterns, correct_patterns):
        classified_patterns = classify(probe, on_all_patterns)
        self.assertTrue(classified_patterns == correct_patterns,
                        f"classified={classified_patterns} not equal to correct={correct_patterns}")

    def assert_sample_probes(self, directory, file_name, correct_pattern):
        with open(f"sample_probes/{directory}/{file_name}", "r") as file:
            lines = file.readlines()

        probes = [eval(line.strip()) for line in lines]

        true_labels = []
        predicted_labels = []

        for probe in probes:
            true_labels.append(correct_pattern)
            predicted_labels.append(get_pattern(probe, False))

        if evaluate(directory, true_labels, predicted_labels) < 1:
            self.fail("")

    def classify_sample_probes(self, directory):
        df = pd.read_csv(f"sample_probes/{directory}/mixed.csv")

        true_labels = []
        predicted_labels = []

        for index, row in df.iterrows():
            probe = eval(row.iloc[0])

            true_labels.append(str(row.iloc[1]))
            predicted_labels.append(get_pattern(probe, get_all=False))

        if evaluate(directory, true_labels, predicted_labels) < 1:
            self.fail("")

    def test_mirror_probe(self):
        mirror_probe = MIRROR_IPIDS[:PROBE_COUNT]
        parts = IPIDParts(mirror_probe)
        # Check if probe itself has pattern
        self.assertTrue(not has_pattern(parts))
        # Check if probe is recognized as mirror
        if DETECT_MIRROR:
            self.assertTrue(is_mirror(parts))
            self.assert_probe(mirror_probe, on_all_patterns=True, correct_patterns={Patterns.MIRROR.value})
        else:
            logger.info("Mirror probes won't be asserted (DETECT_MIRROR=false)")

    def test_const_pattern(self):
        self.assert_sample_probes(
            self.sample_set, "const.txt", Patterns.CONST.value
        )

    def test_global_pattern(self):
        case_1 = unit_probe(size=PROBE_COUNT, off=0, inc=1)
        case_2 = unit_probe(size=PROBE_COUNT, off=0, inc=5)
        case_3 = unit_probe(size=PROBE_COUNT, off=-5, inc=5)

        cases = [case_1, case_2, case_3]
        for case in cases:
            self.assert_probe(
                case, on_all_patterns=True, correct_patterns={Patterns.GLOBAL.value, Patterns.LOCAL_GE1.value}
            )

        self.assert_sample_probes(
            self.sample_set, "global.txt", Patterns.GLOBAL.value
        )

    def test_local_eq1_pattern(self):
        case_1 = combine_probes(
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
        )
        case_2 = combine_probes(
            unit_probe(size=PROBE_COUNT_PER_VP, off=5, inc=1),
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
        )
        case_3 = combine_probes(
            unit_probe(size=PROBE_COUNT_PER_VP, off=-5, inc=1),
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
        )

        cases = [case_1, case_2, case_3]
        for case in cases:
            self.assert_probe(
                case, on_all_patterns=True, correct_patterns={Patterns.LOCAL_EQ1.value, Patterns.LOCAL_GE1.value}
            )

        self.assert_sample_probes(
            self.sample_set, "local_eq1.txt", Patterns.LOCAL_EQ1.value
        )

    def test_local_ge1_pattern(self):
        case_1 = combine_probes(
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=1),
        )
        self.assert_probe(
            case_1,
            on_all_patterns=True,
            correct_patterns={Patterns.LOCAL_EQ1.value, Patterns.LOCAL_GE1.value}
        )
        case_2 = combine_probes(
            unit_probe(size=PROBE_COUNT_PER_VP, off=0, inc=2),
            unit_probe(size=PROBE_COUNT_PER_VP, off=1, inc=2),
        )
        self.assert_probe(
            case_2,
            on_all_patterns=True,
            correct_patterns={Patterns.GLOBAL.value, Patterns.LOCAL_GE1.value}
        )

        self.assert_sample_probes(
            self.sample_set, "local_ge1.txt", Patterns.LOCAL_GE1.value
        )

    def test_random_pattern(self):
        self.assert_sample_probes(
            self.sample_set, "random.txt", Patterns.RANDOM.value
        )

    def test_odd_pattern(self):
        case_1 = tuple(x + 1 for x in MIRROR_IPIDS)
        self.assert_probe(case_1, on_all_patterns=False, correct_patterns={Patterns.ODD.value})

        self.assert_sample_probes(
            self.sample_set, "odd.txt", Patterns.ODD.value
        )

    def test_mixed_pattern(self):
        self.classify_sample_probes(self.sample_set)

    # def test_rossi_training_data(self):
    #     training_data = "IPID-G"
    #     total_valid_ips = 0
    #     rossi_pattern_to_ips = {}
    #     my_pattern_to_ips = {}
    #
    #     ip_to_ipids = {}
    #
    #     rossi_to_my_pattern = {
    #         "constant": "const",
    #         "global": "global",
    #         "local": "local",
    #         "random": "random",
    #         "odd": "odd",
    #     }
    #
    #     with open(training_data, newline="", encoding="utf-8") as csvfile:
    #         csv_reader = csv.reader(csvfile, delimiter=";")
    #         next(csv_reader)
    #         for row in csv_reader:
    #             total_valid_ips += 1
    #             ip = row[0]
    #             ipids = tuple(map(int, row[2].split(",")))
    #             ip_to_ipids[ip] = ipids
    #
    #             rossi_pattern = row[1]
    #             rossi_pattern_to_ips.setdefault(
    #                 rossi_to_my_pattern[rossi_pattern], []
    #             ).append(ip)
    #
    #     for ip in ip_to_ipids:
    #         pattern = get_pattern(ip_to_ipids[ip])
    #         pattern = (
    #             "local" if pattern == "local_eq1" or pattern == "local_ge1" else pattern
    #         )
    #         my_pattern_to_ips.setdefault(pattern, []).append(ip)
    #
    #     logger.info(headline_str("My"))
    #     pattern_distribution_df(my_pattern_to_ips, total_valid_ips, log=True, save_dir=None)
    #     logger.info(headline_str("Rossi"))
    #     pattern_distribution_df(rossi_pattern_to_ips, total_valid_ips, log=True, save_dir=None)
    #
    #     pattern_dist_dev_data = []
    #     for rossi_pattern in rossi_pattern_to_ips:
    #         rossi_size = len(rossi_pattern_to_ips[rossi_pattern])
    #         my_size = len(my_pattern_to_ips[rossi_pattern])
    #
    #         diff = 0 if rossi_size == 0 else my_size - rossi_size
    #         dev = 0 if rossi_size == 0 else diff / rossi_size
    #         dev_text = f"{dev * 100:.2f}%"
    #         pattern_dist_dev_data.append(
    #             {
    #                 "Pattern": rossi_pattern,
    #                 "Difference Count": diff,
    #                 "Deviation Percentage": dev_text,
    #             }
    #         )
    #
    #     logger.info(headline_str("Difference"))
    #     logger.info(
    #         "Positive Difference => My pattern has more ips than Rossi's pattern"
    #     )
    #     logger.info(
    #         "Negative Difference => My pattern has less ips than Rossi's pattern"
    #     )
    #     pattern_dist_dev_df = pd.DataFrame(pattern_dist_dev_data)
    #     log_df(logger, pattern_dist_dev_df)
    #
    #     logger.info(headline_str("Detailed Comparison"))
    #
    #     def compare_patterns(ips_a, ips_b, pattern_name):
    #         set_a, set_b = set(ips_a), set(ips_b)
    #         intersection, false_positives, false_negatives = (
    #             set_a & set_b,
    #             set_a - set_b,
    #             set_b - set_a,
    #         )
    #         logger.info(headline_str(f"{pattern_name} Pattern"))
    #         logger.info(f"Intersection: {len(intersection)} IPs")
    #         logger.info(
    #             f"False Positives: {len(false_positives)} IPs (My measurement includes these incorrectly)"
    #         )
    #         logger.info(
    #             f"False Negatives: {len(false_negatives)} IPs (These should be included but are missing)"
    #         )
    #         if false_positives:
    #             logger.info(f"False Positives IPs: {false_positives}")
    #         if false_negatives:
    #             logger.info(f"False Negatives IPs: {false_negatives}")
    #
    #     for pattern in rossi_pattern_to_ips:
    #         rossi_ips = rossi_pattern_to_ips[pattern]
    #         my_ips = my_pattern_to_ips[pattern]
    #         compare_patterns(my_ips, rossi_ips, pattern)


if __name__ == "__main__":
    unittest.main()
