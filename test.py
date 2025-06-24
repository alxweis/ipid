import unittest

from core.classifier import IPIDSequence, get_pattern, Pattern
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


class ClassifierTests(unittest.TestCase):
    pass


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
