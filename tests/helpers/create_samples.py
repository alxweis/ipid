import os
import random

from utils import PROBE_COUNT, MAX_IPID, MAX_INC


def create_samples_file(dir_name, file_name, class_fn, noise_fn, line_count):
    sample_probes_dir = f"../sample_probes/{dir_name}"
    if not os.path.exists(sample_probes_dir):
        os.makedirs(sample_probes_dir)
    with open(os.path.join(sample_probes_dir, file_name), "w") as file:
        for _ in range(line_count):
            if noise_fn:
                file.write(str(noise_fn(class_fn())) + "\n")
            else:
                file.write(str(class_fn()) + "\n")


def create_odd_samples_file(dir_name, noise_fn, line_count):
    sample_probes_dir = f"../sample_probes/{dir_name}"
    if not os.path.exists(sample_probes_dir):
        os.makedirs(sample_probes_dir)

    with open(os.path.join(sample_probes_dir, "odd.txt"), "w") as file:

        fns = [(constant_probe, const_odd_noise), (global_probe, global_odd_noise), (local_eq1_probe, local_odd_noise),
               (local_ge1_probe, local_odd_noise), (random_probe, rand_odd_noise)]

        for create_probe, odd_noise in fns:
            for _ in range(line_count // len(fns)):
                result = odd_noise(create_probe())
                if result:
                    if noise_fn:
                        file.write(str(noise_fn(result)) + "\n")
                    else:
                        file.write(str(result) + "\n")


def create_mixed_samples_file(dir_name, line_count):
    sample_probes_dir = f"../sample_probes/{dir_name}"
    os.makedirs(sample_probes_dir, exist_ok=True)

    output_file_path = os.path.join(sample_probes_dir, "mixed.csv")
    sample_file_names = ["const.txt", "global.txt", "local_eq1.txt", "local_ge1.txt", "random.txt", "odd.txt"]

    with open(output_file_path, "w") as output_file:
        for sample_file_name in sample_file_names:
            input_file_path = os.path.join(sample_probes_dir, sample_file_name)

            with open(input_file_path, "r") as file:
                lines = file.readlines()

            random_lines = random.sample(lines, min(line_count, len(lines)))

            class_name = sample_file_name.replace(".txt", "")
            for i in range(len(random_lines)):
                random_lines[i] = f"\"{random_lines[i].strip()}\",{class_name}\n"

            output_file.writelines(random_lines)


def rand_ipid():
    return random.randint(0, MAX_IPID)


def clamp(value, min_value, max_value):
    return max(min_value, min(value, max_value))


def inc_ipid(ipid, inc):
    return (ipid + inc) % (MAX_IPID + 1)


def constant_probe():
    seq = []
    s = rand_ipid()
    for i in range(PROBE_COUNT):
        seq.append(s)
    return tuple(seq)


def local_eq1_probe():
    seq = []
    a = rand_ipid()
    b = rand_ipid()
    for i in range(PROBE_COUNT):
        if i % 2 == 0:
            a = inc_ipid(a, 1)
            seq.append(a)
        else:
            b = inc_ipid(b, 1)
            seq.append(b)
    return tuple(seq)


def local_ge1_probe():
    seq = []
    a = rand_ipid()
    b = rand_ipid()
    max_inc = 2000  # 1 tick = 1ms => Max RTT of 2000ms = 2000 ticks
    for i in range(PROBE_COUNT):
        if i % 2 == 0:
            a = inc_ipid(a, random.randint(1, max_inc))
            seq.append(a)
        else:
            b = inc_ipid(b, random.randint(1, max_inc))
            seq.append(b)
    return tuple(seq)


def global_probe():
    seq = []
    s = rand_ipid()
    avg_inc = random.randint(1, MAX_INC)  # correlated with avg pps of device
    dev = max(int(0.5 * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(PROBE_COUNT):
        s = inc_ipid(s, clamp(avg_inc + random.randint(-dev, dev), 1, MAX_INC))
        seq.append(s)
    return tuple(seq)


def random_probe():
    seq = []
    for i in range(PROBE_COUNT):
        seq.append(rand_ipid())
    return tuple(seq)


# region Noise Behaviour

# region Odd Noise
def const_odd_noise(seq):
    seq = list(seq)

    if random.random() < 0.5:
        # Outsider Single Value
        x = random.choice(range(len(seq)))
        seq[x] = inc_ipid(seq[x], random.randint(1, MAX_INC))
    else:
        # Outsider Constant Sequence
        count = 3
        x = random.choice(range(len(seq) - count))
        value = inc_ipid(seq[x], random.randint(1, MAX_INC))
        for i in range(count):
            seq[x + i] = value

    return tuple(seq)


def global_odd_noise(seq):
    seq = list(seq)

    if random.random() < 0.5:
        # Outsider Single Value
        x = random.choice(range(0, len(seq) - 2))
        seq[x + 2] = seq[x]
    else:
        # Outsider Constant Sequence
        count = 3
        x = random.choice(range(len(seq) - count))
        value = seq[x]
        for i in range(count):
            seq[x + i] = value

    return tuple(seq)


def local_odd_noise(seq):
    seq = list(seq)

    if random.random() < 0.5:
        # Outsider Single Value
        x = random.choice(range(0, len(seq) - 1))
        seq[x + 1] = seq[x]
    else:
        # Outsider Constant Sequence
        count = 3
        x = random.choice(range(len(seq) - count))
        value = seq[x]
        for i in range(count):
            seq[x + i] = value

    return tuple(seq)


def rand_odd_noise(seq):
    seq = list(seq)

    # Outsider Constant Sequence
    count = int(PROBE_COUNT * 0.5)
    x = random.choice(range(0, len(seq) - count))
    value = seq[x]
    for i in range(count):
        seq[x + i] = value

    return tuple(seq)


# endregion

# region Lossy and Reorder Noise
def lossy_noise(seq):
    loss_count = int(len(seq) * 0.2)
    indices_to_remove = set(random.sample(range(len(seq)), loss_count))
    return tuple(seq[i] for i in range(len(seq)) if i not in indices_to_remove)


def reorder_noise(seq):
    seq = list(seq)
    num_swaps = max(1, int(len(seq) * 0.2))

    for _ in range(num_swaps):
        idx1, idx2 = random.sample(range(len(seq)), 2)
        seq[idx1], seq[idx2] = seq[idx2], seq[idx1]

    return tuple(seq)


# endregion

# endregion


def process_samples(env, noise_fn, count):
    create_samples_file(env, "const.txt", constant_probe, noise_fn, 1000)
    create_samples_file(env, "global.txt", global_probe, noise_fn, count)
    create_samples_file(env, "local_eq1.txt", local_eq1_probe, noise_fn, count)
    create_samples_file(env, "local_ge1.txt", local_ge1_probe, noise_fn, count)
    create_samples_file(env, "random.txt", random_probe, noise_fn, count)
    create_odd_samples_file(env, noise_fn, count)
    create_mixed_samples_file(env, count)


sample_count = 1_000_000
ideal = "ideal"
lossy = "lossy"
reorder = "reorder"

process_samples(ideal, None, sample_count)
process_samples(lossy, lossy_noise, sample_count)
process_samples(reorder, reorder_noise, sample_count)
