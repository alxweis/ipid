import math
import os
import sys
import time

import geoip2
import numpy as np
import pandas as pd
import seaborn as sns
from geoip2 import database
from geoip2.errors import AddressNotFoundError
from matplotlib import pyplot as plt
from scipy.stats import chi2, chisquare
from statsmodels.distributions import ECDF

from utils import (
    create_logger,
    get_percent_str,
    log_df,
    DETECT_MIRROR,
    MIRROR_IPIDS,
    MAX_INC,
    MAX_IPID, get_ip_info, get_msm
)

logger = create_logger(__name__)


# region Pattern Recognition
def ent(values):
    values = np.array(values)
    value, counts = np.unique(values, return_counts=True)
    probabilities = counts / counts.sum()
    entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(values))
    return entropy / max_entropy


def is_increasing(incs):
    return np.all((1 <= incs) & (incs <= MAX_INC))


def get_p_value(seq):
    seq = list(seq)
    intervals = int(math.ceil(math.sqrt(len(seq))))
    interval_edges = np.linspace(0, MAX_IPID, intervals + 1)
    observed_frequencies, _ = np.histogram(seq, bins=interval_edges)
    total_numbers = len(seq)
    expected_frequencies = np.full(intervals, total_numbers / intervals)

    chi2_stat, p_value = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
    return p_value


def is_uniform(seq, alpha):
    return get_p_value(seq) > alpha


def is_mirror(parts):
    if not DETECT_MIRROR:
        return False

    for i, ipid in enumerate(parts.s):
        if ipid != MIRROR_IPIDS[i % len(MIRROR_IPIDS)]:
            return False
    return True


def is_const(parts):
    return np.all(parts.incs_s == 0)


def is_local(parts):
    is_a_increasing = is_increasing(parts.incs_a)
    is_b_increasing = is_increasing(parts.incs_b)
    return is_a_increasing and is_b_increasing


def is_local_eq1(parts):
    return (is_local(parts)
            and np.all(parts.incs_a == 1)
            and np.all(parts.incs_b == 1))


def is_local_ge1(parts):
    return (is_local(parts)
            and np.all(parts.incs_a >= 1)
            and np.all(parts.incs_b >= 1))


def is_global(parts):
    is_s_increasing = is_increasing(parts.incs_s)
    return is_s_increasing


def is_random(parts):
    alpha = 0.01
    return is_uniform(parts.incs_s, alpha) and is_uniform(parts.incs_a, alpha) and is_uniform(parts.incs_b, alpha)


def is_odd(parts):
    return not (is_mirror(parts) or has_pattern(parts))


def has_pattern(parts):
    return (
            is_const(parts)
            or is_local_eq1(parts)
            or is_local_ge1(parts)
            or is_global(parts)
            or is_random(parts)
    )


class IPIDParts:
    def __init__(self, ipids):
        self.a = ipids[0::2]
        self.b = ipids[1::2]
        self.s = tuple(ipids)

        def incs(tup):
            return np.diff(tup) % (MAX_IPID + 1)

        self.incs_a = incs(self.a)
        self.incs_b = incs(self.b)
        self.incs_s = incs(ipids)


# endregion


def get_pattern(ipids, get_all=False):
    parts = IPIDParts(ipids)
    result = []
    if is_mirror(parts):
        result.append("mirror")
    if is_const(parts):
        result.append("const")
    if is_global(parts):
        result.append("global")
    if is_local_eq1(parts):
        result.append("local_eq1")
    if is_local_ge1(parts):
        result.append("local_ge1")
    if is_random(parts):
        result.append("random")
    if is_odd(parts):
        result.append("odd")
    return result if get_all else result[0]


def patterns():
    return {
        "mirror": "Mirror",
        "const": "Constant",
        "global": "Global",
        "local": "Local",
        "local_eq1": "Local(inc==1)",
        "local_ge1": "Local(inc>=1)",
        "random": "Random",
        "odd": "Odd",
    }


def ipid_classification(ip_to_ipids, total_valid_ips, log, save_dir):
    ip_to_pattern = {}
    pattern_to_ips = {}
    for ip in ip_to_ipids:
        ipids = ip_to_ipids[ip]
        pattern = get_pattern(ipids)
        ip_to_pattern[ip] = pattern
        pattern_to_ips.setdefault(pattern, []).append(ip)

    return (
        ip_to_pattern,
        pattern_to_ips,
        pattern_distribution_df(pattern_to_ips, total_valid_ips, log=log, save_dir=save_dir),
    )


def pattern_distribution_df(pattern_to_ips, total_valid_ips, log, save_dir):
    file = f"{save_dir}/pattern.csv"
    if save_dir and os.path.exists(file):
        logger.info("Pattern Distribution dataframe already exists")
        return

    data = []
    for pattern in patterns():
        if (
                pattern == "local"
                and "local_eq1" in pattern_to_ips
                and "local_ge1" in pattern_to_ips
        ):
            ips = pattern_to_ips["local_eq1"] + pattern_to_ips["local_ge1"]
        elif pattern in pattern_to_ips:
            ips = pattern_to_ips[pattern]
        else:
            ips = []

        count = len(ips)
        data.append(
            {
                "Pattern": pattern,
                "Count": count,
                "Percentage": get_percent_str(count, total_valid_ips),
            }
        )

    df = pd.DataFrame(data)
    if log:
        log_df(logger, df, "Pattern Distribution")
    if save_dir:
        df.to_csv(f"{save_dir}/pattern.csv", index=False)
    return df


def quantity_df(total_requested_ips, total_valid_ips, total_invalid_ips, log, save_dir):
    file = f"{save_dir}/quantity.csv"
    if save_dir and os.path.exists(file):
        logger.info("Quantity dataframe already exists")
        return

    quantity_data = [
        {
            "IP Addresses": "Requested",
            "Count": total_requested_ips,
            "Percentage": "",
        },
        {
            "IP Addresses": "Invalid",
            "Count": total_invalid_ips,
            "Percentage": get_percent_str(total_invalid_ips, total_requested_ips),
        },
        {
            "IP Addresses": "Valid (Probed)",
            "Count": total_valid_ips,
            "Percentage": get_percent_str(total_valid_ips, total_requested_ips),
        },
    ]
    df = pd.DataFrame(quantity_data)
    if log:
        log_df(logger, df, "Quantity")
    if save_dir:
        df.to_csv(file, index=False)
    return df


def evaluation_df(ip_to_os, ip_to_pattern, ip_to_rtts, log, save_dir):
    file = f"{save_dir}/eval.csv"
    if save_dir and os.path.exists(file):
        logger.info("Evaluation dataframe already exists")
        return

    asn_reader = geoip2.database.Reader(get_ip_info("GeoLite2-ASN.mmdb"))
    city_reader = geoip2.database.Reader(get_ip_info("GeoLite2-City.mmdb"))
    country_reader = geoip2.database.Reader(get_ip_info("GeoLite2-Country.mmdb"))
    data = []

    asn_to_ips = {}
    country_to_ips = {}
    ip_to_continent = {}

    for ip in ip_to_pattern:
        try:
            asn_response = asn_reader.asn(ip)
            city_response = city_reader.city(ip)
            country_response = country_reader.country(ip)
            asn = asn_response.autonomous_system_number
            country = country_response.country.name
            continent = city_response.continent.name

            asn_to_ips.setdefault(asn, []).append(ip)
            country_to_ips.setdefault(country, []).append(ip)
            ip_to_continent[ip] = continent

            data.append(
                {
                    "IP": ip,
                    "OS": ip_to_os[ip],
                    "IPID Pattern": ip_to_pattern[ip],
                    "Avg RTT": np.average(ip_to_rtts[ip]) * 1000,
                    "Std RTT": np.std(ip_to_rtts[ip]) * 1000,
                    "ASN": asn_response.autonomous_system_number,
                    "AS Organization": asn_response.autonomous_system_organization,
                    # 'City': city_response.city.name,
                    "Country": country_response.country.name,
                    # 'Country ISO Code': country_response.country.iso_code,
                    # 'Region': city_response.subdivisions.most_specific.name,
                    # 'Region ISO Code': city_response.subdivisions.most_specific.iso_code,
                    # 'Postal Code': city_response.postal.code,
                    # 'Latitude': city_response.location.latitude,
                    # 'Longitude': city_response.location.longitude,
                    # 'Time Zone': city_response.location.time_zone,
                    "Continent": city_response.continent.name,
                    # 'ISP': asn_response.autonomous_system_organization,
                    # 'Domain': asn_response.autonomous_system_organization
                }
            )
        except AddressNotFoundError:
            pass

    asn_reader.close()
    city_reader.close()
    country_reader.close()

    df = pd.DataFrame(data)
    if log:
        log_df(logger, df, "Evaluation")
    if save_dir:
        df.to_csv(file, index=False)
    return df


def continent_stats_df(eval_df, log, save_dir):
    file = f"{save_dir}/continent.csv"
    if save_dir and os.path.exists(file):
        logger.info("Continent Stats dataframe already exists")
        return

    df = (
        eval_df.groupby("Continent")
        .agg({"Avg RTT": "mean", "IP": "count"})
        .reset_index()
    )

    df.columns = ["Continent", "Avg RTT", "IP Count"]
    df["IP Portion"] = df["IP Count"].apply(
        lambda x: get_percent_str(x, eval_df["IP"].nunique())
    )

    if log:
        log_df(logger, df, "Continent Stats")
    if save_dir:
        df.to_csv(file, index=False)
    return df


def asn_stats_df(eval_df, log, save_dir):
    file = f"{save_dir}/asn.csv"
    if save_dir and os.path.exists(file):
        logger.info("ASN Stats dataframe already exists")
        return

    def calculate_pattern_distribution(df):
        pattern_counts = df["IPID Pattern"].value_counts(normalize=True).to_dict()
        return {k: f"{v * 100:.2f}%" for k, v in pattern_counts.items()}  #

    df = (
        eval_df.groupby("ASN")
        .agg(
            {
                "AS Organization": lambda x: x.mode()[0],
                "IP": "count",
                "Avg RTT": "mean",
                "Std RTT": "mean",
                "Continent": lambda x: x.mode()[0] if not x.mode().empty else None,
                "Country": lambda x: x.mode()[0] if not x.mode().empty else None,
            }
        )
        .reset_index()
    )

    df["IPID Pattern Distribution"] = (
        eval_df.groupby("ASN", group_keys=False)
        .apply(lambda df: calculate_pattern_distribution(df), include_groups=False)
        .reset_index(drop=True)
    )

    df.rename(columns={"IP": "IP Count"}, inplace=True)

    if log:
        log_df(logger, df, "ASN Stats")
    if save_dir:
        df.to_csv(file, index=False)
    return df


class Plotter:
    def __init__(self, ip_to_ipids, pattern_to_ips, ip_to_sent_times, ip_to_recv_times, ip_to_rtts, eval_df,
                 total_valid_ips):
        self.total_valid_ips = total_valid_ips
        self.ip_to_ipids = ip_to_ipids
        self.pattern_to_ips = pattern_to_ips
        self.ip_to_sent_times = ip_to_sent_times
        self.ip_to_recv_times = ip_to_recv_times
        self.ip_to_rtts = ip_to_rtts
        self.eval_df = eval_df

    # region Help Functions
    def _norm_times(self, ips, times):
        return {
            ip: [t - times[ip][0] for t in times[ip]]
            for ip in ips
            if ip in times
        }

    def _get_ips(self, ip_count, ip_offset, ips=None):
        ips = ips or list(self.ip_to_ipids.keys())
        if ip_count:
            ip_offset = (ip_offset or 0) % len(ips)
            ip_count = max(ip_count % len(ips), 1)
            return ips[ip_offset: ip_count + ip_offset]
        return ips

    # endregion

    # region Distributions
    def distribution_local_global_inc(self):
        data = []

        for ip in self.ip_to_ipids:
            ipids = self.ip_to_ipids[ip]
            pattern = get_pattern(ipids)
            parts = IPIDParts(ipids)
            if pattern == "local":
                data.extend(parts.incs_a.tolist())
                data.extend(parts.incs_b.tolist())
            elif pattern == "global":
                data.extend(parts.incs_s.tolist())

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=100, alpha=0.7)
        plt.xlabel("IP-ID Increment")
        plt.ylabel("Count")
        plt.title("Frequency Distribution: IP-ID Increment for Local & Global Counter")
        plt.grid(True)
        plt.show()

    def ecdf_local_global_inc(self):
        data = []

        for ip in self.ip_to_ipids:
            ipids = self.ip_to_ipids[ip]
            pattern = get_pattern(ipids)
            parts = IPIDParts(ipids)
            if pattern == "local":
                data.extend(parts.incs_a.tolist())
                data.extend(parts.incs_b.tolist())
            elif pattern == "global":
                data.extend(parts.incs_s.tolist())

        ecdf = ECDF(data)

        plt.figure(figsize=(10, 6))
        plt.plot(ecdf.x, ecdf.y, marker=".", linestyle="none")
        plt.xlabel("IP-ID Increment")
        plt.ylabel("ECDF")
        plt.title("ECDF: IP-ID Increment for Local & Global Counter")
        plt.grid(True)
        plt.show()

    def distribution_inc(self):
        data = []

        for ip in self.ip_to_ipids:
            ipids = self.ip_to_ipids[ip]
            pattern = get_pattern(ipids)
            parts = IPIDParts(ipids)
            if pattern != "mirror":
                data.extend(parts.incs_s.tolist())

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=200, alpha=0.7)
        plt.xlabel("IP-ID Increment")
        plt.ylabel("Count")
        plt.title("Frequency Distribution: IP-ID Increment")
        plt.grid(True)
        plt.show()

    def ecdf_inc(self):
        data = []

        for ip in self.ip_to_ipids:
            ipids = self.ip_to_ipids[ip]
            pattern = get_pattern(ipids)
            parts = IPIDParts(ipids)
            if pattern != "mirror":
                data.extend(parts.incs_s.tolist())

        ecdf = ECDF(data)

        plt.figure(figsize=(10, 6))
        plt.plot(ecdf.x, ecdf.y, marker=".", linestyle="none", markersize=1)
        plt.xlabel("IP-ID Increment")
        plt.ylabel("ECDF")
        plt.title(f"ECDF: IP-ID Increment")
        plt.axvline(x=400, color="red", linestyle="--", linewidth=1)
        plt.grid(True)
        plt.show()

    def distribution_delta_recv_time(self):
        data = []

        for ip in self.ip_to_recv_times:
            data.extend(np.diff(self.ip_to_recv_times[ip]))

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=100, alpha=0.7)
        plt.xlabel("Time between Replies")
        plt.ylabel("Count")
        plt.title("Frequency Distribution: Time between Replies")
        plt.grid(True)
        plt.show()

    def distribution_delta_sent_time(self):
        data = []

        for ip in self.ip_to_sent_times:
            data.extend(np.diff(self.ip_to_sent_times[ip]))

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=100, alpha=0.7)
        plt.xlabel("Time between Requests")
        plt.ylabel("Count")
        plt.title("Frequency Distribution: Time between Requests")
        plt.grid(True)
        plt.show()

    def distribution_probing_time_per_target(self):
        data = [
            recv_times[-1] - sent_times[0]
            for sent_times, recv_times in zip(
                self.ip_to_sent_times.values(),
                self.ip_to_recv_times.values()
            )
        ]

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=100, alpha=0.7)
        plt.xlabel("Probing Time per Target")
        plt.ylabel("Count")
        plt.title("Frequency Distribution: Probing Time per Target")
        plt.grid(True)
        plt.show()

    def distribution_rtt(self):
        data = [rtt for rtts in self.ip_to_rtts.values() for rtt in rtts]

        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=100, alpha=0.7)
        plt.xlabel("RTT (ms)")
        plt.ylabel("Number of Occurrences")
        plt.title("Distribution of RTT")
        plt.grid(True)
        plt.show()

    def distribution_rtt_by_continent(self):
        plt.figure(figsize=(10, 6))
        sns.violinplot(
            x="Continent", y="Avg RTT", data=self.eval_df, density_norm="count"
        )
        plt.xlabel("Continent")
        plt.ylabel("Avg RTT (ms)")
        plt.title("RTT Distribution by Continent")
        plt.show()

    def distribution_pattern_by_max_inc(self):
        data = []
        for max_inc in range(0, MAX_IPID + 1, 1000):
            # global MAX_INC
            # MAX_INC = max_inc
            _, _, classification_df = ipid_classification(
                self.ip_to_ipids, self.total_valid_ips
            )
            row_data = {"max_inc": max_inc}
            for _, row in classification_df.iterrows():
                row_data[row["Pattern"]] = float(row["Percentage"].strip("%")) / 100
            data.append(row_data)

        df = pd.DataFrame(data)

        plt.figure(figsize=(12, 8))
        for column in df.columns[1:]:
            plt.plot(df["max_inc"], df[column], label=column)

        plt.xlabel("MAX_INC")
        plt.ylabel("Percentage")
        plt.title("Pattern Distribution by MAX_INC")
        plt.legend()
        plt.grid(True)
        plt.axvline(
            x=math.floor((MAX_IPID + 1) / 2) - 1,
            color="red",
            linestyle="--",
            linewidth=1,
        )
        plt.show()

    # endregion

    # region IPID Plots
    def target_by_time_and_ipid(
            self,
            ips=None,
            count=None,
            offset=None,
            show_legend=False,
            show_bounds=True,
    ):
        ips = self._get_ips(count, offset, ips)
        recv_times = self._norm_times(ips, self.ip_to_recv_times)

        fig = plt.figure()
        ax = fig.add_subplot(111, projection="3d")

        for i, ip in enumerate(ips):
            if ip in self.ip_to_ipids and ip in recv_times:
                x = [i] * len(self.ip_to_ipids[ip])
                y = recv_times[ip]
                z = list(self.ip_to_ipids[ip])
                ax.scatter(x, y, z, label=ip)

        ax.set_xlabel("Target")
        ax.set_ylabel("Normalized Time")
        ax.set_zlabel("IP-ID")
        plt.title("Target x Normalized Time x IP-ID")

        if show_legend:
            ax.legend()

        if show_bounds:
            ax.set_xlim(0, len(ips) - 1)
            ax.set_ylim(
                min(min(recv_times[ip]) for ip in recv_times), max(max(recv_times[ip]) for ip in recv_times)
            )
            ax.set_zlim(0, MAX_IPID)

        plt.show()

    def ipid_hops(
            self,
            ips=None,
            count=None,
            offset=None,
            show_legend=False,
            show_bounds=True,
    ):
        ips = self._get_ips(count, offset, ips)
        fig, ax = plt.subplots()

        for ip in ips:
            if ip in self.ip_to_ipids:
                x = list(self.ip_to_ipids[ip])
                y = [ip] * len(self.ip_to_ipids[ip])
                ax.scatter(x, y, label=ip)
                for j in range(len(x) - 1):
                    ax.annotate(
                        "",
                        xy=(x[j + 1], y[j + 1]),
                        xytext=(x[j], y[j]),
                        arrowprops=dict(
                            arrowstyle="->",
                            connectionstyle="arc3,rad=0.3",
                            color="grey",
                        ),
                    )

        ax.set_xlabel("IP-ID")
        ax.set_ylabel("Target IP")
        ax.set_yticks(range(len(ips)))
        ax.set_yticklabels(ips, rotation=0)

        if show_bounds:
            ax.axvline(x=0, color="grey", linestyle="--", linewidth=0.5)
            ax.axvline(x=MAX_IPID, color="grey", linestyle="--", linewidth=0.5)

        if show_legend:
            ax.legend()

        plt.title("IP-ID x Target")
        plt.show()

    def ipid_by_time(
            self,
            ips=None,
            count=None,
            offset=None,
            show_legend=False,
            show_bounds=True,
    ):
        ips = self._get_ips(count, offset, ips)
        fig, ax = plt.subplots()

        for ip in ips:
            if ip in self.ip_to_ipids and ip in self.ip_to_sent_times:
                probes = list(self.ip_to_ipids[ip])
                times = [(t - self.ip_to_sent_times[ip][0]) * 1000 for t in self.ip_to_sent_times[ip]]

                (line,) = ax.plot(times, probes, label=ip, linewidth=0.5)
                color = line.get_color()

                for i, (x, y) in enumerate(zip(times, probes)):
                    fill_color = color if i % 2 == 0 else "white"
                    ax.plot(x, y, marker="o", color=color, markerfacecolor=fill_color)

        ax.set_xlabel("Time (ms)")
        ax.set_ylabel("IP-ID")

        if show_bounds:
            ax.axhline(y=0, color="grey", linestyle="--", linewidth=0.5)
            ax.axhline(y=MAX_IPID, color="grey", linestyle="--", linewidth=0.5)

        if show_legend:
            ax.legend()

        plt.title("IP-ID by Time")
        plt.show()

    # endregion

    def pattern_distribution(self):
        sorted_patterns = sorted(self.pattern_to_ips.keys())

        lengths = [len(self.pattern_to_ips[pattern]) for pattern in sorted_patterns]

        total_ips = sum(lengths)

        percentages = [(length / total_ips) * 100 for length in lengths]

        plt.figure(figsize=(10, 6))
        plt.bar(sorted_patterns, percentages)

        plt.xlabel('Pattern')
        plt.ylabel('%')
        plt.title('Percentage Distribution of IPs per Pattern')

        plt.xticks(rotation=45, ha='right')

        plt.ylim(0, 100)

        plt.tight_layout()
        plt.show()


def main():
    if len(sys.argv) != 2:
        logger.error("Usage: python3 postprocessing.py <msm>")
        sys.exit(1)

    msm_path = get_msm(sys.argv[1])
    probing_file = f"{msm_path}/probing.csv"

    logger.info(f"Start Post-Processing")
    proc_probes_df = pd.read_csv(probing_file)

    # region Load Probing Data
    logger.info(f"Probe data loading...")
    start_time = time.time()

    def eval_timestamps(lst):
        return np.array(eval(lst), dtype=float) / 1_000_000_000

    ips = proc_probes_df["IP"]
    oses = proc_probes_df["OS"]
    ipid_seqs = proc_probes_df["IPID-Sequence"].apply(eval)
    sent_time_seqs = proc_probes_df["SentTime-Sequence"].apply(eval_timestamps)
    recv_time_seqs = proc_probes_df["ReceivedTime-Sequence"].apply(eval_timestamps)
    isvalid_seqs = proc_probes_df["IsValid-Sequence"].apply(eval)

    valid = isvalid_seqs.apply(lambda lst: all(x == 1 for x in lst))
    invalid = ~valid

    ip_to_os = {}
    ip_to_ipids = {}
    ip_to_sent_times = {}
    ip_to_recv_times = {}
    ip_to_rtts = {}

    for ip, op_sys, ipid_seq, sent_time_seq, recv_time_seq in zip(
            ips[valid],
            oses[valid],
            ipid_seqs[valid],
            sent_time_seqs[valid],
            recv_time_seqs[valid]
    ):
        ip_to_os[ip] = op_sys
        ip_to_ipids[ip] = ipid_seq
        ip_to_sent_times[ip] = sent_time_seq
        ip_to_recv_times[ip] = recv_time_seq
        ip_to_rtts[ip] = recv_time_seq - sent_time_seq

    total_requested_ips = proc_probes_df.shape[0]
    total_valid_ips = len(ips[valid])
    total_invalid_ips = len(ips[invalid])
    assert total_requested_ips == total_valid_ips + total_invalid_ips

    end_time = time.time()
    run_time = end_time - start_time
    logger.info(f"Probing data loaded in {run_time:.2f}s")
    # endregion

    # region Dataframes
    quantity_df(total_requested_ips, total_valid_ips, total_invalid_ips, log=True, save_dir=msm_path)
    ip_to_pattern, pattern_to_ips, _ = ipid_classification(
        ip_to_ipids, total_valid_ips, log=True, save_dir=msm_path
    )
    eval_df = evaluation_df(ip_to_os, ip_to_pattern, ip_to_rtts, log=True, save_dir=msm_path)
    continent_stats_df(eval_df, log=True, save_dir=msm_path)
    asn_stats_df(eval_df, log=True, save_dir=msm_path)
    # endregion

    if os.name == 'posix':
        return

    plotter = Plotter(ip_to_ipids, pattern_to_ips, ip_to_sent_times, ip_to_recv_times, ip_to_rtts, eval_df,
                      total_valid_ips)

    # plotter.pattern_distribution()
    # plotter.distribution_local_global_inc()
    # plotter.ecdf_local_global_inc()
    # plotter.distribution_inc()
    # plotter.ecdf_inc()
    # plotter.distribution_delta_recv_time()
    # plotter.distribution_delta_sent_time()
    # plotter.distribution_probing_time_per_target()
    # plotter.distribution_rtt()
    # plotter.distribution_rtt_by_continent()
    #
    # plotter.target_by_time_and_ipid(count=5, show_legend=True)
    # plotter.ipid_hops(count=5, show_legend=True)

    # for i in range(300):
    #     plotter.ipid_by_time(pattern_to_ips["const"], count=10, offset=10*i, show_legend=True)

    # ips = ["36.131.160.1"]
    # for ip in ips:
    #     plotter.ipid_by_time([ip], show_bounds=False)

    # for p in ["const"]: # "const", "local_eq1", "global", "random", "odd"
    #     pat = pattern_to_ips[p]
    #     for i in range(100):
    #         plotter.ipid_by_time([pat[i]], offset=i, show_bounds=False)

    # ip = "188.191.146.220"
    # plotter.ipid_by_time([ip])
    # plotter.ipid_by_time([ip], show_bounds=False)


if __name__ == "__main__":
    main()
