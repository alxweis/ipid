import json
import os
from ast import literal_eval
from collections import Counter
from dataclasses import dataclass
import re

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.lines import Line2D
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

from postprocessing import IPIDParts


def class_distribution(eval_file, os_filter):
    df = pd.read_csv(eval_file)

    # Filter OS based on regex
    regex_pattern = re.compile(os_filter.filter, re.IGNORECASE)
    df = df[df['OS'].str.contains(regex_pattern, na=False)]

    # Map IPID patterns to readable names
    pattern_mapping = {
        'const': 'Constant',
        'global': 'Global',
        'local_eq1': 'Local (=1)',
        'local_ge1': 'Local (≥1)',
        'random': 'Random',
        'odd': 'Anomalous'
    }
    df['IPID Pattern'] = df['IPID Pattern'].replace(pattern_mapping)

    # Calculate percentage distribution
    pattern_counts = df['IPID Pattern'].value_counts(normalize=True) * 100

    # Reorder bars based on pattern_mapping
    ordered_counts = pd.Series(
        [pattern_counts.get(pattern, 0) for pattern in pattern_mapping.values()],
        index=pattern_mapping.values()
    )

    # Create bar plot
    plt.figure(figsize=(5, 5))
    bars = ordered_counts.plot(kind='bar', color='tab:blue', width=0.8)  # Store the plot object
    print(f"Class Distribution: name={os_filter.name} targets={len(df)}")

    # Set labels and styling
    plt.ylabel('Percentage (%)', fontsize=16)
    plt.xlabel('Class', fontsize=16)
    plt.xticks(rotation=45, fontsize=14)
    plt.yticks(fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.ylim(0, 100)

    # Annotate each bar with its percentage value
    for bar in bars.containers[0]:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2, height + 1, f'{height:.1f}%',
            ha='center', va='bottom', fontsize=12, color='black'
        )

    plt.tight_layout()
    # plt.savefig(f"{os_filter.name}.pdf", format='pdf')  # Uncomment to save the figure
    plt.show()


def class_dist(df, file_name):
    import matplotlib.pyplot as plt
    import pandas as pd

    print(f"Unique IPs: {df['IP'].nunique()}")
    print(f"Unique ASNs: {df['ASN'].nunique()}")

    pattern_mapping = {
        'const': 'Constant',
        'global': 'Global',
        'local_eq1': 'Local (=1)',
        'local_ge1': 'Local (≥1)',
        'random': 'Random',
        'odd': 'Anomalous'
    }
    df['IPID Pattern'] = df['IPID Pattern'].replace(pattern_mapping)

    # Calculate percentage distribution
    pattern_counts = df['IPID Pattern'].value_counts(normalize=True) * 100

    # Reorder bars based on pattern_mapping
    ordered_counts = pd.Series(
        [pattern_counts.get(pattern, 0) for pattern in pattern_mapping.values()],
        index=pattern_mapping.values()
    )

    print(ordered_counts)

    # Create bar plot
    plt.figure(figsize=(5, 5))
    bars = ordered_counts.plot(kind='bar', color='tab:blue', width=0.8)

    plt.ylabel('Percentage (%)', fontsize=16)
    plt.xlabel('Class', fontsize=16)
    plt.xticks(rotation=45, fontsize=14)
    plt.yticks(fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.ylim(0, 100)

    # Annotate each bar with percentage value
    for bar in bars.patches:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2, height, f'{height:.1f}%',
            ha='center', va='bottom', fontsize=12, color='black'
        )

    plt.tight_layout()
    plt.savefig(f"{file_name}.pdf", format="pdf", bbox_inches="tight")

    return ordered_counts


def os_distribution(eval_file, os_filter):
    # Daten laden
    df = pd.read_csv(eval_file)

    # OS-Filter anwenden
    regex_pattern = re.compile(os_filter.filter, re.IGNORECASE)
    df = df[df['OS'].str.contains(regex_pattern, na=False)]

    # OS-Werte bereinigen
    df['OS'] = df['OS'].str.capitalize()  # Erster Buchstabe großschreiben
    df['OS'] = df['OS'].replace({'Linux': 'Linux (other)'})  # "Linux" ersetzen

    # Prozentuale Verteilung der Top 10 OS berechnen
    pattern_counts = df['OS'].value_counts(normalize=True).head(8) * 100

    # Plot erstellen
    plt.figure(figsize=(5, 5))
    bars = pattern_counts.plot(kind='bar', color='tab:blue', width=0.8)
    plt.ylim(0, 100)
    # Achsenbeschriftungen und Layout anpassen
    plt.ylabel('Percentage (%)', fontsize=16)
    plt.xlabel('OS', fontsize=16)
    plt.xticks(rotation=45, fontsize=14)
    plt.yticks(fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Prozentwerte über den Balken anzeigen
    for bar in bars.containers[0]:
        height = bar.get_height()
        if height > 0:
            plt.text(
                bar.get_x() + bar.get_width() / 2, height + 0.5, f'{height:.1f}%',
                ha='center', va='bottom', fontsize=12, color='black'
            )

    plt.tight_layout()
    # plt.savefig("os_distribution.pdf", format='pdf')  # Zum Speichern
    plt.show()


def fast_slow_comparison(fast_msm, slow_msm):
    # # Absolute Differenz
    # absolute_diff = fast_pattern - slow_pattern
    # print("Absolute Difference:")
    # print(absolute_diff)
    #
    # # Relative Differenz (im Verhältnis zu fast_pattern)
    # relative_diff = (absolute_diff / fast_pattern) * 100
    # print("Relative Difference (in %):")
    # print(relative_diff)
    # Zeigt Abweichungen in fast_pattern von der korrekten Tabelle slow_pattern. Positive Werte bedeuten
    # Überschätzungen in fast_pattern, negative Werte zeigen Unterschätzungen.

    def class_dist(df, file_name):
        pattern_mapping = {
            'const': 'Constant',
            'global': 'Global',
            'local_eq1': 'Local (=1)',
            'local_ge1': 'Local (≥1)',
            'random': 'Random',
            'odd': 'Anomalous'
        }
        df['IPID Pattern'] = df['IPID Pattern'].replace(pattern_mapping)

        # Calculate percentage distribution
        pattern_counts = df['IPID Pattern'].value_counts(normalize=True) * 100

        # Reorder bars based on pattern_mapping
        ordered_counts = pd.Series(
            [pattern_counts.get(pattern, 0) for pattern in pattern_mapping.values()],
            index=pattern_mapping.values()
        )

        print(ordered_counts)

        # Create bar plot
        plt.figure(figsize=(5, 5))
        bars = ordered_counts.plot(kind='bar', color='tab:blue', width=0.8)

        plt.ylabel('Percentage (%)', fontsize=16)
        plt.xlabel('Class', fontsize=16)
        plt.xticks(rotation=45, fontsize=14)
        plt.yticks(fontsize=14)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.ylim(0, 100)

        # Annotate each bar with percentage value
        for bar in bars.patches:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2, height, f'{height:.1f}%',
                ha='center', va='bottom', fontsize=12, color='black'
            )

        plt.tight_layout()
        plt.savefig(f"{file_name}.pdf", format="pdf", bbox_inches="tight")

        return ordered_counts

    def plt_difference(diff_df):
        plt.figure(figsize=(5, 5))
        ax = diff_df.plot(kind='bar', color='tab:blue', width=0.8)
        plt.axhline(0, color="black", linewidth=0.8, linestyle="--")
        plt.ylabel('Percentage (%)', fontsize=16)
        plt.xlabel('Class', fontsize=16)
        plt.xticks(rotation=45, fontsize=14)
        plt.yticks(fontsize=14)
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Text oberhalb oder unterhalb der Balken abhängig von der Höhe platzieren
        for bar in ax.patches:
            height = bar.get_height()
            position = height if height >= 0 else height - 0.05  # Kleiner Offset für negative Werte
            alignment = 'bottom' if height >= 0 else 'top'       # Position abhängig von Höhe
            ax.text(
                bar.get_x() + bar.get_width() / 2,  # X-Position
                position,                           # Y-Position
                f'{height:.1f}%',                   # Formatierter Text
                ha='center', va=alignment, fontsize=12, color='black'
            )

        plt.tight_layout()
        plt.savefig("diff_class_dist.pdf", format="pdf", bbox_inches="tight")

    def confusion_mtx_optimized():
        # Führe die beiden DataFrames auf Basis der IP-Spalte zusammen
        merged_df = slow_eval.merge(fast_eval, on='IP', suffixes=('_slow', '_fast'))

        # Extrahiere die wahren und vorhergesagten Labels
        true_labels = merged_df['IPID Pattern_slow']
        predicted_labels = merged_df['IPID Pattern_fast']

        # Vorgegebene Klassenreihenfolge
        classes = ["Constant", "Global", "Local (=1)", "Local (≥1)", "Random", "Anomalous"]

        # Erstelle die Confusion Matrix
        conf_matrix = confusion_matrix(true_labels, predicted_labels, labels=classes)

        # Normalisiere jede Zeile der Confusion Matrix
        conf_matrix_relative = (conf_matrix.T / conf_matrix.sum(axis=1)).T * 100
        conf_matrix_relative = np.nan_to_num(conf_matrix_relative)
        conf_matrix_relative = np.round(conf_matrix_relative).astype(int)

        # IP-Adressen für falsch klassifizierte Einträge
        output = []
        for i, true_class in enumerate(classes):
            for j, predicted_class in enumerate(classes):
                if i != j:  # Nur Nicht-Diagonalen prüfen
                    misclassified = merged_df[
                        (true_labels == true_class) & (predicted_labels == predicted_class)
                        ]
                    if not misclassified.empty:
                        output.append(
                            f"Von '{true_class}' falsch klassifiziert als '{predicted_class}': {len(misclassified)} IP-Adressen"
                        )
                        output.append(
                            ", ".join(misclassified['IP'].to_list()[:10]) + " ...")  # Zeige nur die ersten 10 IPs

        # Drucke zusammengefasste und gekürzte Ausgabe
        print("\nIP-Adressen der falsch klassifizierten IP-ID Sequenzen:")
        for line in output:
            print(line)

        # Visualisiere die Confusion Matrix
        disp = ConfusionMatrixDisplay(conf_matrix_relative, display_labels=classes)
        disp.plot(cmap="Blues", xticks_rotation=45, values_format='d')

        # Setze Farbskala auf festen Bereich (0 bis 100)
        disp.im_.set_clim(0, 100)

        # Beschriftungen anpassen
        plt.setp(disp.ax_.get_xticklabels(), fontsize=12)
        plt.setp(disp.ax_.get_yticklabels(), fontsize=12)
        disp.ax_.set_xlabel("Back-To-Back", fontsize=14)
        disp.ax_.set_ylabel("Sequential", fontsize=14)
        cbar = disp.im_.colorbar
        cbar.ax.tick_params(labelsize=12)
        plt.tight_layout()
        # plt.show()
        plt.savefig("confusion_matrix.pdf", format="pdf", bbox_inches="tight")

    # Probing Intervals
    def probing_intervals(probing_df, max_probing_interval, mode):
        probing_df = probing_df[probing_df['IsValid-Sequence'].apply(lambda x: all(i == 1 for i in literal_eval(x)))]
        probing_df = probing_df[['IP', 'SentTime-Sequence']]

        data = [
            diff for sent_time_sequence in probing_df['SentTime-Sequence'].apply(literal_eval)
            for diff in np.diff(sent_time_sequence) / 1_000_000
        ]

        filtered_data = [value for value in data if value <= max_probing_interval]
        plt.figure(figsize=(10, 6))
        plt.hist(filtered_data, bins=80, weights=np.ones(len(filtered_data)) * 100 / len(filtered_data))
        plt.xlabel("Time between Requests (ms)", fontsize=20)
        plt.ylabel("Relative Frequency (%)", fontsize=20)
        # plt.title("Relative Frequency Distribution: Time between Requests")
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.xlim(0, max_probing_interval)
        plt.xticks(fontsize=20)
        plt.yticks(fontsize=20)
        plt.tight_layout()
        # plt.show()
        plt.savefig(f"{mode}_probing_intervals.pdf", format="pdf", bbox_inches="tight")

        counts = Counter(data)
        total_count = sum(counts.values())
        less_equal_max = sum(count for value, count in counts.items() if value <= max_probing_interval)
        greater_than_max = sum(count for value, count in counts.items() if value > max_probing_interval)
        print(f"Probing Interval:")
        print(f"0-{max_probing_interval}: {less_equal_max} ({(less_equal_max / total_count) * 100:.2f}%)")
        print(f">{max_probing_interval}: {greater_than_max} ({(greater_than_max / total_count) * 100:.2f}%)")

    # RTT by Continent Distribution
    def distribution_rtt_by_continent(eval_df, max_avg_rtt):
        filtered_df = eval_df[(eval_df["Avg RTT"] <= max_avg_rtt) & (eval_df["Continent"] != "Antarctica")]
        continent_order = (
            filtered_df["Continent"].value_counts()
            .sort_values(ascending=False)
            .index
        )

        plt.figure(figsize=(10, 6))
        sns.violinplot(
            x="Continent",
            y="Avg RTT",
            data=filtered_df,
            cut=0,
            inner="quartile",
            density_norm="count",
            order=continent_order,
        )
        plt.xlabel("")
        plt.ylabel("Average RTT (ms)", fontsize=20)
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.ylim(0, max_avg_rtt)
        plt.xticks(fontsize=20, rotation=30)
        plt.yticks(fontsize=20)
        plt.tight_layout()
        # plt.show()
        plt.savefig("seq_rtt_dist.pdf", format="pdf", bbox_inches="tight")

    # Inc Distribution
    def distribution_counter_inc(probing_df, eval_df, global_max_inc, local_ge1_max_inc, mode):
        probing_df = probing_df[probing_df['IsValid-Sequence'].apply(lambda x: all(i == 1 for i in literal_eval(x)))]
        probing_df = probing_df[['IP', 'IPID-Sequence']]

        eval_df = eval_df[eval_df['IPID Pattern'].isin(['Global', 'Local (≥1)'])]

        df = pd.merge(probing_df, eval_df, on="IP", how="inner")

        data_local_ge1 = []
        data_global = []
        for _, row in df.iterrows():
            ipid_sequence = literal_eval(row['IPID-Sequence'])
            pattern = row['IPID Pattern']
            parts = IPIDParts(ipid_sequence)
            if pattern == 'Local (≥1)':
                a_incs = [value for value in parts.incs_a.tolist()]  # if value <= local_ge1_max_inc]
                b_incs = [value for value in parts.incs_b.tolist()]  # if value <= local_ge1_max_inc]
                data_local_ge1.extend(a_incs)
                data_local_ge1.extend(b_incs)
            elif pattern == 'Global':
                s_incs = [value for value in parts.incs_s.tolist()]  # if value <= 200]
                data_global.extend(s_incs)

        def plot_ipid_distribution(data, max_inc, label, mode):
            filtered_data = [value for value in data if value <= max_inc]
            plt.figure(figsize=(10, 6))
            plt.hist(filtered_data, bins=50, weights=np.ones(len(filtered_data)) * 100 / len(filtered_data))
            plt.xlabel("IP-ID Increment", fontsize=20)
            plt.ylabel("Relative Frequency (%)", fontsize=20)
            plt.xlim(0, max_inc)
            plt.grid(True, linestyle='--', alpha=0.6)
            plt.xticks(fontsize=20)
            plt.yticks(fontsize=20)
            plt.tight_layout()
            # plt.show()
            plt.savefig(f"{mode}_{label}_inc_dist.pdf", format="pdf", bbox_inches="tight")

            counts = Counter(data)
            total_count = sum(counts.values())
            less_equal_max = sum(count for value, count in counts.items() if value <= max_inc)
            greater_than_max = sum(count for value, count in counts.items() if value > max_inc)
            print(f"{label.capitalize()}:")
            print(f"0-{max_inc}: {less_equal_max} ({(less_equal_max / total_count) * 100:.2f}%)")
            print(f">{max_inc}: {greater_than_max} ({(greater_than_max / total_count) * 100:.2f}%)")

        plot_ipid_distribution(data_global, global_max_inc, "global", mode)
        plot_ipid_distribution(data_local_ge1, local_ge1_max_inc, "local_ge1", mode)

    fast_eval = pd.read_csv(get_csv_file(fast_msm, "eval"))
    fast_probing = pd.read_csv(get_csv_file(fast_msm, "probing"))

    slow_eval = pd.read_csv(get_csv_file(slow_msm, "eval"))
    slow_probing = pd.read_csv(get_csv_file(slow_msm, "probing"))

    slow_eval = slow_eval[slow_eval['IP'].isin(fast_eval['IP'])]
    fast_eval = fast_eval[fast_eval['IP'].isin(slow_eval['IP'])]

    slow_probing = slow_probing[slow_probing['IP'].isin(slow_eval['IP'])]
    fast_probing = fast_probing[fast_probing['IP'].isin(fast_eval['IP'])]

    print(len(slow_eval))
    print(len(fast_eval))
    print(len(slow_probing))
    print(len(fast_probing))

    print("Fast:")
    fast_pattern = class_dist(fast_eval, "b2b_class_dist")
    print("Slow:")
    slow_pattern = class_dist(slow_eval, "seq_class_dist")

    print("Difference:")
    diff_pattern = fast_pattern - slow_pattern
    print(diff_pattern)
    plt_difference(diff_pattern)

    confusion_mtx_optimized()
    #
    # probing_intervals(slow_probing, 800, "seq")
    # distribution_rtt_by_continent(slow_eval, 500)
    # distribution_counter_inc(slow_probing, slow_eval, 2500, 800, "seq")
    #
    # probing_intervals(fast_probing, 20, "b2b")
    # distribution_counter_inc(fast_probing, fast_eval, 800, 100, "b2b")


def class_distribution_per_hop(proto, hops_msm, endpoints_msm):
    import pandas as pd
    import matplotlib.pyplot as plt
    import json

    # Lade die Auswertungsdaten
    hops_eval_df = pd.read_csv(get_csv_file(hops_msm, "eval"))
    endpoints_eval_df = pd.read_csv(get_csv_file(endpoints_msm, "eval"))

    # Lade die Hops-to-IPs-Daten
    with open("create_ripe_hitlist/hop_to_ips.json", "r") as f:
        hop_to_ips = {k: set(v) for k, v in json.load(f).items()}

    # Entferne Hop Nummer 255
    hop_to_ips = {k: v for k, v in hop_to_ips.items() if int(k) != 255}

    # Extrahiere Hops und IP-Anzahlen
    hops = sorted(hop_to_ips.keys(), key=int)

    # Berechne Klassenverteilung pro Hop (Prozente) und Gesamtanzahl der IPs
    pattern_mapping = {
        'const': 'Constant',
        'global': 'Global',
        'local_eq1': 'Local (=1)',
        'local_ge1': 'Local (≥1)',
        'random': 'Random',
        'odd': 'Anomalous'
    }

    class_distributions = []
    total_ips_per_hop = []

    for hop in hops:
        hop_ips = hop_to_ips[hop]
        ip_pattern_counts = hops_eval_df[hops_eval_df['IP'].isin(hop_ips)]['IPID Pattern'].map(pattern_mapping).value_counts()
        total = sum(ip_pattern_counts)
        percentages = (ip_pattern_counts / total * 100).to_dict()
        class_distributions.append(percentages)
        total_ips_per_hop.append(total)

    # Füge die Verteilung des letzten Hops (Endpoints) hinzu
    endpoint_pattern_counts = endpoints_eval_df['IPID Pattern'].map(pattern_mapping).value_counts()
    total_endpoints = sum(endpoint_pattern_counts)
    endpoint_percentages = (endpoint_pattern_counts / total_endpoints * 100).to_dict()
    class_distributions.append(endpoint_percentages)
    total_ips_per_hop.append(total_endpoints)

    # Farben für die Klassen
    colors = {
        "Constant": "#2ca02c",
        "Global": "#1f77b4",
        "Local (=1)": "#ff7f0e",
        "Local (≥1)": "#d62728",
        "Random": "#bcbd22",
        "Anomalous": "#7f7f7f"
    }

    # Erstelle das Diagramm
    x_labels = hops + ["Endpoint"]
    bottoms = [0] * len(x_labels)

    fig, ax1 = plt.subplots(figsize=(13, 8))
    ax2 = ax1.twinx()

    # Gestapelte Balken
    for cls in colors:
        values = [dist.get(cls, 0) for dist in class_distributions]
        ax1.bar(x_labels, values, bottom=bottoms, color=colors[cls], label=cls)
        bottoms = [b + v for b, v in zip(bottoms, values)]

    # Scatterplot für die Anzahl der IPs
    ax2.scatter(x_labels, total_ips_per_hop, color="black", label="IP Address Count", zorder=5)

    # Achsentitel und Beschriftungen mit Schriftgröße 14
    ax1.set_xlabel("Hop Number", fontsize=16)
    ax1.set_ylabel("Class Share (%)", fontsize=16)
    ax2.set_ylabel("IP Address Count", fontsize=16)
    ax1.set_ylim(0, 100)
    ax2.set_ylim(0, max(total_ips_per_hop) * 1.1)

    # ax1.set_title(f"Relative Class Distribution per Hop with Total IPs for Measurement {hops_msm}", fontsize=14)
    ax1.set_xticks(range(len(x_labels)))
    ax1.set_xticklabels(x_labels, rotation=45, fontsize=10)
    ax1.yaxis.set_tick_params(labelsize=14)
    ax2.yaxis.set_tick_params(labelsize=14)

    # Legenden kombinieren und außerhalb platzieren
    handles1, labels1 = ax1.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(handles1 + handles2, labels1 + labels2, loc="upper left", bbox_to_anchor=(1.15, 1), fontsize=16)

    plt.tight_layout()
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    # plt.show()
    plt.savefig(f"{proto}_class_dist_per_hop.pdf", format="pdf", bbox_inches="tight")


def plot_ipid_sequence():
    # Daten und Indizes
    data = [
        6260, 20171, 20172, 20173, 20174, 6261, 20175, 20177, 20178, 20179,
        20180, 6262, 20181, 20182, 6263, 20183, 20185, 20186, 20187, 20188
    ]

    indices = list(range(len(data)))

    # Plot erstellen
    plt.figure(figsize=(8, 5))

    # Linie für VP₁ mit dünner Linie
    plt.plot(indices, data, linestyle='-', color='tab:blue', linewidth=0.5,
             markerfacecolor='white', marker='o', markersize=8, markeredgecolor='tab:blue',
             label=r'$\mathrm{VP}_1$')

    # VP₂ mit leeren Punkten
    plt.plot(indices[::2], data[::2], linestyle='None', marker='o', markersize=8,
             markeredgecolor='tab:blue', linewidth=0.5,
             label=r'$\mathrm{VP}_2$')

    # Achsentitel und Beschriftungen
    plt.xticks(indices[::2], fontsize=16)
    plt.yticks(fontsize=16)
    plt.xlabel("Sequence Index", fontsize=16)
    plt.ylabel("IP-ID", fontsize=16)

    # Gitterlinien
    plt.grid(True, linestyle='--', alpha=0.7)

    # Custom Legendeneinträge erstellen
    custom_legend = [
        Line2D([0], [0], linestyle='-', markersize=8, linewidth=0.5, marker='o', color='tab:blue', label=r'$\mathrm{VP}_1$'),
        Line2D([0], [0], linestyle='-', markerfacecolor='white', markersize=8, linewidth=0.5, marker='o', color='tab:blue', label=r'$\mathrm{VP}_2$')
    ]

    # Hauptlegende + Custom-Legende
    plt.legend(handles=custom_legend, fontsize=16)

    # Layout anpassen und anzeigen
    plt.tight_layout()
    plt.savefig("per_cpu_counter_2_cores.pdf", format='pdf', bbox_inches='tight')
    plt.show()


def get_csv_file(msm, file):
    return f"../{msm}/{file}.csv"


@dataclass
class OSFilter:
    name: str
    filter: str


# df_hops = pd.read_csv(get_csv_file(f"measurements/slow/hops_{proto}", "eval"))
# df_endpoints = pd.read_csv(get_csv_file(f"measurements/slow/endpoints_{proto}", "eval"))
# a = class_dist(df_hops, f"hops_{proto}_class_dist")
# b = class_dist(df_endpoints, f"endpoints_{proto}_class_dist")
# print()
# print("Difference")
# print(a - b)

# proto = "dns"
# class_distribution_per_hop(proto, f"measurements/slow/hops_{proto}", f"measurements/slow/endpoints_{proto}")

fast_slow_comparison("measurements/fast/base_icmp", "measurements/slow/base_icmp")

# plot_ipid_sequence()

# all_oses = ("ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows "
#             "server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt"
#             "|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco "
#             "ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos"
#             "|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos"
#             "|openembedded|yocto|utm|gaia|router")

# no_filter = OSFilter(
#     name="Total",
#     filter=all_oses
# )
#
# linux_filter = OSFilter(
#     name="Linux",
#     filter="ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|linux"
# )

# ubuntu_filter = OSFilter(
#     name="Ubuntu",
#     filter="ubuntu"
# )
#
# debian_filter = OSFilter(
#     name="Debian",
#     filter="debian"
# )
#
# centos_filter = OSFilter(
#     name="Centos",
#     filter="centos"
# )
#
# linux_filter = OSFilter(
#     name="Other Linux Distributions",
#     filter="redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|linux"
# )

# windows_server_filter = OSFilter(
#     name="Windows_Server",
#     filter="windows server",
# )
#
# windows_filter = OSFilter(
#     name="Windows",
#     filter="windows",
# )
#
# macos_filter = OSFilter(
#     name="macOS",
#     filter="macos|darwin",
# )
#
# free_bsd_filter = OSFilter(
#     name="Free_BSD",
#     filter="freebsd",
# )
#
# open_bsd_filter = OSFilter(
#     name="Open_BSD",
#     filter="openbsd",
# )
#
# sonic_filter = OSFilter(
#     name="SonicOS",
#     filter="sonic|sonicwall",
# )
#
# cisco_filter = OSFilter(
#     name="Cisco",
#     filter="cisco ios|ios-xe|nx-os|ios|cisco",
# )
#
# rasp_filter = OSFilter(
#     name="Raspberry",
#     filter="rasp",
# )
#
# mikrotik_filter = OSFilter(
#     name="Mikrotik",
#     filter="mikrotik",
# )
#
# aruba_filter = OSFilter(
#     name="Aruba",
#     filter="aruba",
# )
#
# dray_filter = OSFilter(
#     name="Dray",
#     filter="dray",
# )
#
# end_filter = OSFilter(
#     name="End devices",
#     filter="ubuntu|centos|debian|redhat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows "
#            "server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|aix|hp-ux|hpux|z/os|zos|openvms|vms"
#            "|busybox|vxworks|qnx|freertos|openembedded|yocto"
# )
#
# router_filter = OSFilter(
#     name="Router devices",
#     filter="junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos"
#            "|aruba|draytek|drayos|vigor|dray|zynos|zyxel|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros"
#            "|mikrotik|edgeos|airos|unifi|ubiquiti|fritz|rasp"
# )
#
# proto = "http"
# msm = f"measurements/slow/banner_grab_{proto}"
# path = f"../{msm}"
#
# eval_csv_file = f"{path}/eval.csv"

# class_distribution(eval_csv_file)
# class_distribution(eval_csv_file, no_filter)
# class_distribution(eval_csv_file, ubuntu_filter)
# class_distribution(eval_csv_file, debian_filter)
# class_distribution(eval_csv_file, centos_filter)
# class_distribution(eval_csv_file, linux_filter)
# class_distribution(eval_csv_file, free_bsd_filter)
# class_distribution(eval_csv_file, open_bsd_filter)
# class_distribution(eval_csv_file, windows_server_filter)
# class_distribution(eval_csv_file, windows_filter)
# class_distribution(eval_csv_file, sonic_filter)
# class_distribution(eval_csv_file, cisco_filter)
# class_distribution(eval_csv_file, rasp_filter)
# class_distribution(eval_csv_file, sonic_filter)
# class_distribution(eval_csv_file, mikrotik_filter)
# class_distribution(eval_csv_file, aruba_filter)
# class_distribution(eval_csv_file, dray_filter)
# class_distribution(eval_csv_file, end_filter)
# class_distribution(eval_csv_file, router_filter)

# os_distribution(eval_csv_file, end_filter)
# os_distribution(eval_csv_file, router_filter)
