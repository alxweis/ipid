# ipid

Measurement and Analysis of the IP Identification Field in IPv4

## Setup

This project is designed **exclusively for Linux systems**. It requires **two network interfaces**, each with a *
*publicly reachable IPv4 address**. Without this setup, the measurements will not work.

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -e .
   ```

2. **Configure your network interfaces** in `config.yaml`:

   ```yaml
   iface_a:
     name: "<your_first_interface_name>"   # e.g. eth0
     ip: "<your_first_interface_ipv4_address>"   # e.g. 123.45.67.89
   iface_b:
     name: "<your_second_interface_name>"  # e.g. eth1
     ip: "<your_second_interface_ipv4_address>"  # e.g. 123.45.67.90
   ```

3. All other parameters in `config.yaml` can be optionally adjusted as needed.

## Pipeline

### 0. Hitlist

Generate a list of IPv4 addresses with associated timestamps indicating when each was discovered. Optional OS
fingerprinting is available.

Available commands for generating a hitlist:

```
python3 0_hitlist.py ip_scan icmp [max_ips] [enable_os_scan]
python3 0_hitlist.py ip_scan tcp <port> [max_ips] [enable_os_scan]
python3 0_hitlist.py ip_scan udp <port> [max_ips] [enable_os_scan]
python3 0_hitlist.py os_scan <targets_path>
```

**Output:**

* IP-Scan: `targets/<protocol>/<port>/<timestamp>/targets.csv.zst`
* OS-Scan: `targets/<protocol>/<port>/<timestamp>/targets_os.csv.zst`

**Example Prompts:**

```
python3 0_hitlist.py ip_scan icmp 10M     // Finds 10M IPv4 addresses responding to ICMP Echo Requests
python3 0_hitlist.py ip_scan tcp 80 0 true     // Finds all IPv4 addresses responding to TCP SYN on port 80. Runs OS fingerprinting
python3 0_hitlist.py ip_scan udp 53 250K false     // Finds 250K IPv4 addresses responding to DNS (UDP) on port 53
python3 0_hitlist.py os_scan targets/tcp/80/2006-01-02_15-04-05      // Runs OS fingerprinting on IP list from the given path
```

### 1. Probing

Configure your desired parameters in `config.yaml`:

```yaml
targets: "targets/<protocol>/<port>/<timestamp>"
protocol: "<protocol>"

# TCP
tcp_dst_port: 80
tcp_request_flags: "S" # S=SYN A=ACK R=RST, e.g. "SA" for SYN-ACK

# UDP
udp_dst_port: 53
```

Other parameters in `config.yaml` can be optionally adjusted as needed.

Available commands for probing:

```
python3 1_probing.py b2b <ip|os>   // Refers to Back-To-Back Probing (B2B)
python3 1_probing.py seq <ip|os>   // Refers to Sequential Probing (SEQ)
```

See `config.yaml` for optional probing parameters.

**Output:**

* `results/<protocol>/<port>/<timestamp>/probing.csv.zst`

### 2. Post-Processing

After probing, process the collected data using:

```
python3 2_postproc.py <result_path>
```

**Output:**

* `results/<protocol>/<port>/<timestamp>/eval.csv.zst`

### 3. Analysis

Once post-processing is complete, analyze the processed data with:

```
python3 3_analysis.py <result_path>
```

**Output:**

* Plots and additional data is saved at: `results/<protocol>/<port>/<timestamp>/analysis/`

## Experimental

Run `X_experimental.py` to perform additional investigations that are not directly part of the core IP-ID measurement
analysis.

The following commands are available:

### Analyze Synthetic Sequence Stable Lengths

Analyze how many IP-IDs are needed in synthetically generated sequences before the classification result becomes stable.

```
python X_experimental.py 1 <sequence_count_per_pattern> <sequence_length>
```

**Output:**

* Plot is saved at: `results/experimental/sequence_stable_classification_len/<sequence_count>_<sequence_length>/`

### Analyze Natural Sequence Stable Lengths

Analyze how many IP-IDs are needed in real measured sequences before the classification result becomes stable.

```
python X_experimental.py 2 <result_path>
```

**Output:**

* Plot and additional data are saved at: `<result_path>/analysis/sequence_stable_classification_len/`

### Analyze Response Rate for IP-Scan or OS-Scan

Analyze how many targets are successfully identified per second in an IP or OS scan.

```
python X_experimental.py 3 <targets_full_path>
```

**Output:**

* Plot and additional data are saved at: `<targets_full_path>/analysis/response_rate_<ip|os>_scan/`

### Analyze Intersections

Analyze how much overlap exists between the targets collected by two or more scans.

```
python X_experimental.py 4 <targets_full_path> <targets_full_path> ...
```

**Example Prompt:**

```
python X_experimental.py 4 targets/tcp/80/2006-01-02_15-04-05/targets.csv.zst targets/udp/53/2006-01-03_16-05-06/targets_os.csv.zst
```

**Output:**

* Results are saved at: `results/experimental/intersections/<targets_full_id>+<targets_full_id>+.../`
