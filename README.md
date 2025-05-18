# ipid

Measurement and Analysis of the IP Identification Field in IPv4

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Pipeline

### 0. Hitlist

Generate a list of IPv4 addresses with associated timestamps indicating when each was discovered.
For TCP/80 and UDP/53, optional OS fingerprinting is available.

Available commands for generating a hitlist:

```
python3 0_hitlist.py ip_scan icmp [max_ips]
python3 0_hitlist.py ip_scan tcp <port> [max_ips] [enable_os_scan]
python3 0_hitlist.py ip_scan udp <port> [max_ips] [enable_os_scan]
python3 0_hitlist.py os_scan <targets_path>
```

### 1. Probing

Configure your desired parameters in `config.yaml`.

Available commands for probing:

```
python3 1_probing.py b2b
python3 1_probing.py seq
```

### 2. Post-Processing

After probing, process the collected data using:

```
python3 2_postproc.py <result_path>
```

### 3. Analysis

Once post-processing is complete, analyze the processed data with:

```
python3 3_analysis.py <result_path>
```








## Example Pipeline

### 0. Hitlist

Generate a list of 10 million IPv4 addresses that respond to TCP/80 SYN packets with a TCP reply.
After collecting the IPs, perform OS fingerprinting to determine the operating system for each IP on port 80.

**Command:**
```
python3 0_hitlist.py ip_scan tcp 80 10M true
```

**Output:**
* IP scan: `targets/tcp/80/<timestamp>/targets.csv.zst`
* OS fingerprinting (enabled by `enable_os_scan=true`): `targets/tcp/80/<timestamp>/targets_os.csv.zst`

### 1. Probing

Edit the following fields in `config.yaml`:
```yaml
targets: "targets/tcp/80/<timestamp>"
protocol: "tcp"
tcp_dst_port: 80
tcp_request_flags: "S"
```

Use the **Sequential** method for probing:

**Command:**
```
python3 1_probing.py seq
```

**Output:**
* Probing results: `results/seq/tcp/80/<timestamp>/probing.csv.zst`

### 2. Post-Processing

Process the probing results:

**Command:**
```
python3 2_postproc.py results/seq/tcp/80/<timestamp>
```

### 3. Analysis

Analyze the processed data:

**Command:**
```
python3 3_analysis.py results/seq/tcp/80/<timestamp>
```

**Output:**
* Analysis results: `results/seq/tcp/80/<timestamp>/analysis`
