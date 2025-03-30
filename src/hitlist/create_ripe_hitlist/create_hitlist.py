import requests
from datetime import datetime, timedelta
import json


def fetch_traceroute_results(measurement_id, minutes=10):
    end_time = int(datetime.now().timestamp())
    start_time = int((datetime.now() - timedelta(minutes=minutes)).timestamp())

    url = f"https://atlas.ripe.net/api/v2/measurements/{measurement_id}/results/?start={start_time}&stop={end_time}"
    response = requests.get(url)

    if response.status_code == 200:
        results = response.text
        with open("data.txt", "w") as file:
            file.write(results)
        print("Results saved successfully!")
    else:
        print(f"Failed to fetch results. Status code: {response.status_code}")


def save_ip_set(file_path, ip_set):
    with open(file_path, "w") as file:
        file.write(f"IP\n")
        for ip in ip_set:
            file.write(f"{ip}\n")


def process_traceroute_data(file_path):
    startpoint_ips = set()
    hop_ips = set()
    endpoint_ips = set()

    try:
        with open(file_path, 'r') as file:
            data = file.read()

        json_data = json.loads(data)

        for probe in json_data:
            # Extract Startpoint IP
            startpoint_ips.add(probe.get("src_addr"))

            # Extract Hop IPs
            for hop in probe.get("result", []):
                for result in hop.get("result", []):
                    hop_ip = result.get("from")
                    if hop_ip:
                        hop_ips.add(hop_ip)

            # Extract Endpoint IP
            endpoint_ips.add(probe.get("dst_addr"))

        save_ip_set("../../targets/startpoints.csv", startpoint_ips)
        save_ip_set("../../targets/hops.csv", hop_ips)
        save_ip_set("../../targets/endpoints.csv", endpoint_ips)

        print("Startpoint IPs:", len(startpoint_ips))
        print("Hop IPs:", len(hop_ips))
        print("Endpoint IPs:", len(endpoint_ips))

    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except json.JSONDecodeError:
        print("Error parsing JSON data.")


def create_hop_to_ips(file_path):
    hop_to_ips = {}

    try:
        with open(file_path, 'r') as file:
            data = file.read()

        json_data = json.loads(data)

        for probe in json_data:
            for hop in probe.get("result", []):
                hop_id = hop.get("hop", None)
                if hop_id:
                    for result in hop.get("result", []):
                        hop_ip = result.get("from")
                        if hop_ip:
                            hop_to_ips.setdefault(hop_id, set()).add(hop_ip)

        with open("data.json", "w") as f:
            json.dump({k: list(v) for k, v in hop_to_ips.items()}, f)

    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except json.JSONDecodeError:
        print("Error parsing JSON data.")


if __name__ == "__main__":
    measurement_id = 5151
    # fetch_traceroute_results(measurement_id, minutes=60*24)
    # process_traceroute_data("data.txt")
    create_hop_to_ips("data.txt")
