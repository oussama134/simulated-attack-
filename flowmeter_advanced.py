import sys
from scapy.all import rdpcap, TCP, UDP, IP
import pandas as pd
import numpy as np
import time

def compute_iat(timestamps):
    if len(timestamps) < 2:
        return 0, 0, 0, 0
    diffs = np.diff([float(t) for t in timestamps])  # convert all to float
    return np.mean(diffs), np.max(diffs), np.min(diffs), np.std(diffs)

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        timestamp = pkt.time
        length = len(pkt)

        forward = (src, dst, proto)
        backward = (dst, src, proto)

        if forward in flows:
            direction = "fwd"
            flow_id = forward
        elif backward in flows:
            direction = "bwd"
            flow_id = backward
        else:
            direction = "fwd"
            flow_id = forward
            flows[flow_id] = {
                "src": src,
                "dst": dst,
                "proto": proto,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "fwd_timestamps": [],
                "bwd_timestamps": [],
                "pkt_lengths": [],
                "flags": {"syn":0, "ack":0, "fin":0, "rst":0}
            }

        # --- Update flow stats ---
        flows[flow_id]["pkt_lengths"].append(length)

        if direction == "fwd":
            flows[flow_id]["fwd_packets"] += 1
            flows[flow_id]["fwd_bytes"] += length
            flows[flow_id]["fwd_timestamps"].append(timestamp)
        else:
            flows[flow_id]["bwd_packets"] += 1
            flows[flow_id]["bwd_bytes"] += length
            flows[flow_id]["bwd_timestamps"].append(timestamp)

        # Parse TCP flags
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02: flows[flow_id]["flags"]["syn"] += 1
            if flags & 0x10: flows[flow_id]["flags"]["ack"] += 1
            if flags & 0x01: flows[flow_id]["flags"]["fin"] += 1
            if flags & 0x04: flows[flow_id]["flags"]["rst"] += 1

    # Convert flows to DataFrame
    rows = []

    for fid, f in flows.items():
        fwd_iat_mean, fwd_iat_max, fwd_iat_min, fwd_iat_std = compute_iat(f["fwd_timestamps"])
        bwd_iat_mean, bwd_iat_max, bwd_iat_min, bwd_iat_std = compute_iat(f["bwd_timestamps"])

        row = {
            "src": f["src"],
            "dst": f["dst"],
            "proto": f["proto"],
            "fwd_packets": f["fwd_packets"],
            "bwd_packets": f["bwd_packets"],
            "fwd_bytes": f["fwd_bytes"],
            "bwd_bytes": f["bwd_bytes"],
            "total_packets": f["fwd_packets"] + f["bwd_packets"],
            "total_bytes": f["fwd_bytes"] + f["bwd_bytes"],

            # Packet length stats
            "pkt_len_mean": np.mean(f["pkt_lengths"]),
            "pkt_len_max": np.max(f["pkt_lengths"]),
            "pkt_len_min": np.min(f["pkt_lengths"]),
            "pkt_len_std": np.std(f["pkt_lengths"]),

            # IAT stats
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_max": fwd_iat_max,
            "fwd_iat_min": fwd_iat_min,
            "fwd_iat_std": fwd_iat_std,

            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_max": bwd_iat_max,
            "bwd_iat_min": bwd_iat_min,
            "bwd_iat_std": bwd_iat_std,

            # Flags
            "syn_count": f["flags"]["syn"],
            "ack_count": f["flags"]["ack"],
            "fin_count": f["flags"]["fin"],
            "rst_count": f["flags"]["rst"],
        }

        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv("/opt/flows_advanced.csv", index=False)
    print("[+] 78-feature flow extraction complete → /opt/flows_advanced.csv")

if __name__ == "__main__":
    extract_features(sys.argv[1])
