import sys
from scapy.all import rdpcap
import pandas as pd

def extract_flows(pcap_file):
    packets = rdpcap(pcap_file)
    flows = {}

    for pkt in packets:
        if 'IP' in pkt:
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            proto = pkt['IP'].proto

            flow_id = (src, dst, proto)

            if flow_id not in flows:
                flows[flow_id] = {
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "packet_count": 0,
                    "byte_count": 0
                }

            flows[flow_id]["packet_count"] += 1
            flows[flow_id]["byte_count"] += len(pkt)

    df = pd.DataFrame(flows.values())
    df.to_csv("/opt/flows.csv", index=False)
    print("[+] Flow extraction complete → /opt/flows.csv")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 flowmeter.py file.pcap")
        sys.exit(1)

    extract_flows(sys.argv[1])
