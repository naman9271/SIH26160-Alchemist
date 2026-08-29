# Dataset Audit

Generated: 2026-08-29T10:07:58.710361+00:00

Each top-level entry is reported independently. No datasets were combined or modified.

## cicdarknet2020.parquet

- Files: 1 (12.2 MiB)
- Formats: parquet
- Raw PCAP/PCAPNG present: False
- Inferred type(s): VPN, Tor
- Label columns: Label
- FlowFeatures overlap: {"duration": ["Flow Duration"], "mean_packet_size": ["Avg Packet Size"]}
- Possible leakage: Label

### Target-class mappings
- None

### Unresolved labels

None

### Labels not to map

Non-Tor, NonVPN, Tor, VPN

### Tabular details

#### `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/data/external/cicdarknet2020.parquet`

- Rows: 103121
- Columns: Protocol, Flow Duration, Total Fwd Packet, Total Bwd packets, Total Length of Fwd Packet, Total Length of Bwd Packet, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Packet Length Min, Packet Length Max, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Avg Packet Size, Fwd Segment Size Avg, Bwd Segment Size Avg, Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg, Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, FWD Init Win Bytes, Bwd Init Win Bytes, Fwd Act Data Packets, Fwd Seg Size Min, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label, Label.1
- Unique labels: `{"Label": ["Non-Tor", "NonVPN", "Tor", "VPN"]}`
- Class counts: `{"Label": {"Non-Tor": 64804, "NonVPN": 20216, "Tor": 1179, "VPN": 16922}}`
- Missing values: `{"ACK Flag Count": 0, "Active Max": 0, "Active Mean": 0, "Active Min": 0, "Active Std": 0, "Avg Packet Size": 0, "Bwd Bulk Rate Avg": 0, "Bwd Bytes/Bulk Avg": 0, "Bwd Header Length": 0, "Bwd IAT Max": 0, "Bwd IAT Mean": 0, "Bwd IAT Min": 0, "Bwd IAT Std": 0, "Bwd IAT Total": 0, "Bwd Init Win Bytes": 0, "Bwd PSH Flags": 0, "Bwd Packet Length Max": 0, "Bwd Packet Length Mean": 0, "Bwd Packet Length Min": 0, "Bwd Packet Length Std": 0, "Bwd Packet/Bulk Avg": 0, "Bwd Packets/s": 0, "Bwd Segment Size Avg": 0, "Bwd URG Flags": 0, "CWE Flag Count": 0, "Down/Up Ratio": 0, "ECE Flag Count": 0, "FIN Flag Count": 0, "FWD Init Win Bytes": 0, "Flow Bytes/s": 0, "Flow Duration": 0, "Flow IAT Max": 0, "Flow IAT Mean": 0, "Flow IAT Min": 0, "Flow IAT Std": 0, "Flow Packets/s": 0, "Fwd Act Data Packets": 0, "Fwd Bulk Rate Avg": 0, "Fwd Bytes/Bulk Avg": 0, "Fwd Header Length": 0, "Fwd IAT Max": 0, "Fwd IAT Mean": 0, "Fwd IAT Min": 0, "Fwd IAT Std": 0, "Fwd IAT Total": 0, "Fwd PSH Flags": 0, "Fwd Packet Length Max": 0, "Fwd Packet Length Mean": 0, "Fwd Packet Length Min": 0, "Fwd Packet Length Std": 0, "Fwd Packet/Bulk Avg": 0, "Fwd Packets/s": 0, "Fwd Seg Size Min": 0, "Fwd Segment Size Avg": 0, "Fwd URG Flags": 0, "Idle Max": 0, "Idle Mean": 0, "Idle Min": 0, "Idle Std": 0, "Label": 0, "Label.1": 0, "PSH Flag Count": 0, "Packet Length Max": 0, "Packet Length Mean": 0, "Packet Length Min": 0, "Packet Length Std": 0, "Packet Length Variance": 0, "Protocol": 0, "RST Flag Count": 0, "SYN Flag Count": 0, "Subflow Bwd Bytes": 0, "Subflow Bwd Packets": 0, "Subflow Fwd Bytes": 0, "Subflow Fwd Packets": 0, "Total Bwd packets": 0, "Total Fwd Packet": 0, "Total Length of Bwd Packet": 0, "Total Length of Fwd Packet": 0, "URG Flag Count": 0}`

## consolidated_traffic_data.csv

- Files: 1 (12.5 MiB)
- Formats: csv
- Raw PCAP/PCAPNG present: False
- Inferred type(s): VPN, application traffic
- Label columns: traffic_type
- FlowFeatures overlap: {"bytes_per_second": ["flowBytesPerSecond"], "duration": ["duration"], "mean_interarrival_time": ["mean_flowiat"], "std_interarrival_time": ["std_flowiat"]}
- Possible leakage: traffic_type

### Target-class mappings
- `BROWSING` → `web` (explicit dataset label or filename)
- `CHAT` → `messaging` (explicit dataset label or filename)
- `FT` → `file_transfer` (explicit dataset label or filename)
- `MAIL` → `email` (explicit dataset label or filename)
- `VOIP` → `voip` (explicit dataset label or filename)
- `VPN-BROWSING` → `web` (explicit traffic label with a VPN transport prefix)
- `VPN-CHAT` → `messaging` (explicit traffic label with a VPN transport prefix)
- `VPN-FT` → `file_transfer` (explicit traffic label with a VPN transport prefix)
- `VPN-MAIL` → `email` (explicit traffic label with a VPN transport prefix)
- `VPN-VOIP` → `voip` (explicit traffic label with a VPN transport prefix)

### Unresolved labels

STREAMING, VPN-P2P, VPN-STREAMING

### Labels not to map

P2P

### Tabular details

#### `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/data/external/consolidated_traffic_data.csv`

- Rows: 59706
- Columns: duration, total_fiat, total_biat, min_fiat, min_biat, max_fiat, max_biat, mean_fiat, mean_biat, flowPktsPerSecond, flowBytesPerSecond, min_flowiat, max_flowiat, mean_flowiat, std_flowiat, min_active, mean_active, max_active, std_active, min_idle, mean_idle, max_idle, std_idle, traffic_type
- Unique labels: `{"traffic_type": ["BROWSING", "CHAT", "FT", "MAIL", "P2P", "STREAMING", "VOIP", "VPN-BROWSING", "VPN-CHAT", "VPN-FT", "VPN-MAIL", "VPN-P2P", "VPN-STREAMING", "VPN-VOIP"]}`
- Class counts: `{"traffic_type": {"BROWSING": 10000, "CHAT": 2505, "FT": 3975, "MAIL": 1364, "P2P": 4000, "STREAMING": 1284, "VOIP": 6485, "VPN-BROWSING": 10000, "VPN-CHAT": 2839, "VPN-FT": 4704, "VPN-MAIL": 2444, "VPN-P2P": 3415, "VPN-STREAMING": 1115, "VPN-VOIP": 5576}}`
- Missing values: `{"duration": 0, "flowBytesPerSecond": 0, "flowPktsPerSecond": 0, "max_active": 0, "max_biat": 0, "max_fiat": 0, "max_flowiat": 0, "max_idle": 0, "mean_active": 0, "mean_biat": 0, "mean_fiat": 0, "mean_flowiat": 0, "mean_idle": 0, "min_active": 0, "min_biat": 0, "min_fiat": 0, "min_flowiat": 0, "min_idle": 0, "std_active": 0, "std_flowiat": 0, "std_idle": 0, "total_biat": 0, "total_fiat": 0, "traffic_type": 0}`

## ipsec-pcap-lab

- Files: 21 (205.4 MiB)
- Formats: csv, pcap
- Raw PCAP/PCAPNG present: True
- Inferred type(s): application traffic
- Label columns: traffic_class
- FlowFeatures overlap: {}
- Possible leakage: cipher, dh_group, esp_proposal, filename/path-derived labels (capture provenance; never use as a feature), ike_proposal, ike_version, integrity, mode, nat_t, nat_t_forced, outer_left, outer_right, pcap_file, pfs, sample_id, sha256, traffic_class, traffic_generator

### Target-class mappings
- `file` → `file_transfer` (explicit dataset label or filename)
- `ping` → `icmp` (explicit dataset label or filename)
- `video` → `video` (explicit dataset label or filename)
- `web` → `web` (explicit dataset label or filename)

### Unresolved labels

file_p, pcaps, ping_p, video_p, web_p

### Labels not to map

None

### Tabular details

#### `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/data/external/ipsec-pcap-lab/metadata.csv`

- Rows: 20
- Columns: sample_id, pcap_file, traffic_class, mode, ike_version, ike_proposal, esp_proposal, cipher, integrity, dh_group, pfs, ip_version, nat_t, nat_t_forced, actual_nat_present, peer_auth, capture_duration_s, outer_left, outer_right, traffic_generator, sha256
- Unique labels: `{"traffic_class": ["file", "ping", "video", "web"]}`
- Class counts: `{"traffic_class": {"file": 5, "ping": 5, "video": 5, "web": 5}}`
- Missing values: `{"actual_nat_present": 0, "capture_duration_s": 0, "cipher": 0, "dh_group": 0, "esp_proposal": 0, "ike_proposal": 0, "ike_version": 0, "integrity": 0, "ip_version": 0, "mode": 0, "nat_t": 0, "nat_t_forced": 0, "outer_left": 0, "outer_right": 0, "pcap_file": 0, "peer_auth": 0, "pfs": 0, "sample_id": 0, "sha256": 0, "traffic_class": 0, "traffic_generator": 0}`

## Network-Traffic-Dataset

- Files: 84 (6.5 GiB)
- Formats: pcap, pcapng
- Raw PCAP/PCAPNG present: True
- Inferred type(s): VPN, application traffic
- Label columns: none
- FlowFeatures overlap: {}
- Possible leakage: filename/path-derived labels (capture provenance; never use as a feature)

### Target-class mappings
- `Amazon Prime Video` → `video` (explicit dataset label or filename)
- `Dropbox` → `file_transfer` (explicit dataset label or filename)
- `Microsoft Teams` → `voip` (explicit dataset label or filename)
- `Skype` → `voip` (explicit dataset label or filename)
- `Slack` → `messaging` (explicit dataset label or filename)
- `Telegram` → `messaging` (explicit dataset label or filename)
- `WhatsApp` → `messaging` (explicit dataset label or filename)
- `Zoom` → `voip` (explicit dataset label or filename)

### Unresolved labels

Discord, Facebook

### Labels not to map

CyberGhost, Deezer, Epic Games, Hotspot Shield, iTunes, ProtonVPN, SoulseekQt, Spotify, Steam, TuneIn, TunnelBear, Ultrasurf

## USTC-TFC2016

- Files: 26 (3.7 GiB)
- Formats: md, no_extension, pcap
- Raw PCAP/PCAPNG present: True
- Inferred type(s): malware, benign, application traffic
- Label columns: none
- FlowFeatures overlap: {}
- Possible leakage: filename/path-derived labels (capture provenance; never use as a feature)

### Target-class mappings
- `Facetime` → `voip` (explicit dataset label or filename)
- `FTP` → `file_transfer` (explicit dataset label or filename)
- `Gmail` → `email` (explicit dataset label or filename)
- `Outlook` → `email` (explicit dataset label or filename)
- `Skype` → `voip` (explicit dataset label or filename)
- `SMB` → `file_transfer` (explicit dataset label or filename)

### Unresolved labels

Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Weibo, Zeus

### Labels not to map

BitTorrent, MySQL, WorldOfWarcraft
