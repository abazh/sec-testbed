#!/usr/bin/env python3
"""
Suricata Eve.json ML Analysis Demo
Demonstrates how to extract features from Suricata 8.0.0 eve.json for Random Forest models
"""

import json
import pandas as pd
from pathlib import Path

def extract_eve_features(eve_file_path):
    """Extract ML features from Suricata eve.json output"""
    features = []
    
    with open(eve_file_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                
                if event.get('event_type') == 'stats':
                    # Extract network statistics for ML
                    stats = event.get('stats', {})
                    capture = stats.get('capture', {})
                    decoder = stats.get('decoder', {})
                    flow = stats.get('flow', {})
                    detect = stats.get('detect', {})
                    
                    feature = {
                        'timestamp': event.get('timestamp'),
                        'event_type': 'stats',
                        'kernel_packets': capture.get('kernel_packets', 0),
                        'kernel_drops': capture.get('kernel_drops', 0),
                        'total_pkts': decoder.get('pkts', 0),
                        'total_bytes': decoder.get('bytes', 0),
                        'ipv4_pkts': decoder.get('ipv4', 0),
                        'ipv6_pkts': decoder.get('ipv6', 0),
                        'tcp_pkts': decoder.get('tcp', 0),
                        'udp_pkts': decoder.get('udp', 0),
                        'active_flows': flow.get('active', 0),
                        'total_flows': flow.get('total', 0),
                        'tcp_flows': flow.get('tcp', 0),
                        'alerts_count': detect.get('alert', 0),
                        'avg_pkt_size': decoder.get('avg_pkt_size', 0),
                        'max_pkt_size': decoder.get('max_pkt_size', 0)
                    }
                    features.append(feature)
                
                elif event.get('event_type') == 'alert':
                    # Extract alert features for ML
                    alert = event.get('alert', {})
                    flow_info = event.get('flow', {})
                    
                    feature = {
                        'timestamp': event.get('timestamp'),
                        'event_type': 'alert',
                        'src_ip': event.get('src_ip', ''),
                        'dest_ip': event.get('dest_ip', ''),
                        'proto': event.get('proto', ''),
                        'signature_id': alert.get('signature_id', 0),
                        'severity': alert.get('severity', 0),
                        'pkts_toserver': flow_info.get('pkts_toserver', 0),
                        'pkts_toclient': flow_info.get('pkts_toclient', 0),
                        'bytes_toserver': flow_info.get('bytes_toserver', 0),
                        'bytes_toclient': flow_info.get('bytes_toclient', 0),
                        'category': alert.get('category', ''),
                        'action': alert.get('action', '')
                    }
                    features.append(feature)
                    
            except json.JSONDecodeError:
                continue
    
    return features

def main():
    """Demonstrate ML feature extraction from Suricata 8.0.0 eve.json"""
    eve_file = Path('/captures/eve.json')
    
    if not eve_file.exists():
        print(f"❌ Eve.json file not found: {eve_file}")
        return
    
    print("🔬 Extracting ML features from Suricata 8.0.0 eve.json...")
    features = extract_eve_features(eve_file)
    
    if not features:
        print("❌ No features extracted")
        return
    
    # Convert to pandas DataFrame for ML analysis
    df = pd.DataFrame(features)
    
    print(f"\n📊 ML Dataset Summary:")
    print(f"   Total Events: {len(df)}")
    print(f"   Event Types: {df['event_type'].value_counts().to_dict()}")
    
    # Stats events analysis
    stats_df = df[df['event_type'] == 'stats']
    if not stats_df.empty:
        print(f"\n📈 Network Statistics Features:")
        print(f"   Total Packets: {stats_df['total_pkts'].sum()}")
        print(f"   Total Bytes: {stats_df['total_bytes'].sum()}")
        print(f"   Max Active Flows: {stats_df['active_flows'].max()}")
        print(f"   IPv4 vs IPv6 Ratio: {stats_df['ipv4_pkts'].sum()}:{stats_df['ipv6_pkts'].sum()}")
        print(f"   TCP vs UDP Ratio: {stats_df['tcp_pkts'].sum()}:{stats_df['udp_pkts'].sum()}")
    
    # Alert events analysis
    alert_df = df[df['event_type'] == 'alert']
    if not alert_df.empty:
        print(f"\n🚨 Security Alert Features:")
        print(f"   Total Alerts: {len(alert_df)}")
        print(f"   Unique Signatures: {alert_df['signature_id'].nunique()}")
        print(f"   Protocol Distribution: {alert_df['proto'].value_counts().to_dict()}")
        print(f"   Severity Levels: {alert_df['severity'].value_counts().to_dict()}")
    
    # Save processed dataset for ML models
    output_file = Path('/analysis/ml_features.csv')
    df.to_csv(output_file, index=False)
    print(f"\n💾 ML features saved to: {output_file}")
    print(f"   Ready for Random Forest training! 🌲")
    
    # Display sample features for ML model input
    print(f"\n🎯 Sample ML Features (first 3 rows):")
    print(df.head(3).to_string())

if __name__ == "__main__":
    main()
