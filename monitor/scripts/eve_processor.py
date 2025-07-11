#!/usr/bin/env python3
"""
Eve.json Processor for Machine Learning Dataset Generation
Processes Suricata eve.json logs and extracts features for ML models like Random Forest
"""

import json
import argparse
import logging
import sys
import time
import os
from datetime import datetime
from typing import Dict, List, Any
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [EVE-PROCESSOR] %(message)s')
logger = logging.getLogger(__name__)

class EveJsonProcessor:
    def __init__(self, input_file: str, output_dir: str):
        self.input_file = input_file
        self.output_dir = output_dir
        self.processed_events = []
        self.last_position = 0
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
    def extract_flow_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract flow-based features from eve.json event"""
        features = {
            'timestamp': event.get('timestamp', ''),
            'event_type': event.get('event_type', ''),
            'src_ip': event.get('src_ip', ''),
            'dest_ip': event.get('dest_ip', ''),
            'src_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'proto': event.get('proto', ''),
            'app_proto': event.get('app_proto', ''),
            'flow_id': event.get('flow_id', 0),
        }
        
        # Flow statistics if available
        if 'flow' in event:
            flow = event['flow']
            features.update({
                'flow_pkts_toserver': flow.get('pkts_toserver', 0),
                'flow_pkts_toclient': flow.get('pkts_toclient', 0),
                'flow_bytes_toserver': flow.get('bytes_toserver', 0),
                'flow_bytes_toclient': flow.get('bytes_toclient', 0),
                'flow_start': flow.get('start', ''),
                'flow_end': flow.get('end', ''),
                'flow_age': flow.get('age', 0),
                'flow_state': flow.get('state', ''),
                'flow_reason': flow.get('reason', '')
            })
        else:
            # Default flow values
            features.update({
                'flow_pkts_toserver': 0,
                'flow_pkts_toclient': 0,
                'flow_bytes_toserver': 0,
                'flow_bytes_toclient': 0,
                'flow_start': '',
                'flow_end': '',
                'flow_age': 0,
                'flow_state': '',
                'flow_reason': ''
            })
            
        return features
    
    def extract_alert_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract alert-specific features"""
        features = self.extract_flow_features(event)
        
        if 'alert' in event:
            alert = event['alert']
            features.update({
                'alert_signature': alert.get('signature', ''),
                'alert_signature_id': alert.get('signature_id', 0),
                'alert_rev': alert.get('rev', 0),
                'alert_severity': alert.get('severity', 0),
                'alert_category': alert.get('category', ''),
                'alert_action': alert.get('action', ''),
                'alert_gid': alert.get('gid', 0)
            })
        
        # Mark as malicious for ML labeling
        features['is_malicious'] = 1
        features['attack_type'] = features.get('alert_category', 'unknown')
        
        return features
    
    def extract_http_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP-specific features"""
        features = self.extract_flow_features(event)
        
        if 'http' in event:
            http = event['http']
            features.update({
                'http_method': http.get('http_method', ''),
                'http_uri': http.get('url', ''),
                'http_user_agent': http.get('http_user_agent', ''),
                'http_status': http.get('status', 0),
                'http_content_type': http.get('http_content_type', ''),
                'http_content_length': http.get('length', 0),
                'http_hostname': http.get('hostname', ''),
                'http_redirect': http.get('redirect', '')
            })
        
        # Default to benign unless it's an alert
        features['is_malicious'] = 0
        features['attack_type'] = 'benign'
        
        return features
    
    def extract_dns_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract DNS-specific features"""
        features = self.extract_flow_features(event)
        
        if 'dns' in event:
            dns = event['dns']
            features.update({
                'dns_query': dns.get('rrname', ''),
                'dns_query_type': dns.get('rrtype', ''),
                'dns_response_code': dns.get('rcode', ''),
                'dns_answers': len(dns.get('answers', [])),
                'dns_flags': dns.get('flags', '')
            })
        
        features['is_malicious'] = 0
        features['attack_type'] = 'benign'
        
        return features
    
    def extract_tls_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract TLS/SSL features"""
        features = self.extract_flow_features(event)
        
        if 'tls' in event:
            tls = event['tls']
            features.update({
                'tls_version': tls.get('version', ''),
                'tls_subject': tls.get('subject', ''),
                'tls_issuer': tls.get('issuer', ''),
                'tls_fingerprint': tls.get('fingerprint', ''),
                'tls_sni': tls.get('sni', ''),
                'tls_ja3': tls.get('ja3', {}).get('hash', '') if 'ja3' in tls else '',
                'tls_ja3s': tls.get('ja3s', {}).get('hash', '') if 'ja3s' in tls else ''
            })
        
        features['is_malicious'] = 0
        features['attack_type'] = 'benign'
        
        return features
    
    def calculate_derived_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate derived features for ML"""
        # Packet ratios
        total_pkts = features.get('flow_pkts_toserver', 0) + features.get('flow_pkts_toclient', 0)
        total_bytes = features.get('flow_bytes_toserver', 0) + features.get('flow_bytes_toclient', 0)
        
        features.update({
            'total_packets': total_pkts,
            'total_bytes': total_bytes,
            'avg_packet_size': total_bytes / total_pkts if total_pkts > 0 else 0,
            'packet_ratio_toserver': features.get('flow_pkts_toserver', 0) / total_pkts if total_pkts > 0 else 0,
            'byte_ratio_toserver': features.get('flow_bytes_toserver', 0) / total_bytes if total_bytes > 0 else 0,
            'packets_per_second': total_pkts / max(features.get('flow_age', 1), 1),
            'bytes_per_second': total_bytes / max(features.get('flow_age', 1), 1)
        })
        
        # Port analysis
        src_port = features.get('src_port', 0)
        dest_port = features.get('dest_port', 0)
        features.update({
            'is_well_known_src_port': 1 if 0 < src_port < 1024 else 0,
            'is_well_known_dest_port': 1 if 0 < dest_port < 1024 else 0,
            'is_ephemeral_src_port': 1 if src_port > 32768 else 0,
            'is_ephemeral_dest_port': 1 if dest_port > 32768 else 0
        })
        
        # Time-based features
        if features.get('timestamp'):
            try:
                ts = datetime.fromisoformat(features['timestamp'].replace('Z', '+00:00'))
                features.update({
                    'hour_of_day': ts.hour,
                    'day_of_week': ts.weekday(),
                    'is_weekend': 1 if ts.weekday() >= 5 else 0,
                    'is_business_hours': 1 if 9 <= ts.hour <= 17 else 0
                })
            except:
                features.update({
                    'hour_of_day': 0,
                    'day_of_week': 0,
                    'is_weekend': 0,
                    'is_business_hours': 0
                })
        
        return features
    
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single eve.json event"""
        event_type = event.get('event_type', '')
        
        if event_type == 'alert':
            features = self.extract_alert_features(event)
        elif event_type == 'http':
            features = self.extract_http_features(event)
        elif event_type == 'dns':
            features = self.extract_dns_features(event)
        elif event_type == 'tls':
            features = self.extract_tls_features(event)
        elif event_type == 'flow':
            features = self.extract_flow_features(event)
            features['is_malicious'] = 0
            features['attack_type'] = 'benign'
        else:
            # Generic event processing
            features = self.extract_flow_features(event)
            features['is_malicious'] = 0
            features['attack_type'] = 'benign'
        
        # Add derived features
        features = self.calculate_derived_features(features)
        
        return features
    
    def process_file(self, follow: bool = True):
        """Process eve.json file, optionally following new entries"""
        logger.info(f"Starting to process {self.input_file}")
        
        while True:
            try:
                if not os.path.exists(self.input_file):
                    if follow:
                        time.sleep(1)
                        continue
                    else:
                        logger.warning(f"File {self.input_file} does not exist")
                        break
                
                with open(self.input_file, 'r') as f:
                    # Seek to last position
                    f.seek(self.last_position)
                    
                    new_events = []
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                            
                        try:
                            event = json.loads(line)
                            features = self.process_event(event)
                            new_events.append(features)
                            
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse JSON line: {e}")
                            continue
                    
                    # Update position
                    self.last_position = f.tell()
                    
                    if new_events:
                        self.processed_events.extend(new_events)
                        logger.info(f"Processed {len(new_events)} new events")
                        
                        # Save incremental results
                        self.save_results(new_events)
                
                if not follow:
                    break
                    
                time.sleep(5)  # Wait 5 seconds before checking for new events
                
            except KeyboardInterrupt:
                logger.info("Processing interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error processing file: {e}")
                if not follow:
                    break
                time.sleep(5)
    
    def save_results(self, events: List[Dict[str, Any]]):
        """Save processed events to CSV for ML analysis"""
        if not events:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        
        # Save full dataset
        full_path = os.path.join(self.output_dir, f'suricata_features_{timestamp}.csv')
        df.to_csv(full_path, index=False)
        logger.info(f"Saved {len(events)} events to {full_path}")
        
        # Save latest dataset (overwrite)
        latest_path = os.path.join(self.output_dir, 'suricata_features_latest.csv')
        
        # Load existing data if it exists
        if os.path.exists(latest_path):
            try:
                existing_df = pd.read_csv(latest_path)
                # Combine with new data (keep last 10000 rows to manage size)
                combined_df = pd.concat([existing_df, df], ignore_index=True).tail(10000)
                combined_df.to_csv(latest_path, index=False)
            except Exception as e:
                logger.warning(f"Could not load existing data: {e}, creating new file")
                df.to_csv(latest_path, index=False)
        else:
            df.to_csv(latest_path, index=False)
        
        # Generate summary statistics
        self.generate_summary(df)
    
    def generate_summary(self, df: pd.DataFrame):
        """Generate summary statistics for the dataset"""
        summary = {
            'total_events': len(df),
            'malicious_events': df['is_malicious'].sum(),
            'benign_events': (df['is_malicious'] == 0).sum(),
            'event_types': df['event_type'].value_counts().to_dict(),
            'attack_types': df['attack_type'].value_counts().to_dict(),
            'protocols': df['proto'].value_counts().to_dict(),
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dest_ips': df['dest_ip'].nunique(),
            'timestamp': datetime.now().isoformat()
        }
        
        summary_path = os.path.join(self.output_dir, 'dataset_summary.json')
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Dataset summary: {summary['total_events']} events, "
                   f"{summary['malicious_events']} malicious, "
                   f"{summary['benign_events']} benign")

def main():
    parser = argparse.ArgumentParser(description='Process Suricata eve.json for ML dataset generation')
    parser.add_argument('--input', required=True, help='Path to eve.json file')
    parser.add_argument('--output', required=True, help='Output directory for processed data')
    parser.add_argument('--follow', action='store_true', help='Follow the file for new entries (like tail -f)')
    parser.add_argument('--batch', action='store_true', help='Process file once and exit')
    
    args = parser.parse_args()
    
    processor = EveJsonProcessor(args.input, args.output)
    
    try:
        processor.process_file(follow=not args.batch)
    except KeyboardInterrupt:
        logger.info("Processing stopped")
        sys.exit(0)

if __name__ == '__main__':
    main()
