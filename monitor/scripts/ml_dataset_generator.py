#!/usr/bin/env python3
"""
ML Dataset Generator for Security Testbed
Correlates Suricata eve.json logs with attack markers for supervised learning
"""

import json
import argparse
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [ML-DATASET] %(message)s')
logger = logging.getLogger(__name__)

class MLDatasetGenerator:
    def __init__(self, eve_log: str, captures_dir: str = "/captures", output_dir: str = "/analysis"):
        self.eve_log = eve_log
        self.captures_dir = captures_dir
        self.output_dir = output_dir
        self.attack_markers = {}
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
    def parse_attack_markers(self) -> Dict[str, Any]:
        """Parse attack markers from capture file names and logs"""
        markers = {}
        
        # Look for attack marker files
        if os.path.exists(self.captures_dir):
            for file in os.listdir(self.captures_dir):
                if 'ATTACK_MARKER' in file or 'attack' in file.lower():
                    try:
                        # Parse attack information from filename
                        # Expected format: ATTACK_MARKER|TYPE|START/END|timestamp
                        if 'ATTACK_MARKER' in file:
                            parts = file.split('|')
                            if len(parts) >= 4:
                                attack_type = parts[1]
                                phase = parts[2]  # START or END
                                timestamp = parts[3]
                                
                                if attack_type not in markers:
                                    markers[attack_type] = {}
                                
                                markers[attack_type][phase.lower()] = timestamp
                                
                    except Exception as e:
                        logger.warning(f"Could not parse attack marker {file}: {e}")
        
        # Also check attacker logs for more detailed attack information
        attacker_logs_dir = "/logs/attacker_logs"
        if os.path.exists(attacker_logs_dir):
            for file in os.listdir(attacker_logs_dir):
                if file.endswith('.log'):
                    try:
                        with open(os.path.join(attacker_logs_dir, file), 'r') as f:
                            content = f.read()
                            
                        # Look for attack markers in log content
                        marker_pattern = r'ATTACK_MARKER\|([^|]+)\|([^|]+)\|([^|]+)'
                        matches = re.findall(marker_pattern, content)
                        
                        for match in matches:
                            attack_type, phase, timestamp = match
                            if attack_type not in markers:
                                markers[attack_type] = {}
                            markers[attack_type][phase.lower()] = timestamp
                            
                    except Exception as e:
                        logger.warning(f"Could not parse attacker log {file}: {e}")
        
        self.attack_markers = markers
        logger.info(f"Found attack markers for {len(markers)} attack types")
        return markers
    
    def correlate_with_attacks(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate events with known attack periods"""
        if not self.attack_markers:
            self.parse_attack_markers()
        
        labeled_events = []
        
        for event in events:
            event_copy = event.copy()
            event_timestamp = event.get('timestamp', '')
            
            if not event_timestamp:
                # If no timestamp, assume benign
                event_copy['is_malicious'] = 0
                event_copy['attack_type'] = 'benign'
                event_copy['attack_correlation'] = 'no_timestamp'
                labeled_events.append(event_copy)
                continue
            
            try:
                # Parse event timestamp
                if event_timestamp.endswith('Z'):
                    event_dt = datetime.fromisoformat(event_timestamp[:-1])
                else:
                    event_dt = datetime.fromisoformat(event_timestamp)
                
                # Check if event falls within any attack period
                in_attack_period = False
                matched_attack_type = 'benign'
                
                for attack_type, periods in self.attack_markers.items():
                    start_time = periods.get('start')
                    end_time = periods.get('end')
                    
                    if start_time and end_time:
                        try:
                            # Parse attack timestamps
                            start_dt = datetime.fromisoformat(start_time.replace('Z', ''))
                            end_dt = datetime.fromisoformat(end_time.replace('Z', ''))
                            
                            # Add some buffer time (±30 seconds) to account for timing variations
                            buffer = timedelta(seconds=30)
                            
                            if (start_dt - buffer) <= event_dt <= (end_dt + buffer):
                                in_attack_period = True
                                matched_attack_type = attack_type
                                break
                                
                        except Exception as e:
                            logger.warning(f"Could not parse attack timestamps for {attack_type}: {e}")
                
                # Set labels based on correlation
                if in_attack_period:
                    event_copy['is_malicious'] = 1
                    event_copy['attack_type'] = matched_attack_type
                    event_copy['attack_correlation'] = 'time_correlated'
                else:
                    # Keep original label if it was already marked as malicious (e.g., by Suricata alert)
                    if event_copy.get('is_malicious', 0) == 0:
                        event_copy['attack_type'] = 'benign'
                        event_copy['attack_correlation'] = 'outside_attack_period'
                    else:
                        event_copy['attack_correlation'] = 'suricata_detected'
                
            except Exception as e:
                logger.warning(f"Could not process timestamp {event_timestamp}: {e}")
                # Default to benign if timestamp parsing fails
                event_copy['is_malicious'] = 0
                event_copy['attack_type'] = 'benign'
                event_copy['attack_correlation'] = 'timestamp_error'
            
            labeled_events.append(event_copy)
        
        return labeled_events
    
    def enhance_features_for_ml(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add additional ML-ready features"""
        enhanced_events = []
        
        # Group events by flow_id for flow-level features
        flow_groups = {}
        for event in events:
            flow_id = event.get('flow_id', 0)
            if flow_id not in flow_groups:
                flow_groups[flow_id] = []
            flow_groups[flow_id].append(event)
        
        for flow_id, flow_events in flow_groups.items():
            if not flow_events:
                continue
                
            # Calculate flow-level statistics
            flow_duration = 0
            total_packets = sum(e.get('total_packets', 0) for e in flow_events)
            total_bytes = sum(e.get('total_bytes', 0) for e in flow_events)
            unique_ports = set()
            
            for event in flow_events:
                unique_ports.add(event.get('src_port', 0))
                unique_ports.add(event.get('dest_port', 0))
            
            # Add flow-level features to each event in the flow
            for event in flow_events:
                enhanced_event = event.copy()
                enhanced_event.update({
                    'flow_total_events': len(flow_events),
                    'flow_total_packets': total_packets,
                    'flow_total_bytes': total_bytes,
                    'flow_unique_ports': len(unique_ports),
                    'flow_avg_packet_size': total_bytes / total_packets if total_packets > 0 else 0,
                })
                
                # Encode categorical variables
                enhanced_event.update({
                    'proto_tcp': 1 if event.get('proto', '').upper() == 'TCP' else 0,
                    'proto_udp': 1 if event.get('proto', '').upper() == 'UDP' else 0,
                    'proto_icmp': 1 if event.get('proto', '').upper() == 'ICMP' else 0,
                    'event_type_alert': 1 if event.get('event_type') == 'alert' else 0,
                    'event_type_http': 1 if event.get('event_type') == 'http' else 0,
                    'event_type_dns': 1 if event.get('event_type') == 'dns' else 0,
                    'event_type_tls': 1 if event.get('event_type') == 'tls' else 0,
                    'event_type_flow': 1 if event.get('event_type') == 'flow' else 0,
                })
                
                # Network-based features
                src_ip = event.get('src_ip', '')
                dest_ip = event.get('dest_ip', '')
                enhanced_event.update({
                    'is_internal_src': 1 if src_ip.startswith('100.64.0.') or src_ip.startswith('192.168.') or src_ip.startswith('10.') else 0,
                    'is_internal_dest': 1 if dest_ip.startswith('100.64.0.') or dest_ip.startswith('192.168.') or dest_ip.startswith('10.') else 0,
                    'is_broadcast': 1 if dest_ip.endswith('.255') else 0,
                    'is_multicast': 1 if dest_ip.startswith('224.') else 0,
                })
                
                enhanced_events.append(enhanced_event)
        
        return enhanced_events
    
    def generate_ml_dataset(self, input_features_file: str = None):
        """Generate final ML-ready dataset"""
        logger.info("Generating ML dataset from Suricata logs")
        
        # If no input file specified, look for latest processed features
        if not input_features_file:
            latest_file = os.path.join(self.output_dir, 'suricata_features_latest.csv')
            if os.path.exists(latest_file):
                input_features_file = latest_file
            else:
                logger.error("No input features file found")
                return
        
        try:
            # Load processed features
            df = pd.read_csv(input_features_file)
            logger.info(f"Loaded {len(df)} events from {input_features_file}")
            
            # Convert to list of dictionaries for processing
            events = df.to_dict('records')
            
            # Correlate with attacks
            correlated_events = self.correlate_with_attacks(events)
            
            # Enhance features
            enhanced_events = self.enhance_features_for_ml(correlated_events)
            
            # Convert back to DataFrame
            ml_df = pd.DataFrame(enhanced_events)
            
            # Select features for ML (numerical features only)
            ml_features = [
                'src_port', 'dest_port', 'flow_pkts_toserver', 'flow_pkts_toclient',
                'flow_bytes_toserver', 'flow_bytes_toclient', 'flow_age',
                'total_packets', 'total_bytes', 'avg_packet_size',
                'packet_ratio_toserver', 'byte_ratio_toserver',
                'packets_per_second', 'bytes_per_second',
                'is_well_known_src_port', 'is_well_known_dest_port',
                'is_ephemeral_src_port', 'is_ephemeral_dest_port',
                'hour_of_day', 'day_of_week', 'is_weekend', 'is_business_hours',
                'flow_total_events', 'flow_total_packets', 'flow_total_bytes',
                'flow_unique_ports', 'flow_avg_packet_size',
                'proto_tcp', 'proto_udp', 'proto_icmp',
                'event_type_alert', 'event_type_http', 'event_type_dns',
                'event_type_tls', 'event_type_flow',
                'is_internal_src', 'is_internal_dest', 'is_broadcast', 'is_multicast',
                'is_malicious'  # Target variable
            ]
            
            # Filter to only include available features
            available_features = [f for f in ml_features if f in ml_df.columns]
            ml_ready_df = ml_df[available_features].copy()
            
            # Fill NaN values
            ml_ready_df = ml_ready_df.fillna(0)
            
            # Save ML-ready dataset
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ml_output_path = os.path.join(self.output_dir, f'ml_dataset_{timestamp}.csv')
            ml_ready_df.to_csv(ml_output_path, index=False)
            
            # Save latest ML dataset (overwrite)
            latest_ml_path = os.path.join(self.output_dir, 'ml_dataset_latest.csv')
            ml_ready_df.to_csv(latest_ml_path, index=False)
            
            # Generate dataset statistics
            stats = {
                'total_samples': len(ml_ready_df),
                'malicious_samples': ml_ready_df['is_malicious'].sum(),
                'benign_samples': (ml_ready_df['is_malicious'] == 0).sum(),
                'feature_count': len(available_features) - 1,  # Exclude target variable
                'features': available_features[:-1],  # Exclude target variable
                'class_distribution': ml_ready_df['is_malicious'].value_counts().to_dict(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Save statistics
            stats_path = os.path.join(self.output_dir, 'ml_dataset_stats.json')
            with open(stats_path, 'w') as f:
                json.dump(stats, f, indent=2)
            
            logger.info(f"Generated ML dataset: {stats['total_samples']} samples, "
                       f"{stats['malicious_samples']} malicious, "
                       f"{stats['benign_samples']} benign")
            logger.info(f"ML dataset saved to: {ml_output_path}")
            
            return ml_output_path
            
        except Exception as e:
            logger.error(f"Error generating ML dataset: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Generate ML dataset from Suricata logs')
    parser.add_argument('--eve-log', required=True, help='Path to Suricata eve.json file')
    parser.add_argument('--captures-dir', default='/captures', help='Directory containing attack markers')
    parser.add_argument('--output-dir', default='/analysis', help='Output directory for ML dataset')
    parser.add_argument('--correlate-attacks', action='store_true', help='Correlate events with attack markers')
    parser.add_argument('--input-features', help='Input features CSV file (if not specified, uses latest)')
    
    args = parser.parse_args()
    
    generator = MLDatasetGenerator(args.eve_log, args.captures_dir, args.output_dir)
    
    if args.correlate_attacks:
        generator.generate_ml_dataset(args.input_features)
    else:
        logger.info("Use --correlate-attacks to generate ML dataset")

if __name__ == '__main__':
    main()
