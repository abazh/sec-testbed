#!/usr/bin/env python3
"""
Streamlined Dataset Generator for Security Testbed
Focus: Attack correlation and meaningful feature extraction
"""

import argparse
import os
import subprocess
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [DATASET] %(message)s')
logger = logging.getLogger(__name__)

class StreamlinedDatasetGenerator:
    def __init__(self, input_dir="/captures", output_dir="/analysis"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.attack_markers = {}
        
    def _parse_address(self, addr_str):
        """Parse address string in format IP.port or IP"""
        if not addr_str or addr_str == '*':
            return '0.0.0.0', '0'
        
        # Split on last dot to separate IP and port
        if '.' in addr_str:
            parts = addr_str.rsplit('.', 1)
            if len(parts) == 2 and (parts[1].startswith('0x') or parts[1].isdigit()):
                return parts[0], parts[1]
        
        # If no port found, return the whole string as IP
        return addr_str, '0'
    
    def _safe_int(self, value):
        """Safely convert value to integer, handling hex and invalid values"""
        if value == '*' or not value:
            return 0
        try:
            # Handle hexadecimal values
            if value.startswith('0x'):
                return int(value, 16)
            # Handle regular integers
            return int(value)
        except (ValueError, TypeError):
            # Return 0 for IPv6 addresses or other non-numeric values
            return 0
    
    def _safe_float(self, value):
        """Safely convert value to float"""
        if value == '*' or not value:
            return 0.0
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    def load_attack_markers(self):
        """Load attack timing markers for correlation"""
        marker_file = "/logs/attacker_logs/attack_markers.log"
        if os.path.exists(marker_file):
            with open(marker_file, 'r') as f:
                for line in f:
                    if 'ATTACK_MARKER' in line:
                        parts = line.strip().split('|')
                        if len(parts) >= 4:
                            attack_type = parts[1]
                            action = parts[2]
                            timestamp = parts[3]
                            self.attack_markers[timestamp] = {
                                'type': attack_type,
                                'action': action
                            }
        logger.info(f"Loaded {len(self.attack_markers)} attack markers")
    
    def extract_flow_features(self, argus_file):
        """Extract features from Argus flow data using ra client with delimiter"""
        features = []
        try:
            # Use delimiter '5' to separate fields clearly
            cmd = ["ra", "-r", argus_file, "-s", "stime,dur,flgs,proto,saddr,sport,daddr,dport,pkts,bytes,state", "-c", "5"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            for line in result.stdout.split('\n'):
                if line.strip() and not "StartTime" in line and not line.startswith('ra['):
                    # Split by delimiter '5'
                    parts = line.split('5')
                    if len(parts) >= 11:
                        try:
                            feature = {
                                'timestamp': parts[0],
                                'duration': self._safe_float(parts[1]),
                                'flags': parts[2],
                                'protocol': parts[3],
                                'src_ip': parts[4],
                                'src_port': parts[5],
                                'dst_ip': parts[6],
                                'dst_port': parts[7],
                                'packets': self._safe_int(parts[8]),
                                'bytes': self._safe_int(parts[9]),
                                'state': parts[10]
                            }
                            features.append(feature)
                        except Exception as e:
                            logger.debug(f"Error parsing line: {line[:100]} - {e}")
                            continue
        except Exception as e:
            logger.error(f"Error processing Argus file {argus_file}: {e}")
        
        return features
    
    def label_features(self, features):
        """Label flows with attack correlation and heuristics"""
        for feature in features:
            feature['label'] = 'normal'
            feature['attack_type'] = 'none'
            
            # Check for timestamp-based attack correlation
            timestamp = feature.get('timestamp', '')
            if timestamp:
                # Convert timestamp to match attack marker format (approximate)
                for marker_time, marker_info in self.attack_markers.items():
                    if marker_info['action'] == 'START':
                        # Simple time-based correlation (you could make this more precise)
                        if timestamp.startswith(marker_time.split(' ')[1][:5]):  # Match HH:MM
                            feature['label'] = 'attack'
                            feature['attack_type'] = marker_info['type']
                            break
            
            # Heuristic-based attack detection for flows without timestamp correlation
            if feature['label'] == 'normal':
                # SYN flood detection - many SYN packets to same destination
                if (feature.get('flags') == 'S' and 
                    feature.get('packets', 0) > 50):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'SYN_FLOOD'
                
                # ICMP flood detection 
                elif (feature.get('protocol') == 'icmp' and
                      feature.get('src_ip', '').startswith('100.64.0.') and
                      feature.get('dst_ip', '').startswith('100.64.0.')):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'ICMP_FLOOD'
                
                # Port scanning detection - connection attempts with rejects/resets
                elif (feature.get('packets', 0) <= 3 and
                      feature.get('state') in ['REJ', 'RST', 'FIN']):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'PORT_SCAN'
                
                # HTTP-based attacks (SQL injection, directory scan, brute force)
                elif (feature.get('protocol') == 'tcp' and
                      feature.get('dst_port') in ['80', '0x0050'] and  # Port 80
                      feature.get('packets', 0) > 1):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'HTTP_ATTACK'
        
        return features
    
    def generate_dataset(self):
        """Generate labeled dataset from captures"""
        logger.info("Starting dataset generation...")
        os.makedirs(self.output_dir, exist_ok=True)
        
        all_features = []
        
        # Load attack markers
        self.load_attack_markers()
        
        # Process Argus flow files
        for filename in os.listdir(self.input_dir):
            if filename.endswith('.arg'):
                argus_path = os.path.join(self.input_dir, filename)
                logger.info(f"Processing {filename}...")
                
                features = self.extract_flow_features(argus_path)
                labeled_features = self.label_features(features)
                all_features.extend(labeled_features)
        
        if not all_features:
            logger.warning("No features extracted")
            return
        
        # Generate summary and save
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Simple CSV output (compatible without pandas)
        output_file = os.path.join(self.output_dir, f"security_dataset_{timestamp}.csv")
        with open(output_file, 'w') as f:
            # Write header
            if all_features:
                headers = list(all_features[0].keys())
                f.write(','.join(headers) + '\n')
                
                # Write data
                for feature in all_features:
                    values = [str(feature.get(h, '')) for h in headers]
                    f.write(','.join(values) + '\n')
        
        logger.info(f"Saved dataset: {output_file}")
        
        # Generate summary report
        attack_count = sum(1 for f in all_features if f['label'] == 'attack')
        normal_count = len(all_features) - attack_count
        
        report = {
            'timestamp': timestamp,
            'total_flows': len(all_features),
            'attack_flows': attack_count,
            'normal_flows': normal_count,
            'attack_percentage': (attack_count / len(all_features)) * 100 if all_features else 0
        }
        
        report_file = os.path.join(self.output_dir, f"analysis_report_{timestamp}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Dataset contains {attack_count} attacks and {normal_count} normal flows")
        logger.info(f"Analysis report saved: {report_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate security dataset')
    parser.add_argument('--input', default='/captures', help='Input directory')
    parser.add_argument('--output', default='/analysis', help='Output directory')
    parser.add_argument('--correlate-attacks', action='store_true', 
                       help='Process attack correlation')
    
    args = parser.parse_args()
    
    generator = StreamlinedDatasetGenerator(args.input, args.output)
    generator.generate_dataset()

if __name__ == "__main__":
    main()
