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
import traceback
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
        marker_file = "/attacker_logs/attack_markers.log"
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
        
        # Debug: Print loaded markers for verification
        for timestamp, marker_info in self.attack_markers.items():
            logger.info(f"Marker: {timestamp} - {marker_info['type']} ({marker_info['action']})")
    
    def process_flow_features_streaming(self, argus_file, output_file):
        """Process and write features directly from Argus flow data - true streaming approach"""
        processed_lines = 0
        attack_flows = 0
        
        try:
            # Check file size first
            file_size = os.path.getsize(argus_file)
            logger.info(f"Processing argus file: {os.path.basename(argus_file)} ({file_size / (1024*1024):.1f} MB)")
            
            # Use delimiter '|' to separate fields clearly
            cmd = ["ra", "-r", argus_file, "-s", "stime,dur,flgs,proto,saddr,sport,daddr,dport,pkts,bytes,state", "-c", "|"]
            
            # Use streaming processing instead of capturing all output at once
            logger.info("Starting ra command...")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            
            # Process output line by line and write immediately
            header_skipped = False
            batch_features = []
            batch_size = 500  # Process in smaller batches for better memory management
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                    
                # Skip header line
                if not header_skipped and "StartTime" in line:
                    header_skipped = True
                    continue
                    
                # Skip error lines
                if line.startswith('ra['):
                    continue
                    
                # Split by delimiter '|'
                parts = line.split('|')
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
                        
                        # Label the feature immediately
                        labeled_feature = self.label_single_feature(feature)
                        batch_features.append(labeled_feature)
                        
                        if labeled_feature.get('label') == 'attack':
                            attack_flows += 1
                        
                        processed_lines += 1
                        
                        # Write batch when it reaches batch_size
                        if len(batch_features) >= batch_size:
                            self.write_features_batch(output_file, batch_features)
                            batch_features = []  # Clear batch
                        
                        # Progress reporting every 10000 lines
                        if processed_lines % 10000 == 0:
                            logger.info(f"Processed {processed_lines:,} flow records...")
                            
                    except Exception as e:
                        logger.debug(f"Error parsing line: {line[:100]} - {e}")
                        continue
            
            # Write remaining features in the final batch
            if batch_features:
                self.write_features_batch(output_file, batch_features)
            
            # Wait for process to complete and check for errors
            return_code = process.wait()
            if return_code != 0:
                stderr_output = process.stderr.read()
                logger.error(f"ra command failed with return code {return_code}: {stderr_output}")
                
            logger.info(f"Successfully processed {processed_lines:,} flow records from {os.path.basename(argus_file)}")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while processing {argus_file}")
            if 'process' in locals():
                process.kill()
        except Exception as e:
            logger.error(f"Error processing Argus file {argus_file}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        
        return processed_lines, attack_flows
    
    def label_single_feature(self, feature):
        """Label a single flow with attack correlation and heuristics"""
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
        
        return feature
    
    def write_features_batch(self, output_file, features_batch):
        """Write a batch of features to the output file"""
        headers = ['timestamp', 'duration', 'flags', 'protocol', 'src_ip', 'src_port', 
                  'dst_ip', 'dst_port', 'packets', 'bytes', 'state', 'label', 'attack_type']
        
        with open(output_file, 'a') as f:  # Append mode
            for feature in features_batch:
                values = [str(feature.get(h, '')) for h in headers]
                f.write(','.join(values) + '\n')
    
    def generate_dataset(self):
        """Generate labeled dataset from captures with true streaming processing"""
        logger.info("Starting dataset generation...")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Load attack markers
        self.load_attack_markers()
        
        # Get list of argus files
        argus_files = [f for f in os.listdir(self.input_dir) if f.endswith('.arg')]
        if not argus_files:
            logger.warning("No .arg files found in input directory")
            return
            
        logger.info(f"Found {len(argus_files)} argus files to process")
        
        # Prepare output file 
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"security_dataset_{timestamp}.csv")
        
        # Write header first
        headers = ['timestamp', 'duration', 'flags', 'protocol', 'src_ip', 'src_port', 
                  'dst_ip', 'dst_port', 'packets', 'bytes', 'state', 'label', 'attack_type']
        with open(output_file, 'w') as f:
            f.write(','.join(headers) + '\n')
        
        total_flows = 0
        total_attack_flows = 0
        
        # Process files one by one with true streaming
        for filename in argus_files:
            argus_path = os.path.join(self.input_dir, filename)
            logger.info(f"Processing {filename}...")
            
            try:
                # Process file with streaming approach
                file_flows, file_attacks = self.process_flow_features_streaming(argus_path, output_file)
                
                total_flows += file_flows
                total_attack_flows += file_attacks
                
                logger.info(f"File {filename}: {file_flows:,} flows ({file_attacks:,} attacks)")
                
            except Exception as e:
                logger.error(f"Error processing file {filename}: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                continue
        
        if total_flows == 0:
            logger.warning("No features extracted from any files")
            return
        
        logger.info(f"Saved dataset: {output_file}")
        
        # Generate summary report
        normal_flows = total_flows - total_attack_flows
        
        report = {
            'timestamp': timestamp,
            'total_flows': total_flows,
            'attack_flows': total_attack_flows,
            'normal_flows': normal_flows,
            'attack_percentage': (total_attack_flows / total_flows) * 100 if total_flows > 0 else 0,
            'files_processed': len(argus_files)
        }
        
        report_file = os.path.join(self.output_dir, f"analysis_report_{timestamp}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Dataset generation complete!")
        logger.info(f"Total flows: {total_flows:,}")
        logger.info(f"Attack flows: {total_attack_flows:,} ({report['attack_percentage']:.1f}%)")
        logger.info(f"Normal flows: {normal_flows:,}")
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
