#!/usr/bin/env python3
"""
Streamlined Dataset Generator for Security Testbed

This script processes Argus flow files and attack marker logs to generate labeled datasets for security research. It extracts flow-level features, correlates attacks using timing markers, and outputs CSV and JSON reports for further analysis.

Usage:
    python dataset_generator.py --input /captures --output /analysis

Dependencies:
    - Argus (ra client)
    - Python 3.6+

Author: abazh
Date: 2025-07-15
"""

import argparse
import os
import subprocess
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s [DATASET] %(message)s')
logger = logging.getLogger(__name__)

class StreamlinedDatasetGenerator:
    """
    Processes Argus flow files and attack marker logs to generate labeled datasets.

    Attributes:
        input_dir (str): Directory containing Argus flow files (.arg).
        output_dir (str): Directory to save generated datasets and reports.
        attack_markers (Dict[str, Dict[str, str]]): Loaded attack timing markers.
    """
    def __init__(self, input_dir: str = "/captures", output_dir: str = "/analysis"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.attack_markers: Dict[str, Dict[str, str]] = {}

    def _parse_address(self, addr_str: str) -> Tuple[str, str]:
        """
        Parse address string in format IP.port or IP.

        Parameters:
            addr_str (str): Address string.
        Returns:
            Tuple[str, str]: IP and port.
        """
        if not addr_str or addr_str == '*':
            return '0.0.0.0', '0'
        if '.' in addr_str:
            parts = addr_str.rsplit('.', 1)
            if len(parts) == 2 and (parts[1].startswith('0x') or parts[1].isdigit()):
                return parts[0], parts[1]
        return addr_str, '0'

    def _safe_int(self, value: str) -> int:
        """
        Safely convert value to integer, handling hex and invalid values.

        Parameters:
            value (str): Value to convert.
        Returns:
            int: Converted integer or 0 if invalid.
        """
        if value == '*' or not value:
            return 0
        try:
            if value.startswith('0x'):
                return int(value, 16)
            return int(value)
        except (ValueError, TypeError):
            return 0

    def _safe_float(self, value: str) -> float:
        """
        Safely convert value to float.

        Parameters:
            value (str): Value to convert.
        Returns:
            float: Converted float or 0.0 if invalid.
        """
        if value == '*' or not value:
            return 0.0
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    def load_attack_markers(self) -> None:
        """
        Load attack timing markers for correlation from log file.
        """
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

    def extract_flow_features(self, argus_file: str) -> List[Dict[str, Any]]:
        """
        Extract features from Argus flow data using ra client with delimiter.

        Parameters:
            argus_file (str): Path to Argus flow file.
        Returns:
            List[Dict[str, Any]]: List of extracted flow features.
        """
        features = []
        try:
            cmd = ["ra", "-r", argus_file, "-s", "stime,dur,flgs,proto,saddr,sport,daddr,dport,pkts,bytes,state", "-c", "5"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            for line in result.stdout.split('\n'):
                if line.strip() and not "StartTime" in line and not line.startswith('ra['):
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

    def label_features(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Label flows with attack correlation and heuristics.

        Parameters:
            features (List[Dict[str, Any]]): List of flow features.
        Returns:
            List[Dict[str, Any]]: Labeled features.
        """
        for feature in features:
            feature['label'] = 'normal'
            feature['attack_type'] = 'none'
            timestamp = feature.get('timestamp', '')
            if timestamp:
                for marker_time, marker_info in self.attack_markers.items():
                    if marker_info['action'] == 'START':
                        if timestamp.startswith(marker_time.split(' ')[1][:5]):
                            feature['label'] = 'attack'
                            feature['attack_type'] = marker_info['type']
                            break
            if feature['label'] == 'normal':
                if (feature.get('flags') == 'S' and feature.get('packets', 0) > 50):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'SYN_FLOOD'
                elif (feature.get('protocol') == 'icmp' and
                      feature.get('src_ip', '').startswith('100.64.0.') and
                      feature.get('dst_ip', '').startswith('100.64.0.')):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'ICMP_FLOOD'
                elif (feature.get('packets', 0) <= 3 and
                      feature.get('state') in ['REJ', 'RST', 'FIN']):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'PORT_SCAN'
                elif (feature.get('protocol') == 'tcp' and
                      feature.get('dst_port') in ['80', '0x0050'] and
                      feature.get('packets', 0) > 1):
                    feature['label'] = 'attack'
                    feature['attack_type'] = 'HTTP_ATTACK'
        return features

    def generate_dataset(self) -> None:
        """
        Generate labeled dataset from Argus captures and attack markers.
        Outputs CSV and JSON summary report.
        """
        logger.info("Starting dataset generation...")
        os.makedirs(self.output_dir, exist_ok=True)
        all_features: List[Dict[str, Any]] = []
        self.load_attack_markers()
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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"security_dataset_{timestamp}.csv")
        with open(output_file, 'w') as f:
            headers = list(all_features[0].keys())
            f.write(','.join(headers) + '\n')
            for feature in all_features:
                values = [str(feature.get(h, '')) for h in headers]
                f.write(','.join(values) + '\n')
        logger.info(f"Saved dataset: {output_file}")
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

def main() -> None:
    """
    Main entry point for dataset generation script.
    Parses command-line arguments and runs the generator.
    """
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
