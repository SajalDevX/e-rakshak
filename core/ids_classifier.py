#!/usr/bin/env python3
"""
RAKSHAK IDS Classifier
======================

Intrusion Detection System classifier using XGBoost model
trained on CICIDS2017 dataset.

Lightweight and optimized for Jetson Xavier NX deployment.

Usage:
    from core.ids_classifier import IDSClassifier

    classifier = IDSClassifier(model_dir="models/ids")
    result = classifier.classify(flow_data)

Author: Team RAKSHAK
"""

import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from loguru import logger

# Optional imports
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    logger.warning("joblib not installed - IDS classifier unavailable")


@dataclass
class ClassificationResult:
    """Result of IDS classification."""
    attack_type: str
    severity: str
    confidence: float
    recommended_action: str
    is_attack: bool
    all_probabilities: Optional[Dict[str, float]] = None


class IDSClassifier:
    """
    Intrusion Detection System Classifier for RAKSHAK.

    Uses XGBoost model trained on CICIDS2017 dataset.
    Lightweight and optimized for Jetson Xavier NX.
    """

    # Attack type mapping to KAAL actions
    ATTACK_TO_ACTION = {
        'BENIGN': 'MONITOR',
        'DoS Hulk': 'ISOLATE_DEVICE',
        'DoS GoldenEye': 'ISOLATE_DEVICE',
        'DoS slowloris': 'ISOLATE_DEVICE',
        'DoS Slowhttptest': 'ISOLATE_DEVICE',
        'DDoS': 'ISOLATE_DEVICE',
        'PortScan': 'DEPLOY_HONEYPOT',
        'FTP-Patator': 'ENGAGE_ATTACKER',
        'SSH-Patator': 'ENGAGE_ATTACKER',
        'Web Attack \x96 Brute Force': 'ENGAGE_ATTACKER',
        'Web Attack \x96 XSS': 'ISOLATE_DEVICE',
        'Web Attack \x96 Sql Injection': 'ISOLATE_DEVICE',
        'Infiltration': 'ISOLATE_DEVICE',
        'Bot': 'ISOLATE_DEVICE',
        'Heartbleed': 'ISOLATE_DEVICE',
    }

    # Severity mapping
    ATTACK_SEVERITY = {
        'BENIGN': 'low',
        'PortScan': 'low',
        'FTP-Patator': 'high',
        'SSH-Patator': 'high',
        'DoS Hulk': 'high',
        'DoS GoldenEye': 'high',
        'DoS slowloris': 'medium',
        'DoS Slowhttptest': 'medium',
        'DDoS': 'critical',
        'Web Attack \x96 Brute Force': 'high',
        'Web Attack \x96 XSS': 'critical',
        'Web Attack \x96 Sql Injection': 'critical',
        'Infiltration': 'critical',
        'Bot': 'critical',
        'Heartbleed': 'critical',
    }

    # KAAL attack type mapping
    ATTACK_TO_KAAL_TYPE = {
        'BENIGN': 'normal',
        'PortScan': 'port_scan',
        'FTP-Patator': 'brute_force',
        'SSH-Patator': 'brute_force',
        'DoS Hulk': 'dos_attack',
        'DoS GoldenEye': 'dos_attack',
        'DoS slowloris': 'dos_attack',
        'DoS Slowhttptest': 'dos_attack',
        'DDoS': 'dos_attack',
        'Web Attack \x96 Brute Force': 'brute_force',
        'Web Attack \x96 XSS': 'exploit_attempt',
        'Web Attack \x96 Sql Injection': 'exploit_attempt',
        'Infiltration': 'malware',
        'Bot': 'malware',
        'Heartbleed': 'exploit_attempt',
    }

    def __init__(self, model_dir: str = "models/ids"):
        """
        Initialize the IDS classifier.

        Args:
            model_dir: Directory containing model files
        """
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.metadata = None
        self.is_loaded = False

        if JOBLIB_AVAILABLE:
            self._load_model()
        else:
            logger.warning("IDS Classifier disabled - joblib not available")

    def _load_model(self) -> bool:
        """Load all model artifacts."""
        try:
            model_path = self.model_dir / "ids_xgboost_model.joblib"
            scaler_path = self.model_dir / "ids_scaler.joblib"
            encoder_path = self.model_dir / "ids_label_encoder.joblib"
            features_path = self.model_dir / "ids_feature_names.joblib"
            metadata_path = self.model_dir / "ids_metadata.joblib"

            if not model_path.exists():
                logger.info(f"IDS model not found at {model_path} - classifier disabled")
                logger.info("Train the model using training/notebooks/CICIDS2017_IDS_Training.py")
                return False

            # Load model components
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(encoder_path)
            self.feature_names = joblib.load(features_path)

            if metadata_path.exists():
                self.metadata = joblib.load(metadata_path)

            self.is_loaded = True
            num_classes = len(self.label_encoder.classes_)
            logger.info(f"IDS model loaded successfully: {num_classes} attack classes")

            return True

        except Exception as e:
            logger.error(f"Failed to load IDS model: {e}")
            self.is_loaded = False
            return False

    def extract_features(self, flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract features from network flow data.

        Maps common flow statistics to CICIDS2017 feature format.

        Args:
            flow_data: Dictionary with flow statistics
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - src_port: Source port
                - dst_port: Destination port
                - protocol: Protocol number (6=TCP, 17=UDP)
                - duration: Flow duration in microseconds
                - fwd_packets: Forward packets
                - bwd_packets: Backward packets
                - fwd_bytes: Forward bytes
                - bwd_bytes: Backward bytes
                - ... other features

        Returns:
            Scaled feature vector or None if extraction fails
        """
        if not self.is_loaded:
            return None

        try:
            # Create feature vector matching training features
            features = np.zeros(len(self.feature_names))

            # Map flow data to CICIDS2017 feature names
            feature_mapping = {
                # Port information
                'Destination Port': flow_data.get('dst_port', 0),
                'Source Port': flow_data.get('src_port', 0),

                # Flow duration
                'Flow Duration': flow_data.get('duration', 0),

                # Packet counts
                'Total Fwd Packets': flow_data.get('fwd_packets', 0),
                'Total Backward Packets': flow_data.get('bwd_packets', 0),

                # Byte counts
                'Total Length of Fwd Packets': flow_data.get('fwd_bytes', 0),
                'Total Length of Bwd Packets': flow_data.get('bwd_bytes', 0),

                # Flow rates
                'Flow Bytes/s': flow_data.get('bytes_per_sec', 0),
                'Flow Packets/s': flow_data.get('packets_per_sec', 0),

                # Inter-arrival times
                'Flow IAT Mean': flow_data.get('iat_mean', 0),
                'Flow IAT Std': flow_data.get('iat_std', 0),
                'Flow IAT Max': flow_data.get('iat_max', 0),
                'Flow IAT Min': flow_data.get('iat_min', 0),
                'Fwd IAT Mean': flow_data.get('fwd_iat_mean', 0),
                'Bwd IAT Mean': flow_data.get('bwd_iat_mean', 0),

                # Flags
                'Fwd PSH Flags': flow_data.get('fwd_psh', 0),
                'Bwd PSH Flags': flow_data.get('bwd_psh', 0),
                'Fwd URG Flags': flow_data.get('fwd_urg', 0),
                'Bwd URG Flags': flow_data.get('bwd_urg', 0),
                'FIN Flag Count': flow_data.get('fin_count', 0),
                'SYN Flag Count': flow_data.get('syn_count', 0),
                'RST Flag Count': flow_data.get('rst_count', 0),
                'PSH Flag Count': flow_data.get('psh_count', 0),
                'ACK Flag Count': flow_data.get('ack_count', 0),
                'URG Flag Count': flow_data.get('urg_count', 0),

                # Packet sizes
                'Fwd Packet Length Max': flow_data.get('fwd_pkt_max', 0),
                'Fwd Packet Length Min': flow_data.get('fwd_pkt_min', 0),
                'Fwd Packet Length Mean': flow_data.get('fwd_pkt_mean', 0),
                'Bwd Packet Length Max': flow_data.get('bwd_pkt_max', 0),
                'Bwd Packet Length Min': flow_data.get('bwd_pkt_min', 0),
                'Bwd Packet Length Mean': flow_data.get('bwd_pkt_mean', 0),
                'Average Packet Size': flow_data.get('avg_packet_size', 0),
                'Avg Fwd Segment Size': flow_data.get('avg_fwd_segment', 0),
                'Avg Bwd Segment Size': flow_data.get('avg_bwd_segment', 0),

                # Header lengths
                'Fwd Header Length': flow_data.get('fwd_header_len', 0),
                'Bwd Header Length': flow_data.get('bwd_header_len', 0),

                # Subflow metrics
                'Subflow Fwd Packets': flow_data.get('subflow_fwd_packets', 0),
                'Subflow Fwd Bytes': flow_data.get('subflow_fwd_bytes', 0),
                'Subflow Bwd Packets': flow_data.get('subflow_bwd_packets', 0),
                'Subflow Bwd Bytes': flow_data.get('subflow_bwd_bytes', 0),

                # Init window
                'Init_Win_bytes_forward': flow_data.get('init_win_fwd', 0),
                'Init_Win_bytes_backward': flow_data.get('init_win_bwd', 0),

                # Active/Idle
                'Active Mean': flow_data.get('active_mean', 0),
                'Active Std': flow_data.get('active_std', 0),
                'Active Max': flow_data.get('active_max', 0),
                'Active Min': flow_data.get('active_min', 0),
                'Idle Mean': flow_data.get('idle_mean', 0),
                'Idle Std': flow_data.get('idle_std', 0),
                'Idle Max': flow_data.get('idle_max', 0),
                'Idle Min': flow_data.get('idle_min', 0),
            }

            # Fill feature vector
            for i, fname in enumerate(self.feature_names):
                # Try exact match first
                if fname in feature_mapping:
                    features[i] = feature_mapping[fname]
                # Try with leading space (CICIDS2017 quirk)
                elif f" {fname}" in feature_mapping:
                    features[i] = feature_mapping[f" {fname}"]
                # Try stripped version
                else:
                    stripped = fname.strip()
                    if stripped in feature_mapping:
                        features[i] = feature_mapping[stripped]

            # Handle infinities and NaNs
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            return features_scaled

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def classify(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify network flow as attack or benign.

        Args:
            flow_data: Dictionary with flow statistics

        Returns:
            Dictionary with:
                - attack_type: Detected attack type
                - severity: low/medium/high/critical
                - confidence: Model confidence (0-1)
                - recommended_action: KAAL action
                - is_attack: Boolean
                - kaal_type: KAAL attack type encoding
                - all_probabilities: Dict of all class probabilities
        """
        if not self.is_loaded:
            return self._default_result()

        try:
            # Extract and scale features
            features = self.extract_features(flow_data)
            if features is None:
                return self._default_result()

            # Predict
            prediction = self.model.predict(features)[0]

            # Get probabilities if available
            try:
                probabilities = self.model.predict_proba(features)[0]
                confidence = float(probabilities[prediction])
                all_probs = {
                    self.label_encoder.classes_[i]: float(p)
                    for i, p in enumerate(probabilities)
                }
            except:
                confidence = 0.9  # Default high confidence
                all_probs = None

            # Get label
            attack_type = self.label_encoder.classes_[prediction]

            # Determine severity and action
            severity = self.ATTACK_SEVERITY.get(attack_type, 'medium')
            action = self.ATTACK_TO_ACTION.get(attack_type, 'MONITOR')
            kaal_type = self.ATTACK_TO_KAAL_TYPE.get(attack_type, 'suspicious_traffic')
            is_attack = attack_type != 'BENIGN'

            return {
                'attack_type': attack_type,
                'severity': severity,
                'confidence': confidence,
                'recommended_action': action,
                'is_attack': is_attack,
                'kaal_type': kaal_type,
                'all_probabilities': all_probs
            }

        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return self._default_result()

    def _default_result(self) -> Dict[str, Any]:
        """Return default result when classification fails."""
        return {
            'attack_type': 'unknown',
            'severity': 'medium',
            'confidence': 0.0,
            'recommended_action': 'ALERT_USER',
            'is_attack': False,
            'kaal_type': 'suspicious_traffic',
            'all_probabilities': None
        }

    def classify_batch(self, flow_data_list: List[Dict]) -> List[Dict]:
        """
        Classify multiple flows at once (more efficient).

        Args:
            flow_data_list: List of flow data dictionaries

        Returns:
            List of classification results
        """
        return [self.classify(flow) for flow in flow_data_list]

    def get_threat_info(self, flow_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get threat info in KAAL-compatible format.

        Useful for direct integration with AgenticDefender.

        Args:
            flow_data: Flow statistics

        Returns:
            Threat info dict compatible with KAAL's decide() method,
            or None if no threat detected
        """
        result = self.classify(flow_data)

        if not result['is_attack']:
            return None

        # Convert to KAAL threat_info format
        return {
            'type': result['kaal_type'],
            'severity': result['severity'],
            'source_ip': flow_data.get('src_ip', 'unknown'),
            'source_port': flow_data.get('src_port', 0),
            'target_ip': flow_data.get('dst_ip', 'unknown'),
            'target_port': flow_data.get('dst_port', 0),
            'protocol': flow_data.get('protocol', 'tcp'),
            'confidence': result['confidence'],
            'ids_attack_type': result['attack_type'],
            'detected_by': 'ids_classifier'
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get classifier statistics and info."""
        if not self.is_loaded:
            return {'status': 'not_loaded'}

        return {
            'status': 'loaded',
            'num_classes': len(self.label_encoder.classes_),
            'classes': list(self.label_encoder.classes_),
            'num_features': len(self.feature_names),
            'model_type': 'XGBoost',
            'metadata': self.metadata
        }


# =============================================================================
# Convenience Functions
# =============================================================================

def create_flow_from_packet(packet_info: Dict) -> Dict:
    """
    Create flow data from packet capture info.

    Helper function to convert raw packet data to flow format.

    Args:
        packet_info: Raw packet information

    Returns:
        Flow data dictionary
    """
    return {
        'src_ip': packet_info.get('src_ip'),
        'dst_ip': packet_info.get('dst_ip'),
        'src_port': packet_info.get('src_port', 0),
        'dst_port': packet_info.get('dst_port', 0),
        'protocol': packet_info.get('protocol', 6),
        'duration': packet_info.get('duration', 0),
        'fwd_packets': packet_info.get('fwd_packets', 1),
        'bwd_packets': packet_info.get('bwd_packets', 0),
        'fwd_bytes': packet_info.get('fwd_bytes', 0),
        'bwd_bytes': packet_info.get('bwd_bytes', 0),
        'syn_count': packet_info.get('syn_count', 0),
        'ack_count': packet_info.get('ack_count', 0),
    }


# =============================================================================
# Main (for testing)
# =============================================================================

if __name__ == "__main__":
    # Test the classifier
    print("Testing IDS Classifier...")
    print("=" * 50)

    classifier = IDSClassifier(model_dir="models/ids")

    if classifier.is_loaded:
        print(f"Model loaded successfully!")
        print(f"Classes: {classifier.get_statistics()['classes']}")

        # Test flow (simulating SSH brute force)
        test_flow = {
            'src_ip': '192.168.100.50',
            'dst_ip': '192.168.100.1',
            'src_port': 54321,
            'dst_port': 22,
            'protocol': 6,
            'duration': 5000000,
            'fwd_packets': 100,
            'bwd_packets': 50,
            'fwd_bytes': 5000,
            'bwd_bytes': 2000,
            'syn_count': 50,
            'ack_count': 45,
        }

        result = classifier.classify(test_flow)

        print("\nClassification Result:")
        print(f"  Attack Type: {result['attack_type']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print(f"  Recommended Action: {result['recommended_action']}")
        print(f"  Is Attack: {result['is_attack']}")

        # Get KAAL-compatible threat info
        threat_info = classifier.get_threat_info(test_flow)
        if threat_info:
            print("\nKAAL Threat Info:")
            for k, v in threat_info.items():
                print(f"  {k}: {v}")
    else:
        print("Model not loaded - train it first using:")
        print("  training/notebooks/CICIDS2017_IDS_Training.py")
