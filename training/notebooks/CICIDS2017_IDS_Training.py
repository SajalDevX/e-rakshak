# =============================================================================
# RAKSHAK IDS Model Training - Google Colab Notebook
# =============================================================================
# Copy each cell into Google Colab and run sequentially
# Dataset: CICIDS2017 from Kaggle
# Model: XGBoost (lightweight for Jetson Xavier NX)
# =============================================================================

# %% [markdown]
# # RAKSHAK IDS Model Training
# ## Train Intrusion Detection System using CICIDS2017 Dataset
#
# This notebook trains a lightweight XGBoost classifier for deployment on Jetson Xavier NX.

# %% [markdown]
# ## Cell 1: Install Dependencies

# %%
# Install required packages
!pip install -q kaggle xgboost scikit-learn pandas numpy matplotlib seaborn joblib

# %% [markdown]
# ## Cell 2: Setup Kaggle API

# %%
# Upload your kaggle.json file
from google.colab import files
import os

# Create kaggle directory
os.makedirs('/root/.kaggle', exist_ok=True)

# Upload kaggle.json (you'll be prompted to upload)
print("Upload your kaggle.json file:")
uploaded = files.upload()

# Move to correct location
!mv kaggle.json /root/.kaggle/
!chmod 600 /root/.kaggle/kaggle.json

print("Kaggle API configured!")

# %% [markdown]
# ## Cell 3: Download CICIDS2017 Dataset

# %%
# Download dataset from Kaggle
!kaggle datasets download -d mdalamintalukder/cicids2017 -p /content/data
!unzip -q /content/data/cicids2017.zip -d /content/data/cicids2017

# List downloaded files
import os
csv_files = [f for f in os.listdir('/content/data/cicids2017') if f.endswith('.csv')]
print(f"Found {len(csv_files)} CSV files:")
for f in csv_files:
    print(f"  - {f}")

# %% [markdown]
# ## Cell 4: Import Libraries

# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings('ignore')

print("Libraries imported successfully!")

# %% [markdown]
# ## Cell 5: Load and Combine CSV Files

# %%
def load_cicids2017(data_dir='/content/data/cicids2017', sample_size=None):
    """
    Load all CICIDS2017 CSV files and combine them.

    Args:
        data_dir: Directory containing CSV files
        sample_size: Number of samples per file (None = all)

    Returns:
        Combined DataFrame
    """
    csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv')]

    all_dfs = []
    for csv_file in csv_files:
        filepath = os.path.join(data_dir, csv_file)
        print(f"Loading {csv_file}...")

        try:
            df = pd.read_csv(filepath, low_memory=False)
            # Clean column names
            df.columns = df.columns.str.strip()

            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)

            all_dfs.append(df)
            print(f"  → Loaded {len(df)} rows")
        except Exception as e:
            print(f"  → Error: {e}")

    # Combine all DataFrames
    combined_df = pd.concat(all_dfs, ignore_index=True)
    print(f"\nTotal samples: {len(combined_df)}")

    return combined_df

# Load data (sample 100k per file to fit in Colab memory)
df = load_cicids2017(sample_size=100000)

# %% [markdown]
# ## Cell 6: Explore the Data

# %%
# Basic info
print("Dataset Shape:", df.shape)
print("\nColumn Names:")
print(df.columns.tolist())

# %%
# Find label column
label_col = None
for col in ['Label', ' Label', 'label']:
    if col in df.columns:
        label_col = col
        break

print(f"Label column: '{label_col}'")
print("\nLabel Distribution:")
print(df[label_col].value_counts())

# %%
# Visualize label distribution
plt.figure(figsize=(12, 6))
df[label_col].value_counts().plot(kind='bar', color='steelblue')
plt.title('Attack Type Distribution in CICIDS2017')
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# %% [markdown]
# ## Cell 7: Data Preprocessing

# %%
def preprocess_data(df, label_col):
    """
    Preprocess CICIDS2017 data for training.

    Steps:
    1. Remove non-numeric columns
    2. Handle missing/infinite values
    3. Encode labels
    4. Scale features
    """
    print("Preprocessing data...")

    # Separate features and labels
    y = df[label_col].copy()
    X = df.drop(columns=[label_col])

    # Keep only numeric columns
    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    X = X[numeric_cols]
    print(f"  → {len(numeric_cols)} numeric features")

    # Remove columns with all NaN
    X = X.dropna(axis=1, how='all')

    # Replace infinite values with NaN, then fill with median
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())

    # Remove any remaining problematic columns
    X = X.loc[:, X.apply(lambda col: col.nunique() > 1)]

    print(f"  → {X.shape[1]} features after cleaning")

    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    print(f"  → {len(label_encoder.classes_)} classes: {list(label_encoder.classes_)}")

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("  → Features scaled")

    return X_scaled, y_encoded, X.columns.tolist(), label_encoder, scaler

# Preprocess
X, y, feature_names, label_encoder, scaler = preprocess_data(df, label_col)

print(f"\nFinal dataset shape: {X.shape}")
print(f"Number of classes: {len(label_encoder.classes_)}")

# %% [markdown]
# ## Cell 8: Train-Test Split

# %%
# Split data (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y  # Maintain class distribution
)

print(f"Training set: {X_train.shape[0]} samples")
print(f"Test set: {X_test.shape[0]} samples")

# %% [markdown]
# ## Cell 9: Train XGBoost Model

# %%
# Configure XGBoost for multi-class classification
# Optimized for Jetson Xavier NX (lightweight)
xgb_params = {
    'objective': 'multi:softmax',
    'num_class': len(label_encoder.classes_),
    'max_depth': 6,              # Not too deep (memory efficient)
    'learning_rate': 0.1,
    'n_estimators': 100,         # Reasonable number of trees
    'min_child_weight': 1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'tree_method': 'hist',       # Fast histogram-based algorithm
    'random_state': 42,
    'n_jobs': -1,                # Use all CPU cores
    'verbosity': 1
}

print("Training XGBoost model...")
print(f"Parameters: {xgb_params}")

# Create and train model
model = xgb.XGBClassifier(**xgb_params)

# Train with progress
model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=True
)

print("\nTraining complete!")

# %% [markdown]
# ## Cell 10: Evaluate Model

# %%
# Make predictions
y_pred = model.predict(X_test)

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')

print("=" * 60)
print("MODEL EVALUATION RESULTS")
print("=" * 60)
print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")

# %%
# Detailed classification report
print("\n" + "=" * 60)
print("DETAILED CLASSIFICATION REPORT")
print("=" * 60)
print(classification_report(
    y_test, y_pred,
    target_names=label_encoder.classes_
))

# %%
# Confusion Matrix
plt.figure(figsize=(14, 10))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=label_encoder.classes_,
    yticklabels=label_encoder.classes_
)
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.xticks(rotation=45, ha='right')
plt.yticks(rotation=0)
plt.tight_layout()
plt.show()

# %% [markdown]
# ## Cell 11: Feature Importance

# %%
# Get feature importance
importance = model.feature_importances_
feature_importance = pd.DataFrame({
    'feature': feature_names,
    'importance': importance
}).sort_values('importance', ascending=False)

# Plot top 20 features
plt.figure(figsize=(12, 8))
top_features = feature_importance.head(20)
plt.barh(range(len(top_features)), top_features['importance'].values)
plt.yticks(range(len(top_features)), top_features['feature'].values)
plt.xlabel('Importance')
plt.title('Top 20 Most Important Features')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()

print("\nTop 10 Features:")
print(feature_importance.head(10).to_string(index=False))

# %% [markdown]
# ## Cell 12: Save Model and Artifacts

# %%
import pickle

# Create output directory
os.makedirs('/content/models', exist_ok=True)

# Save XGBoost model (joblib format - works on Jetson)
model_path = '/content/models/ids_xgboost_model.joblib'
joblib.dump(model, model_path)
print(f"Model saved: {model_path}")

# Save scaler
scaler_path = '/content/models/ids_scaler.joblib'
joblib.dump(scaler, scaler_path)
print(f"Scaler saved: {scaler_path}")

# Save label encoder
encoder_path = '/content/models/ids_label_encoder.joblib'
joblib.dump(label_encoder, encoder_path)
print(f"Label encoder saved: {encoder_path}")

# Save feature names
features_path = '/content/models/ids_feature_names.joblib'
joblib.dump(feature_names, features_path)
print(f"Feature names saved: {features_path}")

# Save model metadata
metadata = {
    'model_type': 'XGBoost',
    'num_features': len(feature_names),
    'num_classes': len(label_encoder.classes_),
    'classes': list(label_encoder.classes_),
    'accuracy': accuracy,
    'f1_score': f1,
    'feature_names': feature_names[:10],  # Top 10
    'xgb_params': xgb_params
}

metadata_path = '/content/models/ids_metadata.joblib'
joblib.dump(metadata, metadata_path)
print(f"Metadata saved: {metadata_path}")

# Check file sizes
print("\nModel file sizes:")
for f in os.listdir('/content/models'):
    size = os.path.getsize(f'/content/models/{f}') / (1024*1024)
    print(f"  {f}: {size:.2f} MB")

# %% [markdown]
# ## Cell 13: Download Models

# %%
# Zip all model files for easy download
!cd /content && zip -r rakshak_ids_model.zip models/

# Download the zip file
from google.colab import files
files.download('/content/rakshak_ids_model.zip')

print("\nDownload complete! Extract and copy to your Jetson.")

# %% [markdown]
# ## Cell 14: Test Inference (Verify Model Works)

# %%
# Simulate loading the model fresh (as you would on Jetson)
print("Testing model inference...")

# Load saved model
loaded_model = joblib.load('/content/models/ids_xgboost_model.joblib')
loaded_scaler = joblib.load('/content/models/ids_scaler.joblib')
loaded_encoder = joblib.load('/content/models/ids_label_encoder.joblib')
loaded_features = joblib.load('/content/models/ids_feature_names.joblib')

# Test on a few samples
test_samples = X_test[:5]
test_labels = y_test[:5]

# Predict
predictions = loaded_model.predict(test_samples)

print("\nInference Test Results:")
print("-" * 40)
for i, (pred, actual) in enumerate(zip(predictions, test_labels)):
    pred_label = loaded_encoder.classes_[pred]
    actual_label = loaded_encoder.classes_[actual]
    match = "✓" if pred == actual else "✗"
    print(f"Sample {i+1}: Predicted={pred_label}, Actual={actual_label} {match}")

# Measure inference time
import time

num_samples = 1000
test_batch = X_test[:num_samples]

start_time = time.time()
_ = loaded_model.predict(test_batch)
end_time = time.time()

inference_time = (end_time - start_time) * 1000 / num_samples
print(f"\nInference time: {inference_time:.3f} ms per sample")
print(f"Throughput: {1000/inference_time:.0f} samples/second")

# %% [markdown]
# ## Cell 15: Generate Integration Code

# %%
integration_code = '''
# =============================================================================
# RAKSHAK IDS Integration Code
# =============================================================================
# Copy this file to your Jetson at: core/ids_classifier.py
# =============================================================================

import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Tuple, Optional
from loguru import logger


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
        'Web Attack \\x96 Brute Force': 'ENGAGE_ATTACKER',
        'Web Attack \\x96 XSS': 'ISOLATE_DEVICE',
        'Web Attack \\x96 Sql Injection': 'ISOLATE_DEVICE',
        'Infiltration': 'ISOLATE_DEVICE',
        'Bot': 'ISOLATE_DEVICE',
        'Heartbleed': 'ISOLATE_DEVICE',
    }

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
        'Web Attack \\x96 Brute Force': 'high',
        'Web Attack \\x96 XSS': 'critical',
        'Web Attack \\x96 Sql Injection': 'critical',
        'Infiltration': 'critical',
        'Bot': 'critical',
        'Heartbleed': 'critical',
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
        self.is_loaded = False

        self._load_model()

    def _load_model(self):
        """Load all model artifacts."""
        try:
            model_path = self.model_dir / "ids_xgboost_model.joblib"
            scaler_path = self.model_dir / "ids_scaler.joblib"
            encoder_path = self.model_dir / "ids_label_encoder.joblib"
            features_path = self.model_dir / "ids_feature_names.joblib"

            if not model_path.exists():
                logger.warning(f"IDS model not found at {model_path}")
                return

            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(encoder_path)
            self.feature_names = joblib.load(features_path)

            self.is_loaded = True
            logger.info(f"IDS model loaded: {len(self.label_encoder.classes_)} classes")

        except Exception as e:
            logger.error(f"Failed to load IDS model: {e}")
            self.is_loaded = False

    def extract_features(self, flow_data: Dict) -> Optional[np.ndarray]:
        """
        Extract features from network flow data.

        Args:
            flow_data: Dictionary with flow statistics

        Returns:
            Feature vector or None if extraction fails
        """
        if not self.is_loaded:
            return None

        try:
            # Create feature vector matching training features
            features = np.zeros(len(self.feature_names))

            # Map common flow data to CICIDS2017 features
            feature_mapping = {
                'Destination Port': flow_data.get('dst_port', 0),
                'Flow Duration': flow_data.get('duration', 0),
                'Total Fwd Packets': flow_data.get('fwd_packets', 0),
                'Total Backward Packets': flow_data.get('bwd_packets', 0),
                'Total Length of Fwd Packets': flow_data.get('fwd_bytes', 0),
                'Total Length of Bwd Packets': flow_data.get('bwd_bytes', 0),
                'Flow Bytes/s': flow_data.get('bytes_per_sec', 0),
                'Flow Packets/s': flow_data.get('packets_per_sec', 0),
                'Flow IAT Mean': flow_data.get('iat_mean', 0),
                'Fwd IAT Mean': flow_data.get('fwd_iat_mean', 0),
                'Bwd IAT Mean': flow_data.get('bwd_iat_mean', 0),
                'Fwd PSH Flags': flow_data.get('fwd_psh', 0),
                'SYN Flag Count': flow_data.get('syn_count', 0),
                'ACK Flag Count': flow_data.get('ack_count', 0),
                'Average Packet Size': flow_data.get('avg_packet_size', 0),
            }

            for i, fname in enumerate(self.feature_names):
                if fname in feature_mapping:
                    features[i] = feature_mapping[fname]

            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            return features_scaled

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def classify(self, flow_data: Dict) -> Dict:
        """
        Classify network flow as attack or benign.

        Args:
            flow_data: Dictionary with flow statistics

        Returns:
            Classification result with attack type, severity, recommended action
        """
        if not self.is_loaded:
            return {
                'attack_type': 'unknown',
                'severity': 'medium',
                'confidence': 0.0,
                'recommended_action': 'MONITOR',
                'is_attack': False
            }

        try:
            # Extract and scale features
            features = self.extract_features(flow_data)
            if features is None:
                return self._default_result()

            # Predict
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]

            # Get label and confidence
            attack_type = self.label_encoder.classes_[prediction]
            confidence = float(probabilities[prediction])

            # Determine severity and action
            severity = self.ATTACK_SEVERITY.get(attack_type, 'medium')
            action = self.ATTACK_TO_ACTION.get(attack_type, 'MONITOR')
            is_attack = attack_type != 'BENIGN'

            return {
                'attack_type': attack_type,
                'severity': severity,
                'confidence': confidence,
                'recommended_action': action,
                'is_attack': is_attack,
                'all_probabilities': {
                    self.label_encoder.classes_[i]: float(p)
                    for i, p in enumerate(probabilities)
                }
            }

        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return self._default_result()

    def _default_result(self) -> Dict:
        """Return default result when classification fails."""
        return {
            'attack_type': 'unknown',
            'severity': 'medium',
            'confidence': 0.0,
            'recommended_action': 'ALERT_USER',
            'is_attack': False
        }

    def classify_batch(self, flow_data_list: list) -> list:
        """Classify multiple flows at once (more efficient)."""
        return [self.classify(flow) for flow in flow_data_list]


# =============================================================================
# Usage Example
# =============================================================================
if __name__ == "__main__":
    # Initialize classifier
    classifier = IDSClassifier(model_dir="models/ids")

    # Example flow data (from packet capture or network scanner)
    test_flow = {
        'dst_port': 22,
        'duration': 5000000,  # microseconds
        'fwd_packets': 100,
        'bwd_packets': 50,
        'fwd_bytes': 5000,
        'bwd_bytes': 2000,
        'bytes_per_sec': 1400,
        'packets_per_sec': 30,
        'syn_count': 50,
        'ack_count': 45,
    }

    # Classify
    result = classifier.classify(test_flow)

    print("Classification Result:")
    print(f"  Attack Type: {result['attack_type']}")
    print(f"  Severity: {result['severity']}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Recommended Action: {result['recommended_action']}")
    print(f"  Is Attack: {result['is_attack']}")
'''

# Save integration code
with open('/content/models/ids_classifier.py', 'w') as f:
    f.write(integration_code)

print("Integration code saved to: /content/models/ids_classifier.py")
print("\nThis file will be included in your download.")

# Re-zip with the integration code
!cd /content && zip -r rakshak_ids_model.zip models/

# %% [markdown]
# # Training Complete!
#
# ## Next Steps:
#
# 1. **Download** the `rakshak_ids_model.zip` file (should auto-download)
#
# 2. **Transfer to Jetson:**
#    ```bash
#    scp rakshak_ids_model.zip user@<jetson-ip>:~/e-raksha/
#    ```
#
# 3. **Extract on Jetson:**
#    ```bash
#    cd ~/e-raksha
#    unzip rakshak_ids_model.zip
#    mv models/ids_* models/ids/
#    ```
#
# 4. **Install dependencies on Jetson:**
#    ```bash
#    pip install xgboost joblib scikit-learn
#    ```
#
# 5. **Copy integration code:**
#    ```bash
#    cp models/ids_classifier.py core/
#    ```
#
# 6. **Use in RAKSHAK** (see integration code above)
