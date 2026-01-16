# RAKSHAK Model Training

This folder contains all training-related code for RAKSHAK's AI models.

## Folder Structure

```
training/
├── README.md                              # This file
├── notebooks/
│   └── CICIDS2017_IDS_Training.py        # Google Colab notebook (IDS)
├── scripts/
│   └── train_kaal.py                     # KAAL DQN training script
└── data/
    └── (place CICIDS2017 dataset here)
```

## Training Options

### Option 1: IDS Classifier (Recommended - Supervised Learning)

**Best for**: Quick deployment, high accuracy, lightweight

Uses XGBoost trained on CICIDS2017 dataset.

#### How to Train:

1. **Open Google Colab**: https://colab.research.google.com
2. **Copy cells** from `notebooks/CICIDS2017_IDS_Training.py`
3. **Upload** your `kaggle.json` when prompted
4. **Run all cells** - takes ~30 minutes
5. **Download** `rakshak_ids_model.zip`
6. **Deploy** to Jetson (see instructions below)

#### Expected Results:
- Accuracy: 95-99%
- Inference: <1ms per sample
- Model size: ~50MB

---

### Option 2: KAAL DQN (Reinforcement Learning)

**Best for**: Autonomous decision making, online learning

Uses Dueling DQN for action selection.

#### How to Train:

```bash
# On training machine (with GPU)
cd training

# Download dataset first
kaggle datasets download -d mdalamintalukder/cicids2017
unzip cicids2017.zip -d data/

# Run training
python scripts/train_kaal.py \
    --data_dir data/cicids2017 \
    --epochs 50 \
    --device cuda
```

---

## Deploying to Jetson

### Step 1: Transfer Files

```bash
# From training machine
scp rakshak_ids_model.zip user@<jetson-ip>:~/e-raksha/
```

### Step 2: Extract on Jetson

```bash
cd ~/e-raksha
unzip rakshak_ids_model.zip
mkdir -p models/ids
mv models/*.joblib models/ids/
```

### Step 3: Install Dependencies

```bash
pip install xgboost joblib scikit-learn
```

### Step 4: Verify

```bash
python -c "
from core.ids_classifier import IDSClassifier
classifier = IDSClassifier()
print('Model loaded!' if classifier.is_loaded else 'Load failed')
"
```

---

## Dataset Info

### CICIDS2017

- **Source**: https://www.kaggle.com/datasets/mdalamintalukder/cicids2017
- **Size**: ~500MB (CSV files)
- **Samples**: ~2.8 million network flows
- **Classes**: 15 attack types + benign

| Attack Type | Category |
|-------------|----------|
| BENIGN | Normal traffic |
| DoS Hulk | Denial of Service |
| DoS GoldenEye | Denial of Service |
| DoS slowloris | Denial of Service |
| DoS Slowhttptest | Denial of Service |
| DDoS | Distributed DoS |
| PortScan | Reconnaissance |
| FTP-Patator | Brute Force |
| SSH-Patator | Brute Force |
| Web Attack – Brute Force | Web Attack |
| Web Attack – XSS | Web Attack |
| Web Attack – SQL Injection | Web Attack |
| Infiltration | Advanced Persistent Threat |
| Bot | Botnet |
| Heartbleed | Vulnerability Exploit |

---

## Model Files

After training, you'll have:

| File | Size | Description |
|------|------|-------------|
| `ids_xgboost_model.joblib` | ~50MB | Trained XGBoost model |
| `ids_scaler.joblib` | ~10KB | Feature scaler |
| `ids_label_encoder.joblib` | ~1KB | Label encoder |
| `ids_feature_names.joblib` | ~1KB | Feature names list |
| `ids_metadata.joblib` | ~1KB | Training metadata |

---

## Integration with RAKSHAK

The trained IDS model integrates with RAKSHAK through `core/ids_classifier.py`.

### Usage in Agentic Defender:

```python
from core.ids_classifier import IDSClassifier

# Initialize
ids = IDSClassifier(model_dir="models/ids")

# Classify network flow
result = ids.classify({
    'dst_port': 22,
    'duration': 5000000,
    'fwd_packets': 100,
    'bwd_packets': 50,
    # ... more flow features
})

# Use result
if result['is_attack']:
    print(f"Attack detected: {result['attack_type']}")
    print(f"Recommended action: {result['recommended_action']}")
```

### Integration with KAAL:

```python
# In agentic_defender.py
class AgenticDefender:
    def __init__(self, config, threat_logger=None):
        # ... existing init ...
        self.ids_classifier = IDSClassifier(model_dir="models/ids")

    def analyze_flow(self, flow_data):
        """Use IDS to classify network flow."""
        result = self.ids_classifier.classify(flow_data)

        if result['is_attack']:
            # Convert to threat_info format
            threat_info = {
                'type': self._map_attack_type(result['attack_type']),
                'severity': result['severity'],
                'source_ip': flow_data.get('src_ip'),
                'confidence': result['confidence']
            }
            return self.decide(threat_info)

        return None
```
