"""Model 1 SQLi detection package: dataset, model, metrics, export and inference."""
from .model import HybridCNNBiLSTMDetector
from .infer import DetectionInferenceEngine
from .dataset import DetectionDataset
