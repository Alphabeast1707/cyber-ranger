from pathlib import Path
from typing import Any, Optional
import joblib

try:
    from features import FEATURE_NAMES, extract_features
except ImportError:
    from .features import FEATURE_NAMES, extract_features


class BlueDetectorModel:
    """Classifier model for blue detector with dynamic hot-reload (§10)."""

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else Path("/app/models")
        if not self.models_dir.exists():
            # Local fallback
            local_fallback = Path(__file__).resolve().parent / "models"
            if local_fallback.exists():
                self.models_dir = local_fallback

        self.model = None
        self.current_model_path: Optional[str] = None
        self.reload()

    def reload(self) -> bool:
        """Hot-reload the latest trained model from the models directory (§10, §14)."""
        if not self.models_dir.exists():
            return False

        latest_link = self.models_dir / "latest_model.joblib"
        target_file = None

        if latest_link.exists():
            target_file = latest_link
        else:
            # Find newest .joblib file
            joblib_files = list(self.models_dir.glob("*.joblib"))
            if joblib_files:
                target_file = max(joblib_files, key=lambda f: f.stat().st_mtime)

        if target_file and target_file.exists():
            try:
                self.model = joblib.load(target_file)
                self.current_model_path = str(target_file)
                return True
            except Exception as e:
                print(f"[BlueDetectorModel] Failed to load {target_file}: {e}")
                return False

        return False

    def predict(self, request_payload: dict[str, Any]) -> tuple[bool, float, Optional[str]]:
        """Predict whether a request is malicious.
        
        Returns:
            (flagged: bool, confidence: float, rule_fired: Optional[str])
        """
        if self.model is None:
            # Check if a model has been dropped in the directory
            self.reload()

        if self.model is None:
            # Milestone 2 stub behavior: not flagged
            return False, 0.0, None

        features = extract_features(request_payload)
        proba = self.model.predict_proba([features])[0]
        malicious_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        flagged = malicious_prob >= 0.5

        # Determine which feature fired most significantly
        rule_fired = None
        if flagged:
            max_idx = max(range(len(features)), key=lambda i: features[i])
            rule_fired = f"rule_{FEATURE_NAMES[max_idx]}"

        return flagged, round(malicious_prob, 3), rule_fired
