from datetime import datetime, timezone
from pathlib import Path
import shutil
import time
from typing import Any, Optional
import joblib
import requests
from sklearn.ensemble import RandomForestClassifier

from cyberranger.features import extract_features
from cyberranger.triage import TriageItem

DEFAULT_MODELS_DIR = Path(__file__).resolve().parent.parent / "blue_detector" / "models"

# Standard benign web request fixtures to provide balanced supervision (§10)
BENIGN_TRAFFIC_SAMPLES = [
    {"url": "/index.php", "params": {"page": "home"}},
    {"url": "/login.php", "params": {"username": "alice", "action": "login"}},
    {"url": "/products.php", "params": {"id": "42", "category": "electronics"}},
    {"url": "/search.php", "params": {"q": "laptop stand", "sort": "price_asc"}},
    {"url": "/account/profile", "params": {"tab": "settings", "view": "compact"}},
    {"url": "/articles/read", "params": {"article_id": "1002", "lang": "en"}},
    {"url": "/api/v1/status", "params": {"service": "inventory"}},
    {"url": "/feedback", "body": "Great service, thank you very much!"},
    {"url": "/contact", "params": {"name": "John Doe", "email": "john@example.com"}},
    {"url": "/blog/page/2", "params": {"theme": "light"}},
]


def build_feature_matrix(
    confirmed_items: list[TriageItem],
    benign_samples: Optional[list[dict[str, Any]]] = None,
) -> tuple[list[list[float]], list[int]]:
    """Build feature matrix X and labels y for classifier training (§10).
    
    Uses request structure, token markers, and statistical properties
    rather than raw payload strings to encourage true generalization.
    """
    X = []
    y = []

    # Positive samples: confirmed exploits from triage
    for item in confirmed_items:
        payload_str = item.genome.rendered_payload
        injection_pt = item.genome.injection_point
        # Construct synthetic request for feature extraction
        req = {
            "url": f"/vulnerabilities/{item.genome.vuln_class.value}/",
            "params": {injection_pt: payload_str},
            "body": payload_str,
        }
        features = extract_features(req)
        X.append(features)
        y.append(1)

    # Negative samples: benign baseline traffic
    benign_list = benign_samples or BENIGN_TRAFFIC_SAMPLES
    # Scale benign samples to roughly match positive sample volume
    multiplier = max(1, len(confirmed_items) // len(benign_list))
    for _ in range(multiplier):
        for sample in benign_list:
            features = extract_features(sample)
            X.append(features)
            y.append(0)

    return X, y


class BlueLearner:
    """Manages blue detector classifier retraining and hot-reloading (§10)."""

    def __init__(
        self,
        models_dir: Optional[Path | str] = None,
        detector_api_url: str = "http://127.0.0.1:8000",
    ):
        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.detector_api_url = detector_api_url.rstrip("/")

    def retrain(
        self,
        confirmed_items: list[TriageItem],
        existing_model: Optional[Any] = None,
    ) -> tuple[RandomForestClassifier, Path]:
        """Retrain random forest classifier and trigger service hot-reload (§10)."""
        if not confirmed_items:
            raise ValueError("Cannot retrain blue detector with zero confirmed items.")

        X, y = build_feature_matrix(confirmed_items)

        # Train Random Forest classifier with balanced weights
        model = RandomForestClassifier(
            n_estimators=100,  # fast and robust
            class_weight="balanced",
            random_state=42,
        )
        model.fit(X, y)

        # Save artifact with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        model_filename = f"blue_model_{timestamp}.joblib"
        model_path = self.models_dir / model_filename
        joblib.dump(model, model_path)

        # Update latest_model.joblib
        latest_path = self.models_dir / "latest_model.joblib"
        shutil.copy2(model_path, latest_path)

        # Trigger hot-reload in blue-detector service
        self.hot_reload_service()

        return model, model_path

    def hot_reload_service(self) -> bool:
        """Call POST /reload on blue-detector service."""
        try:
            resp = requests.post(f"{self.detector_api_url}/reload", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
