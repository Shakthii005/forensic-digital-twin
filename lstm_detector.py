"""
lstm_detector.py — LSTM-based Behavioral Anomaly Detector
Patent Claim: "Device-specific learned behavioral baseline using LSTM neural networks
for anomaly detection in IoT digital twin forensic systems."

Each device gets its own LSTM model trained on its rolling window of readings.
The model predicts the next value; large prediction error = anomaly.

Uses numpy only (no heavy ML deps) via a hand-rolled single-layer LSTM cell
so it runs without GPU / TensorFlow on any student machine.
"""

import math
import random
from collections import deque
from typing import Dict, Optional
import threading


# ── Minimal LSTM cell (numpy-free, pure Python) ───────────────────────────────

def _sigmoid(x: float) -> float:
    x = max(-500, min(500, x))
    return 1.0 / (1.0 + math.exp(-x))

def _tanh(x: float) -> float:
    return math.tanh(max(-500, min(500, x)))


class _LSTMCell:
    """Single scalar-input, scalar-output LSTM cell."""

    def __init__(self):
        # Random init weights (small)
        rng = lambda: random.uniform(-0.1, 0.1)
        # Gates: forget, input, output, cell
        self.wf = rng(); self.bf = 0.5
        self.wi = rng(); self.bi = 0.0
        self.wo = rng(); self.bo = 0.0
        self.wg = rng(); self.bg = 0.0
        # Hidden → gates
        self.uf = rng()
        self.ui = rng()
        self.uo = rng()
        self.ug = rng()
        # Output
        self.wy = rng(); self.by = 0.0

        self.h = 0.0   # hidden state
        self.c = 0.0   # cell state

    def forward(self, x: float) -> float:
        f  = _sigmoid(self.wf * x + self.uf * self.h + self.bf)
        i  = _sigmoid(self.wi * x + self.ui * self.h + self.bi)
        o  = _sigmoid(self.wo * x + self.uo * self.h + self.bo)
        g  = _tanh   (self.wg * x + self.ug * self.h + self.bg)
        self.c = f * self.c + i * g
        self.h = o * _tanh(self.c)
        y  = self.wy * self.h + self.by
        return y

    def train_step(self, x: float, target: float, lr: float = 0.01):
        pred  = self.forward(x)
        error = pred - target
        # Simplified gradient descent on output weights only
        self.wy -= lr * error * self.h
        self.by -= lr * error
        return abs(error)


class DeviceLSTM:
    """
    Per-device LSTM predictor.
    Maintains a rolling buffer, trains online, and detects anomalies
    when prediction error exceeds a learned threshold.
    """

    WARMUP        = 20    # readings before anomaly detection activates
    BUFFER_SIZE   = 60
    ANOMALY_MULT  = 2.8   # prediction error > ANOMALY_MULT * avg_error → anomaly

    def __init__(self, device_id: str):
        self.device_id    = device_id
        self._cell        = _LSTMCell()
        self._buffer      = deque(maxlen=self.BUFFER_SIZE)
        self._errors      = deque(maxlen=30)
        self._step        = 0
        self._lock        = threading.Lock()

        # Normalisation params (running mean/std)
        self._mu          = 0.0
        self._sigma       = 1.0
        self._m2          = 0.0   # Welford variance

    def _update_stats(self, val: float):
        """Welford online mean/variance."""
        self._step += 1
        delta      = val - self._mu
        self._mu  += delta / self._step
        delta2     = val - self._mu
        self._m2  += delta * delta2
        if self._step > 1:
            self._sigma = max(math.sqrt(self._m2 / (self._step - 1)), 0.01)

    def _normalize(self, val: float) -> float:
        return (val - self._mu) / self._sigma

    def update(self, temp: float) -> dict:
        """
        Feed one temperature reading.
        Returns: {"anomaly": bool, "score": float, "prediction": float, "error": float}
        """
        with self._lock:
            self._update_stats(temp)
            x_norm = self._normalize(temp)
            self._buffer.append(x_norm)

            if len(self._buffer) < 2:
                return {"anomaly": False, "score": 0.0, "prediction": temp, "error": 0.0}

            # Train on previous → current
            prev  = list(self._buffer)[-2]
            error = self._cell.train_step(prev, x_norm, lr=0.005)
            self._errors.append(error)

            # Predict next (informational)
            pred_norm = self._cell.forward(x_norm)
            pred_real = pred_norm * self._sigma + self._mu

            # Anomaly if error >> average error (only after warmup)
            avg_err = sum(self._errors) / len(self._errors) if self._errors else 1.0
            score   = error / (avg_err + 1e-9)   # relative anomaly score
            anomaly = (self._step >= self.WARMUP) and (score > self.ANOMALY_MULT)

            return {
                "anomaly":    anomaly,
                "score":      round(score, 3),
                "prediction": round(pred_real, 2),
                "error":      round(error, 4),
                "step":       self._step,
            }


class LSTMFleet:
    """Manages one LSTM model per device."""

    def __init__(self, device_ids: list):
        self._models: Dict[str, DeviceLSTM] = {
            did: DeviceLSTM(did) for did in device_ids
        }

    def update(self, device_id: str, temp: float) -> dict:
        model = self._models.get(device_id)
        if model is None:
            return {"anomaly": False, "score": 0.0}
        return model.update(temp)

    def get_model(self, device_id: str) -> Optional[DeviceLSTM]:
        return self._models.get(device_id)
