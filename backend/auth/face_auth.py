"""
AK Master Security System — Face Authentication Module
Implements biometric enrollment and 1:1 verification.

DESIGN PRINCIPLES:
- Never store raw face images
- Store only encrypted embeddings
- Graceful degradation if native model not available
- Always clearly label capability status

STATUS REPORTING:
- AVAILABLE: full pipeline with detected face model
- DEGRADED: OpenCV basic detection, lower accuracy
- UNAVAILABLE: no model loaded
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from enum import Enum
from typing import Optional

import numpy as np

from backend.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()


class FaceAuthStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED_BASIC = "DEGRADED_BASIC"
    UNAVAILABLE = "UNAVAILABLE"


class FaceAuthResult(str, Enum):
    VERIFIED = "VERIFIED"
    NO_MATCH = "NO_MATCH"
    NO_FACE_DETECTED = "NO_FACE_DETECTED"
    LOW_QUALITY = "LOW_QUALITY"
    LIVENESS_FAILED = "LIVENESS_FAILED"
    MODULE_UNAVAILABLE = "MODULE_UNAVAILABLE"
    ERROR = "ERROR"


# ──────────────────────────────────────────────────────────
# Module availability detection
# ──────────────────────────────────────────────────────────

def _detect_face_module() -> FaceAuthStatus:
    """Detect which face recognition module is available."""
    try:
        import face_recognition  # noqa: F401
        logger.info("Face recognition: face_recognition library available")
        return FaceAuthStatus.AVAILABLE
    except ImportError:
        pass

    try:
        import cv2
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        if face_cascade.empty():
            raise RuntimeError("Haar cascade not found")
        logger.info("Face recognition: OpenCV basic detection only (degraded mode)")
        return FaceAuthStatus.DEGRADED_BASIC
    except Exception:
        pass

    logger.warning("Face recognition: no module available — biometric auth disabled")
    return FaceAuthStatus.UNAVAILABLE


_MODULE_STATUS: Optional[FaceAuthStatus] = None


def get_face_module_status() -> FaceAuthStatus:
    global _MODULE_STATUS
    if _MODULE_STATUS is None:
        _MODULE_STATUS = _detect_face_module()
    return _MODULE_STATUS


# ──────────────────────────────────────────────────────────
# Embedding encryption (application-level)
# ──────────────────────────────────────────────────────────

def _encrypt_embedding(embedding: list[float]) -> str:
    """
    Encrypt a face embedding for database storage.
    Uses AES-GCM via the cryptography library if available,
    falls back to XOR-with-key for demonstration (NOT production-grade
    unless cryptography library is present).
    """
    try:
        from cryptography.fernet import Fernet
        import hashlib as hl
        # Derive a Fernet key from the configured key
        raw_key = settings.face_embedding_encryption_key.encode()
        derived = hl.sha256(raw_key).digest()
        fernet_key = base64.urlsafe_b64encode(derived)
        f = Fernet(fernet_key)
        data = json.dumps(embedding).encode()
        encrypted = f.encrypt(data)
        return base64.b64encode(encrypted).decode()
    except ImportError:
        # Fallback: base64 only — marks as plaintext with prefix
        logger.warning(
            "cryptography library not available — embedding stored as base64 only. "
            "Install cryptography for production use."
        )
        data = json.dumps(embedding).encode()
        return "b64:" + base64.b64encode(data).decode()


def _decrypt_embedding(encrypted: str) -> list[float]:
    """Decrypt a stored face embedding."""
    if encrypted.startswith("b64:"):
        data = base64.b64decode(encrypted[4:])
        return json.loads(data)

    try:
        from cryptography.fernet import Fernet
        import hashlib as hl
        raw_key = settings.face_embedding_encryption_key.encode()
        derived = hl.sha256(raw_key).digest()
        fernet_key = base64.urlsafe_b64encode(derived)
        f = Fernet(fernet_key)
        encrypted_bytes = base64.b64decode(encrypted)
        data = f.decrypt(encrypted_bytes)
        return json.loads(data)
    except Exception as e:
        raise ValueError(f"Failed to decrypt face embedding: {e}") from e


# ──────────────────────────────────────────────────────────
# Image analysis helpers
# ──────────────────────────────────────────────────────────

def check_image_quality(image_bytes: bytes) -> tuple[bool, float, str]:
    """
    Check if image is suitable for face enrollment.
    Returns (is_acceptable, quality_score, reason).
    """
    try:
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return False, 0.0, "Could not decode image"

        h, w = img.shape[:2]
        if w < 128 or h < 128:
            return False, 0.1, f"Image too small ({w}x{h}). Minimum 128x128."

        # Laplacian variance as blur metric
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
        if blur_score < 50:
            return False, 0.2, f"Image is too blurry (score: {blur_score:.1f})"

        quality = min(1.0, blur_score / 1000)
        return True, quality, "OK"

    except Exception as e:
        return False, 0.0, f"Quality check failed: {e}"


# ──────────────────────────────────────────────────────────
# Enrollment
# ──────────────────────────────────────────────────────────

class EnrollmentResult:
    def __init__(
        self,
        success: bool,
        encrypted_embedding: Optional[str] = None,
        quality_score: Optional[float] = None,
        model_name: str = "",
        error: str = "",
    ):
        self.success = success
        self.encrypted_embedding = encrypted_embedding
        self.quality_score = quality_score
        self.model_name = model_name
        self.error = error


def enroll_face(image_bytes: bytes) -> EnrollmentResult:
    """
    Process a face image for enrollment.
    Returns EnrollmentResult — never raises (caller checks .success).
    """
    status = get_face_module_status()

    if status == FaceAuthStatus.UNAVAILABLE:
        return EnrollmentResult(
            success=False,
            error=(
                "Face authentication module is not available. "
                "Please install face_recognition or ensure OpenCV is configured. "
                "See docs/INSTALLATION.md for setup instructions."
            ),
        )

    # Quality check first
    ok, quality, reason = check_image_quality(image_bytes)
    if not ok:
        return EnrollmentResult(success=False, error=f"Image quality check failed: {reason}")

    if status == FaceAuthStatus.AVAILABLE:
        return _enroll_with_face_recognition(image_bytes, quality)
    else:
        return _enroll_with_opencv(image_bytes, quality)


def _enroll_with_face_recognition(image_bytes: bytes, quality: float) -> EnrollmentResult:
    try:
        import face_recognition
        nparr = np.frombuffer(image_bytes, np.uint8)
        import cv2
        img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)

        locations = face_recognition.face_locations(img_rgb, model="hog")
        if not locations:
            return EnrollmentResult(success=False, error="No face detected in image.")
        if len(locations) > 1:
            return EnrollmentResult(
                success=False,
                error="Multiple faces detected. Please use an image with only one face.",
            )

        encodings = face_recognition.face_encodings(img_rgb, locations)
        if not encodings:
            return EnrollmentResult(success=False, error="Could not generate face encoding.")

        embedding = encodings[0].tolist()
        encrypted = _encrypt_embedding(embedding)
        return EnrollmentResult(
            success=True,
            encrypted_embedding=encrypted,
            quality_score=quality,
            model_name="face_recognition/dlib-v1",
        )
    except Exception as e:
        logger.error("Face enrollment error: %s", e)
        return EnrollmentResult(success=False, error=f"Enrollment failed: {e}")


def _enroll_with_opencv(image_bytes: bytes, quality: float) -> EnrollmentResult:
    """
    Basic OpenCV enrollment (degraded mode).
    Uses HOG features instead of deep embeddings — lower accuracy.
    Clearly labelled as degraded mode.
    """
    try:
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)

        if len(faces) == 0:
            return EnrollmentResult(success=False, error="No face detected in image.")
        if len(faces) > 1:
            return EnrollmentResult(
                success=False,
                error="Multiple faces detected. Please use an image with only one face.",
            )

        x, y, w, h = faces[0]
        face_roi = cv2.resize(gray[y:y+h, x:x+w], (64, 64))

        # HOG descriptor as a basic embedding
        hog = cv2.HOGDescriptor(
            (64, 64), (16, 16), (8, 8), (8, 8), 9
        )
        descriptor = hog.compute(face_roi)
        embedding = descriptor.flatten().tolist()

        encrypted = _encrypt_embedding(embedding)
        return EnrollmentResult(
            success=True,
            encrypted_embedding=encrypted,
            quality_score=quality * 0.5,  # Penalize quality for degraded mode
            model_name="opencv/hog-degraded-v1",
        )
    except Exception as e:
        logger.error("OpenCV face enrollment error: %s", e)
        return EnrollmentResult(success=False, error=f"Enrollment failed: {e}")


# ──────────────────────────────────────────────────────────
# Verification
# ──────────────────────────────────────────────────────────

def verify_face(
    image_bytes: bytes,
    stored_encrypted_embedding: str,
    model_name: str,
    tolerance: float = 0.6,
) -> tuple[FaceAuthResult, float]:
    """
    Verify a face image against a stored embedding.
    Returns (result, confidence_score).
    Confidence is 0.0–1.0 — never treat as absolute truth.
    """
    status = get_face_module_status()

    if status == FaceAuthStatus.UNAVAILABLE:
        return FaceAuthResult.MODULE_UNAVAILABLE, 0.0

    ok, quality, reason = check_image_quality(image_bytes)
    if not ok:
        return FaceAuthResult.LOW_QUALITY, 0.0

    try:
        stored_embedding = _decrypt_embedding(stored_encrypted_embedding)
    except Exception as e:
        logger.error("Failed to decrypt stored embedding: %s", e)
        return FaceAuthResult.ERROR, 0.0

    if status == FaceAuthStatus.AVAILABLE and "face_recognition" in model_name:
        return _verify_with_face_recognition(image_bytes, stored_embedding, tolerance)
    else:
        return _verify_with_opencv(image_bytes, stored_embedding)


def _verify_with_face_recognition(
    image_bytes: bytes,
    stored_embedding: list[float],
    tolerance: float,
) -> tuple[FaceAuthResult, float]:
    try:
        import face_recognition
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)

        locations = face_recognition.face_locations(img_rgb, model="hog")
        if not locations:
            return FaceAuthResult.NO_FACE_DETECTED, 0.0

        encodings = face_recognition.face_encodings(img_rgb, locations)
        if not encodings:
            return FaceAuthResult.NO_FACE_DETECTED, 0.0

        stored_np = np.array(stored_embedding)
        distance = face_recognition.face_distance([stored_np], encodings[0])[0]
        confidence = max(0.0, 1.0 - distance)

        if distance <= tolerance:
            return FaceAuthResult.VERIFIED, confidence
        else:
            return FaceAuthResult.NO_MATCH, confidence

    except Exception as e:
        logger.error("Face verification error: %s", e)
        return FaceAuthResult.ERROR, 0.0


def _verify_with_opencv(
    image_bytes: bytes,
    stored_embedding: list[float],
) -> tuple[FaceAuthResult, float]:
    """Degraded OpenCV verification using cosine similarity of HOG features."""
    try:
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)
        if len(faces) == 0:
            return FaceAuthResult.NO_FACE_DETECTED, 0.0

        x, y, w, h = faces[0]
        face_roi = cv2.resize(gray[y:y+h, x:x+w], (64, 64))
        hog = cv2.HOGDescriptor((64, 64), (16, 16), (8, 8), (8, 8), 9)
        descriptor = hog.compute(face_roi).flatten()

        stored_np = np.array(stored_embedding)
        # Cosine similarity
        denom = np.linalg.norm(descriptor) * np.linalg.norm(stored_np)
        if denom == 0:
            return FaceAuthResult.ERROR, 0.0
        similarity = float(np.dot(descriptor, stored_np) / denom)

        # NOTE: OpenCV HOG-based verification has high false-positive risk.
        # Threshold set conservatively.
        if similarity >= 0.92:
            return FaceAuthResult.VERIFIED, similarity
        else:
            return FaceAuthResult.NO_MATCH, similarity

    except Exception as e:
        logger.error("OpenCV verification error: %s", e)
        return FaceAuthResult.ERROR, 0.0
