from typing import Dict, Any, Tuple

class ConfidenceCalculator:
    """
    Analytical Recovery Confidence Scoring Engine.
    Calculates a 0-100 analytical confidence score based on structure validation,
    format decoding checks, filesystem metadata correlation, size consistency, and fragment continuity.
    """

    @classmethod
    def calculate_confidence(
        cls,
        val_status: str,
        val_confidence: int,
        recovery_source: str,
        has_original_metadata: bool,
        fragment_status: str
    ) -> Tuple[int, str]:
        """
        Returns (confidence_score [0-100], confidence_label).
        """
        score = val_confidence

        # Bonus for Filesystem Metadata Correlation (MFT / Dir entry correlation)
        if has_original_metadata or 'MFT' in recovery_source or 'Filesystem' in recovery_source:
            score += 10

        # Adjustment for fragment status
        if fragment_status == 'PARTIAL':
            score = min(score, 75)
        elif fragment_status == 'NOT_POSSIBLE':
            score = min(score, 45)

        # Cap score between 0 and 100
        score = max(0, min(100, score))

        if score >= 90:
            label = "Very High"
        elif score >= 75:
            label = "High"
        elif score >= 50:
            label = "Medium"
        elif score >= 25:
            label = "Low"
        else:
            label = "Very Low"

        return score, label
