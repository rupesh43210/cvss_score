from typing import Dict, Optional, Tuple
from cvss.utils.logger import setup_logger

logger = setup_logger(__name__)

class CVSSService:
    # CVSS v3.1 weights
    _weights = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {
            'N': {'U': 0.85, 'C': 0.85},
            'L': {'U': 0.62, 'C': 0.68},
            'H': {'U': 0.27, 'C': 0.5}
        },
        'UI': {'N': 0.85, 'R': 0.62},
        'C': {'H': 0.56, 'L': 0.22, 'N': 0},
        'I': {'H': 0.56, 'L': 0.22, 'N': 0},
        'A': {'H': 0.56, 'L': 0.22, 'N': 0}
    }

    def calculate_score(self, metrics: Dict) -> Tuple[Optional[float], Optional[str]]:
        """
        Calculate CVSS v3.1 score from metrics.
        
        Args:
            metrics (Dict): Dictionary containing CVSS metrics
            
        Returns:
            Tuple[Optional[float], Optional[str]]: (CVSS score, severity level) or (None, None) if calculation fails
        """
        try:
            # Validate metrics
            if not self._validate_metrics(metrics):
                return None, None

            # Calculate base score
            impact_sub_score = self._calculate_impact_sub_score(metrics)
            exploitability_sub_score = self._calculate_exploitability_sub_score(metrics)
            
            if metrics['S'] == 'U':
                base_score = min(10, round(
                    ((impact_sub_score + exploitability_sub_score) * 10) / 10, 1
                ))
            else:  # Changed
                base_score = min(10, round(
                    (1.08 * (impact_sub_score + exploitability_sub_score)) / 10, 1
                ))

            severity = self._get_severity_level(base_score)
            return base_score, severity

        except Exception as e:
            logger.error(f"Error calculating CVSS score: {str(e)}", exc_info=True)
            return None, None

    def _validate_metrics(self, metrics: Dict) -> bool:
        """Validate CVSS metrics."""
        try:
            required_metrics = {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}
            
            # Check if all required metrics are present
            if not all(metric in metrics for metric in required_metrics):
                logger.error("Missing required metrics")
                return False

            # Validate Attack Vector (AV)
            if metrics['AV'] not in self._weights['AV']:
                logger.error(f"Invalid Attack Vector value: {metrics['AV']}")
                return False

            # Validate Attack Complexity (AC)
            if metrics['AC'] not in self._weights['AC']:
                logger.error(f"Invalid Attack Complexity value: {metrics['AC']}")
                return False

            # Validate Privileges Required (PR)
            if metrics['PR'] not in self._weights['PR']:
                logger.error(f"Invalid Privileges Required value: {metrics['PR']}")
                return False

            # Validate User Interaction (UI)
            if metrics['UI'] not in self._weights['UI']:
                logger.error(f"Invalid User Interaction value: {metrics['UI']}")
                return False

            # Validate Scope (S)
            if metrics['S'] not in ['U', 'C']:
                logger.error(f"Invalid Scope value: {metrics['S']}")
                return False

            # Validate CIA Impact
            for impact in ['C', 'I', 'A']:
                if metrics[impact] not in self._weights[impact]:
                    logger.error(f"Invalid {impact} Impact value: {metrics[impact]}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error validating metrics: {str(e)}", exc_info=True)
            return False

    def _calculate_impact_sub_score(self, metrics: Dict) -> float:
        """Calculate Impact Sub Score."""
        try:
            # Calculate ISS (Impact Sub Score)
            iss_base = 1 - (
                (1 - self._weights['C'][metrics['C']]) *
                (1 - self._weights['I'][metrics['I']]) *
                (1 - self._weights['A'][metrics['A']])
            )

            if metrics['S'] == 'U':
                return 6.42 * iss_base
            else:  # Changed
                return 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)

        except Exception as e:
            logger.error(f"Error calculating impact sub score: {str(e)}", exc_info=True)
            raise

    def _calculate_exploitability_sub_score(self, metrics: Dict) -> float:
        """Calculate Exploitability Sub Score."""
        try:
            return 8.22 * (
                self._weights['AV'][metrics['AV']] *
                self._weights['AC'][metrics['AC']] *
                self._weights['PR'][metrics['PR']][metrics['S']] *
                self._weights['UI'][metrics['UI']]
            )
        except Exception as e:
            logger.error(f"Error calculating exploitability sub score: {str(e)}", exc_info=True)
            raise

    def _get_severity_level(self, score: float) -> str:
        """Get severity level from CVSS score."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "NONE"
