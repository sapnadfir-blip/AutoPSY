"""
Anti-forensic tamper detection for software-defined vehicles.

Detects evidence of:
  - ECU reflashing / firmware tampering
  - DTC clearing (evidence destruction)
  - CAN injection artifacts
  - Diagnostic session traces (unauthorized access)
  - Clock manipulation
  - OTA update evidence destruction
"""
import time
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple

from ..protocols.can_bus import CANFrame, analyze_can_traffic
from ..protocols.forensic_container import ForensicContainer, EvidenceBlock


@dataclass
class TamperIndicator:
    indicator_type: str = ""
    severity: str = "medium"  # low, medium, high, critical
    confidence: float = 0.0
    description: str = ""
    evidence: str = ""
    forensic_significance: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "type": self.indicator_type,
            "severity": self.severity,
            "confidence": f"{self.confidence:.0%}",
            "description": self.description,
            "evidence": self.evidence,
            "forensic_significance": self.forensic_significance,
        }


@dataclass
class AntiForensicReport:
    vehicle_vin: str = ""
    analysis_time: float = 0.0
    indicators: List[TamperIndicator] = field(default_factory=list)
    ecu_baselines: Dict[str, Dict] = field(default_factory=dict)
    overall_risk: str = "unknown"

    def __post_init__(self):
        if self.analysis_time == 0.0:
            self.analysis_time = time.time()

    def compute_risk(self):
        if not self.indicators:
            self.overall_risk = "clean"
            return
        severities = [i.severity for i in self.indicators]
        if "critical" in severities:
            self.overall_risk = "critical"
        elif severities.count("high") >= 2:
            self.overall_risk = "critical"
        elif "high" in severities:
            self.overall_risk = "high"
        elif severities.count("medium") >= 3:
            self.overall_risk = "high"
        elif "medium" in severities:
            self.overall_risk = "medium"
        else:
            self.overall_risk = "low"

    def to_dict(self) -> dict:
        self.compute_risk()
        return {
            "vehicle_vin": self.vehicle_vin,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.analysis_time)),
            "overall_risk": self.overall_risk,
            "indicator_count": len(self.indicators),
            "indicators": [i.to_dict() for i in self.indicators],
            "ecu_baselines_count": len(self.ecu_baselines),
        }


class AntiForensicDetector:
    """Detect anti-forensic tampering in vehicle systems."""

    def __init__(self, vin: str = ""):
        self.vin = vin
        self.report = AntiForensicReport(vehicle_vin=vin)
        self.baselines: Dict[str, Dict] = {}

    def set_ecu_baseline(self, ecu_name: str, firmware_hash: str,
                         software_version: str, did_values: Dict[int, str],
                         dtc_count: int = 0):
        """Register known-good state for an ECU."""
        self.baselines[ecu_name] = {
            "firmware_hash": firmware_hash,
            "software_version": software_version,
            "did_values": {f"0x{k:04X}": v for k, v in did_values.items()},
            "dtc_count_at_baseline": dtc_count,
            "baseline_time": time.time(),
        }
        self.report.ecu_baselines = self.baselines

    def detect_firmware_tampering(self, ecu_name: str, current_hash: str,
                                   current_version: str) -> Optional[TamperIndicator]:
        """Compare current firmware against baseline — detect reflashing."""
        baseline = self.baselines.get(ecu_name)
        if not baseline:
            return None

        if current_hash != baseline["firmware_hash"]:
            indicator = TamperIndicator(
                indicator_type="firmware_tamper",
                severity="critical",
                confidence=0.95,
                description=f"ECU '{ecu_name}' firmware hash changed since baseline",
                evidence=(f"Baseline: {baseline['firmware_hash'][:16]}... "
                         f"Current: {current_hash[:16]}..."),
                forensic_significance=(
                    "Firmware was reflashed after baseline was taken. This could indicate: "
                    "unauthorized ECU reprogramming to hide modifications, rollback to hide "
                    "a tuning/chipping operation, or OTA update that destroyed evidence state."
                ),
            )
            self.report.indicators.append(indicator)
            return indicator

        if current_version != baseline["software_version"]:
            indicator = TamperIndicator(
                indicator_type="version_mismatch",
                severity="high",
                confidence=0.85,
                description=f"ECU '{ecu_name}' software version changed but hash matches",
                evidence=(f"Baseline version: {baseline['software_version']} "
                         f"Current: {current_version}"),
                forensic_significance=(
                    "Version string changed without firmware hash change. Possible metadata "
                    "manipulation to disguise the current software state."
                ),
            )
            self.report.indicators.append(indicator)
            return indicator
        return None

    def detect_dtc_clearing(self, ecu_name: str, current_dtc_count: int,
                            dtc_clear_timestamp: Optional[str] = None,
                            since_clear_counters: Optional[Dict] = None) -> List[TamperIndicator]:
        """Detect suspicious DTC clearing — key anti-forensic technique."""
        indicators = []
        baseline = self.baselines.get(ecu_name, {})
        baseline_count = baseline.get("dtc_count_at_baseline", -1)

        if baseline_count > 0 and current_dtc_count == 0:
            indicators.append(TamperIndicator(
                indicator_type="dtc_cleared",
                severity="high",
                confidence=0.90,
                description=f"ECU '{ecu_name}' had {baseline_count} DTCs at baseline, now has 0",
                evidence=f"Baseline DTCs: {baseline_count}, Current: {current_dtc_count}",
                forensic_significance=(
                    "All DTCs were cleared after baseline. DTC clearing is a primary "
                    "anti-forensic technique — it destroys evidence of malfunctions, "
                    "crashes, and unauthorized operations. Court-critical: a suspiciously "
                    "clean ECU after an incident indicates deliberate evidence destruction."
                ),
            ))

        if dtc_clear_timestamp:
            indicators.append(TamperIndicator(
                indicator_type="recent_dtc_clear",
                severity="medium",
                confidence=0.80,
                description=f"DTC clear event recorded at {dtc_clear_timestamp}",
                evidence=f"Last DTC clear: {dtc_clear_timestamp}",
                forensic_significance=(
                    "The ECU records when DTCs were last cleared. A recent clear timestamp "
                    "near the incident time is strong evidence of anti-forensic activity."
                ),
            ))

        if since_clear_counters:
            for counter_name, value in since_clear_counters.items():
                if value == 0 or (isinstance(value, int) and value < 5):
                    indicators.append(TamperIndicator(
                        indicator_type="counter_reset",
                        severity="medium",
                        confidence=0.70,
                        description=f"Counter '{counter_name}' is suspiciously low ({value})",
                        evidence=f"{counter_name} = {value}",
                        forensic_significance=(
                            "Counters 'since last clear' near zero indicate a recent DTC clear. "
                            "Normal ECU operation accumulates these counters over time."
                        ),
                    ))

        self.report.indicators.extend(indicators)
        return indicators

    def detect_can_injection(self, frames: List[CANFrame]) -> List[TamperIndicator]:
        """Analyze CAN traffic for injection artifacts."""
        indicators = []
        analysis = analyze_can_traffic(frames)

        for anomaly in analysis.get("anomalies", []):
            atype = anomaly.get("type", "")

            if atype == "timing_anomaly":
                indicators.append(TamperIndicator(
                    indicator_type="can_injection_timing",
                    severity="high",
                    confidence=0.85,
                    description=f"CAN ID 0x{anomaly.get('id', '???')} has abnormal timing jitter",
                    evidence=f"Jitter ratio: {anomaly.get('jitter_ratio', 'N/A')}x normal",
                    forensic_significance=(
                        "CAN message injection produces timing artifacts — injected frames "
                        "arrive at different intervals than the legitimate ECU's cycle time. "
                        "This is the primary detection method for CAN bus attacks."
                    ),
                ))

            elif atype == "unknown_id":
                indicators.append(TamperIndicator(
                    indicator_type="can_unknown_id",
                    severity="medium",
                    confidence=0.75,
                    description=f"Unknown CAN ID 0x{anomaly.get('id', '???')} detected",
                    evidence=f"ID not in known vehicle ID database, count: {anomaly.get('count', 0)}",
                    forensic_significance=(
                        "CAN IDs not in the vehicle's normal traffic pattern may indicate "
                        "a connected external device (OBD-II dongle, attack tool) or "
                        "an ECU in an abnormal diagnostic state."
                    ),
                ))

            elif atype == "diagnostic_activity":
                indicators.append(TamperIndicator(
                    indicator_type="can_diagnostic_activity",
                    severity="medium",
                    confidence=0.80,
                    description="Diagnostic CAN messages detected (0x7D0-0x7FF range)",
                    evidence=f"Diagnostic frames: {anomaly.get('count', 0)}",
                    forensic_significance=(
                        "Diagnostic messages on the CAN bus indicate a diagnostic tool was "
                        "connected. This could be legitimate service or unauthorized access. "
                        "Cross-reference with workshop visit records."
                    ),
                ))

        # Check for message frequency anomalies
        id_dist = analysis.get("id_distribution", {})
        if id_dist:
            counts = list(id_dist.values())
            if counts:
                avg = sum(counts) / len(counts)
                for id_hex, count in id_dist.items():
                    if count > avg * 5 and count > 100:
                        indicators.append(TamperIndicator(
                            indicator_type="can_flood",
                            severity="high",
                            confidence=0.80,
                            description=f"CAN ID 0x{id_hex} has abnormally high message count",
                            evidence=f"Count: {count}, Average: {avg:.0f} (ratio: {count/avg:.1f}x)",
                            forensic_significance=(
                                "Abnormally high message rate for a single CAN ID indicates "
                                "message injection, replay attack, or bus-off attack attempt."
                            ),
                        ))

        self.report.indicators.extend(indicators)
        return indicators

    def detect_diagnostic_traces(self, did_values: Dict[str, str]) -> List[TamperIndicator]:
        """Detect traces of unauthorized diagnostic sessions."""
        indicators = []

        active_session = did_values.get("0xF186", did_values.get("F186", ""))
        if active_session and active_session not in ("01", "1", "default", ""):
            session_names = {"02": "Programming", "03": "Extended"}
            sname = session_names.get(active_session, f"Unknown(0x{active_session})")
            indicators.append(TamperIndicator(
                indicator_type="active_diagnostic_session",
                severity="critical",
                confidence=0.95,
                description=f"ECU is in {sname} diagnostic session (not default)",
                evidence=f"Active session DID F186 = {active_session}",
                forensic_significance=(
                    "The ECU is currently in a non-default diagnostic session. "
                    "Programming session allows firmware reflashing. Extended session "
                    "allows security-sensitive operations. This indicates active or "
                    "recent diagnostic tool connection."
                ),
            ))

        programming_counter = did_values.get("0xF199", did_values.get("F199", ""))
        if programming_counter:
            try:
                count = int(programming_counter, 16) if len(programming_counter) <= 4 else int(programming_counter)
                if count > 0:
                    indicators.append(TamperIndicator(
                        indicator_type="programming_history",
                        severity="high",
                        confidence=0.85,
                        description=f"ECU has been reprogrammed {count} time(s)",
                        evidence=f"Programming counter (F199) = {count}",
                        forensic_significance=(
                            "The programming counter tracks how many times the ECU firmware "
                            "was reflashed. Cross-reference with authorized service records — "
                            "any discrepancy indicates unauthorized reprogramming."
                        ),
                    ))
            except ValueError:
                pass

        self.report.indicators.extend(indicators)
        return indicators

    def detect_clock_manipulation(self, ecu_time: Optional[float] = None,
                                   reference_time: Optional[float] = None,
                                   dtc_timestamps: Optional[List[float]] = None) -> List[TamperIndicator]:
        """Detect clock tampering via time inconsistencies."""
        indicators = []

        if ecu_time is not None and reference_time is not None:
            drift = abs(ecu_time - reference_time)
            if drift > 3600:
                indicators.append(TamperIndicator(
                    indicator_type="clock_drift",
                    severity="high",
                    confidence=0.75,
                    description=f"ECU clock deviates from reference by {drift:.0f} seconds ({drift/3600:.1f} hours)",
                    evidence=f"ECU time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ecu_time))}, "
                             f"Reference: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(reference_time))}",
                    forensic_significance=(
                        "Large clock deviation may indicate clock manipulation to alter "
                        "the apparent time of events in ECU logs. Anti-forensic technique "
                        "to create alibis or invalidate timeline analysis."
                    ),
                ))

        if dtc_timestamps and len(dtc_timestamps) >= 2:
            sorted_ts = sorted(dtc_timestamps)
            for i in range(1, len(sorted_ts)):
                if sorted_ts[i] < sorted_ts[i-1]:
                    indicators.append(TamperIndicator(
                        indicator_type="timestamp_regression",
                        severity="critical",
                        confidence=0.90,
                        description="DTC timestamps are not monotonically increasing",
                        evidence=f"Timestamp[{i-1}]={sorted_ts[i-1]} > Timestamp[{i}]={sorted_ts[i]}",
                        forensic_significance=(
                            "Non-monotonic timestamps in DTC records indicate clock "
                            "manipulation between events. This is strong evidence of "
                            "deliberate timeline tampering."
                        ),
                    ))
                    break

        self.report.indicators.extend(indicators)
        return indicators

    def detect_ota_evidence_destruction(self, current_version: str,
                                         known_versions: List[str],
                                         update_log: Optional[List[Dict]] = None) -> List[TamperIndicator]:
        """Detect OTA updates that may have destroyed forensic evidence."""
        indicators = []

        if known_versions and current_version not in known_versions:
            indicators.append(TamperIndicator(
                indicator_type="unknown_firmware_version",
                severity="high",
                confidence=0.80,
                description=f"Current firmware version '{current_version}' is not in known version list",
                evidence=f"Known versions: {known_versions}, Current: {current_version}",
                forensic_significance=(
                    "Unknown firmware version may indicate: unauthorized reflashing, "
                    "a custom/modified firmware, or an OTA update from an unrecognized source. "
                    "OTA updates overwrite previous firmware and can destroy evidence state."
                ),
            ))

        if update_log:
            for entry in update_log:
                if entry.get("rollback"):
                    indicators.append(TamperIndicator(
                        indicator_type="firmware_rollback",
                        severity="critical",
                        confidence=0.90,
                        description=f"Firmware rollback detected: {entry.get('from', '?')} → {entry.get('to', '?')}",
                        evidence=json.dumps(entry),
                        forensic_significance=(
                            "Firmware rollback is a strong anti-forensic indicator. Rolling back "
                            "firmware destroys any evidence recorded by the newer version and "
                            "restores a previous state, potentially hiding modifications."
                        ),
                    ))

        self.report.indicators.extend(indicators)
        return indicators

    def full_analysis(self, container: Optional[ForensicContainer] = None) -> AntiForensicReport:
        """Run all detection modules against collected evidence."""
        if container:
            for block in container.evidence_blocks:
                if block.block_type == "can_capture":
                    frames = self._reconstruct_can_frames(block)
                    self.detect_can_injection(frames)

                elif block.block_type == "ecu_data":
                    did_values = block.metadata.get("did_values", {})
                    flat = {}
                    for k, v in did_values.items():
                        if isinstance(v, dict):
                            flat[k] = v.get("value", "")
                        else:
                            flat[k] = str(v)
                    self.detect_diagnostic_traces(flat)

                elif block.block_type == "dtc_data":
                    dtc_count = block.metadata.get("dtc_count", 0)
                    for ecu_name, baseline in self.baselines.items():
                        if baseline.get("dtc_count_at_baseline", 0) > 0 and dtc_count == 0:
                            self.detect_dtc_clearing(ecu_name, dtc_count)

        self.report.compute_risk()
        return self.report

    def _reconstruct_can_frames(self, block: EvidenceBlock) -> List[CANFrame]:
        """Reconstruct CAN frames from evidence block data."""
        frames = []
        data = block.data
        offset = 0
        while offset + 16 <= len(data):
            try:
                frame = CANFrame.from_bytes(data[offset:offset + 16])
                if frame:
                    frames.append(frame)
            except Exception:
                pass
            offset += 16
        if not frames:
            from ..protocols.can_bus import CANBusInterface
            can = CANBusInterface("demo")
            frames = can.capture(duration=0)
        return frames


def run_demo_analysis() -> AntiForensicReport:
    """Demo: show detection capabilities with realistic indicators."""
    detector = AntiForensicDetector(vin="WBA11CF090CH77832")

    detector.set_ecu_baseline(
        "Gateway_ECU",
        firmware_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        software_version="V03.02.01",
        did_values={0xF189: "V03.02.01", 0xF191: "HW-GW-2024-A"},
        dtc_count=3,
    )
    detector.set_ecu_baseline(
        "Engine_ECU",
        firmware_hash="f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3",
        software_version="V05.11.03",
        did_values={0xF189: "V05.11.03"},
        dtc_count=5,
    )

    detector.detect_firmware_tampering(
        "Gateway_ECU",
        current_hash="deadbeef12345678deadbeef12345678",
        current_version="V03.02.01",
    )
    detector.detect_dtc_clearing("Engine_ECU", current_dtc_count=0,
                                  dtc_clear_timestamp="2026-10-26 14:30:00")
    detector.detect_diagnostic_traces({"0xF186": "02"})
    detector.detect_clock_manipulation(
        ecu_time=time.time() - 7200,
        reference_time=time.time(),
    )
    detector.detect_ota_evidence_destruction(
        current_version="V03.03.00",
        known_versions=["V03.01.00", "V03.02.00", "V03.02.01"],
    )

    from ..protocols.can_bus import CANBusInterface
    can = CANBusInterface("demo")
    frames = can.capture(duration=0)
    detector.detect_can_injection(frames)

    detector.report.compute_risk()
    return detector.report
