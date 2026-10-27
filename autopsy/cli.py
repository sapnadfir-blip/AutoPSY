"""
AutoPSY CLI — Anti-Forensic Detection & Evidence Integrity Framework for SDVs.
"""
import argparse
import json
import sys
import time

from . import __version__


def cmd_recon(args):
    from .recon.scanner import VehicleScanner
    scanner = VehicleScanner(target=args.target, interface=args.interface)
    print(f"[*] AutoPSY Recon — scanning {args.target}")
    result = scanner.full_scan(timeout=args.timeout)
    summary = result.summary()
    print(f"\n{'='*60}")
    print(f"  AutoPSY RECON Results")
    print(f"{'='*60}")
    print(f"  DoIP Entities:       {summary['doip_entities']}")
    print(f"  ECUs Fingerprinted:  {summary['ecus_fingerprinted']}")
    print(f"  SOME/IP Services:    {summary['someip_services']}")
    print(f"  CAN Unique IDs:      {summary['can_unique_ids']}")
    print(f"  CAN Anomalies:       {summary['can_anomalies']}")
    print(f"  Scan Duration:       {summary['scan_duration']}")
    print(f"{'='*60}")

    if result.ecus:
        print(f"\n  ECU Details:")
        for ecu in result.ecus:
            d = ecu.to_dict()
            print(f"\n    [{d['name']}]")
            print(f"      Address:  {d['logical_address']}")
            print(f"      IP:       {d['ip_address']}")
            print(f"      VIN:      {d['vin']}")
            print(f"      Software: {d['software_version']}")
            print(f"      Hardware: {d['hardware_number']}")
            print(f"      Serial:   {d['serial_number']}")
            print(f"      FW Hash:  {d['firmware_hash']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"scan_result": summary, "ecus": [e.to_dict() for e in result.ecus]}, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


def cmd_attack(args):
    from .attack.vehicle_attacks import (
        CANAttacks, DoIPAttacks, SOMEIPAttacks, run_all_attacks_demo
    )
    print(f"[*] AutoPSY Attack Module")

    if args.attack_type == "all":
        results = run_all_attacks_demo(args.target)
    elif args.attack_type == "can-inject":
        data = bytes.fromhex(args.data) if args.data else b"\x00" * 8
        results = [CANAttacks.message_injection(args.interface, args.arb_id, data, args.count)]
    elif args.attack_type == "can-busoff":
        results = [CANAttacks.bus_off_attack(args.interface, args.arb_id)]
    elif args.attack_type == "doip-hijack":
        results = [DoIPAttacks.session_hijack(args.target)]
    elif args.attack_type == "did-dump":
        results = [DoIPAttacks.did_dump(args.target)]
    elif args.attack_type == "ecu-reset":
        results = [DoIPAttacks.ecu_reset(args.target)]
    elif args.attack_type == "security-bruteforce":
        results = [DoIPAttacks.security_access_bruteforce(args.target)]
    elif args.attack_type == "dtc-clear":
        results = [DoIPAttacks.dtc_clearing(args.target)]
    elif args.attack_type == "someip-offer":
        results = [SOMEIPAttacks.fake_service_offer()]
    elif args.attack_type == "someip-inject":
        results = [SOMEIPAttacks.method_call_injection(args.target)]
    else:
        print(f"[-] Unknown attack type: {args.attack_type}")
        return

    print(f"\n{'='*60}")
    print(f"  Attack Results ({len(results)} attacks)")
    print(f"{'='*60}")
    for r in results:
        status = "SUCCESS" if r.success else "FAILED"
        print(f"\n  [{status}] {r.attack_name}")
        print(f"    Target:   {r.target}")
        print(f"    Packets:  {r.packets_sent}")
        print(f"    Detail:   {r.detail}")
        if r.wire_data:
            print(f"    Wire:     {r.wire_data[:32].hex()}")
        if r.artifacts:
            print(f"    Artifacts:")
            for a in r.artifacts:
                print(f"      - {a}")

    if args.output:
        out = [{"attack": r.attack_name, "target": r.target, "success": r.success,
                "packets": r.packets_sent, "detail": r.detail,
                "wire_hex": r.wire_data[:64].hex() if r.wire_data else "",
                "artifacts": r.artifacts} for r in results]
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


def cmd_forensics(args):
    from .protocols.forensic_container import CaseInfo
    from .forensics.acquisition import ForensicAcquisition

    case = CaseInfo(
        case_id=args.case_id or f"CASE-{int(time.time())}",
        examiner=args.examiner or "AutoPSY Operator",
        vehicle_vin=args.vin or "UNKNOWN",
    )
    print(f"[*] AutoPSY Forensic Acquisition")
    print(f"    Case: {case.case_id}  VIN: {case.vehicle_vin}")

    acq = ForensicAcquisition(case)
    container = acq.full_acquisition(
        target_ip=args.target,
        can_interface=args.interface,
        can_duration=args.can_duration,
    )

    summary = container.summary()
    print(f"\n{'='*60}")
    print(f"  Forensic Acquisition Complete")
    print(f"{'='*60}")
    print(f"  Evidence Blocks:  {summary['evidence_blocks']}")
    print(f"  Total Bytes:      {summary['total_evidence_bytes']}")
    print(f"  Integrity:        {'VERIFIED' if summary['integrity'] else 'FAILED'}")
    print(f"  Master Hash:      {summary['master_hash']}")

    output = args.output or f"autopsy_evidence_{case.case_id}.json"
    container.save(output)
    print(f"\n[+] Evidence container saved to {output}")


def cmd_antiforensics(args):
    from .antiforensics.detector import AntiForensicDetector, run_demo_analysis
    from .protocols.forensic_container import ForensicContainer

    if args.evidence_file:
        print(f"[*] Loading evidence from {args.evidence_file}")
        container = ForensicContainer.load(args.evidence_file)
        detector = AntiForensicDetector(vin=container.case_info.vehicle_vin)
        report = detector.full_analysis(container)
    else:
        print(f"[*] Running anti-forensic detection demo")
        report = run_demo_analysis()

    rd = report.to_dict()
    print(f"\n{'='*60}")
    print(f"  Anti-Forensic Analysis Report")
    print(f"{'='*60}")
    print(f"  Vehicle VIN:     {rd['vehicle_vin']}")
    print(f"  Overall Risk:    {rd['overall_risk'].upper()}")
    print(f"  Indicators:      {rd['indicator_count']}")
    print(f"{'='*60}")

    for i, ind in enumerate(rd.get("indicators", []), 1):
        print(f"\n  [{ind['severity'].upper()}] {ind['type']}")
        print(f"    Confidence:  {ind['confidence']}")
        print(f"    {ind['description']}")
        print(f"    Evidence:    {ind['evidence']}")
        print(f"    Significance: {ind['forensic_significance'][:120]}...")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(rd, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")


def cmd_report(args):
    from .protocols.forensic_container import ForensicContainer
    from .antiforensics.detector import AntiForensicDetector
    from .reporting.report_gen import generate_json_report, generate_markdown_report

    print(f"[*] Generating forensic report")
    container = ForensicContainer.load(args.evidence_file)
    af_report = None
    if not args.skip_antiforensics:
        detector = AntiForensicDetector(vin=container.case_info.vehicle_vin)
        af_report = detector.full_analysis(container)

    if args.format == "json":
        out = args.output or "autopsy_report.json"
        generate_json_report(container, af_report, out)
    else:
        out = args.output or "autopsy_report.md"
        generate_markdown_report(container, af_report, out)
    print(f"[+] Report saved to {out}")


def cmd_demo(args):
    """Run full demo — recon, attack, forensics, anti-forensics."""
    from .recon.scanner import VehicleScanner
    from .attack.vehicle_attacks import run_all_attacks_demo
    from .protocols.forensic_container import CaseInfo
    from .forensics.acquisition import ForensicAcquisition
    from .antiforensics.detector import AntiForensicDetector
    from .reporting.report_gen import generate_json_report, generate_markdown_report

    print(f"""
{'='*60}
     _         _        ____  ______   __
    / \\  _   _| |_ ___ |  _ \\/ ___\\ \\ / /
   / _ \\| | | | __/ _ \\| |_) \\___ \\\\ V /
  / ___ \\ |_| | || (_) |  __/ ___) || |
 /_/   \\_\\__,_|\\__\\___/|_|   |____/ |_|

 Anti-Forensic Detection & Evidence Integrity
 Framework for Software-Defined Vehicles v{__version__}
{'='*60}
""")

    target = args.target
    interface = args.interface

    # Phase 1: RECON
    print("[Phase 1] RECONNAISSANCE")
    print("-" * 40)
    scanner = VehicleScanner(target=target, interface=interface)
    scan_result = scanner.full_scan()
    s = scan_result.summary()
    print(f"  DoIP entities: {s['doip_entities']}")
    print(f"  ECUs found:    {s['ecus_fingerprinted']}")
    print(f"  SOME/IP svcs:  {s['someip_services']}")
    print(f"  CAN IDs:       {s['can_unique_ids']}")

    # Phase 2: ATTACK
    print(f"\n[Phase 2] ATTACK SIMULATION")
    print("-" * 40)
    attacks = run_all_attacks_demo(target)
    success = sum(1 for a in attacks if a.success)
    print(f"  Attacks run:    {len(attacks)}")
    print(f"  Successful:     {success}")
    total_packets = sum(a.packets_sent for a in attacks)
    print(f"  Total packets:  {total_packets}")
    all_artifacts = []
    for a in attacks:
        all_artifacts.extend(a.artifacts)
    print(f"  Forensic artifacts generated: {len(all_artifacts)}")

    # Phase 3: FORENSICS
    print(f"\n[Phase 3] FORENSIC ACQUISITION")
    print("-" * 40)
    case = CaseInfo(
        case_id=f"DEMO-{int(time.time())}",
        examiner="AutoPSY Demo",
        vehicle_vin="WBA11CF090CH77832",
        vehicle_make="BMW", vehicle_model="3 Series", vehicle_year="2024",
        incident_date=time.strftime("%Y-%m-%d"),
        incident_description="AutoPSY demonstration — full vehicle forensic analysis",
    )
    acq = ForensicAcquisition(case)
    container = acq.full_acquisition(target_ip=target, can_interface=interface)
    cs = container.summary()
    print(f"  Evidence blocks: {cs['evidence_blocks']}")
    print(f"  Total bytes:     {cs['total_evidence_bytes']}")
    print(f"  Integrity:       {'VERIFIED' if cs['integrity'] else 'FAILED'}")
    print(f"  Master hash:     {cs['master_hash']}")

    # Phase 4: ANTI-FORENSICS
    print(f"\n[Phase 4] ANTI-FORENSIC DETECTION")
    print("-" * 40)
    detector = AntiForensicDetector(vin="WBA11CF090CH77832")
    for ecu in scan_result.ecus:
        detector.set_ecu_baseline(
            ecu.name, ecu.firmware_hash, ecu.software_version,
            {int(k, 16) if isinstance(k, str) else k: v for k, v in ecu.all_dids.items()},
            dtc_count=3,
        )
    af_report = detector.full_analysis(container)
    from .antiforensics.detector import run_demo_analysis
    demo_report = run_demo_analysis()
    rd = demo_report.to_dict()
    print(f"  Risk level:      {rd['overall_risk'].upper()}")
    print(f"  Indicators:      {rd['indicator_count']}")
    for ind in rd.get("indicators", []):
        print(f"    [{ind['severity'].upper()}] {ind['type']}: {ind['description'][:80]}")

    # Generate reports
    print(f"\n[Phase 5] REPORT GENERATION")
    print("-" * 40)
    json_path = generate_json_report(container, demo_report, "autopsy_demo_report.json")
    md_path = generate_markdown_report(container, demo_report, "autopsy_demo_report.md")
    evidence_path = "autopsy_demo_evidence.json"
    container.save(evidence_path)
    print(f"  JSON report:      {json_path}")
    print(f"  Markdown report:  {md_path}")
    print(f"  Evidence file:    {evidence_path}")

    print(f"\n{'='*60}")
    print(f"  AutoPSY Demo Complete")
    print(f"  {len(attacks)} attacks | {cs['evidence_blocks']} evidence blocks | {rd['indicator_count']} indicators")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        prog="autopsy",
        description="AutoPSY — Anti-Forensic Detection & Evidence Integrity Framework for SDVs",
    )
    parser.add_argument("--version", action="version", version=f"AutoPSY {__version__}")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # recon
    p = sub.add_parser("recon", help="Vehicle network reconnaissance")
    p.add_argument("--target", default="255.255.255.255", help="Target IP or broadcast")
    p.add_argument("--interface", default="vcan0", help="CAN interface")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--output", "-o", help="Save results to JSON file")

    # attack
    p = sub.add_parser("attack", help="Vehicle attack modules")
    p.add_argument("attack_type", choices=[
        "all", "can-inject", "can-busoff", "doip-hijack", "did-dump",
        "ecu-reset", "security-bruteforce", "dtc-clear",
        "someip-offer", "someip-inject",
    ])
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--interface", default="vcan0")
    p.add_argument("--arb-id", type=lambda x: int(x, 0), default=0x0C0)
    p.add_argument("--data", default=None, help="CAN data hex string")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--output", "-o")

    # forensics
    p = sub.add_parser("forensics", help="Forensic evidence acquisition")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--interface", default="vcan0")
    p.add_argument("--case-id")
    p.add_argument("--examiner")
    p.add_argument("--vin")
    p.add_argument("--can-duration", type=float, default=30.0)
    p.add_argument("--output", "-o")

    # anti-forensics
    p = sub.add_parser("anti-forensics", help="Anti-forensic tamper detection")
    p.add_argument("--evidence-file", help="Path to evidence container JSON")
    p.add_argument("--output", "-o")

    # report
    p = sub.add_parser("report", help="Generate forensic report")
    p.add_argument("evidence_file", help="Path to evidence container JSON")
    p.add_argument("--format", choices=["json", "markdown"], default="markdown")
    p.add_argument("--skip-antiforensics", action="store_true")
    p.add_argument("--output", "-o")

    # demo
    p = sub.add_parser("demo", help="Full demonstration of all capabilities")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--interface", default="vcan0")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "recon": cmd_recon, "attack": cmd_attack, "forensics": cmd_forensics,
        "anti-forensics": cmd_antiforensics, "report": cmd_report, "demo": cmd_demo,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
