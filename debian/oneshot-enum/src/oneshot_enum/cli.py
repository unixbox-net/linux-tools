import os, argparse, json, asyncio
from . import scanner, automator, report

def main(argv=None):
    ap=argparse.ArgumentParser(prog="oneshot-enum", description="One-shot enumeration + automations + report")
    ap.add_argument("target", help="Domain or IP")
    ap.add_argument("--full", action="store_true", help="Full safe suite (broader ports + crawl)")
    ap.add_argument("--ports", default=scanner.CFG.SCAN_PORTS, help="popular|1-1024,443,8443|range")
    ap.add_argument("--timeout", type=float, default=scanner.CFG.TIMEOUT)
    ap.add_argument("--concurrency", type=int, default=scanner.CFG.CONCURRENCY)
    ap.add_argument("--assume-yes", action="store_true")
    ap.add_argument("-o","--out", help="Write raw JSON here")
    ap.add_argument("--report-html", help="Write HTML report here")
    ap.add_argument("--automate", action="store_true", help="Run rules-based follow-ups and embed results")
    ap.add_argument("--rules", help="Optional override rules.yaml path")
    ap.add_argument("--actions-out", default="out/actions", help="Where to store action artifacts")
    ap.add_argument("--actions-par", type=int, default=6, help="Max parallel actions")
    args = ap.parse_args(argv)

    if args.full:
        scanner.CFG.SCAN_PORTS="top1k" if scanner.CFG.SCAN_PORTS=="popular" else scanner.CFG.SCAN_PORTS
        scanner.CFG.CRAWL_DEPTH=1; scanner.CFG.MAX_PAGES=150
        scanner.CFG.PROBE_BANNERS=True

    scanner.CFG.TIMEOUT = float(args.timeout)
    scanner.CFG.CONCURRENCY = int(args.concurrency)

    data = asyncio.run(scanner.run_all(args.target, args.ports))

    # Optional automations
    actions_summary = []
    actions_root = None
    if args.automate:
        findings = {
            "host": data.get("host"),
            "open": (data.get("ports") or {}).get("open") or [],
            "banners": (data.get("ports") or {}).get("banners") or {},
            "http_titles": data.get("http_titles") or {},
            "base_url": (data.get("http_probe") or {}).get("final_url") or (data.get("http_probe") or {}).get("target_url"),
            "verify": True,
        }
        rules = automator.load_rules(args.rules) if args.rules and os.path.isfile(args.rules) else automator.load_default_rules()
        jobs = automator.plan_for(findings, rules)
        actions_root = os.path.join(args.actions_out, findings["host"].replace(":","_"))
        base_env = {"HOST": findings["host"], "PORTS": ",".join(map(str, findings["open"])), "BASE_URL": findings.get("base_url") or "", "VERIFY_TLS": "1" if findings.get("verify") else "0"}
        actions_summary = automator.execute(findings["host"], jobs, actions_root, base_env, args.actions_par)
        data["actions"] = actions_summary
        data["actions_out"] = actions_root

    # Write artifacts
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

    if args.report_html:
        meta={"project":f"Enumeration Report for {data.get('host')}", "scope": f"Target: {data.get('target')}"}
        report.write_report_html(args.report_html, data, meta)

    # Console summary
    print(json.dumps({
        "host": data.get("host"),
        "ports_open": (data.get("ports") or {}).get("open"),
        "actions": len(actions_summary) if actions_summary else 0,
        "actions_out": actions_root
    }, indent=2))

if __name__ == "__main__":
    main()
