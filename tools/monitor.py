#!/usr/bin/env python3
"""Repeatable bounded local snapshot monitor. JSON alerts go to stdout or a file.

A supervisor supplies scheduling and alert delivery. Monitoring does not fetch
untrusted evidence or turn declared profiles into verified TLS negotiations.
"""
import argparse
import datetime as dt
import json
import hashlib
import sys
from pathlib import Path
import time
try:
    from tools.verifier import assess, load_manifest
    from tools.attestation import ReplayStore
    from tools.observatory_ingestion import ingest_measurement
    from tools.discovery import DiscoveryClient
    from tools.compatibility import assess_pair
    from tools.state import update_state, fingerprint, acknowledge_alerts, enqueue_failure
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools.attestation import ReplayStore
    from tools.observatory_ingestion import ingest_measurement
    from tools.discovery import DiscoveryClient
    from verifier import assess, load_manifest
    from compatibility import assess_pair
    from state import update_state, fingerprint, acknowledge_alerts, enqueue_failure


def snapshot(manifest, schema, now, *, authenticated_observations=()):
    """authenticated_observations must be in-process ingest_measurement successes.

    These are trusted function results, never entries read from a manifest/file.
    The CLI intentionally does not accept purported authenticated dictionaries.
    """
    result = assess(manifest, schema, now)
    manifest = manifest if isinstance(manifest, dict) else {}
    profiles = manifest.get("profiles", []) if result["status"] != "invalid" else []
    clients = [p for p in profiles if p.get("endpointRole") in ("client", "peer")]
    servers = [p for p in profiles if p.get("endpointRole") in ("server", "gateway", "peer")]
    if len(clients) * len(servers) > 10000:
        raise ValueError("compatibility assessment exceeds 10000 pairs")
    pairs = [{"client": c.get("id"), "server": s.get("id"), "assessment": assess_pair(c, s)}
             for c in clients for s in servers if c is not s]
    subject = manifest.get("subject")
    subject_id = subject.get("id") if isinstance(subject, dict) else None
    measurements = {}
    for item in authenticated_observations:
        if item.get("accepted") is not True or item.get("issuerAuthenticated") is not True or item.get("subject") != subject_id:
            raise ValueError("only authenticated ingestion results for the manifest subject are accepted")
        observed = dt.datetime.fromisoformat(item["observedAt"].replace("Z", "+00:00"))
        if observed.tzinfo is None or observed > now:
            raise ValueError("invalid authenticated observation time")
        summary = {"issuer": item["issuer"], "subject": subject_id, "observedAt": item["observedAt"],
                   "expiresAt": item["expiresAt"], "validUntil": item["validUntil"],
                   "status": "stale" if min(item["expiresAt"], item["validUntil"]) <= now.timestamp() else "authenticated-observation",
                   "negotiatedGroup": item["observation"]["negotiatedGroup"],
                   "hybridKexObserved": item["observation"]["hybridKexObserved"],
                   "independentlyVerified": False}
        key = (item["issuer"], subject_id)
        if key in measurements:
            raise ValueError("duplicate collector measurements require explicit selection")
        measurements[key] = summary
    return {"subject": subject_id, "measurements": list(measurements.values()),
            "checkedAt": now.isoformat(), "manifestGeneratedAt": manifest.get("generatedAt"),
            "profileIds": sorted(p["id"] for p in profiles), "assessment": result, "pairs": pairs}


def _bounded_read(path, limit=1048576):
    with Path(path).open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input exceeds size limit")
    return raw


def run_once(manifest_path, schema, state_path=None, now=None, *, evidence=None,
             measurement_cache=None, discovery=None, origin=None, expected_subject=None):
    """Read/refresh, authenticate, assess and atomically record one check.

    evidence contains token/transcript/trust paths, audience and ReplayStore.
    A process-local cache reuses only identical authenticated input bytes and
    policy. Expiry is reevaluated each cycle; a restart requires a fresh JWT.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        if discovery is not None:
            fetched = discovery.fetch(origin, expected_subject, now=now)
            manifest, raw = fetched["manifest"], fetched["body"]
        else:
            raw = _bounded_read(manifest_path)
            manifest = load_manifest(raw)
        report = snapshot(manifest, schema, now)
        measurements = []
        rejection = None
        if evidence and report["assessment"]["status"] != "invalid":
            token = _bounded_read(evidence["token"]).decode("ascii").strip()
            transcript = _bounded_read(evidence["transcript"], 65536)
            trust_raw = _bounded_read(evidence["trust"])
            trust = load_manifest(trust_raw)
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            cache_key = fingerprint([token, hashlib.sha256(transcript).hexdigest(),
                                     hashlib.sha256(trust_raw).hexdigest(), digest,
                                     evidence["audience"], report["subject"]])
            cached = (measurement_cache or {}).get(cache_key)
            if cached is not None:
                observed = dt.datetime.fromisoformat(cached["observedAt"].replace("Z", "+00:00"))
                if now < observed:
                    raise ValueError("monitor clock rollback")
                measurements = [cached]
            else:
                result = ingest_measurement(token, transcript, trust, report["subject"],
                                            expected_audience=evidence["audience"],
                                            replay_store=evidence["replay_store"], now=now,
                                            expected_snapshot=digest)
                if result["accepted"]:
                    measurements = [result]
                    if measurement_cache is not None:
                        measurement_cache.clear()
                        measurement_cache[cache_key] = result
                else:
                    rejection = result["reason"]
            report = snapshot(manifest, schema, now, authenticated_observations=measurements)
            if rejection:
                report["assessment"]["findings"].append({"code": "measurement-rejected", "ref": rejection})
                report["assessment"]["status"] = "needs-review"
            elif any(m["status"] == "stale" for m in report["measurements"]):
                report["assessment"]["findings"].append({"code": "measurement-expired", "ref": report["subject"]})
                report["assessment"]["status"] = "needs-review"
        if state_path and report["assessment"]["status"] != "invalid":
            report["changes"] = update_state(state_path, report)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        finding = {"code": "monitor-input-or-state-failure", "message": str(exc)}
        report = {"subject": None, "checkedAt": now.isoformat(),
                  "assessment": {"status": "invalid", "findings": [finding]}, "pairs": []}
    if report["assessment"]["status"] == "invalid":
        alert = {"type": "monitor-failure", "severity": "error",
                 "action": "Repair the input or state failure; the previous baseline was retained."}
        alert["id"] = fingerprint({"type": alert["type"], "findings": report["assessment"]["findings"]})
        report["changes"] = {"alerts": [alert], "resolved": []}
        if state_path:
            try:
                report["changes"]["alerts"] = enqueue_failure(state_path, alert)
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
                # State failure cannot promise durability. Keep an explicit output
                # signal for the supervisor rather than silently losing the failure.
                report["changes"]["deliveryPersistenceFailure"] = str(exc)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path, nargs="?")
    parser.add_argument("--origin", help="explicit public HTTPS discovery origin")
    parser.add_argument("--subject", help="expected manifest subject for remote discovery")
    parser.add_argument("--token", type=Path, help="locally supplied compact observation JWT")
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--trust", type=Path, help="operator-provisioned issuer configuration")
    parser.add_argument("--audience")
    parser.add_argument("--replay-state", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("schema/crypto-agility-v2.schema.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--state", type=Path, help="owner-only local state for regression detection")
    parser.add_argument("--ack-alert", action="append", default=[], metavar="DELIVERY_ID",
                        help="with --state alone, acknowledge this deliveryId only after confirmed delivery; repeatable")
    parser.add_argument("--interval", type=float, default=60, help="seconds between local checks, minimum 1")
    parser.add_argument("--iterations", type=int, default=1, help="number of checks, 0 repeats until interrupted")
    args = parser.parse_args()
    if args.ack_alert:
        if not args.state or any((args.manifest, args.origin, args.token, args.transcript,
                                  args.trust, args.audience, args.replay_state, args.output)):
            parser.error("--ack-alert requires --state and no monitoring inputs or output")
        try:
            count = acknowledge_alerts(args.state, args.ack_alert)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            parser.exit(2, "alert acknowledgment failed: " + str(exc) + "\n")
        print(json.dumps({"acknowledged": count}))
        return 0
    if not 1 <= args.interval <= 86400 or args.iterations < 0:
        parser.error("interval must be 1..86400 seconds and iterations must be nonnegative")
    if bool(args.manifest) == bool(args.origin) or (args.origin and not args.subject):
        parser.error("provide either a manifest file or --origin with --subject")
    inputs = (args.token, args.transcript, args.trust, args.audience, args.replay_state)
    if any(inputs) and not all(inputs):
        parser.error("token, transcript, trust, audience and replay-state are all required together")
    evidence = {"token": args.token, "transcript": args.transcript, "trust": args.trust,
                "audience": args.audience, "replay_store": ReplayStore(args.replay_state)} if all(inputs) else None
    measurement_cache = {}
    discovery = DiscoveryClient([args.origin]) if args.origin else None
    try:
        schema = json.loads(args.schema.read_bytes())
    except (OSError, ValueError) as exc:
        parser.exit(2, "schema could not be loaded: " + str(exc) + "\n")
    count = 0
    exit_code = 0
    while args.iterations == 0 or count < args.iterations:
        report = run_once(args.manifest, schema, args.state, evidence=evidence,
                          measurement_cache=measurement_cache, discovery=discovery,
                          origin=args.origin, expected_subject=args.subject)
        output = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(output)
        else:
            print(output, end="", flush=True)
        exit_code = max(exit_code, int(report["assessment"]["status"] != "unverified"))
        count += 1
        if args.iterations == 0 or count < args.iterations:
            time.sleep(args.interval)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
