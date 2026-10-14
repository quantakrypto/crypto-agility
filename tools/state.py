"""Bounded owner-only local state, serialized writers and durable atomic replacement.

The operator must protect the containing directory and backups. This does not
protect against the account owner, root, disk rollback, or state deletion.
POSIX only: use a service supervisor to schedule the monitor and route its alerts.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

MAX_STATE_BYTES = 4 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def fingerprint(report):
    return hashlib.sha256(canonical(report)).hexdigest()


def _owned_regular(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise ValueError("state must be an owner-controlled regular file")
    if info.st_mode & 0o077:
        raise ValueError("state permissions must be 0600")


@contextlib.contextmanager
def locked_document(path, *, require_existing=False):
    """Yield (previous, save), holding a separate lock across read/replace/fsync."""
    path = Path(path).absolute()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("state directory must be owned and not writable by others")
        try:
            lock = os.open(path.name + ".lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
        except FileExistsError:
            # Separate creation from opening an existing lock: concurrent openat
            # with O_CREAT|O_NOFOLLOW can spuriously return ENOENT on macOS.
            lock = os.open(path.name + ".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                           dir_fd=directory)
        _owned_regular(lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            if require_existing:
                raise ValueError("initialized state file is missing")
            previous = None
        else:
            with os.fdopen(fd, "rb") as source:
                _owned_regular(source.fileno())
                raw = source.read(MAX_STATE_BYTES + 1)
                if len(raw) > MAX_STATE_BYTES:
                    raise ValueError("state exceeds size limit")
                previous = json.loads(raw)
                if not isinstance(previous, dict):
                    raise ValueError("state must be an object")

        def save(value):
            raw = canonical(value) + b"\n"
            if len(raw) > MAX_STATE_BYTES:
                raise ValueError("state exceeds size limit")
            name = "." + path.name + "." + uuid.uuid4().hex + ".tmp"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as target:
                    target.write(raw)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass
        yield previous, save
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def _alert(kind, **details):
    action = {
        "new-finding": "Review the referenced evidence and refresh or correct the manifest.",
        "compatibility-regression": "Check both endpoint configurations and negotiate a fresh TLS probe.",
        "coverage-lost": "Restore the missing endpoint profile or record its retirement explicitly.",
        "verification-regression": "Refresh authenticated evidence; do not rely on the previous assurance.",
        "tls-regression": "Investigate the collector evidence and negotiate a fresh authenticated TLS probe.",
    }[kind]
    result = {"type": kind, "severity": "warning", "action": action, **details}
    result["id"] = fingerprint(result)
    return result


def compare(previous, current):
    old = {(f["code"], f.get("ref", "")) for f in previous.get("assessment", {}).get("findings", [])}
    new = {(f["code"], f.get("ref", "")) for f in current.get("assessment", {}).get("findings", [])}
    prev_pairs = {(p["client"], p["server"]): p["assessment"]["status"] for p in previous.get("pairs", [])}
    curr_pairs = {(p["client"], p["server"]): p["assessment"]["status"] for p in current.get("pairs", [])}
    alerts = [_alert("new-finding", code=c, ref=r) for c, r in sorted(new - old)]
    for (client, server), status in sorted(curr_pairs.items()):
        prior = prev_pairs.get((client, server))
        if prior is not None and prior != status and status in ("incompatible", "unknown"):
            alerts.append(_alert("compatibility-regression", client=client, server=server,
                                 **{"from": prior, "to": status}))
    for client, server in sorted(prev_pairs.keys() - curr_pairs.keys()):
        alerts.append(_alert("coverage-lost", client=client, server=server))
    for profile in sorted(set(previous.get("profileIds", [])) - set(current.get("profileIds", []))):
        alerts.append(_alert("coverage-lost", profile=profile))
    old_measurements = {(m["issuer"], m["subject"]): m for m in previous.get("measurements", [])}
    new_measurements = {(m["issuer"], m["subject"]): m for m in current.get("measurements", [])}
    for key, prior in sorted(old_measurements.items()):
        latest = new_measurements.get(key)
        if latest is None:
            alerts.append(_alert("verification-regression", issuer=key[0], subject=key[1], reason="measurement-missing"))
        elif prior["status"] != "stale" and latest["status"] == "stale":
            alerts.append(_alert("verification-regression", issuer=key[0], subject=key[1], reason="measurement-expired"))
    # Historical authenticated evidence is a regression baseline, never current assurance.
    trusted = previous.get("lastAuthenticatedMeasurements", previous.get("measurements", []))
    for prior in trusted:
        key = (prior["issuer"], prior["subject"])
        latest = new_measurements.get(key)
        if latest and latest["status"] == "authenticated-observation" and prior.get("hybridKexObserved") and not latest.get("hybridKexObserved"):
            alerts.append(_alert("tls-regression", issuer=key[0], subject=key[1],
                                 **{"from": prior.get("negotiatedGroup"), "to": latest.get("negotiatedGroup")}))
    old_status = previous.get("assessment", {}).get("status")
    new_status = current.get("assessment", {}).get("status")
    if old_status == "verified" and new_status != old_status:
        alerts.append(_alert("verification-regression", **{"from": old_status, "to": new_status}))
    return {"alerts": alerts, "resolved": [{"code": c, "ref": r} for c, r in sorted(old - new)]}


def _time(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("state timestamp requires timezone")
    return parsed


def update_state(path, report, *, require_existing=False):
    if not isinstance(report.get("subject"), str) or not report["subject"]:
        raise ValueError("state subject required")
    if report.get("assessment", {}).get("status") == "invalid":
        raise ValueError("invalid assessments cannot replace monitoring state")
    with locked_document(path, require_existing=require_existing) as (previous, save):
        if previous is not None and not previous.get("noBaseline", False):
            if previous.get("subject") != report["subject"]:
                raise ValueError("state subject mismatch")
            for field in ("checkedAt", "manifestGeneratedAt"):
                if previous.get(field) and (not report.get(field) or _time(report[field]) < _time(previous[field])):
                    raise ValueError("state rollback: " + field)
            delta = compare(previous, report)
        else:
            delta = compare({}, report)
            delta["initialBaseline"] = True
        pending = {a["id"]: a for a in (previous or {}).get("pendingAlerts", [])}
        for alert in delta["alerts"]:
            if alert["id"] not in pending:
                pending[alert["id"]] = {**alert, "deliveryId": uuid.uuid4().hex, "queuedAt": report["checkedAt"]}
        # Save alerts with the baseline before output or external delivery. Retry the
        # same deliveryId until the supervisor explicitly acknowledges delivery.
        historical = (previous or {}).get("lastAuthenticatedMeasurements", (previous or {}).get("measurements", []))
        trusted = {(m["issuer"], m["subject"]): m for m in historical}
        for measurement in report.get("measurements", []):
            if measurement["status"] == "authenticated-observation":
                trusted[(measurement["issuer"], measurement["subject"])] = measurement
        saved = {**report, "pendingAlerts": list(pending.values()),
                 "lastAuthenticatedMeasurements": list(trusted.values())}
        save(saved)
        delta["alerts"] = saved["pendingAlerts"]
        return delta


def acknowledge_alerts(path, delivery_ids):
    """Call only after confirmed delivery; old acknowledgments cannot clear recurrence."""
    if (not isinstance(delivery_ids, (list, tuple)) or not delivery_ids
            or any(not isinstance(value, str) or len(value) != 32
                   or any(c not in "0123456789abcdef" for c in value) for value in delivery_ids)):
        raise ValueError("delivery IDs must be 32 lowercase hexadecimal characters")
    with locked_document(path) as (previous, save):
        if previous is None:
            raise ValueError("monitor state does not exist")
        ids = set(delivery_ids)
        pending = previous.get("pendingAlerts", [])
        remaining = [a for a in pending if a["deliveryId"] not in ids]
        previous["pendingAlerts"] = remaining
        save(previous)
        return len(pending) - len(remaining)


FAILURE_REMINDER_SECONDS = 24 * 3600


def enqueue_failure(path, alert, *, require_existing=False, now=None):
    """Durably queue an input failure without advancing a successful baseline.

    A failure that persists across checks queues one occurrence, then one reminder per
    day while it lasts, instead of a new occurrence each check once the last one was
    delivered. A successful check replaces the state and so forgets active failures."""
    now = now or dt.datetime.now(dt.timezone.utc)
    with locked_document(path, require_existing=require_existing) as (previous, save):
        state = previous if previous is not None else {"noBaseline": True}
        pending = {a["id"]: a for a in state.get("pendingAlerts", [])}
        active = state.get("activeFailures", {})
        active = {k: v for k, v in active.items() if type(v) in (int, float)} if isinstance(active, dict) else {}
        last = active.get(alert["id"])
        recent = last is not None and 0 <= now.timestamp() - last < FAILURE_REMINDER_SECONDS
        if alert["id"] not in pending and not recent:
            pending[alert["id"]] = {**alert, "deliveryId": uuid.uuid4().hex, "queuedAt": now.isoformat()}
            active[alert["id"]] = now.timestamp()
        state["pendingAlerts"] = list(pending.values())
        state["activeFailures"] = active
        save(state)
        # Lead with the current failure, followed by any other undelivered alerts.
        current = [pending[alert["id"]]] if alert["id"] in pending else []
        return current + [a for k, a in pending.items() if k != alert["id"]]
