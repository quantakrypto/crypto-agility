#!/usr/bin/env python3
"""Bounded offline structural/semantic assessment, never a trust assertion."""
import argparse
import datetime as dt
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from jsonschema import Draft202012Validator, FormatChecker

MAX_BYTES = 1048576
UTC_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d(?:\.\d{1,6})?Z$')


def parse_time(value):
    if not isinstance(value, str) or not UTC_TIME.fullmatch(value):
        raise ValueError('UTC RFC3339 timestamp required (no leap seconds)')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def load_manifest(data):
    """Reject duplicate keys, non-JSON numbers, excess bytes/depth before validation."""
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise ValueError('manifest too large')
        data = data.decode('utf-8')
    if not isinstance(data, str) or len(data.encode('utf-8')) > MAX_BYTES:
        raise ValueError('manifest too large or invalid')
    # Enforce nesting limit before json.loads consumes stack/memory.
    depth = 0
    quoted = escaped = False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > 16:
                raise ValueError('manifest nesting exceeds 16')
        elif char in ']}':
            depth -= 1
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON member')
            value[key] = item
        return value
    def invalid_number(_):
        raise ValueError('non-JSON number')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_number)


def assess(m, schema, now=None, max_observation_age=86400, expected_subject=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or not 0 < max_observation_age <= 31536000:
        raise ValueError('invalid local time or observation freshness policy')
    checker = FormatChecker()
    @checker.checks('date-time', raises=(ValueError, TypeError))
    def calendar_timestamp(value):
        if not isinstance(value, str):
            return True
        parse_time(value)
        return True
    errors = list(Draft202012Validator(schema, format_checker=checker).iter_errors(m))
    if errors:
        return {'status': 'invalid', 'findings': [{'code': 'schema', 'message': e.message[:512]} for e in errors[:100]]}
    findings = []
    def add(code, ref):
        findings.append({'code': code, 'ref': ref})
    if expected_subject is not None and m['subject']['id'] != expected_subject:
        add('subject-mismatch', 'manifest')
    if m['subject']['kind'] == 'origin':
        subject = m['subject']['id']
        try:
            origin = urlsplit(subject)
            if (not subject.isascii() or origin.scheme != 'https' or not origin.hostname
                    or origin.username is not None or origin.password is not None
                    or origin.path or origin.query or origin.fragment
                    or origin.port is not None or subject != 'https://' + origin.hostname
                    or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', origin.hostname)):
                add('invalid-origin', 'manifest')
        except ValueError:
            add('invalid-origin', 'manifest')
    generated = parse_time(m['generatedAt'])
    expires = parse_time(m['expiresAt'])
    if generated > now + dt.timedelta(minutes=5):
        add('future-manifest', 'manifest')
    if expires <= now or expires <= generated:
        add('expired', 'manifest')
    evidence = {x['id']: x for x in m.get('evidence', [])}
    profiles = {x['id']: x for x in m['profiles']}
    for group in ('observations', 'migration', 'profiles', 'evidence', 'policies'):
        items = m.get(group, [])
        if len(items) != len({x['id'] for x in items}):
            add('duplicate-id', group)
    for e in evidence.values():
        if e['subjectId'] != m['subject']['id']:
            add('subject-mismatch', e['id'])
    by_capability = {}
    for o in m['observations']:
        if o['method'] == 'observed' and not o.get('evidenceIds'):
            add('unsubstantiated-observation', o['id'])
        observed = parse_time(o['observedAt'])
        if observed > now + dt.timedelta(minutes=5) or observed > generated + dt.timedelta(minutes=5):
            add('future-observation', o['id'])
        if (now - observed).total_seconds() > max_observation_age:
            add('stale-observation', o['id'])
        by_capability.setdefault(o['capability'], set()).add(o['value'])
        for ref in o.get('evidenceIds', []):
            if ref not in evidence:
                add('missing-evidence', ref)
    for capability, values in by_capability.items():
        if {'supported', 'unsupported'} <= values:
            add('conflicting-observations', capability)
    for p in m['profiles']:
        if p['fallback'] != 'deny-classical':
            add('fallback-risk', p['id'])
        for ref in p.get('evidenceIds', []):
            if ref not in evidence:
                add('missing-evidence', ref)
    for item in m['migration']:
        if item['status'] in ('validated', 'deployed') and not item.get('evidenceIds'):
            add('unsubstantiated-deployment', item['id'])
        for ref in item.get('profileIds', []):
            if ref not in profiles:
                add('missing-profile', ref)
        for ref in item.get('evidenceIds', []):
            if ref not in evidence:
                add('missing-evidence', ref)
    for exception in m.get('exceptions', []):
        if parse_time(exception['expiresAt']) <= now:
            add('expired-exception', exception['findingId'])
        if not exception.get('owner'):
            add('unowned-exception', exception['findingId'])
    return {'status': 'needs-review' if findings else 'unverified', 'findings': findings,
            'limitations': 'No signatures, evidence truth, live negotiation or deployment verified; policies and exceptions never suppress findings'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--schema', type=Path, default=Path('schema/crypto-agility-v2.schema.json'))
    parser.add_argument('--now')
    args = parser.parse_args()
    try:
        with args.manifest.open('rb') as source:
            manifest = load_manifest(source.read(MAX_BYTES + 1))
        schema = json.loads(args.schema.read_text())
        result = assess(manifest, schema, parse_time(args.now) if args.now else None)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {'status': 'invalid', 'findings': [{'code': 'input', 'message': str(exc)}]}
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'unverified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
