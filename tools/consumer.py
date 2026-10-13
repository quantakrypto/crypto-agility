"""Owner-provisioned immutable-bundle supervisor; no signing or alert transport."""
import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import ipaddress
import math
import os
from pathlib import Path
import re
import stat
import time

from tools.attestation import ReplayStore
from urllib.parse import urlsplit
from tools.monitor import run_once
from tools.state import canonical, enqueue_failure, fingerprint, locked_document
from tools.verifier import load_manifest, parse_time

ROOT = Path(__file__).resolve().parents[1]
FILES = {'manifest.json': 1048576, 'observation.jwt': 1048576, 'transcript.txt': 65536}


def _private(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ValueError('owner-only regular file or directory required')


@contextmanager
def _directory(path):
    # Traverse every component with no-follow; Path.resolve would hide symlinks.
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute paths without traversal required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        _private(os.fstat(fd), directory=True)
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as source:
        _private(os.fstat(fd))
        raw = source.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('input size limit')
        return raw


def _origin(value):
    """Local identity only; this performs no discovery and allows explicit TLS ports."""
    if not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid canonical HTTPS origin')
    parts = urlsplit(value)
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.path or parts.query or parts.fragment or '?' in value or '#' in value):
        raise ValueError('canonical HTTPS origin required')
    host = parts.hostname
    if ':' in host:
        host = '[' + ipaddress.IPv6Address(host).compressed + ']'
    elif not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
        raise ValueError('invalid origin hostname')
    port = parts.port
    if port == 0:
        raise ValueError('invalid origin port')
    canonical_origin = 'https://' + host + (':' + str(port) if port not in (None, 443) else '')
    if value != canonical_origin:
        raise ValueError('canonical HTTPS origin required')
    return value


def _config(path, now):
    with _directory(path.parent) as parent:
        config = load_manifest(_read(parent, path.name, 1048576))
    if set(config) != {'version', 'issuer', 'subject', 'audience', 'keyId', 'keyStatus', 'trust'} or type(config['version']) is not int or config['version'] != 1:
        raise ValueError('explicit consumer configuration required')
    for key in ('issuer', 'subject', 'audience', 'keyId'):
        if not isinstance(config[key], str) or not 1 <= len(config[key]) <= 2048:
            raise ValueError('invalid consumer identity')
    if _origin(config['subject']) != config['subject']:
        raise ValueError('canonical origin subject required')
    status = config['keyStatus']
    if not isinstance(status, dict) or set(status) != {'status', 'checkedAt', 'validUntil', 'source'}:
        raise ValueError('explicit operator key status required')
    checked, until = parse_time(status['checkedAt']), parse_time(status['validUntil'])
    if (status['status'] != 'active' or not checked <= now < until or (until-checked).total_seconds() > 86400
            or not isinstance(status['source'], str) or not 1 <= len(status['source'].strip()) <= 2048):
        raise ValueError('operator key status absent, inactive, future, expired or unbounded')
    trust = config['trust']
    if not isinstance(trust, dict) or set(trust) != {'issuers'} or set(trust['issuers']) != {config['issuer']}:
        raise ValueError('exact issuer trust required')
    policy = trust['issuers'][config['issuer']]
    if (not isinstance(policy, dict) or set(policy.get('keys', {})) != {config['keyId']}
            or policy.get('subjects') != [config['subject']] or policy.get('audiences') != [config['audience']]
            or policy.get('purposes') != ['pqc-observation'] or policy.get('disabled', False) is not False
            or config['keyId'] in policy.get('revokedKeys', [])):
        raise ValueError('exact enabled key and consumer scopes required')
    return config


def _bundle(root):
    with _directory(root) as directory:
        identity = _read(directory, 'current', 65).decode('ascii').removesuffix('\n')
        if not re.fullmatch('[a-f0-9]{64}', identity):
            raise ValueError('invalid bundle selector')
        fd = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            _private(os.fstat(fd), directory=True)
            if set(os.listdir(fd)) != set(FILES):
                raise ValueError('complete bundle requires exactly three files')
            values = {name: _read(fd, name, limit) for name, limit in FILES.items()}
        finally:
            os.close(fd)
    commitment = canonical({name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()})
    if hashlib.sha256(commitment).hexdigest() != identity:
        raise ValueError('bundle content commitment mismatch')
    return values


def initialize_state(directory, now=None):
    """Explicit first bootstrap only; missing existing state requires recovery."""
    directory = Path(directory)
    now = now or dt.datetime.now(dt.timezone.utc)
    with _directory(directory) as fd:
        with locked_document(directory/'initialized.json') as (previous, finish):
            if previous is not None or set(os.listdir(fd)) != {'initialized.json.lock'}:
                raise ValueError('initialization requires an empty private directory; never reset existing state')
            documents = {'clock.json': {'lastNow': now.timestamp()},
                         'state.json': {'noBaseline': True, 'pendingAlerts': []},
                         'replay.json': {'version': 1, 'lastNow': now.timestamp(), 'entries': {}, 'latest': {}}}
            for name, value in documents.items():
                with locked_document(directory/name) as (_, save):
                    save(value)
            finish({'version': 1})


def _check_state(directory):
    with _directory(directory) as fd:
        marker = load_manifest(_read(fd, 'initialized.json', 128))
        if marker != {'version': 1} or type(marker['version']) is not int:
            raise ValueError('invalid initialization marker')
        # Missing or unsafe files cannot trigger implicit baseline/replay reset.
        for name in ('state.json', 'replay.json', 'clock.json'):
            value = load_manifest(_read(fd, name, 4 * 1024 * 1024))
            if name == 'clock.json' and (set(value) != {'lastNow'} or type(value['lastNow']) not in (int, float)
                                         or not math.isfinite(value['lastNow'])):
                raise ValueError('invalid consumer clock state')


class Consumer:
    def __init__(self, config, bundles, state_directory):
        self.config_path, self.bundles, self.directory = map(Path, (config, bundles, state_directory))
        self.schema = json.loads((ROOT/'schema/crypto-agility-v2.schema.json').read_bytes())
        self.cache = {}

    def check(self, now=None):
        now = now or dt.datetime.now(dt.timezone.utc)
        state_safe = False
        try:
            _check_state(self.directory)
            state_safe = True
            with locked_document(self.directory/'clock.json', require_existing=True) as (clock, save):
                if now.tzinfo is None or (clock and now.timestamp() < clock['lastNow']):
                    raise ValueError('consumer clock rollback')
                save({'lastNow': now.timestamp()})
            config = _config(self.config_path, now)
            values = _bundle(self.bundles)
            manifest = load_manifest(values['manifest.json'])
            if manifest.get('subject', {}).get('kind') != 'origin' or manifest['subject'].get('id') != config['subject']:
                raise ValueError('bundle must explicitly declare the configured origin subject')
            return run_once(None, self.schema, self.directory/'state.json', now,
                            evidence={'audience': config['audience'], 'replay_store': ReplayStore(self.directory/'replay.json', require_existing=True)},
                            measurement_cache=self.cache, require_existing_state=True,
                            input_bytes={'manifest': values['manifest.json'], 'token': values['observation.jwt'],
                                         'transcript': values['transcript.txt'], 'trust': canonical(config['trust'])})
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            finding = {'code': 'consumer-input-or-state-failure', 'message': str(exc)}
            alert = {'type': 'monitor-failure', 'severity': 'error', 'action': 'Repair consumer input or state; retain the previous baseline and pending alerts.', 'id': fingerprint(finding)}
            changes = {'alerts': [alert], 'resolved': []}
            try:
                if not state_safe:
                    raise ValueError('consumer state directory is unsafe or unavailable')
                changes['alerts'] = enqueue_failure(self.directory/'state.json', alert, require_existing=True)
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                changes['deliveryPersistenceFailure'] = str(error)
            return {'subject': None, 'checkedAt': now.isoformat(), 'assessment': {'status': 'invalid', 'findings': [finding]}, 'pairs': [], 'changes': changes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--bundles', type=Path)
    parser.add_argument('--state-directory', type=Path, required=True)
    parser.add_argument('--initialize-state', action='store_true', help='explicit first bootstrap; refuses existing state')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--iterations', type=int, default=0, help='0 runs continuously')
    args = parser.parse_args()
    if not 1 <= args.interval <= 86400 or args.iterations < 0:
        parser.error('invalid interval or iterations')
    os.umask(0o077)
    if args.initialize_state:
        if args.config or args.bundles:
            parser.error('initialize state separately from consumer inputs')
        initialize_state(args.state_directory)
        return 0
    if not args.config or not args.bundles:
        parser.error('config and bundles are required')
    consumer = Consumer(args.config, args.bundles, args.state_directory)
    # Separate singleton lock never unlinked/replaced. State/replay retain their own
    # transaction locks so delivery acknowledgments remain independent.
    with _directory(args.state_directory) as directory:
        try:
            fd = os.open('consumer.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            fd = os.open('consumer.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'r+b') as lock:
        _private(os.fstat(lock.fileno()))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        count = 0
        while args.iterations == 0 or count < args.iterations:
            print(json.dumps(consumer.check(), separators=(',', ':')), flush=True)
            count += 1
            if args.iterations == 0 or count < args.iterations:
                time.sleep(args.interval)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
