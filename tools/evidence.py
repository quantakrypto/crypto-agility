"""Offline byte integrity checks. Digest validity is not issuer authenticity."""
import hashlib
import os
from pathlib import Path
import re
import stat

ALGORITHMS = {'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512'}


def verify_local_evidence(manifest, evidence_root, max_bytes=8*1024*1024):
    """Open relative local evidence with descriptor-relative no-symlink traversal.

    No remote URL is fetched. Files are read at most max_bytes+1 even if growing.
    The evidence directory is provisioned by the local operator, never a manifest.
    """
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError('invalid evidence byte limit')
    root = Path(evidence_root)
    results = []
    for item in manifest.get('evidence', []):
        eid = item.get('id', '')
        uri = item.get('uri', '')
        if not isinstance(uri, str) or not uri.startswith('file:'):
            results.append({'id': eid, 'status': 'unavailable', 'reason': 'local file URI required'})
            continue
        relative = uri[5:]
        parts = relative.split('/')
        if not parts or any(p in ('', '.', '..') for p in parts) or any(c in relative for c in '\\%?#\x00'):
            results.append({'id': eid, 'status': 'rejected', 'reason': 'absolute or ambiguous path'})
            continue
        handles = []
        try:
            digest = item['digest']
            h = hashlib.new(ALGORITHMS[digest['algorithm']])
            if not re.fullmatch('[0-9a-f]{%d}' % (h.digest_size*2), digest['value']):
                raise ValueError('invalid digest')
            handles.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            for part in parts[:-1]:
                handles.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[-1]))
            # NONBLOCK avoids hanging on an attacker-supplied FIFO before fstat.
            handles.append(os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=handles[-1]))
            fd = handles[-1]
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('regular file required')
            count = 0
            while True:
                chunk = os.read(fd, min(65536, max_bytes + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > max_bytes:
                    raise ValueError('evidence too large')
                h.update(chunk)
            results.append({'id': eid, 'status': 'digest-valid' if h.hexdigest() == digest['value'] else 'digest-mismatch'})
        except (OSError, ValueError, TypeError, KeyError):
            results.append({'id': eid, 'status': 'rejected', 'reason': 'unsafe path, malformed digest or oversized evidence'})
        finally:
            for fd in reversed(handles):
                os.close(fd)
    return results
