"""Authenticate and validate bounded Observatory evidence without network access.

A signed measurement authenticates the collector, not the truth of its report.
Existing unsigned Observatory database rows deliberately cannot use this profile.
"""
import datetime as dt
import hashlib
import ipaddress
from urllib.parse import urlsplit
from tools.attestation import verify_envelope
from tools.openssl_observation import parse_openssl_observation, MAX_TRANSCRIPT_BYTES, HYBRID_GROUPS, CLASSICAL_GROUPS
from tools.tls_probe import validate_endpoint


def ingest_measurement(token, transcript, trust_config, expected_subject, *, expected_audience,
                       replay_store, now=None, max_age_seconds=86400, expected_snapshot=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if type(transcript) is not bytes or len(transcript) > MAX_TRANSCRIPT_BYTES:
        return {'accepted': False, 'reason': 'invalid-transcript'}
    if type(max_age_seconds) is not int or not 0 < max_age_seconds <= 86400:
        return {'accepted': False, 'reason': 'invalid-freshness-policy'}
    verified = verify_envelope(token, trust_config, expected_subject, now=now,
                               expected_audience=expected_audience, replay_store=replay_store,
                               expected_snapshot=expected_snapshot)
    if not verified['verified']:
        return {'accepted': False, 'reason': verified['reason']}
    claims = verified['claims']
    try:
        observation = claims['observation']
        if not isinstance(observation, dict) or set(observation) != {'profile', 'observedAt', 'endpoint', 'probe', 'transcriptSha256'}:
            raise ValueError('invalid-observation')
        if observation['profile'] != 'openssl-tls13-v1':
            raise ValueError('unsupported-observation-profile')
        endpoint, probe = observation['endpoint'], observation['probe']
        if set(endpoint) != {'host', 'port', 'address'} or set(probe) != {'name', 'version', 'groups', 'certificateValidation', 'exitCode'}:
            raise ValueError('invalid-provenance')
        validate_endpoint(endpoint['host'], endpoint['port'])
        ipaddress.ip_address(endpoint['address'])
        subject = urlsplit(expected_subject)
        # This collector observes TLS endpoints, not repositories, URL paths or identities.
        if (subject.scheme != 'https' or subject.username is not None or subject.password is not None or subject.query or subject.fragment or
            subject.path not in ('', '/') or subject.hostname != endpoint['host'].lower() or (subject.port or 443) != endpoint['port']):
            raise ValueError('endpoint-subject-mismatch')
        observed = dt.datetime.fromisoformat(observation['observedAt'].replace('Z', '+00:00'))
        if observed.tzinfo is None or not dt.timedelta(0) <= now-observed <= dt.timedelta(seconds=max_age_seconds):
            raise ValueError('stale-or-future-measurement')
        if observed.timestamp() > claims['iat']:
            raise ValueError('measurement-after-issuance')
        if observation['transcriptSha256'] != hashlib.sha256(transcript).hexdigest():
            raise ValueError('transcript-digest-mismatch')
        groups = probe['groups']
        if (probe['name'] != 'openssl' or not isinstance(probe['version'], str) or
            not probe['version'].startswith('OpenSSL ') or len(probe['version']) > 256 or
            type(probe['exitCode']) is not int or probe['exitCode'] != 0 or
            probe['certificateValidation'] != 'pkix-hostname' or not isinstance(groups, list) or
            not 1 <= len(groups) <= 16 or any(g not in HYBRID_GROUPS | CLASSICAL_GROUPS for g in groups)):
            raise ValueError('invalid-probe-configuration')
        parsed = parse_openssl_observation(transcript.decode('utf-8'))
        if parsed['status'] != 'observed' or parsed['negotiatedGroup'] not in groups or not parsed['peerSignatureType']:
            raise ValueError('unverified-connection')
        return {'accepted': True, 'reason': 'authenticated-observation',
                'subject': expected_subject, 'issuer': claims['iss'], 'measurementId': claims['jti'],
                'observedAt': observation['observedAt'], 'expiresAt': claims['exp'],
                'validUntil': min(claims['exp'],
                                  claims['iat'] + trust_config['issuers'][claims['iss']].get('maxAgeSeconds', 3600),
                                  observed.timestamp() + max_age_seconds),
                'provenance': observation, 'observation': parsed,
                'issuerAuthenticated': True, 'independentlyVerified': False,
                'authenticationPqcVerified': False,
                'limitation': 'Trusted collector statement; no independent runtime verification, fleet coverage, or PQC authentication established'}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        # A valid JWT is consumed even when its measurement is rejected. Producers
        # must issue a new jti for corrected evidence, never replay a rejected token.
        return {'accepted': False, 'reason': 'invalid-measurement'}
