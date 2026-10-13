"""Durable Resend delivery of explicitly configured consumer alerts."""
import argparse
import datetime as dt
from email.utils import parseaddr
import http.client
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import ssl

from tools.consumer import _check_state, _directory
from tools.kms_status import private_json
from tools.state import acknowledge_alerts, canonical, locked_document
from tools.verifier import load_manifest

DELIVERED = {'delivered', 'opened', 'clicked'}
FAILED = {'bounced', 'canceled', 'complained', 'failed', 'suppressed'}
IDEMPOTENCY_SECONDS = 23 * 3600  # Provider retains keys 24h; allow clock/network margin.


def _resend_worker(pipe, key, method, path, payload, idempotency_key):
    connection = None
    try:
        connection = http.client.HTTPSConnection('api.resend.com', timeout=10, context=ssl.create_default_context())
        headers = {'Authorization': 'Bearer '+key, 'Content-Type': 'application/json', 'User-Agent': 'crypto-agility-monitor/1'}
        if idempotency_key:
            headers['Idempotency-Key'] = idempotency_key
        connection.request(method, path, body=canonical(payload) if payload is not None else None, headers=headers)
        response = connection.getresponse()
        raw = response.read(65537)
        if not 200 <= response.status < 300 or len(raw) > 65536:
            raise ValueError('provider HTTP response rejected')
        pipe.send(('ok', load_manifest(raw)))
    except Exception:
        pipe.send(('error', None))
    finally:
        if connection:
            connection.close()
        pipe.close()


class ResendClient:
    def __init__(self, api_key):
        if not isinstance(api_key, str) or not 1 <= len(api_key) <= 2048 or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise ValueError('existing RESEND_API_KEY is required')
        self.key = api_key

    def request(self, method, path, payload=None, idempotency_key=None):
        if not ((method == 'POST' and path == '/emails') or (method == 'GET' and re.fullmatch(r'/emails/[A-Za-z0-9-]{1,128}', path))):
            raise ValueError('unsupported email operation')
        context = multiprocessing.get_context('spawn')
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=_resend_worker, args=(send, self.key, method, path, payload, idempotency_key), daemon=True)
        process.start()
        send.close()
        try:
            if not receive.poll(15):
                raise ValueError('provider request deadline exceeded')
            outcome, result = receive.recv()
            if outcome != 'ok':
                raise ValueError('provider request failed')
            return result
        finally:
            receive.close()
            if process.is_alive(): process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)


def initialize_delivery(directory, now=None):
    directory = Path(directory)
    _check_state(directory)
    now = now or dt.datetime.now(dt.timezone.utc)
    with _directory(directory) as fd:
        if 'delivery.json.lock' in os.listdir(fd):
            raise ValueError('delivery initialization refuses previous state or interrupted initialization')
    with locked_document(directory/'delivery.json') as (previous, save):
        if previous is not None:
            raise ValueError('delivery state already exists')
        save({'version': 1, 'lastNow': now.timestamp(), 'records': {}})


def _configuration(path):
    config = private_json(path)
    if set(config) != {'version', 'recipient', 'sender'} or type(config['version']) is not int or config['version'] != 1:
        raise ValueError('explicit delivery configuration required')
    for key in ('recipient', 'sender'):
        value = config[key]
        if not isinstance(value, str) or not 1 <= len(value) <= 320 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError('invalid mail address')
        _, address = parseaddr(value)
        if not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', address):
            raise ValueError('invalid mail address')
        if key == 'recipient' and value != address:
            raise ValueError('one explicit recipient address required')
    return config


def _payload(alert, state, config):
    label = str(alert.get('type', 'monitor-failure'))
    if not re.fullmatch('[a-z0-9-]{1,80}', label):
        raise ValueError('invalid alert type')
    text = ('Crypto-agility monitoring alert\n\nSubject: '+str(state.get('subject') or 'unavailable')+
            '\nOccurrence: '+alert['deliveryId']+'\nAction: '+str(alert.get('action', 'Review the monitor findings.'))+
            '\n\nDetails:\n'+json.dumps(alert, sort_keys=True, indent=2)+'\n')
    if len(text.encode()) > 16384:
        raise ValueError('alert message size limit')
    return {'from': config['sender'], 'to': [config['recipient']], 'subject': '[QuantaKrypto] Crypto-agility '+label,
            'text': text, 'tags': [{'name': 'monitor', 'value': 'crypto-agility'}, {'name': 'delivery', 'value': alert['deliveryId']}]}


def deliver_pending(directory, config_path, client, *, now=None):
    directory = Path(directory)
    now = now or dt.datetime.now(dt.timezone.utc)
    _check_state(directory)
    config = _configuration(config_path)
    with locked_document(directory/'state.json', require_existing=True) as (state, _):
        pending = state.get('pendingAlerts', [])
    results = []
    # Serialize delivery separately from monitoring so network waits never block
    # collection/assessment. The committed provider receipt precedes outbox ack.
    with locked_document(directory/'delivery.json', require_existing=True) as (journal, save):
        if (set(journal) != {'version', 'lastNow', 'records'} or journal['version'] != 1
                or type(journal['version']) is not int or type(journal['lastNow']) not in (int, float)
                or not math.isfinite(journal['lastNow']) or not isinstance(journal['records'], dict)
                or now.tzinfo is None or now.timestamp() < journal['lastNow']):
            raise ValueError('invalid delivery state or clock rollback')
        journal['lastNow'] = now.timestamp()
        save(journal)
        for record in journal['records'].values():
            if (not isinstance(record, dict) or 'firstAttempt' not in record
                    or any(type(record[name]) not in (int, float) or not math.isfinite(record[name]) or record[name] > now.timestamp()
                           for name in ('firstAttempt', 'lastChecked', 'deliveredAt') if name in record)):
                raise ValueError('invalid delivery receipt timestamp')
        pending = sorted(pending, key=lambda alert: journal['records'].get(alert.get('deliveryId'), {}).get('lastChecked', -1))[:3]
        for alert in pending:
            identity = alert.get('deliveryId', '')
            if not isinstance(identity, str) or not re.fullmatch('[a-f0-9]{32}', identity):
                raise ValueError('invalid alert occurrence')
            record = journal['records'].get(identity)
            if record is None:
                if len(journal['records']) >= 10000:
                    raise ValueError('delivery receipt capacity requires archival')
                record = {'firstAttempt': now.timestamp(), 'payload': _payload(alert, state, config)}
                journal['records'][identity] = record
                save(journal)  # Durable intent before any external request.
            record['lastChecked'] = now.timestamp()
            save(journal)
            result = {'deliveryId': identity, 'status': 'pending'}
            try:
                payload = record['payload']
                if payload['to'] != [config['recipient']] or payload['from'] != config['sender']:
                    raise ValueError('delivery configuration changed; reconcile pending receipt')
                if not record.get('providerId'):
                    if now.timestamp()-record['firstAttempt'] >= IDEMPOTENCY_SECONDS:
                        result['status'] = 'reconciliation-required'
                        results.append(result)
                        continue
                    response = client.request('POST', '/emails', payload, 'crypto-agility/'+identity)
                    provider_id = response.get('id')
                    if not isinstance(provider_id, str) or not re.fullmatch('[A-Za-z0-9-]{1,128}', provider_id):
                        raise ValueError('provider receipt missing')
                    record['providerId'] = provider_id
                    save(journal)
                if not record.get('deliveredAt'):
                    response = client.request('GET', '/emails/'+record['providerId'])
                    if (response.get('id') != record['providerId'] or response.get('to') != payload['to']
                            or response.get('from') != payload['from'] or response.get('subject') != payload['subject']):
                        raise ValueError('provider receipt does not match submitted message')
                    event = response.get('last_event')
                    if event not in DELIVERED | FAILED | {'queued', 'sent', 'scheduled', 'delivery_delayed'}:
                        raise ValueError('unknown provider delivery event')
                    record['lastEvent'] = event
                    if event in DELIVERED:
                        record['deliveredAt'] = now.timestamp()
                    save(journal)
                if record.get('deliveredAt'):
                    acknowledge_alerts(directory/'state.json', [identity])
                    result['status'] = 'delivered'
                elif record.get('lastEvent') in FAILED:
                    result['status'] = 'delivery-failed'
            except Exception:
                # Do not serialize exception text, response bodies or secrets.
                record['lastError'] = 'delivery-or-acknowledgment-failed'
                save(journal)
                result['status'] = 'retry-pending'
            results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-directory', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--initialize-delivery', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if args.initialize_delivery:
        if args.config: parser.error('initialize delivery separately from configuration')
        initialize_delivery(args.state_directory)
        return 0
    if not args.config: parser.error('explicit delivery configuration required')
    try:
        result = deliver_pending(args.state_directory, args.config, ResendClient(os.environ.get('RESEND_API_KEY', '')))
        print(json.dumps(result, separators=(',', ':')))
        return int(any(item['status'] not in ('pending', 'delivered') for item in result))
    except Exception:
        # CLI diagnostics are deliberately fixed; inspect protected state locally.
        print('{"status":"delivery-unavailable","pendingAlertsRetained":true}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
