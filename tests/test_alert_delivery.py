"""Durable provider receipts, bounded idempotency and precise outbox acknowledgment."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.consumer import initialize_state
from tools.state import enqueue_failure
from test_consumer import NOW, put


class Provider:
    def __init__(self):
        self.sent = []
        self.event = 'sent'
        self.payload = None
        self.failure = False
    def request(self, method, path, payload=None, idempotency_key=None):
        if method == 'POST':
            self.sent.append(idempotency_key)
            self.payload = payload
            if self.failure: raise RuntimeError('provider timeout with sensitive detail')
            return {'id': 'receipt-1'}
        return {'id': 'receipt-1', 'to': self.payload['to'], 'from': self.payload['from'], 'subject': self.payload['subject'], 'last_event': self.event}


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = self.root/'state'
        self.state.mkdir(mode=0o700)
        initialize_state(self.state, NOW)
        self.config = self.root/'delivery.json'
        put(self.config, b'{"version":1,"recipient":"leon@quantakrypto.com","sender":"quantakrypto <no-reply@quantakrypto.com>"}')
        self.alert = {'id': 'test-alert', 'type': 'tls-regression', 'severity': 'error', 'action': 'Inspect the TLS deployment and restore approved hybrid key exchange.'}
        self.pending = enqueue_failure(self.state/'state.json', self.alert, now=NOW)[0]
        self.provider = Provider()
        from tools.alert_delivery import initialize_delivery
        initialize_delivery(self.state, NOW)

    def deliver(self, now=NOW):
        from tools.alert_delivery import deliver_pending
        return deliver_pending(self.state, self.config, self.provider, now=now)

    def pending_alerts(self):
        return json.loads((self.state/'state.json').read_bytes())['pendingAlerts']

    def test_acceptance_is_not_delivery_and_restart_polls_saved_receipt(self):
        self.deliver()
        self.assertTrue(self.pending_alerts())
        self.assertEqual(len(self.provider.sent), 1)
        self.provider.event = 'delivered'
        self.deliver()
        self.assertEqual(len(self.provider.sent), 1)
        self.assertEqual(self.pending_alerts(), [])
        self.assertIn('restore approved hybrid', self.provider.payload['text'])
        self.assertEqual(self.provider.payload['to'], ['leon@quantakrypto.com'])

    def test_failed_send_retains_same_occurrence_and_idempotency_key(self):
        self.provider.failure = True
        self.deliver()
        self.deliver(NOW+dt.timedelta(seconds=60))
        self.assertEqual(self.provider.sent[0], self.provider.sent[1])
        self.assertEqual(self.pending_alerts()[0]['deliveryId'], self.pending['deliveryId'])
        self.assertNotIn('sensitive detail', (self.state/'delivery.json').read_text())

    def test_ambiguous_send_beyond_idempotency_window_is_not_blindly_resent(self):
        self.provider.failure = True
        self.deliver()
        results = self.deliver(NOW+dt.timedelta(hours=24))
        self.assertEqual(len(self.provider.sent), 1)
        self.assertEqual(results[0]['status'], 'reconciliation-required')
        self.assertTrue(self.pending_alerts())

    def test_receipt_persisted_before_ack_and_old_receipt_cannot_ack_recurrence(self):
        self.provider.event = 'delivered'
        with patch('tools.alert_delivery.acknowledge_alerts', side_effect=OSError('disk failure')):
            self.deliver()
        self.assertTrue(self.pending_alerts())
        self.deliver()
        self.assertEqual(self.pending_alerts(), [])
        self.assertEqual(len(self.provider.sent), 1)
        # A persisting failure is reminded daily; the old receipt cannot acknowledge it.
        new = enqueue_failure(self.state/'state.json', self.alert, now=NOW+dt.timedelta(hours=25))[0]
        self.assertNotEqual(new['deliveryId'], self.pending['deliveryId'])
        self.provider.event = 'sent'
        self.deliver(NOW+dt.timedelta(hours=25))
        self.assertEqual(self.pending_alerts()[0]['deliveryId'], new['deliveryId'])
        self.assertEqual(len(self.provider.sent), 2)

    def test_bounce_and_mismatched_provider_receipt_never_acknowledge(self):
        self.provider.event = 'bounced'
        result = self.deliver()
        self.assertEqual(result[0]['status'], 'delivery-failed')
        self.assertTrue(self.pending_alerts())
        self.provider.event = 'delivered'
        with patch.object(self.provider, 'request', return_value={'id': 'wrong', 'last_event': 'delivered'}):
            self.deliver()
        self.assertTrue(self.pending_alerts())

    def test_missing_receipt_journal_or_clock_rollback_never_resets_delivery(self):
        self.deliver()
        with self.assertRaises(ValueError): self.deliver(NOW-dt.timedelta(seconds=1))
        (self.state/'delivery.json').unlink()
        with self.assertRaises(ValueError): self.deliver()
        self.assertFalse((self.state/'delivery.json').exists())
        self.assertTrue(self.pending_alerts())

    def test_no_network_without_api_key(self):
        from tools.alert_delivery import ResendClient
        with self.assertRaises(ValueError): ResendClient('')

    def test_failed_first_batch_does_not_starve_later_occurrences(self):
        for number in range(3):
            enqueue_failure(self.state/'state.json', dict(self.alert, id='other-'+str(number)), now=NOW)
        self.provider.failure = True
        self.deliver()
        first = set(self.provider.sent)
        self.deliver(NOW+dt.timedelta(seconds=60))
        self.assertEqual(len(set(self.provider.sent)), 4)
        self.assertEqual(len(first), 3)

    def test_corrupted_delivery_clock_is_not_accepted(self):
        path = self.state/'delivery.json'
        raw = json.loads(path.read_bytes())
        raw['lastNow'] = float('nan')
        put(path, json.dumps(raw).encode())
        with self.assertRaises(ValueError): self.deliver()
        self.assertEqual(self.provider.sent, [])

    def test_persistent_failure_is_one_occurrence_until_daily_reminder(self):
        self.provider.event = 'delivered'
        self.deliver()
        self.assertEqual(self.pending_alerts(), [])
        for minutes in (1, 2, 60, 23*60):
            later = NOW+dt.timedelta(minutes=minutes)
            self.assertEqual(enqueue_failure(self.state/'state.json', self.alert, now=later), [])
            self.deliver(later)
        self.assertEqual(len(self.provider.sent), 1)
        other = enqueue_failure(self.state/'state.json', dict(self.alert, id='different-failure'), now=NOW+dt.timedelta(minutes=5))
        self.assertEqual(other[0]['id'], 'different-failure')
        reminder = enqueue_failure(self.state/'state.json', self.alert, now=NOW+dt.timedelta(hours=24))
        self.assertIn(self.alert['id'], [a['id'] for a in reminder])

    def routine(self, number, minutes=0):
        alert = {'id': 'routine-'+str(number), 'type': 'new-finding', 'severity': 'warning', 'code': 'fallback-risk', 'ref': 'r'+str(number),
                 'action': 'Review the referenced evidence and refresh or correct the manifest.'}
        return enqueue_failure(self.state/'state.json', alert, now=NOW+dt.timedelta(minutes=minutes))[0]

    def test_non_critical_alerts_wait_and_go_out_as_one_digest(self):
        self.provider.event = 'delivered'
        self.deliver()
        self.assertEqual(len(self.provider.sent), 1)
        first, second = self.routine(1), self.routine(2, 30)
        self.deliver(NOW+dt.timedelta(minutes=59))
        self.assertEqual(len(self.provider.sent), 1)
        self.assertEqual(len(self.pending_alerts()), 2)
        self.provider.event = 'sent'
        results = self.deliver(NOW+dt.timedelta(minutes=61))
        self.assertEqual(len(self.provider.sent), 2)
        self.assertEqual(sorted(results[0]['members']), sorted([first['deliveryId'], second['deliveryId']]))
        self.assertIn('digest (2 alerts)', self.provider.payload['subject'])
        self.assertIn(first['deliveryId'], self.provider.payload['text'])
        # A third alert arriving meanwhile does not change the unfinished digest.
        self.routine(3, 62)
        self.provider.event = 'delivered'
        self.deliver(NOW+dt.timedelta(minutes=63))
        self.assertEqual(len(self.provider.sent), 2)
        self.assertEqual([a['id'] for a in self.pending_alerts()], ['routine-3'])

    def test_critical_alert_is_not_held_for_the_digest(self):
        self.provider.event = 'delivered'
        self.deliver()
        self.routine(1)
        critical = enqueue_failure(self.state/'state.json', dict(self.alert, id='downgrade', severity='warning'), now=NOW)[0]
        results = self.deliver(NOW+dt.timedelta(minutes=1))
        self.assertEqual([r['deliveryId'] for r in results], [critical['deliveryId']])
        self.assertEqual([a['id'] for a in self.pending_alerts()], ['routine-1'])


if __name__ == '__main__': unittest.main()
