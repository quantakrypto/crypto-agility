"""Offline integration tests spanning schema, assessment, monitoring and state."""
import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from tools.monitor import snapshot
from tools.state import update_state

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=json.loads((ROOT/"schema/crypto-agility-v2.schema.json").read_text())
EXAMPLE=json.loads((ROOT/"examples/crypto-agility-v2.json").read_text())
NOW=dt.datetime(2026,10,12,tzinfo=dt.timezone.utc)

class IntegrationTests(unittest.TestCase):
 def test_snapshot_to_state_and_regression(self):
  m=copy.deepcopy(EXAMPLE)
  m["profiles"].append({"id":"server","endpointRole":"server","deviceClass":"server","protocol":"TLS 1.3","keyEstablishment":["X25519MLKEM768"],"authentication":["ECDSA"],"fallback":"deny-classical"})
  first=snapshot(m,SCHEMA,NOW)
  self.assertEqual(first["assessment"]["status"],"needs-review")
  pair=[p for p in first["pairs"] if p["client"]=="modern-browser" and p["server"]=="server"]
  self.assertEqual(pair[0]["assessment"]["status"],"declared-compatible")
  with tempfile.TemporaryDirectory() as d:
   state=Path(d)/"state.json"
   self.assertTrue(update_state(state,first)["initialBaseline"])
   m["profiles"][-1]["keyEstablishment"]=["X448"]
   second=snapshot(m,SCHEMA,NOW)
   delta=update_state(state,second)
   self.assertIn("compatibility-regression",{a["type"] for a in delta["alerts"]})
 def test_invalid_manifest_does_not_generate_pairs(self):
  m=copy.deepcopy(EXAMPLE);m["profiles"]="not an array"
  result=snapshot(m,SCHEMA,NOW)
  self.assertEqual(result["assessment"]["status"],"invalid")
  self.assertEqual(result["pairs"],[])
 def test_gateway_hops_are_not_end_to_end_proof(self):
  m=copy.deepcopy(EXAMPLE)
  m["profiles"].append({"id":"gateway","endpointRole":"gateway","deviceClass":"network","protocol":"TLS 1.3","keyEstablishment":["X25519MLKEM768"],"authentication":["ECDSA"],"fallback":"deny-classical"})
  report=snapshot(m,SCHEMA,NOW)
  self.assertTrue(any(p["server"]=="gateway" for p in report["pairs"]))
  self.assertFalse(any(p["assessment"]["status"]=="verified" for p in report["pairs"]))
 def test_expiry_propagates_to_monitor(self):
  result=snapshot(EXAMPLE,SCHEMA,dt.datetime(2026,11,1,tzinfo=dt.timezone.utc))
  self.assertIn("expired",{x["code"] for x in result["assessment"]["findings"]})

class AlertDeliveryIntegrationTests(unittest.TestCase):
 def manifest_text(self):
  manifest=copy.deepcopy(EXAMPLE)
  now=dt.datetime.now(dt.timezone.utc)
  manifest["generatedAt"]=(now-dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
  manifest["expiresAt"]=(now+dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
  return json.dumps(manifest)
 def command(self, *args):
  import subprocess,sys
  return subprocess.run([sys.executable,'-m','tools.monitor',*map(str,args)],cwd=ROOT,text=True,capture_output=True)
 def test_failed_output_retries_pending_alert_and_cli_acknowledges_delivery(self):
  with tempfile.TemporaryDirectory() as d:
   directory=Path(d);state=directory/'state.json';manifest=directory/'manifest.json'
   manifest.write_text(self.manifest_text())
   failed=self.command(manifest,'--state',state,'--output',directory/'missing'/'out.json')
   self.assertNotEqual(failed.returncode,0)
   pending=json.loads(state.read_text())['pendingAlerts']
   self.assertTrue(pending)
   retry=self.command(manifest,'--state',state)
   report=json.loads(retry.stdout)
   self.assertEqual(report['changes']['alerts'],pending)
   ack_args=[arg for alert in pending for arg in ('--ack-alert',alert['deliveryId'])]
   ack=self.command('--state',state,*ack_args)
   self.assertEqual(ack.returncode,0,ack.stderr)
   self.assertEqual(json.loads(ack.stdout)['acknowledged'],len(pending))
   again=json.loads(self.command(manifest,'--state',state).stdout)
   self.assertEqual(again['changes']['alerts'],[])

 def test_invalid_input_alert_survives_output_failure_and_repair(self):
  with tempfile.TemporaryDirectory() as d:
   directory=Path(d);state=directory/'state.json';manifest=directory/'manifest.json'
   manifest.write_text(self.manifest_text())
   self.command(manifest,'--state',state)
   before=json.loads(state.read_text())
   manifest.write_text('{broken')
   self.command(manifest,'--state',state,'--output',directory/'missing'/'out.json')
   after=json.loads(state.read_text())
   self.assertEqual(after['subject'],before['subject'])
   self.assertEqual(after['assessment'],before['assessment'])
   manifest.write_text(self.manifest_text())
   repaired=json.loads(self.command(manifest,'--state',state).stdout)
   self.assertIn('monitor-failure',{a['type'] for a in repaired['changes']['alerts']})
 def test_invalid_first_input_retains_alert_without_establishing_baseline(self):
  with tempfile.TemporaryDirectory() as d:
   directory=Path(d);state=directory/'state.json';manifest=directory/'manifest.json'
   manifest.write_text('{broken')
   invalid=json.loads(self.command(manifest,'--state',state).stdout)
   self.assertEqual(invalid['assessment']['status'],'invalid')
   saved=json.loads(state.read_text())
   self.assertNotIn('subject',saved)
   manifest.write_text(self.manifest_text())
   repaired=json.loads(self.command(manifest,'--state',state).stdout)
   self.assertTrue(repaired['changes']['initialBaseline'])
   self.assertIn('monitor-failure',{a['type'] for a in repaired['changes']['alerts']})

if __name__=="__main__":
 unittest.main()
