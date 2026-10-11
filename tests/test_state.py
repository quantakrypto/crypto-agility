import tempfile,unittest
from pathlib import Path
from tools.state import compare,update_state
class StateTests(unittest.TestCase):
 def test_regression(self):
  a={"subject":"s","assessment":{"findings":[]},"pairs":[{"client":"c","server":"s","assessment":{"status":"declared-compatible"}}]}
  b={"subject":"s","assessment":{"findings":[{"code":"expired","ref":"manifest"}]},"pairs":[{"client":"c","server":"s","assessment":{"status":"incompatible"}}]}
  alerts=compare(a,b)["alerts"]
  self.assertEqual(len(alerts),2)
 def test_subject_binding(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"state.json"
   update_state(p,{"subject":"one","assessment":{"findings":[]},"pairs":[]})
   with self.assertRaises(ValueError): update_state(p,{"subject":"two","assessment":{"findings":[]},"pairs":[]})
 def test_invalid_does_not_replace_state(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"state.json"
   update_state(p,{"subject":"one","assessment":{"status":"unverified","findings":[]},"pairs":[]})
   original=p.read_bytes()
   with self.assertRaises(ValueError):
    update_state(p,{"subject":"one","assessment":{"status":"invalid","findings":[]},"pairs":[]})
   self.assertEqual(p.read_bytes(),original)
 def test_baseline(self):
  with tempfile.TemporaryDirectory() as d:
   result=update_state(Path(d)/"state.json",{"subject":"one","assessment":{"findings":[]},"pairs":[]})
   self.assertTrue(result["initialBaseline"])

class SecureStateTests(unittest.TestCase):
 def report(self, when='2026-10-12T00:00:00+00:00'):
  return {'subject':'s','checkedAt':when,'manifestGeneratedAt':when,'assessment':{'status':'unverified','findings':[]},'pairs':[]}
 def test_predictable_temp_symlink_cannot_modify_target(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'; target=Path(d)/'valuable'
   target.write_text('valuable');Path(str(p)+'.tmp').symlink_to(target)
   update_state(p,self.report())
   self.assertEqual(target.read_text(),'valuable')
   self.assertEqual(p.stat().st_mode&0o777,0o600)
 def test_symlink_state_lock_and_fifo_rejected(self):
  import os
  for variant in ('state','lock','fifo'):
   with self.subTest(variant=variant),tempfile.TemporaryDirectory() as d:
    p=Path(d)/'state.json'; target=Path(d)/'target';target.write_text('{}');target.chmod(0o600)
    if variant=='state':p.symlink_to(target)
    elif variant=='lock':Path(str(p)+'.lock').symlink_to(target)
    else:os.mkfifo(p,0o600)
    with self.assertRaises((ValueError,OSError)):update_state(p,self.report())
    self.assertEqual(target.read_text(),'{}')
 def test_clock_and_manifest_rollback(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json';update_state(p,self.report())
   with self.assertRaises(ValueError):update_state(p,self.report('2026-10-11T00:00:00Z'))
   newer=self.report('2026-10-13T00:00:00Z');newer['manifestGeneratedAt']='2026-10-11T00:00:00Z'
   with self.assertRaises(ValueError):update_state(p,newer)
 def test_concurrent_locked_updates(self):
  from concurrent.futures import ThreadPoolExecutor
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'
   with ThreadPoolExecutor(max_workers=4) as pool:
    results=list(pool.map(lambda _:update_state(p,self.report()),range(20)))
   self.assertEqual(sum(bool(r.get('initialBaseline')) for r in results),1)
 def test_removed_coverage_and_alert_deduplication(self):
  a=self.report(); a['profileIds']=['client'];a['pairs']=[{'client':'client','server':'server','assessment':{'status':'declared-compatible'}}]
  b=self.report();b['profileIds']=[]
  alerts=compare(a,b)['alerts']
  self.assertEqual(len(alerts),2)
  self.assertTrue(all(x['action'] and x['id'] for x in alerts))
  self.assertEqual(compare(b,b)['alerts'],[])
 def test_measurement_loss_expiry_and_classical_regression(self):
  a=self.report();a['measurements']=[{'issuer':'p','subject':'s','status':'authenticated-observation','negotiatedGroup':'X25519MLKEM768','hybridKexObserved':True}]
  for state in ('stale','classical','removed'):
   import copy
   b=copy.deepcopy(a)
   if state=='stale':b['measurements'][0]['status']='stale'
   elif state=='classical':b['measurements'][0].update(negotiatedGroup='X25519',hybridKexObserved=False)
   else:b['measurements']=[]
   self.assertEqual(len(compare(a,b)['alerts']),1)

class DeliveryStateTests(unittest.TestCase):
 def report(self, findings=(), measurements=()):
  return {'subject':'s','checkedAt':'2026-10-12T00:00:00Z','assessment':{'status':'needs-review','findings':list(findings)},'pairs':[],'measurements':list(measurements)}
 def test_undelivered_alert_survives_restart_and_explicit_ack(self):
  from tools.state import acknowledge_alerts
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'; report=self.report([{'code':'expired','ref':'manifest'}])
   first=update_state(p,report)['alerts']
   retry=update_state(p,report)['alerts']
   self.assertEqual(first,retry)
   self.assertEqual(len(first),1)
   acknowledge_alerts(p,[first[0]['deliveryId']])
   self.assertEqual(update_state(p,report)['alerts'],[])
 def test_ack_is_bound_to_delivery_occurrence(self):
  from tools.state import acknowledge_alerts
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'; report=self.report([{'code':'expired','ref':'manifest'}])
   first=update_state(p,report)['alerts'][0]
   acknowledge_alerts(p,[first['deliveryId']])
   update_state(p,self.report())
   again=update_state(p,report)['alerts'][0]
   self.assertEqual(first['id'],again['id'])
   self.assertNotEqual(first['deliveryId'],again['deliveryId'])
   acknowledge_alerts(p,[first['deliveryId']])
   self.assertEqual(update_state(p,report)['alerts'],[again])
 def test_pending_alerts_survive_concurrent_ack_and_check(self):
  from tools.state import acknowledge_alerts
  from concurrent.futures import ThreadPoolExecutor
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'; old=self.report([{'code':'expired','ref':'manifest'}])
   alert=update_state(p,old)['alerts'][0]
   new=self.report([{'code':'expired','ref':'manifest'},{'code':'measurement-rejected','ref':'replay'}])
   with ThreadPoolExecutor(max_workers=2) as pool:
    tasks=[pool.submit(acknowledge_alerts,p,[alert['deliveryId']]),pool.submit(update_state,p,new)]
    for task in tasks:task.result()
   pending=update_state(p,new)['alerts']
   self.assertEqual([a['code'] for a in pending],['measurement-rejected'])
 def test_rejection_does_not_erase_last_authenticated_regression_baseline(self):
  import json
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state.json'
   hybrid={'issuer':'issuer','subject':'s','status':'authenticated-observation','negotiatedGroup':'X25519MLKEM768','hybridKexObserved':True}
   update_state(p,self.report(measurements=[hybrid]))
   rejected=self.report([{'code':'measurement-rejected','ref':'replay'}])
   update_state(p,rejected)
   self.assertEqual(json.loads(p.read_text())['measurements'],[])
   classical=dict(hybrid,negotiatedGroup='X25519',hybridKexObserved=False)
   alerts=update_state(p,self.report(measurements=[classical]))['alerts']
   self.assertIn('tls-regression',{a['type'] for a in alerts})
