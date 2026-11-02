"""Repository age advisory never broadens the submission gate."""
import copy
import unittest

from tools.idnits_gate import check


class IdnitsGateTests(unittest.TestCase):
    def report(self):
        return {'result': 'fail', 'nitsBySeverity': {'error': 0, 'warning': 1, 'comment': 0},
                'nits': [{'severity': 'ValidationWarning', 'code': 'DOC_DATE_IN_PAST',
                          'path': 'rfc.front.date', 'desc': 'The document date is 21 days in the past.'}]}

    def test_age_is_explicit_repository_advisory_only(self):
        report = self.report()
        self.assertEqual(check(report, repository=True), [report['nits'][0]['desc']])
        with self.assertRaises(ValueError):
            check(report)
        self.assertEqual(check({'result': 'pass', 'nitsBySeverity': {'error': 0, 'warning': 0, 'comment': 0}, 'nits': []}), [])

    def test_other_diagnostics_and_malformed_reports_fail(self):
        variants = []
        for key, value in [('severity', 'ValidationError'), ('code', 'DOC_DATE_IN_FUTURE'), ('path', 'rfc')]:
            report = self.report()
            report['nits'][0][key] = value
            variants.append(report)
        for counts in [{'error': 1, 'warning': 1, 'comment': 0}, {'error': 0, 'warning': 0, 'comment': 1}, {'error': False, 'warning': 1, 'comment': 0}, {'error': 0, 'warning': 0, 'comment': 0}]:
            report = self.report()
            report['nitsBySeverity'] = counts
            variants.append(report)
        variants += [{}, {'result': 'fail', 'nitsBySeverity': {'error': 0, 'warning': 0, 'comment': 0}, 'nits': []}]
        report = self.report()
        report['nits'].append(copy.deepcopy(report['nits'][0]))
        variants.append(report)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(ValueError):
                check(report, repository=True)
