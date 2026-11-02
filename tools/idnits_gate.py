"""Strict submission gate; optional age advisory for repository regression checks."""
import argparse
import json


def check(report, *, repository=False):
    if not isinstance(report, dict):
        raise ValueError('invalid idnits report')
    counts = report.get('nitsBySeverity')
    nits = report.get('nits')
    if (not isinstance(counts, dict) or set(counts) != {'error', 'warning', 'comment'}
            or any(type(value) is not int or value < 0 for value in counts.values())
            or not isinstance(nits, list) or sum(counts.values()) != len(nits)):
        raise ValueError('invalid idnits diagnostics')
    if not nits and report.get('result') == 'pass':
        return []
    if (repository and report.get('result') == 'fail'
            and counts == {'error': 0, 'warning': 1, 'comment': 0}
            and len(nits) == 1 and isinstance(nits[0], dict)
            and nits[0].get('severity') == 'ValidationWarning'
            and nits[0].get('code') == 'DOC_DATE_IN_PAST'
            and nits[0].get('path') == 'rfc.front.date'
            and isinstance(nits[0].get('desc'), str) and nits[0]['desc']):
        return [nits[0]['desc']]
    raise ValueError('idnits reported fatal diagnostics')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--repository', action='store_true', help='Report only draft age as advisory; never use for submission readiness')
    args = parser.parse_args()
    with open(args.report, encoding='utf-8') as stream:
        report = json.load(stream)
    for advisory in check(report, repository=args.repository):
        print(f'Repository age advisory: {advisory} Submission readiness still requires a strict check.')


if __name__ == '__main__':
    main()
