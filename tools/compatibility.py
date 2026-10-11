"""Conservative declared-profile intersection across endpoint classes.

Device labels never establish capability. Gateway termination covers one hop only.
Free-text resource/firmware constraints cannot be safely evaluated automatically.
"""

def assess_pair(client, server):
    if client.get('endpointRole') not in ('client', 'peer') or server.get('endpointRole') not in ('server', 'peer', 'gateway'):
        return {'status': 'unknown', 'reason': 'endpoint roles not compatible with this evaluator'}
    if not client.get('protocol') or not server.get('protocol'):
        return {'status': 'unknown', 'reason': 'protocol unspecified'}
    if client['protocol'] != server['protocol']:
        return {'status': 'incompatible', 'reason': 'protocol mismatch'}
    for endpoint in (client, server):
        for field in ('keyEstablishment', 'authentication'):
            values = endpoint.get(field)
            if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
                return {'status': 'unknown', 'reason': 'algorithm inventory incomplete'}
    common_kex = sorted(set(client['keyEstablishment']) & set(server['keyEstablishment']))
    common_auth = sorted(set(client['authentication']) & set(server['authentication']))
    if not common_kex or not common_auth:
        return {'status': 'incompatible', 'reason': 'no shared declared key establishment or authentication'}
    if client.get('constraints') or server.get('constraints'):
        return {'status': 'unknown', 'reason': 'resource, connectivity or firmware constraints require explicit testing',
                'keyEstablishment': common_kex, 'authentication': common_auth}
    return {'status': 'declared-compatible', 'keyEstablishment': common_kex, 'authentication': common_auth,
            'reason': 'Intersection only; runtime negotiation, certificate trust, resource limits and fallback remain unverified',
            'scope': 'single-hop'}
