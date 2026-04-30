#!/usr/bin/env python3
"""Generate CycloneDX SBOMs from npm lockfiles."""
import json
import uuid
import sys
import os

def generate_sbom(lockfile_path, component_name, component_version):
    with open(lockfile_path) as f:
        lockdata = json.load(f)
    
    packages = lockdata.get('packages', {})
    components = []
    
    for path, info in sorted(packages.items()):
        if not path or path == '':
            continue
        name = path.split('node_modules/')[-1]
        version = info.get('version', 'unknown')
        resolved = info.get('resolved', '')
        integrity = info.get('integrity', '')
        license_val = info.get('license', '')
        dev = info.get('dev', False)
        
        comp = {
            'type': 'library',
            'name': name,
            'version': version,
            'scope': 'optional' if dev else 'required',
            'purl': 'pkg:npm/{}@{}'.format(name, version),
        }
        
        if license_val and isinstance(license_val, str):
            comp['licenses'] = [{'license': {'id': license_val}}]
        
        if integrity and '-' in integrity:
            algo, digest = integrity.split('-', 1)
            comp['hashes'] = [{'alg': algo.upper().replace('SHA', 'SHA-'), 'content': digest}]
        
        components.append(comp)
    
    sbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': 'urn:uuid:{}'.format(uuid.uuid4()),
        'version': 1,
        'metadata': {
            'timestamp': '2026-04-30T06:55:00Z',
            'tools': [{'vendor': 'PERN-Store Security', 'name': 'sbom-generator', 'version': '1.0.0'}],
            'component': {
                'type': 'application',
                'name': component_name,
                'version': component_version
            }
        },
        'components': components
    }
    
    return sbom

base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

server_sbom = generate_sbom(
    os.path.join(base, 'server', 'package-lock.json'),
    'pern-store-server', '1.0.0'
)
out_server = os.path.join(base, 'security', 'sbom', 'sbom-server.cdx.json')
with open(out_server, 'w') as f:
    json.dump(server_sbom, f, indent=2)
print('Server SBOM: {} components -> {}'.format(len(server_sbom['components']), out_server))

client_sbom = generate_sbom(
    os.path.join(base, 'client', 'package-lock.json'),
    'pern-store-client', '0.1.0'
)
out_client = os.path.join(base, 'security', 'sbom', 'sbom-client.cdx.json')
with open(out_client, 'w') as f:
    json.dump(client_sbom, f, indent=2)
print('Client SBOM: {} components -> {}'.format(len(client_sbom['components']), out_client))

print('Done.')
