import json
import logging
import re
import os
import time
import urllib3
from flask import Flask, jsonify, send_from_directory
import requests
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

app = Flask(__name__, static_folder='public')

# Load config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
log.info("Loading config from %s", CONFIG_PATH)
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)
log.info("Loaded %d cluster(s): %s", len(config['clusters']),
         ', '.join(c['name'] for c in config['clusters']))


def extract_entitlement_cns(rules, filter_text):
    """
    Walk the role mapping rules tree and extract DNs that contain the entitlement filter.
    Elasticsearch role mapping rules can have nested all/any/except/field structures.
    """
    cns = set()

    def walk(node):
        if not node or not isinstance(node, dict):
            return

        # Check "field" rules for dn or groups matching
        if 'field' in node:
            for field_key in ('dn', 'groups'):
                values = node['field'].get(field_key)
                if values is None:
                    continue
                if isinstance(values, str):
                    values = [values]
                for v in values:
                    if filter_text.lower() in v.lower():
                        cns.add(v)

        # Recurse into all/any/except
        for key in ('all', 'any'):
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    walk(child)
        if 'except' in node:
            walk(node['except'])

    walk(rules)
    return list(cns)


def parse_cn(dn):
    """Extract the CN value from a full DN string."""
    match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
    return match.group(1) if match else dn


def fetch_role_mappings(cluster):
    """Fetch role mappings from an Elasticsearch cluster via the Security API."""
    url = f"{cluster['url'].rstrip('/')}/_security/role_mapping"
    log.info("Cluster [%s] — requesting %s", cluster['name'], url)
    start = time.time()
    try:
        resp = requests.get(
            url,
            auth=HTTPBasicAuth(cluster['username'], cluster['password']),
            verify=False,
            timeout=(10, 120)
        )
        elapsed = time.time() - start
        log.info("Cluster [%s] — %d response in %.2fs", cluster['name'], resp.status_code, elapsed)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectTimeout:
        log.error("Cluster [%s] — connection timed out after %.2fs to %s", cluster['name'], time.time() - start, url)
        raise
    except requests.exceptions.ReadTimeout:
        log.error("Cluster [%s] — read timed out after %.2fs to %s", cluster['name'], time.time() - start, url)
        raise
    except requests.exceptions.ConnectionError as e:
        log.error("Cluster [%s] — connection error after %.2fs: %s", cluster['name'], time.time() - start, e)
        raise
    except requests.exceptions.RequestException as e:
        log.error("Cluster [%s] — request failed after %.2fs: %s", cluster['name'], time.time() - start, e)
        raise


@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/api/entitlements')
def get_entitlements():
    filter_text = config.get('entitlementFilter', '')
    results = []

    log.info("Entitlements API called — filter: '%s'", filter_text)
    for cluster in config['clusters']:
        try:
            role_mappings = fetch_role_mappings(cluster)
            log.info("Cluster [%s] — %d role mappings returned", cluster['name'], len(role_mappings))

            for mapping_name, mapping in role_mappings.items():
                entitlement_dns = extract_entitlement_cns(
                    mapping.get('rules', {}), filter_text
                )

                for dn in entitlement_dns:
                    results.append({
                        'cluster': cluster['name'],
                        'mappingName': mapping_name,
                        'entitlement': parse_cn(dn),
                        'entitlementDN': dn,
                        'roles': mapping.get('roles', []),
                        'enabled': mapping.get('enabled', False),
                    })

        except Exception as e:
            log.exception("Cluster [%s] — failed: %s", cluster['name'], e)
            results.append({
                'cluster': cluster['name'],
                'mappingName': '-',
                'entitlement': f'ERROR: {str(e)}',
                'entitlementDN': '',
                'roles': [],
                'enabled': False,
                'error': True,
            })

    # Sort by cluster then entitlement
    results.sort(key=lambda r: (r['cluster'], r['entitlement']))
    return jsonify(results)


if __name__ == '__main__':
    log.info("ELK Entitlement Viewer running at http://localhost:8282")
    app.run(host='0.0.0.0', port=8282, debug=True)
