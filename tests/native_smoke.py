"""Exercise an installed EAOS wheel over stdio against the documented fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import subprocess
import time
from urllib.parse import unquote, urlparse


def check(command, target, report):
    report.parent.mkdir(parents=True, exist_ok=True)
    calls = []
    with report.with_suffix('.stderr.log').open('w') as log:
        process = subprocess.Popen([command, 'mcp', str(target)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        sequence = 0
        def request(method, params=None):
            nonlocal sequence
            sequence += 1
            process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': sequence, 'method': method, 'params': params or {}}) + '\n')
            process.stdin.flush()
            if not select.select([process.stdout], [], [], 180)[0]:
                raise RuntimeError('MCP response timed out')
            response = json.loads(process.stdout.readline())
            if response.get('error') or response.get('result', {}).get('isError'):
                raise RuntimeError(response)
            return response['result']
        def tool(name, arguments=None):
            result = json.loads(request('tools/call', {'name': name, 'arguments': arguments or {}})['content'][0]['text'])
            assert result['classification'] in {'fact', 'computed', 'guess'}
            if 'evidence' in result:
                path = Path(unquote(urlparse(result['evidence']['uri']).path))
                assert path.is_file()
            calls.append({'tool': name, 'result': result})
            return result
        try:
            initialized = request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'eaos-wheel-smoke', 'version': '1'}})
            assert initialized['serverInfo']['version'] == '0.1.3'
            catalog = request('tools/list')['tools']
            assert len(catalog) == 7
            opened = tool('open_program')
            deadline = time.monotonic() + 180
            while 'analysis' in opened['data']:
                assert opened['data']['analysis']['state'] == 'running'
                if time.monotonic() > deadline:
                    raise RuntimeError('Example analysis did not finish within the smoke-test budget')
                time.sleep(1)
                opened = tool('open_program')
            assert opened['data']['sha256'] == hashlib.sha256(target.read_bytes()).hexdigest()
            found = tool('search', {'kind': 'functions', 'pattern': 'quote'})
            assert found['data']['items']
            address = found['data']['items'][0]['address']
            inspected = tool('inspect', {'addresses': [address]})
            code = inspected['data'][0]['pseudocode']
            assert '0x13' in code or '19' in code
            assert '* 7' in code or '* 0x7' in code
            memory = tool('read_memory', {'address': address, 'length': 16})
            assert memory['classification'] == 'fact' and len(memory['data']['hex']) == 32
            assert tool('calculate', {'expression': '6 * 7 + 3'})['data']['value'] == '45'
            raw = b'hello' + b'\0' * 10 + bytes([0xe5])
            words = [int.from_bytes(raw[:8], 'little'), int.from_bytes(raw[8:], 'little')]
            assert tool('decode_swift_string', {'words': words})['data']['text'] == 'hello'
            assert tool('read_evidence', {'id': inspected['evidence']['id']})['text']
            assert tool('open_program')['data']['analysis_count'] == opened['data']['analysis_count']
            # Inspect an invalid result directly: the request wrapper rejects isError.
            sequence += 1
            process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': sequence, 'method': 'tools/call', 'params': {'name': 'open_program', 'arguments': {'full': 'false'}}}) + '\n')
            process.stdin.flush()
            assert select.select([process.stdout], [], [], 10)[0]
            assert json.loads(process.stdout.readline())['result']['isError']
            output = {'status': 'passed', 'version': initialized['serverInfo']['version'],
                      'tools': [item['name'] for item in catalog], 'calls': calls,
                      'invalid_boolean_rejected': True, 'target_executed': False}
            report.write_text(json.dumps(output, indent=2) + '\n')
            print('PASS: installed wheel, seven MCP tools, example logic, evidence links, cache reuse and invalid boolean rejection.')
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--eaos', required=True)
    parser.add_argument('--target', type=Path, required=True, help='A compiled tests/fixture.c')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    check(args.eaos, args.target.resolve(), args.report.resolve())
