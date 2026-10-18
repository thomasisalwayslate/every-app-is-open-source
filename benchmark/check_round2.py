"""Real PyGhidra checks on the original tiny fixture, not Doom test questions."""
from pathlib import Path
import hashlib
import json
from urllib.parse import urlparse,unquote
from eaos.backend import Backend
from eaos.cli import TOOLS

ROOT=Path(__file__).resolve().parents[1]
b=Backend(str(ROOT/'private/fixture'));checks=[]
def check(label,condition):
 if not condition:raise AssertionError(label)
 checks.append(label)
try:
 short=b.open_program();full=b.open_program(full=True)
 check('compact metadata preserves full metadata access',len(json.dumps(short))<len(json.dumps(full)) and 'cache' in full['data'])
 fn='100000460'
 short=b.inspect([fn]);full=b.inspect([fn],full=True)
 check('default decompile omits automatic call graph, full retains it','callers' not in short['data'][0] and 'callers' in full['data'][0])
 check('decompilation honestly computed',short['classification']=='computed')
 check('deterministic identical evidence',short==b.inspect([fn]))
 check('explicit calls retained','callees' in b.inspect([fn],mode='calls')['data'][0])
 check('assembly retained and labelled fact',b.inspect([fn],mode='assembly')['classification']=='fact')
 search=b.search(pattern='eaos fixture anchor');fullsearch=b.search(pattern='eaos fixture anchor',full=True)
 check('search hit and full reference metadata',bool(search['data']['items']) and 'signature' in fullsearch['data']['items'][0]['references'][0]['function'])
 check('references retained',bool(b.inspect([search['data']['items'][0]['address']],mode='references')['data']))
 memory=b.read_memory(fn,16);both=b.read_memory(fn,16,format='both')
 check('hex default with explicit text capability','utf8' not in memory['data'] and 'utf8' in both['data'] and memory['data']['hex']==both['data']['hex'])
 for item in [short,full,search,fullsearch,memory,both]:
  evidence=item['evidence'];path=Path(unquote(urlparse(evidence['uri']).path))
  check('resolvable evidence '+evidence['id'],path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==path.with_suffix('.sha256').read_text().strip())
  text='';offset=0
  while True:
   page=b.read_evidence(evidence['id'],offset,100);text+=page['text']
   if page['next_offset'] is None:break
   offset=page['next_offset']
  check('paged full evidence '+evidence['id'],json.loads(text)['classification']==item['classification'])
 check('calculator actual subprocess',b.calculate('sum(range(5))')['data']['value']=='10')
 raw=b'hello'+b'\0'*10+bytes([0xE5]);words=[int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:],'little')]
 decoded=b.decode_swift_string(words=words)
 check('Apple inline text and caller premise warning',decoded['data']['text']=='hello' and 'caller' in str(decoded['limitations']))
 check('seven capabilities retained',len(TOOLS)==7)
finally:b.close()
(ROOT/'reports/round2/contract-checks.json').write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2))
print(len(checks),'real-fixture contract checks passed')
