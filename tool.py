#!/usr/bin/env python3
import argparse, base64, csv, hashlib, ipaddress, json, os, re, socket, ssl, subprocess, sys, urllib.parse, urllib.request, uuid
from pathlib import Path
from datetime import datetime, timezone
from configparser import ConfigParser

NAME = 'Test Data Generator'
KIND = 'test_data'

def read_text(path): return Path(path).read_text(encoding='utf-8', errors='replace')
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description='توليد بيانات اختبار وهمية قابلة لإعادة الإنتاج')
    p.add_argument('input', nargs='?')
    p.add_argument('--output')
    p.add_argument('--value')
    p.add_argument('--count', type=int, default=5)
    p.add_argument('--pattern')
    p.add_argument('--confirm-localhost', action='store_true')
    a=p.parse_args(); k=KIND
    if k in ('url_headers','security_txt','robots_txt','cookie_flags','http_status'):
        url=a.input or a.value
        if not url or not url.startswith('https://'): raise SystemExit('Use an HTTPS URL.')
        req=urllib.request.Request(url, headers={{'User-Agent':'MURTAZA-Safe-Tool/1.0'}})
        with urllib.request.urlopen(req, timeout=8) as r:
            print('status:', r.status, 'final_url:', r.url)
            if k=='url_headers':
                for key,val in r.headers.items(): print(key+':', val)
            elif k in ('security_txt','robots_txt'):
                print(r.read(20000).decode('utf-8','replace'))
            elif k=='cookie_flags':
                for val in r.headers.get_all('Set-Cookie',[]): print(val, '| Secure=', 'Secure' in val, '| HttpOnly=', 'HttpOnly' in val, '| SameSite=', 'SameSite' in val)
        return
    if k=='tls_cert':
        host=a.input or a.value
        if not host: raise SystemExit('Provide a hostname.')
        with socket.create_connection((host,443), timeout=5) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
                c=t.getpeercert(); print('subject:', c.get('subject')); print('issuer:', c.get('issuer')); print('expires:', c.get('notAfter')); print('protocol:', t.version())
        return
    if k=='dns':
        host=a.input or a.value
        print(socket.gethostbyname_ex(host)); return
    if k=='password_policy':
        v=a.value or a.input or ''
        if not v: raise SystemExit('Pass value through --value; it is not stored.')
        checks=[('length>=12',len(v)>=12),('upper',bool(re.search('[A-Z]',v))),('lower',bool(re.search('[a-z]',v))),('digit',bool(re.search(r'\d',v))),('symbol',bool(re.search(r'[^A-Za-z0-9]',v)))]
        print('score:', sum(x for _,ok in checks if ok), '/', len(checks)); print(*[f'{{n}}: {{"ok" if ok else "missing"}}' for n,ok in checks], sep='\n'); return
    if k=='secret_scan':
        text=read_text(a.input or '.'); patterns=[r'AKIA[0-9A-Z]{{16}}',r'gh[pousr]_[A-Za-z0-9_]+',r'-----BEGIN [A-Z ]+PRIVATE KEY-----',r'(?i)password\s*[:=]']
        for pat in patterns: print(pat, 'matches=', len(re.findall(pat,text)))
        return
    if k=='manifest':
        path=Path(a.input or '.'); items={{}}
        for f in path.rglob('*') if path.is_dir() else [path]:
            if f.is_file(): items[str(f)]=sha(f)
        out=a.output or 'manifest.json'; Path(out).write_text(json.dumps(items,indent=2), encoding='utf-8'); print('written:',out,'files:',len(items)); return
    if k=='json_log':
        rows=[json.loads(x) for x in read_text(a.input).splitlines() if x.strip()]; print(json.dumps({{'rows':len(rows),'levels':{{str(x.get('level','unknown')):sum(1 for y in rows if y.get('level')==x.get('level')) for x in rows}}}},indent=2)); return
    if k=='csv_summary':
        with open(a.input,newline='',encoding='utf-8') as f: rows=list(csv.DictReader(f))
        print(json.dumps({{'rows':len(rows),'columns':list(rows[0]) if rows else []}},indent=2)); return
    if k=='pii_redact':
        text=read_text(a.input); text=re.sub(r'[\w.+-]+@[\w.-]+\.\w+','[EMAIL]',text); text=re.sub(r'\+?\d[\d ()-]{{7,}}','[PHONE]',text); text=re.sub(r'\b(?:\d{{1,3}}\.){{3}}\d{{1,3}}\b','[IP]',text); print(text); return
    if k=='ip_classify':
        for x in (a.input or a.value or '').split(','):
            ip=ipaddress.ip_address(x.strip()); print(x, 'private' if ip.is_private else 'loopback' if ip.is_loopback else 'global')
        return
    if k=='cidr': print(ipaddress.ip_network(a.input or a.value, strict=False)); return
    if k=='port_validate':
        vals=sorted({int(x) for x in (a.input or '').split(',') if x.isdigit() and 1<=int(x)<=65535}); print(','.join(map(str,vals))); return
    if k in ('firewall_lint','ssh_lint','nginx_lint','docker_lint','env_audit','access_report'):
        text=read_text(a.input); checks={'firewall_lint':['0.0.0.0/0','any any'],'ssh_lint':['PermitRootLogin yes','PasswordAuthentication yes'],'nginx_lint':['autoindex on','server_tokens on'],'docker_lint':['ADD http://','USER root'],'env_audit':['PASSWORD','SECRET','TOKEN'],'access_report':[]}[k]
        for item in checks: print(item, 'found' if item in text else 'not found')
        if k=='env_audit': print('variable names only; values are never printed')
        return
    if k=='gitignore': Path(a.output or '.gitignore').write_text('.env\n*.key\n*.pem\n__pycache__/\n.venv/\n',encoding='utf-8'); print('written'); return
    if k=='backup': print('CHECKLIST\n[ ] 3-2-1 copies\n[ ] encrypted backup\n[ ] restore test\n[ ] offline copy'); return
    if k=='timeline':
        with open(a.input,newline='',encoding='utf-8') as f:
            for row in sorted(csv.DictReader(f), key=lambda x:x.get('timestamp','')): print(row)
        return
    if k=='checklist': print('Update dependencies\nEnable MFA\nUse least privilege\nBack up data\nReview logs\nDocument incident contacts'); return
    if k=='json_format': print(json.dumps(json.loads(read_text(a.input)),indent=2,ensure_ascii=False)); return
    if k=='csv_json':
        with open(a.input,newline='',encoding='utf-8') as f: print(json.dumps(list(csv.DictReader(f)),ensure_ascii=False,indent=2)); return
    if k=='md_toc':
        for line in read_text(a.input).splitlines():
            m=re.match(r'^(#+)\s+(.+)',line)
            if m: print('  '*(len(m.group(1))-1)+'- ['+m.group(2)+'](#'+re.sub(r'[^a-z0-9 ]','',m.group(2).lower()).replace(' ','-')+')')
        return
    if k=='regex':
        if not a.pattern: raise SystemExit('--pattern is required')
        for m in re.finditer(a.pattern, read_text(a.input)): print(m.group(0))
        return
    if k=='uuid': print(*[str(uuid.uuid4()) for _ in range(max(1,a.count))],sep='\n'); return
    if k=='timestamp': print(datetime.fromtimestamp(float(a.value or a.input),tz=timezone.utc).isoformat()); return
    if k=='text_stats':
        t=read_text(a.input); print(json.dumps({'chars':len(t),'words':len(t.split()),'lines':len(t.splitlines())}, indent=2)); return
    if k in ('duplicates','organizer'):
        root=Path(a.input or '.'); groups={{}}
        for f in root.rglob('*'):
            if f.is_file(): groups.setdefault((f.stat().st_size,sha(f) if k=='duplicates' else f.suffix.lower()),[]).append(str(f))
        for key,vals in groups.items():
            if k=='duplicates' and len(vals)>1: print('DUPLICATE',*vals,sep='\n')
            elif k=='organizer': print(f'{{vals[0]}} -> {{key[1] or "[no extension]"}}')
        return
    if k=='checksum': print(sha(a.input), sha(a.value)); return
    if k=='base64':
        v=a.value or a.input or ''; print(base64.b64decode(v).decode() if a.output=='decode' else base64.b64encode(v.encode()).decode()); return
    if k=='url_encode': print(urllib.parse.unquote(a.value or a.input) if a.output=='decode' else urllib.parse.quote(a.value or a.input)); return
    if k=='html_escape':
        import html; print(html.unescape(a.value or a.input) if a.output=='decode' else html.escape(a.value or a.input)); return
    if k=='ini':
        c=ConfigParser(); c.read(a.input); print(json.dumps({s:dict(c[s]) for s in c.sections()},indent=2)); return
    if k=='palette':
        base=(a.value or '3366cc').lstrip('#'); n=max(1,a.count); x=int(base,16)
        for i in range(n): print('#'+format((x+i*0x111111)%0xffffff,'06x'))
        return
    if k=='token': print(*[__import__('secrets').token_urlsafe(24) for _ in range(max(1,a.count))],sep='\n'); return
    if k=='test_data':
        import random; r=random.Random(int(a.value or 42)); print(json.dumps([{{'id':i+1,'score':r.randint(0,100)}} for i in range(max(1,a.count))],indent=2)); return
    if k=='imports':
        for line in read_text(a.input).splitlines():
            if line.startswith('import ') or line.startswith('from '): print(line)
        return
    if k=='project_report':
        files=list(Path(a.input or '.').rglob('*.py')); print('files:',len(files),'lines:',sum(len(read_text(f).splitlines()) for f in files)); return
    if k=='compile':
        r=subprocess.run([sys.executable,'-m','compileall','-q',a.input or '.']); print('ok' if r.returncode==0 else 'failed'); return
    if k in ('api_mock','health_server'):
        if not a.confirm_localhost: raise SystemExit('Add --confirm-localhost; server binds only to 127.0.0.1.')
        from http.server import HTTPServer, BaseHTTPRequestHandler
        class H(BaseHTTPRequestHandler):
            def do_GET(self): self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write((json.dumps({'status':'ok','tool':NAME})).encode())
            def log_message(self,*args): pass
        print('http://127.0.0.1:8080'); HTTPServer(('127.0.0.1',8080),H).serve_forever(); return
    if k=='extract':
        if not a.pattern: raise SystemExit('--pattern is required')
        for line in read_text(a.input).splitlines():
            if re.search(a.pattern,line): print(line)
        return
    if k=='git_report':
        subprocess.run(['git','-C',a.input or '.', 'log','-n','10','--pretty=format:%h %ad %s','--date=short'],check=False); return
    print('Tool ready. Run --help and provide an input file or value.')
if __name__=='__main__': main()
