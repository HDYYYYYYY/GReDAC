"""Recheck saved Tamarin certificates and their equality to current source.
Run under Linux/WSL: python3 replay.py [--regenerate]. No network needed.
The negative mutation must be falsified; that is an expected PASS.
"""
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,time,shutil
P=Path(__file__).resolve().parent
outname=os.environ.get('GREDAC_SYMBOLIC_RESULTS','results')
assert re.fullmatch(r'[A-Za-z0-9_-]+',outname), 'results must be a subdirectory name'
OUT=P/outname; OUT.mkdir(exist_ok=True)
MODELS=('control_authentication','bilateral_delegation','credential_authentication','pcdf_knowledge','request_binding','negative_payload_only')
TAM=Path(os.environ.get('TAMARIN',shutil.which('tamarin-prover') or 'tamarin-prover'))
MAUDE=Path(os.environ.get('MAUDE',shutil.which('maude') or 'maude'))
ENV=os.environ.copy(); ENV['PATH']=str(TAM.parent)+':'+str(MAUDE.parent)+':/usr/local/bin:/usr/bin:/bin'
ENV['LANG']='C.UTF-8'; ENV['LC_ALL']='C.UTF-8'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,log,timeout=180):
 start=time.monotonic()
 with log.open('w',encoding='utf-8') as f:
  try:r=subprocess.run(cmd,cwd=P,env=ENV,stdout=f,stderr=subprocess.STDOUT,timeout=timeout); rc=r.returncode
  except subprocess.TimeoutExpired:rc=124
 return rc,round(time.monotonic()-start,3)
def normalized(text):
 text=text[text.index('theory '):]
 text=re.sub(r'/\*.*?\*/','',text,flags=re.S)
 text=re.sub(r'//[^\n]*','',text)
 # Parser emits redundant type annotations for builtins in closed theories.
 # Keep all user function declarations/equations/rules/restrictions.
 annotations=re.findall(r'^\s*function:[^\n]*',text,re.M)
 allowed={'function:fst(Any):Any','function:pair(Any,Any):Any','function:snd(Any):Any','function:pk(Any):Any','function:sign(Any,Any):Any','function:true():Any','function:verify(Any,Any,Any):Any'}
 allowed.update({'function:mac(Any,Any):Any','function:channel_packet(Any,Any):Any[private]','function:auth(Any,Any):Any[private]','function:split_label(Any):Any','function:grant_label(Any):Any','function:anchor_label(Any,Any):Any','function:spend_label():Any','function:step(Any,Any):Any'})
 assert all(re.sub(r'\s+','',a) in allowed for a in annotations)
 text=re.sub(r'^\s*function:[^\n]*','',text,flags=re.M)
 # Expanded signing functions and equations remain compared verbatim above.
 builtins=re.findall(r'^\s*builtin[^\n]*',text,re.M)
 assert all(re.sub(r'\s+','',a)=='builtinsigning' for a in builtins)
 text=re.sub(r'^\s*builtin[^\n]*','',text,flags=re.M)
 prefix=text.split('lemma ',1)[0]
 lemmas=re.findall(r'lemma\s+(\w+)([^:]*):\s*(all-traces|exists-trace)?\s*"([^"]*)"',text,re.S)
 return (re.sub(r'\s+','',prefix),[(n,re.sub(r'\s+','',a),q,re.sub(r'\s+','',f)) for n,a,q,f in lemmas])
def main():
 regenerate='--regenerate' in sys.argv
 versions={}
 for name,path,arg in [('tamarin',TAM,'--version'),('maude',MAUDE,'--version')]:
  versions[name]={'path':str(path),'sha256':digest(path),'version':subprocess.check_output([str(path),arg],env=ENV,text=True,stderr=subprocess.STDOUT).strip()}
 rows=[]
 for name in MODELS:
  src=P/(name+'.spthy'); cert=P/(name+'.proof.spthy')
  expected=re.findall(r'^lemma\s+(\w+)',src.read_text(),re.M)
  row={'model':name,'source_sha256':digest(src),'expected_lemmas':expected}
  if regenerate:
   cmd=[str(TAM),str(src),'--prove','--quit-on-warning','--derivcheck-timeout=60','--output='+str(cert),'+RTS','-N2','-RTS']
   row['generation_exit'],row['generation_seconds']=run(cmd,OUT/(name+'.generation.log'))
   if row['generation_exit']!=0:raise RuntimeError(row)
  if not cert.exists():raise FileNotFoundError(cert)
  row['certificate_sha256']=digest(cert)
  parsed=[]
  for label,inputfile in [('source',src),('certificate',cert)]:
   cmd=[str(TAM),str(inputfile),'--parse-only']
   dest=OUT/(name+'.'+label+'.parsed.spthy')
   rc,_=run(cmd,dest,60)
   if rc:raise RuntimeError('parse failed: '+str(dest))
   parsed.append(normalized(dest.read_text()))
  if parsed[0]!=parsed[1]:raise RuntimeError('certificate/source model mismatch: '+name)
  assert digest(src)==row['source_sha256'], 'source changed during run'
  assert digest(cert)==row['certificate_sha256'], 'certificate changed during run'
  row['certificate_matches_source']=True
  row['normalized_model_sha256']=hashlib.sha256(repr(parsed[0]).encode()).hexdigest()
  cmd=[str(TAM),str(cert),'--quit-on-warning','--derivcheck-timeout=60','--output='+str(OUT/(name+'.replayed.spthy')),'+RTS','-N2','-RTS']
  row['replay_command']=cmd
  row['exit_code'],row['replay_seconds']=run(cmd,OUT/(name+'.replay.log'))
  log=(OUT/(name+'.replay.log')).read_text()
  summaries=re.findall(r'^\s*(\w+) \((all-traces|exists-trace)\): (.+)$',log,re.M)
  assert digest(src)==row['source_sha256'], 'source changed during replay'
  assert digest(cert)==row['certificate_sha256'], 'certificate changed during replay'
  row['lemmas']=summaries
  row['expected_negative_control']=name=='negative_payload_only'
  row['passed']=row['exit_code']==0 and len(summaries)==len(expected) and {x[0] for x in summaries}==set(expected) and all((status.startswith('falsified') if name=='negative_payload_only' and lemma=='complete_message_origin' else status.startswith('verified')) for lemma,kind,status in summaries)
  rows.append(row)
  result={'versions':versions,'mode':'saved proof-tree replay; normalized current source and certificate compared','models':rows,'complete':len(rows)==len(MODELS),'all_expected_results':len(rows)==len(MODELS) and all(x['passed'] for x in rows)}
  (OUT/'RESULTS.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
  print(name,row['passed'],summaries,flush=True)
 return 0 if all(x['passed'] for x in rows) else 1
if __name__=='__main__':sys.exit(main())
