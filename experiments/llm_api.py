"""Real DeepSeek strict-tool client. No automatic retry or response repair.

Writes exact per-call JSONL request/response excluding authentication headers.
The provided history contains only actual assistant tool calls and their
actual tool responses. Controller observations are ordinary user messages.
"""
import json
import os
import time
import urllib.request
import urllib.error
from .travel_domain import validate
from .agent_input import text,object_order,messages


class StrictAPI:
    def __init__(self,key,model,max_calls,out,max_tokens=1800):
        self.key,self.model,self.limit,self.out=key,model,max_calls,out
        self.max_tokens=max_tokens
        self.calls=[]

    def call(self,role,history,offered,observation,case):
        if len(self.calls)>=self.limit:raise RuntimeError('API budget exhausted')
        history.append({'role':'user','content':text(observation)})
        body=dict(model=self.model,messages=messages(history),tools=[object_order(offered)],
            tool_choice={'type':'function','function':{'name':offered['function']['name']}},
            temperature=0,max_tokens=self.max_tokens,thinking={'type':'disabled'})
        assert len(json.dumps(body))<250000,'input budget exceeded'
        row=dict(index=len(self.calls),case=case,role=role,request=body,start=time.monotonic(),api_process_pid=os.getpid())
        self.calls.append(row)
        req=urllib.request.Request('https://api.deepseek.com/beta/chat/completions',
            data=json.dumps(body).encode(),headers={'Content-Type':'application/json',
                                                   'Authorization':'Bearer '+self.key})
        try:
            with urllib.request.urlopen(req,timeout=90) as response:result=json.load(response)
            row['response']=result
            message=result['choices'][0]['message'];calls=message.get('tool_calls',[])
            # A forced function name and strict argument schema do not limit
            # call cardinality. Prompts request one action; a batch is retained
            # as a failed trajectory, never silently truncated or replayed.
            assert len(calls)==1,'exactly one tool call required'
            tc=calls[0]
            assert tc['function']['name']==offered['function']['name'],'unexpected tool'
            args=json.loads(tc['function']['arguments'])
            validate(args,offered['function']['parameters'])
            normalized=object_order(calls)
            normalized[0]['function']['arguments']=text(args)
            history.append({'role':'assistant','content':message.get('content'), 'tool_calls':normalized})
            row['status']='ok'
            return args,tc['id']
        except urllib.error.HTTPError as exc:
            row.update(status='api_error',http_status=exc.code,error=exc.read().decode()[:1000])
            raise RuntimeError('DeepSeek HTTP '+str(exc.code)) from None
        except Exception as exc:
            row.update(status='error',error=type(exc).__name__+': '+str(exc));raise
        finally:
            row['seconds']=time.monotonic()-row['start']
            with (self.out/'api_calls.jsonl').open('a',encoding='utf-8') as f:
                f.write(json.dumps(row,ensure_ascii=False)+'\n')

    @staticmethod
    def feedback(history,call_id,result):
        history.append({'role':'tool','tool_call_id':call_id,'content':text(result)})
