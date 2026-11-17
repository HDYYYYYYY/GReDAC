"""RQ3-scoped model recovery; core protocol and shared source are unchanged.

Each ask RPC makes at most ONE external API attempt in the receiving Agent.
The Agent owns its history, retry counters and correction observation. A small
driver loop only forwards the Agent's retry decision. This avoids holding one
RPC open for 5*90 seconds, without changing any TCP/TLS timeout or protocol RPC.
Model generations have no business side effect; parsed actions execute only
after success. All errors, rejected responses and wait times remain recorded.
"""
import copy,json,os,time
from http.client import IncompleteRead
from .policy import RETRY


def transient(last,error):
    code=last.get('http_status')
    if code is not None:return code in (408,429) or 500<=code<=599
    # urllib's interrupted HTTP body raises IncompleteRead (HTTPException),
    # not OSError. No complete response/action exists yet: retry this model
    # generation under the SAME transient and per-action budgets.
    return 'response' not in last and isinstance(error,(TimeoutError,ConnectionError,OSError,IncompleteRead))


def one_attempt(node,offered,observation,case,remaining,action_id):
    from gredac.crypto import digest
    binding=digest([offered,observation,case])
    state=getattr(node,'rq3_retry_state',None)
    if state is None or state['id']!=action_id:
        state=node.rq3_retry_state=dict(id=action_id,binding=binding,attempt=0,transient_retries=0,
            next_observation=copy.deepcopy(observation),delay=0,finished=False)
    assert state['binding']==binding and not state['finished'],'model action changed or already completed'
    assert remaining>0,'episode API cap'
    first=len(node.api.calls);state['attempt']+=1;assert state['attempt']<=RETRY['max_action_attempts']
    delay=state['delay'];wait_start=time.monotonic()
    if delay:time.sleep(delay)
    waited=time.monotonic()-wait_start if delay else 0.
    outcome=dict(action_id=action_id,attempt=state['attempt'],wait_seconds=waited,requested_wait_seconds=delay,
        kind='success',will_retry=False)
    answer={};history_length=len(node.history)
    try:
        arguments,call_id=node.api.call(node.name,node.history,offered,state['next_observation'],case)
        answer.update(arguments=arguments,call_id=call_id);state['finished']=True
    except Exception as exc:
        last=node.api.calls[-1] if len(node.api.calls)>first else {}
        is_transient=transient(last,exc);has_response='response' in last
        kind='api_transient' if is_transient else ('model_format' if has_response else 'nonretryable_api_or_budget')
        allowed=(state['attempt']<RETRY['max_action_attempts'] and remaining>1 and bool(last)
            and (has_response or (is_transient and state['transient_retries']<RETRY['max_transient_retries'])))
        outcome.update(kind=kind,will_retry=allowed,error=type(exc).__name__+': '+str(exc))
        if allowed:
            if is_transient:
                state['delay']=RETRY['backoff_seconds'][state['transient_retries']]
                state['transient_retries']+=1
                del node.history[history_length:]  # retry identical unfinished generation input
                # Replay only the same model generation request. No tool or
                # protocol operation has executed, and no history is reset.
            else:
                state['delay']=0
                response=last['response'];choices=response.get('choices') or [{}]
                state['next_observation']=dict(validation_error=str(exc),attempt=state['attempt'],
                    offered_tool=offered['function']['name'],finish_reason=choices[0].get('finish_reason'),
                    instruction='Correct the pending action using the exact offered tool and all schema fields. '
                    'Refer to the original task already in your history. Do not reproduce rejected drafts. '
                    'If truncated, submit compact complete arguments, including the entire schedule; '
                    'keep explanations concise. Never invent missing facts or a checker result.')
            answer['retry']=True
        else:answer['error']=outcome['error'];state['finished']=True
    # The raw HTTP record is already in the actor API log. The extra retry
    # metadata is also retained separately and in the controller aggregate.
    for row in node.api.calls[first:]:row['rq3_retry']=dict(outcome)
    node.record('rq3_model_attempt',dict(attempt_outcome=outcome));node.save_history()
    return dict(**answer,calls=node.api.calls[first:],retry_event=outcome,pid=os.getpid())


def install_actor():
    import experiments.network_actor as actor
    if getattr(actor.Node,'_rq3_current_installed',False):return
    actor.Node._rq3_current_installed=True
    actor.Node.ask=one_attempt


def process_main(name,directory,path,pipe):
    from experiments.network_actor import process_main as original
    install_actor();original(name,directory,path,pipe)


def install_driver():
    import experiments.network_actor as actor
    from experiments.task_backend import TaskBackend,AgentCommunicationError
    actor.process_main=process_main
    def ask_agent(self,api,identity,prompt,offered,observation,case,remaining):
        if identity not in self.configured_models:
            self.mesh.call(identity,'model_config',prompt=prompt,model=api.model,max_calls=api.limit,
                max_tokens=api.max_tokens,format_retries=0,test_profile=getattr(api,'test_profile',None),api_key=getattr(api,'key',None))
            self.configured_models.add(identity)
        self.rq3_action_sequence=getattr(self,'rq3_action_sequence',0)+1
        action_id=case+':'+str(self.rq3_action_sequence);used=0
        for _ in range(RETRY['max_action_attempts']):
            left=min(remaining-used,api.limit-getattr(api,'attempts_reserved',0));assert left>0,'episode API cap'
            # Reserve before dispatch: an actor/channel failure cannot silently
            # refund a possibly executed API request into the hard budget.
            api.attempts_reserved=getattr(api,'attempts_reserved',0)+1
            try:response=self.mesh.call(identity,'ask',offered=offered,observation=observation,case=case,remaining=left,action_id=action_id)
            except (OSError,ConnectionError,RuntimeError) as exc:
                # A role/TLS/protocol transport error is NOT an LLM retry.
                raise AgentCommunicationError(type(exc).__name__+': '+str(exc)) from exc
            for row in response['calls']:
                row={**row,'index':len(api.calls),'actor_pid':response['pid']};api.calls.append(row);used+=1
                with (self.run.out/'api_calls.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
            event=dict(**response['retry_event'],actor_pid=response['pid'],identity=identity,case=case)
            with (self.run.out/'model_retry_events.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')
            if response.get('retry'):continue
            if 'error' in response:raise RuntimeError(response['error'])
            return response['arguments'],lambda value:self.mesh.call(identity,'feedback',call_id=response['call_id'],value=value)
        raise RuntimeError('model action attempt cap')
    TaskBackend.ask_agent=ask_agent


def retry_statistics(calls):
    from collections import Counter
    marked=[r['rq3_retry'] for r in calls if 'rq3_retry' in r]
    actions={}
    for row in marked:actions.setdefault(row['action_id'],[]).append(row)
    return dict(attempts=len(calls),retried_api_calls=sum(r['attempt']>1 for r in marked),
        recovered_actions=sum(len(v)>1 and v[-1]['kind']=='success' for v in actions.values()),
        failed_attempts_by_kind=dict(Counter(r['kind'] for r in marked if r['kind']!='success')),
        retry_wait_seconds=sum(r['wait_seconds'] for r in marked),
        usage_unknown_calls=sum(not r.get('response',{}).get('usage') for r in calls))
