"""Small shared measurement adapter for the preregistered 75-pair batch.

No scene decisions or reference answers live here. Expected old-credential
rejections are explicit diagnostics with separate timing. All normal work,
including protocol preparation, is timed; offline judge/audit time is not
included in task completion time. Exceptions are recorded, never repaired.
"""
from collections import Counter
import time
from .scene_harness import Session
from .task_backend import TaskBackend,BusinessToolError,AgentCommunicationError
from .support import write_json
from .evaluation_judge import process_verdict,failure_category


class EvaluatedBackend(TaskBackend):
    def __init__(self,*args,**kwargs):
        self.safety_checks=[]
        super().__init__(*args,**kwargs)

    def after_replacement(self,ctx,side,old):
        """Try a fresh request with the retired credentials after reallocation.

        An old credential must remain unusable even after its unused quota is
        given to the replacement. This diagnostic does not consume new quota.
        It is not a model action, and has no counterpart in the no-system arm.
        """
        from gredac.crypto import Denied
        started=time.monotonic();row=dict(kind='old_credential_after_reallocation',context=ctx,side=side,
            origin='controller_safety_probe',expected='KNOWN_REVOKED',start=started)
        self.safety_checks.append(row)
        try:
            selections={s:min(r['slot'] for r in old.lane['rows'] if r['source']==s)
                        for s in set(self.contexts[ctx])}
            try:self.lab.measure('safety.old_credential',lambda:self.lab.probe_old(old,'old-'+side+'-'+ctx,selections))
            except Denied as exc:
                row.update(observed=exc.code,passed=exc.code=='KNOWN_REVOKED')
            else:row.update(observed='UNEXPECTED_ACCEPT',passed=False)
            assert row['passed'],row
        finally:
            row.update(end=time.monotonic(),seconds=time.monotonic()-started)
            write_json(self.lab.path/'safety_checks.json',self.safety_checks)


class EvaluationSession(Session):
    backend_type=EvaluatedBackend

    def __init__(self,*args,**kwargs):
        self.layer='protocol';self.actions=[]
        super().__init__(*args,**kwargs)
        self.layer='model_action'

    def ask(self,role,offered,observation):
        self.layer='api'
        row=dict(role=role,identity=self.roles[role],tool=offered['function']['name'],
                 start=time.monotonic(),status='started')
        self.actions.append(row)
        try:
            result=super().ask(role,offered,observation)
            row['status']='returned';self.layer='model_action'
            return result
        except Exception as exc:
            if isinstance(exc,AgentCommunicationError):self.layer='protocol'
            row.update(status='failed',error=type(exc).__name__+': '+str(exc));raise
        finally:
            row['end']=time.monotonic();write_json(self.path/'model_actions.json',self.actions)

    def admit(self,*args,**kwargs):
        self.layer='protocol'
        try:result=super().admit(*args,**kwargs)
        except BusinessToolError:
            self.layer='model_action';raise
        self.layer='model_action';return result

    def delegate(self):
        self.layer='protocol';result=super().delegate();self.layer='model_action';return result

    def replace(self,side):
        self.layer='protocol';result=super().replace(side);self.layer='model_action';return result

    def evaluate(self,scene,original_roles,judge,error,returned,evaluate_business=True):
        ended=time.monotonic();calls=self.api.calls[self.first_call:]
        category=failure_category(error,self.layer,calls[-1] if calls else None)
        if not self.enabled and category=='system_protocol_runtime':category='experiment_transport_runtime'
        flow=process_verdict(scene,original_roles,self.events,self.actions,self.admissions,self.artifacts,returned,error)
        judge_error=None;audit_error=None
        business=None
        if evaluate_business:
            try:business=judge(self.facts,self.artifacts,self.events)
            except Exception as exc:
                judge_error=type(exc).__name__+': '+str(exc)
                business=dict(business_pass=False,errors=['independent judge exception'])
        counts=Counter(r['context'] for r in self.admissions)
        expected={'B':sum(counts.values())}
        audit={'protocol_present':self.enabled};protocol_ok=None
        try:
            audit=self.backend.close()
            if self.enabled:
                actual=audit['audit']['spent_by_source']
                assert all(actual.get(k,0)==v for k,v in expected.items()),(actual,expected)
                assert audit['audit']['new_requests']==len(self.admissions)
                assert all(r['passed'] for r in self.backend.safety_checks)
                protocol_ok=True
            else:assert not list(self.path.rglob('*.sqlite'))
        except Exception as exc:
            audit_error=type(exc).__name__+': '+str(exc)
            if self.enabled:protocol_ok=False
        if self.enabled and category=='system_protocol_runtime':protocol_ok=False
        diagnostics=sum(r['seconds'] for r in self.backend.safety_checks)
        gross=sum(s['seconds'] for s in self.backend.spans)
        assert gross+1e-6>=diagnostics
        result=dict(scene=scene,case=self.case,with_system=self.enabled,**flow,
            protocol_protection_scope='B admits/debits caller business-tool requests and delivers authenticated tool responses; model opinions/approvals are ordinary TLS orchestration messages, not separately debited',
            workflow_scope='stage schedule, permission replacement and injected business changes are controller presets; models author business decisions',
            business_evaluated=evaluate_business,business_pass=business['business_pass'] if business is not None else None,business_verdict=business,
            failure=error,failure_origin=category,
            system_unexpected_interruption=category=='system_protocol_runtime',
            independent_judge_error=judge_error,audit_error=audit_error,
            protocol_correct=protocol_ok,protocol_applicability='applicable' if self.enabled else 'not_applicable',
            protocol=audit,expected_spent=expected if self.enabled else None,
            safety_checks=self.backend.safety_checks if self.enabled else None,
            api_calls=len(calls),total_seconds=ended-self.started,api_seconds=sum(c['seconds'] for c in calls),
            direct_protocol_seconds=gross-diagnostics-self.backend.business_seconds if self.enabled else 0,diagnostic_seconds=diagnostics,
            inclusive_protocol_span_seconds=gross,judge_audit_seconds=time.monotonic()-ended,
            protocol_timing_scope='enabled path spans minus business handler and explicit safety probes; includes process setup/TCP; not the paired incremental estimate',
            network_setup_seconds=sum(x['seconds'] for x in self.backend.spans if x['label']=='setup'),
            served_models=sorted({c.get('response',{}).get('model','unavailable') for c in calls}),
            usage={k:sum(c.get('response',{}).get('usage',{}).get(k,0) for c in calls)
                for k in ('prompt_tokens','completion_tokens','total_tokens','prompt_cache_hit_tokens','prompt_cache_miss_tokens')})
        # A model can emit an unacceptable report/calendar and still finish all
        # collaboration stages. Never overwrite flow_complete with quality.
        write_json(self.path/'result.json',result)
        return result
