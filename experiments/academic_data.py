"""Controlled research dossier and calculator, not measured system evidence.

The synthetic input is explicitly labelled in every case. The calculator
aggregates the rows the model requests, including mistakes/omissions; it never
selects an answer, drops an outlier, writes a claim or repairs a report.
"""
import random
from collections import defaultdict

MATERIALS=[
('D01','Study scope',
'''This dossier describes a controlled synthetic research exercise about two configurations A and B. It is not a new benchmark of the authorization prototype. Each configuration was observed under light and heavy workload with three independent replicate records. The task is to write a balanced experimental analysis for a collaborating research team and data analysis team. The report must allow a reader to reconstruct its claims from row identifiers. A configuration can have a favorable latency at one load and a poor latency at another; reporting a single winning label would hide that distinction. The decision question is the observed effect, operating cost, and interpretation of the unusual replicate, rather than a production purchase recommendation. The author should separate measurements, explanations consistent with those measurements, and explanations proven by interventions. The team did not randomize storage load and has no causal experiment identifying why a replicate changed. Every final claim needs a declared scope and evidence. Numeric conclusions must use the supplied records without silently treating these numbers as externally collected measurements.'''),
('D02','Experimental units',
'''A row represents one independent process replicate, not one request and not one token. There are three replicates for each configuration and workload. Individual transactions within a run would be correlated and cannot inflate the sample size. The requested results table contains all four groups, and each table row lists its three source row identifiers. Averages are ordinary arithmetic means over the three records; the provided integer values have been chosen so that these means are integers. The workload labels are experimental conditions, not descriptions of user populations. Do not pool light and heavy into one speed claim. There is no experiment measuring a saturation boundary, no repeated day-level deployment study, and no noninferiority margin. All records belong to the same synthetic case. The number in a row identifier is only an index and must not be interpreted as evidence ranking. A second report revision must remain anchored to the same input; replacing the inputs while revising an explanation would invalidate the collaboration record.'''),
('D03','Metric definitions',
'''Latency is represented in milliseconds and lower is better. Throughput is requests per second and higher is better. Cost is a synthetic operating unit per run, not dollars and not provider billing tokens. The deliverable requires arithmetic mean latency, arithmetic mean throughput and arithmetic mean cost in each group. Because the reported effect finding refers specifically to latency, the author should not silently substitute throughput when choosing the structured effect category. The narrative may discuss throughput in addition to the required latency finding. Counts are three unless a source row was omitted, in which case a complete report must reject that partial calculation. No conversion from cost units to money is justified. A lower time does not by itself make a configuration preferable when cost or instability differs. Readers should be able to locate exactly which field and group support a claim. The calculator is transparent: it returns aggregates for the selected row identifiers and reports the included count; it does not decide what a reviewer should conclude.'''),
('D04','Anomaly handling',
'''The collection note marks the last B-heavy record as unusual. The row remains part of the supplied primary data. A temporary device-write increase was noticed around that run, but no controlled intervention identified a cause. The authors must retain the record in the main table, acknowledge that the mean reflects it, and propose investigation without claiming storage causation is proven. Removing a record only because it makes a result less favorable would change the estimand. A sensitivity analysis might be useful in a larger study, but none is requested as a replacement for the all-record table. The current exercise does not supply replication after an intervention, a counterfactual machine, or per-device attribution. It therefore cannot establish a unique root cause. An acceptable anomaly conclusion says that the observation is retained and merits investigation. It should cite the marked row and the surrounding B-heavy records, not merely quote a policy sentence. This distinction is central to the evidence review.'''),
('D05','Cost and tradeoffs',
'''The two configurations use different operating resources. The team wants cost reported alongside performance for both workload levels. A statement that one system is always better cannot be inferred from a single metric. Use the calculator to aggregate cost units and inspect both configurations under both loads. The final cost finding must be derived from the input, even if a previous author used an attractive label. Do not introduce invented energy measurements, prices or token savings. Equal API call counts in a separate experiment would not prove equal operating cost here. The cost conclusion requires source rows, and the table must make the comparison visible. It is acceptable to recommend further work or a conditional choice in prose, but those recommendations are not measured results. The group has not supplied a preference weight converting one millisecond into cost units. A single composite score would therefore introduce an unreported policy. Keep effect and cost findings distinct, then explain their practical tradeoff in the report.'''),
('D06','Review and revision protocol',
'''The research analyst writes a draft, a partner reviewer identifies specific issues, and the analyst revises the same report twice. Each reviewer issue has an identifier and supporting source identifiers. The next revision lists the issue identifiers it addressed. A reviewer can request better explanation, evidence coverage, or narrower scope even if the arithmetic is already correct. Approval does not mean that the reviewer generated the author's answer. The author must choose wording, claims and tables, and is responsible for carrying valid evidence across role handoffs. A replacement analyst receives the existing draft, computed aggregates and review comments. A replacement reviewer checks the revised document using the same original dossier. Changes of roles are independent of changes of scientific conclusions. Both teams eventually approve the same final report version. The history should make a substantive text revision observable; merely increasing a revision number or changing an approval flag does not demonstrate revision work.'''),
('D07','Earlier informal memo',
'''An informal memo from a fictional colleague suggested declaring a stable universal capacity and excluding the unusual run to simplify the presentation. This memo is an opinion to evaluate, not authoritative ground truth. The collaboration must check it against the actual design and retained records. The memo does not supply additional data or an experiment that justifies its claims. A fluent sentence can still be unsupported; the reviewer should ask what observation would distinguish the proposed explanation from alternatives. The author is expected to preserve the useful contextual questions while correcting unsupported claims. The final report need not quote the memo, but it must avoid inheriting its unjustified certainty. Do not add a benchmark or a causality study that is absent from the dossier. The evidence map should reference source rows for numeric findings and policy material for methodological limitations. Keeping the data and interpretation separate is more valuable here than presenting an artificially clean success story.'''),
('D08','Deliverable and reader',
'''Deliver a report of at least 150 English words, a structured four-row results table, and three evidence-linked conclusions covering latency effect, cost and anomaly handling. The narrative should explain the pattern, the practical tradeoff, the unusual measurement and the limits of inference in connected paragraphs. The table is machine checked, while prose quality is only partially covered by the structured evidence and scope fields; do not claim a rule-based checker can judge every sentence. Cite all records used in each cross-group effect or cost comparison. Cite the anomalous row in the anomaly finding. Scope is measured_only unless the experiment actually establishes a general or causal claim, which this dossier does not. Both report revisions must be authored by the model, retain the supplied evidence, and address actual reviewer issue identifiers. The final author and partner approvals refer to revision two. This small exercise tests a constrained collaboration process and should not be described as a general scientific reasoning benchmark.''')]

def facts(seed):
    rng=random.Random(seed);rows=[]
    for variant in ('A','B'):
        for workload in ('light','heavy'):
            for rep in range(3):
                base=(30 if variant=='A' else 20)*(1 if workload=='light' else 2)
                latency=(base+rng.randrange(1,5))*3
                throughput=((300 if variant=='A' else 400)-(40 if workload=='heavy' else 0)+rng.randrange(1,5))*3
                if variant=='B' and workload=='heavy' and rep==2:latency*=8;throughput=180
                rows.append(dict(id=f'{variant}-{workload}-{rep}',group=f'{variant}-{workload}',
                    latency_ms=latency,throughput_rps=throughput,cost_units=(4 if variant=='A' else 10)*3))
    return dict(seed=seed,label='synthetic controlled research dossier; NOT measured prototype results',
        rows=rows,materials=[dict(id=i,title=t,text=x) for i,t,x in MATERIALS],anomaly_id='B-heavy-2')

def aggregate_rows(initial,ids):
    assert len(ids)==len(set(ids)),'duplicate input row'
    groups=defaultdict(list);lookup={r['id']:r for r in initial['rows']}
    for rid in ids:groups[lookup[rid]['group']].append(lookup[rid])
    return [dict(group=g,count=len(rs),row_ids=sorted(r['id'] for r in rs),
        **{'mean_'+key:sum(r[key] for r in rs)//len(rs) for key in ('latency_ms','throughput_rps','cost_units')})
        for g,rs in sorted(groups.items())]

def check_report(initial,report):
    """Local consistency feedback only; never generate a replacement report."""
    issues=[];expected={r['group']:r for r in aggregate_rows(initial,[r['id'] for r in initial['rows']])}
    if len(report['table'])!=4:issues.append('four groups required')
    for row in report['table']:
        # Row-ID ordering carries no numerical meaning; retain multiplicity so
        # duplicated or omitted evidence still fails. No values are repaired.
        normalized={**row,'row_ids':sorted(row['row_ids'])}
        if normalized!=expected.get(row['group']):issues.append('table mismatch in '+row['group'])
    known={r['id'] for r in initial['rows']}|{d['id'] for d in initial['materials']}
    for c in report['conclusions']:
        if not set(c['evidence_ids'])<=known:issues.append('unknown evidence id')
    return dict(violations=issues,checked='table and reference existence only; interpretation is reviewed separately')
