"""Immutable RDF capability records and Authority-only historical reconstruction."""
import copy
from .crypto import (SCHEME, CODEC, SLOT_BITS, Bundle, anchor_secret, by_slot,
                     cover, ident, require)


class Forest:
    def __init__(self, store):
        self.store = store

    def new_anchor(self, source, context, creation, operation, receiver):
        aid = ident()
        require(not self.store.get('anchors', aid), 'ANCHOR_REUSE')
        record = {'id': aid, 'source': source, 'context': context, 'guard': self.store.get('sources',source).get('endpoint','G'),
                  'scheme': SCHEME, 'codec': CODEC, 'slot_bits': SLOT_BITS,
                  'creation': creation, 'operation': operation, 'receiver': receiver}
        self.store.put('anchors', aid, record)
        return aid

    def cap(self, gid):
        record = self.store.get('caps', gid)
        require(record is not None, 'UNKNOWN_CAP')
        return record

    def create(self, source, context, holder, domain, hard, operation,
               parent=None, creation='initial'):
        domain = sorted(set(domain))
        require(domain, 'EMPTY_DOMAIN')
        gid = ident()
        require(not self.store.get('caps', gid), 'GID_REUSE')
        if parent:
            old = self.cap(parent)
            require(old['source'] == source and old['context'] == context
                    and set(domain) <= set(old['domain']), 'CAP_PARENT_SCOPE')
            aid, key_parent = old['anchor'], {'kind': 'cap', 'id': parent}
        else:
            aid = self.new_anchor(source, context, creation, operation, holder)
            key_parent = {'kind': 'anchor', 'id': aid}
        record = {'gid': gid, 'anchor': aid, 'source': source, 'context': context,
                  'guard': self.store.get('sources',source).get('endpoint','G'), 'holder_right': holder, 'key_parent': key_parent,
                  'domain': domain, 'cover': list(cover(domain)), 'operation': operation}
        if getattr(self,'retain_hard_snapshot',True):record['hard_snapshot']=copy.deepcopy(hard)
        self.store.put('caps', gid, record)
        self.store.event('cap', record)
        return record

    def rebuild(self, gid, memo=None):
        memo = {} if memo is None else memo
        if gid in memo:
            return memo[gid]
        cap = self.cap(gid)
        require(cap['cover'] == list(cover(cap['domain'])), 'CAP_COVER_CHANGED')
        parent = cap['key_parent']
        if parent['kind'] == 'anchor':
            anchor = self.store.get('anchors', cap['anchor'])
            require(anchor and parent['id'] == anchor['id']
                    and anchor['source'] == cap['source']
                    and anchor['context'] == cap['context']
                    and anchor['guard'] == cap['guard']
                    and anchor['scheme'] == SCHEME and anchor['codec'] == CODEC
                    and anchor['slot_bits'] == SLOT_BITS, 'ANCHOR_BINDING')
            master = bytes.fromhex(self.store.get('source_masters', cap['source']))
            root = anchor_secret(master, anchor['id'], cap['source'], cap['context'],cap['guard'])
            result = Bundle.initial(gid, cap['anchor'], root, cap['domain'])
        else:
            require(parent['kind'] == 'cap', 'KEY_PARENT_KIND')
            old = self.cap(parent['id'])
            require(old['anchor'] == cap['anchor'] and old['source'] == cap['source']
                    and old['context'] == cap['context'] and old['guard']==cap['guard'], 'KEY_PARENT_BINDING')
            result = self.rebuild(parent['id'], memo).child(gid, cap['domain'])
        memo[gid] = result
        return result

    def binding(self, gid):
        cap = self.cap(gid)
        return {'anchor': cap['anchor'], 'gid': gid, 'holder_right': cap['holder_right']}
