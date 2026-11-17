"""Identical 1024-byte request / 256-byte result, computed at the service."""
import hashlib,json


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def padded(value,size,letter):
    value={**value,'padding':''};value['padding']=letter*(size-len(encoded(value)))
    assert len(encoded(value))==size;return value


def request(index):return padded(dict(kind='query',index=index),1024,'p')


def result(payload):
    # Same schema as the current fixed service handler, target='rq2'.
    return padded(dict(target='rq2',value=hashlib.sha256(encoded(payload)).hexdigest()),256,'x')


def verify(index,value):assert value==result(request(index)),'incorrect actual service result'
