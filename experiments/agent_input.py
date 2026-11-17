"""Business presentation only: recursive object-key ordering, arrays untouched.

This must never replace gredac.crypto.canonical or change signed messages.
All real model clients use this entry for observations, tool results and tools.
Raw provider responses remain unmodified in evidence.
"""
import json
def text(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def object_order(value):return json.loads(text(value))

def messages(values):
    """Normalize JSON business messages, retaining non-JSON prose verbatim."""
    out=object_order(values)
    for message in out:
        if message.get('role') in ('user','tool') and isinstance(message.get('content'),str):
            try:value=json.loads(message['content'])
            except (ValueError,TypeError):continue
            if isinstance(value,(dict,list)):message['content']=text(value)
    return out
