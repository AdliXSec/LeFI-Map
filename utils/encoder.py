import urllib.parse
import base64

def encode_url(payload):
    return urllib.parse.quote(payload, safe='')

def encode_double_url(payload):
    return urllib.parse.quote(encode_url(payload), safe='')

def encode_base64(payload):
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

def encode_hex(payload):
    return payload.encode('utf-8').hex()

def encode_utf8_bypass(payload):
    encoded = payload.replace("/", "%c0%af")
    encoded = encoded.replace(".", "%c0%ae")
    return encoded

def bypass_traversal_variation(payload):
    encoded = payload.replace("../", "....//")
    return encoded

def nullbyte(payloads, suffix = '%00'):
    if payloads.lower().endswith(suffix.lower()):
        return payloads
    return payloads+suffix

FILTER_MAP = {
    'url': encode_url,
    'doubleurl': encode_double_url,
    'base64': encode_base64,
    'hex': encode_hex,
    'utf8': encode_utf8_bypass,
    'traversal': bypass_traversal_variation,
    'nullbyte': nullbyte
}

def apply_filters(payload, filter_names):
    processed_payload = payload
    for name in filter_names:
        func = FILTER_MAP.get(name)
        if func:
            processed_payload = func(processed_payload)
    return processed_payload

def apply_custom_replace(payload, replace_rule):
    if not replace_rule:
        return payload
    
    try:
        old_str, new_str = replace_rule.split(',', 1)
        return payload.replace(old_str, new_str)
    except ValueError:
        return payload