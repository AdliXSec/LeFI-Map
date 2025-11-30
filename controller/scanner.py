import requests, time, textwrap, base64, binascii, re
from urllib.parse import urlparse, parse_qs, urlencode
import concurrent.futures
import threading
from utils.output_handler import write_to_output, write_benchmark_report
from utils.patterns import NEGATIVE_PATTERNS, POSITIVE_PATTERNS, HARD_POSITIVE_PATTERNS
from utils.encoder import apply_filters, apply_custom_replace
from utils.user_agents import get_random_agent
from utils.generate_payloads import get_payloads
from utils.banner import info, warning, danger, success, responses, truncated, vuln


def is_plausible_base64(s):
    if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', s):
        return False
    
    if len(s) % 4 != 0:
        return False

    if '=' in s[:-2]:
        return False
        
    return True

def is_vulnerable(content, level, success_key, failed_key, wrapper):
    
    if wrapper:
        for match in re.finditer(r'([A-Za-z0-9+/=]{40,})', content):
            potential_b64 = match.group(1)

            if is_plausible_base64(potential_b64):
                try:
                    decoded_content = base64.b64decode(potential_b64, validate=True)
                    if decoded_content:
                        return True
                except (binascii.Error, ValueError):
                    continue
    
        
    if failed_key:
        if failed_key in content:
            return False # Ditemukan pesan error, langsung anggap tidak vuln
    else:
        for pattern in NEGATIVE_PATTERNS:
            if pattern in content:
                return False # Ditemukan pesan error, langsung anggap tidak vuln

    if success_key:
        if success_key in content:
            return True # Ditemukan indikator sukses
    else:
        if level == "EASY":
            for pattern in POSITIVE_PATTERNS:
                if pattern in content:
                    return True # Ditemukan indikator sukses

        if level == "HARD":
            for pattern in HARD_POSITIVE_PATTERNS:
                if pattern in content:
                    return True # Ditemukan indikator sukses

    return False # Tidak ada pola yang cocok

# def read_payloads(wordlist_path):
#     """Membaca payloads dari file wordlist."""
#     try:
#         with open(wordlist_path, 'r') as f:
#             payloads = [line.strip() for line in f.readlines()]
#             print(f"{info()} Berhasil memuat {len(payloads)} payload dari {wordlist_path}")
#             return payloads
#     except FileNotFoundError:
#         print(f"{warning()} Error: File wordlist tidak ditemukan di '{wordlist_path}'")
#         return None

def test_payload(session, target_url, payload, timeout, method, post_data_template, benchmark_mode, silent_mode, level, random_agent, custom_agent_list, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled):
    # if random_agent:
    #     random_agent = get_random_agent()
    #     session.headers.update({'User-Agent': random_agent})
    local_headers = {}
    if random_agent:
        random_agent_string = get_random_agent(custom_list=custom_agent_list)
        local_headers['User-Agent'] = random_agent_string
    
    start_time = 0
    if benchmark_mode:
        start_time = time.time()
    
    try:
        response = None
        if method == "GET":
            final_url = target_url.replace("FUZZ", payload)
            response = session.get(final_url, timeout=timeout, headers=local_headers)
        
        elif method == "POST":
            injected_data_str = post_data_template.replace("FUZZ", payload)
            post_data_dict = dict(item.split('=', 1) for item in injected_data_str.split('&'))
            response = session.post(target_url, data=post_data_dict, timeout=timeout, headers=local_headers)

        if response and is_vulnerable(response.text, level, success_key, failed_key, wrapper):
            
            vulnerable_line_1 = f"{success()} {vuln()} Payload ditemukan: {payload}"
            if method == "GET":
                vulnerable_line_2 = f"    URL: {target_url.replace('FUZZ', payload)}"
            else:
                vulnerable_line_2 = f"    Data: {post_data_template.replace('FUZZ', payload)}"
            vulnerable_line_3 = f"    {warning()} Ditemukan pola file '{payload.replace('../', '')}' dalam respons."
            indented_response = textwrap.indent(response.text.strip(), "    ")
            # Tampilkan di layar
            with print_lock:
                if not silent_mode:
                    print(f"\n{vulnerable_line_1}")
                    print(vulnerable_line_2)
                    print(vulnerable_line_3)
                    if  capture is not None:
                        if capture == "all":
                            vulnerable_line_4 = f"    {responses()}\n{indented_response}\n"
                        else:
                            vulnerable_line_4 = f"    {responses()}\n{indented_response[:capture]}\n{f"    {truncated()}" if len(indented_response) > capture else ""}\n"
                        print(vulnerable_line_4)
                else:
                    print(f"{vulnerable_line_1} \n{vulnerable_line_2}")
                    if  capture is not None:
                        vulnerable_line_4 = f"    {responses()}\n{indented_response[:500]}{truncated()}\n"
                        print(vulnerable_line_4)

                if benchmark_mode:
                    end_time = time.time()
                    duration = end_time - start_time
                    target_host = urlparse(target_url).netloc
                    write_benchmark_report(target_host, payload, duration)
                # Tulis ke file
                if not silent_mode:
                    write_to_output(vulnerable_line_1)
                    write_to_output(vulnerable_line_2)
                    write_to_output(vulnerable_line_3)
                    if  capture is not None:
                        if capture == "all":
                            vulnerable_line_4 = f"    {responses()}\n{indented_response}\n"
                        else:
                            vulnerable_line_4 = f"    {responses()}\n{indented_response[:capture]}\n{f"    {truncated()}" if len(indented_response) > capture else ""}\n"
                        write_to_output(vulnerable_line_4)
                else:
                    write_to_output(f"{vulnerable_line_1} \n{vulnerable_line_2}")
                    if  capture is not None:
                        vulnerable_line_4 = f"    {responses()}\n{indented_response[:500]}{truncated()}\n"
                        write_to_output(vulnerable_line_4)
                write_to_output("") # Pemisah
            return True
        elif response and dom_scan_enabled and payload in response.text:
            vulnerable_line_1 = f"{success()} {vuln()} DOM-based VULN! Payload reflected: {payload}"
            vulnerable_line_2 = f"    {warning()} Input dicerminkan di dalam respons HTML/JS."
            vulnerable_line_3 = f"    {warning()} Ini bisa mengindikasikan DOM LFI atau Reflected XSS."
            if method == "GET":
                vulnerable_line_3 += f"\n    URL: {target_url.replace('FUZZ', payload)}"
            else:
                vulnerable_line_3 += f"\n    Data: {post_data_template.replace('FUZZ', payload)}"
            indented_response = textwrap.indent(response.text.strip(), "    ")
            with print_lock:
                if not silent_mode:
                    print(f"\n{vulnerable_line_1}")
                    print(vulnerable_line_2)
                    print(vulnerable_line_3)
                    if  capture is not None:
                        if capture == "all":
                            vulnerable_line_4 = f"    {responses()}\n{indented_response}\n"
                        else:
                            vulnerable_line_4 = f"    {responses()}\n{indented_response[:capture]}\n{f"    {truncated()}" if len(indented_response) > capture else ""}\n"
                        print(vulnerable_line_4)
                else:
                    print(f"{vulnerable_line_1} \n{vulnerable_line_2}")
                    if  capture is not None:
                        vulnerable_line_4 = f"    {responses()}\n{indented_response[:500]}{truncated()}\n"
                        print(vulnerable_line_4)

                if benchmark_mode:
                    end_time = time.time()
                    duration = end_time - start_time
                    target_host = urlparse(target_url).netloc
                    write_benchmark_report(target_host, payload, duration)
                # Tulis ke file
                if not silent_mode:
                    write_to_output(vulnerable_line_1)
                    write_to_output(vulnerable_line_2)
                    write_to_output(vulnerable_line_3)
                    if  capture is not None:
                        if capture == "all":
                            vulnerable_line_4 = f"    {responses()}\n{indented_response}\n"
                        else:
                            vulnerable_line_4 = f"    {responses()}\n{indented_response[:capture]}\n{f"    {truncated()}" if len(indented_response) > capture else ""}\n"
                        write_to_output(vulnerable_line_4)
                else:
                    write_to_output(f"{vulnerable_line_1} \n{vulnerable_line_2}")
                    if  capture is not None:
                        vulnerable_line_4 = f"    {responses()}\n{indented_response[:500]}{truncated()}\n"
                        write_to_output(vulnerable_line_4)
                write_to_output("") # Pemisah
            return True
            
        # else:
        #     # print(response.text)
        #     print(payload)

    except requests.exceptions.RequestException:
        pass

def execute_tests(session, target_url, payloads, timeout, method, post_data, benchmark_mode, silent_mode, level, filter_name, random_agent, custom_agent_list, replace_rule, threads, limit_params, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled):
    if not silent_mode:
        print(f"\n{info()} Menguji injection point: {target_url if method == 'GET' else post_data}")
        print(f"{info()} Menggunakan {threads} thread...")

    count = 0
    
    if replace_rule:
        replace_payload = [apply_custom_replace(p, replace_rule) for p in payloads]
    else:
        replace_payload = payloads
    
    if filter_name:
        payloads_to_test = [apply_filters(p, filter_name) for p in replace_payload]
    else:
        payloads_to_test = replace_payload
    
    limit_requests, sleep_duration = limit_params if limit_params else (None, None)
    if limit_requests and not silent_mode:
        print(f"{info()} Rate limit aktif: jeda {sleep_duration} detik setiap {limit_requests} request.")
    
    request_counter = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for i in range(0, len(payloads_to_test), limit_requests if limit_requests else len(payloads_to_test) or 1):
            
            batch = payloads_to_test[i:i+(limit_requests if limit_requests else len(payloads_to_test) or 1)]
            if not batch:
                continue
            
            futures = {executor.submit(
                test_payload, 
                session, target_url, payload, timeout, method, post_data, benchmark_mode, silent_mode, level, random_agent, custom_agent_list, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled
            ) for payload in batch}
            #     
                
            #     if limit_requests and (request_counter % limit_requests == 0) and (request_counter < len(payloads_to_test)):
            #         time.sleep(sleep_duration)

            for future in concurrent.futures.as_completed(futures):
                try:
                    if future.result():
                        count += 1
                except Exception as e:
                    if not silent_mode:
                        print(f"{warning()} Sebuah thread menghasilkan error: {e}")    
    
            is_last_batch = (i + (limit_requests if limit_requests else len(payloads_to_test)) >= len(payloads_to_test))
            if limit_requests and not is_last_batch:
                time.sleep(sleep_duration)
    
    # for payload in payloads_to_test:
    #     # print(replace_payload)
    #     vuln = test_payload(session, target_url, payload, timeout, method, post_data, benchmark_mode, silent_mode, level, random_agent)
    #     if vuln:
    #         count = count + 1
            
    if count == 0:
        print(f"\n{danger()} Not Vulnerable")

def run_scan(target_url, wordlist_path, timeout, method, post_data, benchmark_mode, silent_mode, level, filter_name, session_cookie, random_agent, custom_agent_list, replace_rule, threads, limit_params, success_key, failed_key, filename, proxies, capture, wrapper, dom_scan_enabled):
    if wrapper:
        payloads = wrapper
        # print(payloads)
    elif filename:
        payloads = get_payloads(filename, 'file')
        # print(payloads)
    else:
        if wordlist_path:
            payloads = get_payloads(wordlist_path, 'path')
            if not payloads:
                return
        else:
            if level == "EASY":
                payloads = get_payloads('payloads/easy.txt', 'path')
            else:
                payloads = get_payloads('payloads/hard.txt', 'path')

    # print(payloads)
    print_lock = threading.Lock()
    session = requests.Session()
    
    if proxies:
        session.proxies.update(proxies)
        if not silent_mode:
            print(f"{info()} Semua request akan dialihkan melalui proxy Tor.")
    
    # if random_agent:
    #     agent = get_random_agent()
    #     session.headers.update({'User-Agent': agent})
    
    if session_cookie:
        if not silent_mode:
            print(f"{info()} Menggunakan cookie sesi...")
        try:
            cookie_pairs = session_cookie.split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    name, value = pair.strip().split('=', 1)
                    session.cookies.set(name, value)
        except Exception as e:
            print(f"{warning()} Format cookie salah atau gagal diproses: {e}")
            return

    fuzz_in_url = "FUZZ" in target_url
    fuzz_in_data = post_data and "FUZZ" in post_data

    if fuzz_in_url or fuzz_in_data:
        template = target_url if method == "GET" else post_data
        num_fuzz = template.count("FUZZ")

        if not silent_mode:
            print(f"{info()} Mode manual: Ditemukan {num_fuzz} keyword 'FUZZ' pada metode {method}.")

        if num_fuzz > 1:
            parts = template.split("FUZZ")
            for i in range(num_fuzz):
                pre_fuzz = "FUZZ".join(parts[:i + 1])
                post_fuzz = "FUZZ".join(parts[i + 1:])
                safe_post_fuzz = post_fuzz.replace("FUZZ", "test")
                
                final_template = pre_fuzz + safe_post_fuzz
                
                if method == "GET":
                    fuzz_url = final_template
                    fuzz_data = None
                else:  # POST
                    fuzz_url = target_url
                    fuzz_data = final_template

                execute_tests(session, fuzz_url, payloads, timeout, method, fuzz_data, benchmark_mode, silent_mode, level, filter_name, random_agent, custom_agent_list, replace_rule, threads, limit_params, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled)
        
        else:
            execute_tests(session, target_url, payloads, timeout, method, post_data, benchmark_mode, silent_mode, level, filter_name, random_agent, custom_agent_list, replace_rule, threads, limit_params, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled)

    else:
        if not silent_mode:
            print(f"{info()} Mode auto-discovery: 'FUZZ' tidak ditemukan. Mencari parameter...")
        
        if method == "GET":
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            if not query_params:
                if not silent_mode:
                    print(f"{warning()} Tidak ada parameter ditemukan di URL untuk diuji.")
                return

            for param in query_params:
                temp_params = query_params.copy()
                temp_params[param] = ["FUZZ"]
                new_query_string = urlencode(temp_params, doseq=True)
                fuzz_url = parsed_url._replace(query=new_query_string).geturl()
                execute_tests(session, fuzz_url, payloads, timeout, "GET", None, benchmark_mode, silent_mode, level, filter_name, random_agent, custom_agent_list, replace_rule, threads, limit_params, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled)
        
        elif method == "POST":
            post_params = parse_qs(post_data)

            if not post_params:
                if not silent_mode:
                    print(f"{warning()} Tidak ada parameter ditemukan di data POST untuk diuji.")
                return
            
            for param in post_params:
                temp_params = post_params.copy()
                temp_params[param] = ["FUZZ"]
                fuzz_data = urlencode(temp_params, doseq=True)
                execute_tests(session, target_url, payloads, timeout, "POST", fuzz_data, benchmark_mode, silent_mode, level, filter_name, random_agent, custom_agent_list, replace_rule, threads, limit_params, print_lock, success_key, failed_key, capture, wrapper, dom_scan_enabled)