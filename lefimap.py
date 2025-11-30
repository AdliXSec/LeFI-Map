import time, requests
from utils.args_parser import parse_args
from controller.scanner import run_scan
from controller.identifier import run_identifier
from controller.shell import start_os_shell
from utils.output_handler import setup_output_file
from urllib.parse import urlparse
from utils.encoder import FILTER_MAP
from utils.user_agents import load_agents_from_file
from utils.tor_handler import check_tor_connection, renew_tor_circuit
from utils.generate_payloads import build_wrapper_payload
from utils.banner import banner, info, warning

def main():
    banner()
    print("")
    
    args = parse_args()
    host = urlparse(args.url).netloc
    proxies = None
    
    if args.tor_renew and not args.tor:
        print(f"{warning()} Error: --tor-renew membutuhkan --tor untuk diaktifkan.")
        return
    
    if args.tor:
        proxy_protocol = ''
        if args.tor_type == 'SOCKS5':
            proxy_protocol = 'socks5h'
        elif args.tor_type == 'SOCKS4':
            proxy_protocol = 'socks4h'
        elif args.tor_type == 'HTTP':
            proxy_protocol = 'http'

        if not check_tor_connection(args.tor_host, args.tor_port, proxy_protocol):
            return 
        
        if args.tor_renew:
            if not args.tor_control_password:
                print(f"{warning()} Error: --tor-renew membutuhkan --tor-control-password.")
                return

            print(f"\n{info()} Mode Advance: Meminta sirkuit Tor baru...")
            if renew_tor_circuit(args.tor_control_port, args.tor_control_password):
                check_tor_connection(args.tor_host, args.tor_port)
            else:
                print(f"{warning()} Gagal mendapatkan sirkuit baru, melanjutkan dengan IP yang ada.")

        proxies = {
            'http': f'{proxy_protocol}://{args.tor_host}:{args.tor_port}',
            'https': f'{proxy_protocol}://{args.tor_host}:{args.tor_port}'
        }
    
    if args.identify:
        run_identifier(args.url, args.level)
        return
    
    if args.wrapper:
        if not args.wrapper_args:
            print(f"{warning()} Error: --wrapper membutuhkan --wrapper-args")
            return
        
        single_payload = build_wrapper_payload(args.wrapper, args.wrapper_args)
        
        if not single_payload:
            print(f"{warning()} Argumen salah untuk --wrapper {args.wrapper}")
            return
    
    if args.file and args.wordlist:
        print(f"{warning()} Error: Tidak boleh menggunakan --file dan --wordlist bersamaan.")
        return
    
    filter_names = []
    if args.filter:
        filter_names = [f.strip() for f in args.filter.split(',')]
        for name in filter_names:
            if name not in FILTER_MAP:
                print(f"{warning()} Error: Filter tidak dikenal '{name}'. Pilihan yang ada: {list(FILTER_MAP.keys())}")
                return
            
    print(f"{info()} Target URL : {host}")
    print(f"{info()} Metode : {args.method}")
    print(f"{info()} Verbose Mode : {"OFF" if args.silent else "ON"}")
    print(f"{info()} Benchmark Mode : {"ON" if args.benchmark else "OFF"}")
    print(f"{info()} Level : {args.level}")
    
    if args.level == "HARD":
        print(f"{warning()} Menggunakan level HARD semua pola file akan diuji dan dapat menyebabkan False Positive secara tidak disengaja.")
        
    if args.replace:
        old, new = args.replace.split(',', 1)
        print(f"{info()} Menerapkan replace kustom: '{old}' -> '{new}'")
        
    if args.filter:
        print(f"{info()} Filter : {filter_names}")
    print("")
    
    use_random_agent = False
    custom_agent_list = None

    if args.random_agent == 'USE_DEFAULT_LIST':
        use_random_agent = True
        print(f"{info()} Menggunakan daftar User-Agent default.")
    elif args.random_agent is not None:
        use_random_agent = True
        print(f"{info()} Membaca User-Agent dari file: {args.random_agent}")
        custom_agent_list = load_agents_from_file(args.random_agent)
        if custom_agent_list is None:
            return
    
    if args.output:
        setup_output_file(host, args.output)
        print(f"{info()} Hasil akan disimpan di: output/{args.output}")
        
    time.sleep(2)
    
    if args.os_shell is not None:
        session = requests.Session()
        if args.session:
            if not args.silent:
                print(f"{info()} Menggunakan cookie sesi untuk shell...")
            try:
                cookie_pairs = args.session.split(';')
                for pair in cookie_pairs:
                    if '=' in pair:
                        name, value = pair.strip().split('=', 1)
                        session.cookies.set(name, value)
            except Exception as e:
                print(f"{warning()} Gagal memproses cookie sesi: {e}")
                return
        proxies = None
        
        # if not args.method == "POST" or not args.data:
        #     print(f"{warning()} Warning: menggunakan metode get mungkin tidak maksimal untuk OS Shell.")
            # print(f"{warning()} Error: --os-shell saat ini hanya mendukung metode POST dengan parameter -d.")
            # return

        start_os_shell(
            session=session, 
            url=args.url, 
            method=args.method, 
            post_data_template=args.data, 
            proxies=proxies,
            filter_name=filter_names,
            timeout=args.timeout,
            payloads=args.os_shell,
            random_agent=use_random_agent,
            custom_agent_list=custom_agent_list
        )
        return    
    
    run_scan(
        target_url=args.url, 
        wordlist_path=args.wordlist, 
        timeout=args.timeout,
        method=args.method,
        post_data=args.data,
        benchmark_mode=args.benchmark,
        silent_mode=args.silent,
        level=args.level,
        filter_name=filter_names,
        session_cookie=args.session,
        random_agent=use_random_agent,
        custom_agent_list=custom_agent_list,
        replace_rule=args.replace,
        threads=args.threads,
        limit_params=args.limit,
        success_key=args.success_key,
        failed_key=args.failed_key,
        filename=args.file,
        proxies=proxies,
        capture=args.capture,
        wrapper=[single_payload] if args.wrapper else None,
        dom_scan_enabled=args.dom_scan
    )
    
    print(f"\n{info()} Scanning selesai.")

if __name__ == "__main__":
    main()