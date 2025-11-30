import os
from datetime import datetime
from utils.banner import info, warning

output_filename = None

def setup_output_file(host, filename):
    global output_filename
    if not filename:
        return

    output_filename = filename
    if not os.path.exists('output'):
        os.makedirs('output')
    
    filepath = os.path.join('output', output_filename)
    
    with open(filepath, 'w') as f:
        f.write(f"--- LFI Scan Results ---\n")
        f.write(host+"\n")
        f.write(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*30 + "\n\n")

def write_to_output(line):
    if not output_filename:
        return
        
    filepath = os.path.join('output', output_filename)
    with open(filepath, 'a') as f:
        f.write(line + "\n")
        
def write_benchmark_report(target, payload, duration):
    report_lines = f"\n{warning()} Benchmark Report [Target : {target}, Payload : {payload}, Waktu : {duration:.2f} detik]"
    
    print(report_lines)
    
    write_to_output(report_lines)
    write_to_output("")