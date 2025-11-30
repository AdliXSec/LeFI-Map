from colorama import Fore, Back, Style, init
init(autoreset=True) 

def banner():
    print(f"""
{Fore.RED}     ⣀⣠⣤⣤⣤⣤⣄⣀⠀⠀⠀⠀⠀
{Fore.RED}⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀  {Fore.RED}██╗     ███████╗███████╗██╗███╗   ███╗ █████╗ ██████╗ 
{Fore.RED}⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢿⣿⣷⡀⠀  {Fore.RED}██║     ██╔════╝██╔════╝██║████╗ ████║██╔══██╗██╔══██╗
{Fore.RED}⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⣴⢿⣿⣧⠀  {Fore.RED}██║     █████╗  █████╗  ██║██╔████╔██║███████║██████╔╝
{Fore.RED}⣿⣿⣿⣿⣿⡿⠛⣩⠍⠀⠀⠀⠐⠉⢠⣿⣿⡇  {Fore.RED}██║     ██╔══╝  ██╔══╝  ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
{Fore.RED}⣿⡿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿  {Fore.RED}███████╗███████╗██║     ██║██║ ╚═╝ ██║██║  ██║██║     
{Fore.RED}⢹⣿⣤⠄⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⡏  {Fore.RED}╚══════╝╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Fore.RED}⠀⠻⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⠟⠀              {Fore.YELLOW + Style.BRIGHT}--- LFI Scanner Tool ---{Style.RESET_ALL}
{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠟⠁              {Fore.YELLOW + Style.BRIGHT}Created by @Adli / @LeexyBoy""")


def info():
    return f"{Fore.BLUE}[*]{Style.RESET_ALL}"

def warning():
    return f"{Fore.YELLOW}[!]{Style.RESET_ALL}"

def danger():
    return f"{Fore.RED}[-]{Style.RESET_ALL}"

def success():
    return f"{Fore.GREEN}[+]{Style.RESET_ALL}"

def vuln():
    return f"{Style.BRIGHT}{Fore.MAGENTA}VULNERABLE!{Style.RESET_ALL}"

def responses():
    return f"{Fore.CYAN}[RESPONSE]{Style.RESET_ALL}"

def truncated():
    return f"{Fore.MAGENTA}[...truncated...]{Style.RESET_ALL}"

def bold(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"