# Cicada-Mastertul

## Description 

The tool allows users to authenticate with a target domain using either usernames and passwords or NTLM hashes, and it provides a wide range of enumeration options to gather information about domain users, services, and vulnerabilities. It can also assist with cracking password hashes and extracting sensitive information for further exploitation.

## Modifications from original

- Removed setup function
- Removed cracking function

<br>

- Instead of CrackMapExec use NetExec
- Change some impacket scripts to use NetExec instead
- Log commands

<br>

- `-d` flag can be domain or DC (if you're targeting DC with NetExec use that)
- `-t` is optional if you're using `-d`
- `-q` to not show banner and warning
- `-k` allows using Kerberos flags in the commands
  - `ldapdomaindump` doesn't allow Kerberos auth, used NetExec which looks kinda ugly..
- Somewhat better logging~

<br>

- `get_NPUsers` and `get_UserSPNs` needs to be tested

<br>

> Note: Somewhat unstable~~

## Installation and Setup on Kali

```bash
sudo apt install impacket-scripts
sudo apt install faketime
sudo apt install netexec
```

```bash
pip install ntplib
```

```bash
git clone -q https://github.com/xHacka/Cicada-Mastertul.git /opt
chmod +x /opt/Cicada-Mastertul/cicada-mastertul.py
ln -s /opt/Cicada-Mastertul/cicada-mastertul.py /usr/local/bin/cicada-mastertul
```


## Help Menu

```markdown
usage: cicada-mastertul.py [-h] [-t TARGET] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-H NTLM_HASH]
                           [-us USERSFILE] [--kerberos] [--lookupsid] [--npusers] [--userspn] [--ldap]
                           [--smb] [--full] [--winrm] [--bloodhound] [-q]

Script description

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target host or IP address
  -d DOMAIN, --domain DOMAIN
                        Domain name of the target machine
  -u USERNAME, --username USERNAME
                        Username for authentication
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -H NTLM_HASH, --ntlm-hash NTLM_HASH
                        NTLM Hash for authentication
  -us USERSFILE, --usersfile USERSFILE
                        List of domain users
  --kerberos            Enable kerberoasting mode
  --lookupsid           Enable lookupsid mode
  --npusers             Enable GetNPUsers mode
  --userspn             Enable GetUserSPNs mode
  --ldap                Enable LDAP mode Enumeration
  --smb                 Enable SMB mode Enumeration
  --full                Enable full mode Enumeration
  --winrm               Enable winrm mode Enumeration
  --bloodhound          Enable bloodhound mode Enumeration
  -q, --quiet           Show banner of script
```
