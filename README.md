
# AD-Enumerator

Windows Active Directory enumeration tool for Linux, written in Python. Can be used to quickly enumerate popular services on a Windows Domain Controller.

## Authors

- [@1ncendium](https://github.com/1ncendium)



## Features

- Check for anonymous access to LDAP and SMB
- Enumerate LDAP anonymously & with credentials
- Enumerate SMB shares anonymously & with credentials
- Enumerate SMB users with credentials
- Enumerate DNS


## Description
ad-enumerator.py can enumerate LDAP, DNS or/and SMB depending on which protocol you choose. You can also choose to enumerate all protocols, see for more info the options. For each protocol it will create a output file that will be saved under the adenumerator directory. You can turn on SSL. This comes in handy for protocols like LDAP. Also you can specify a domain which is required for DNS and some of the SMB enumerator options.


## Compatibility

Tested only on Kali Linux with Python 3.10.8. The tool should work on other distro's and Python versions.



## Requirements

- [crackmapexec](https://www.kali.org/tools/crackmapexec/)
- [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- Python3
- Linux distro




## Installation

Install AD-Enumerator

```bash
  git clone https://github.com/1ncendium/AD-Enumerator.git
  cd AD-Enumerator
  pip install -r requirements.txt
```

## Options

```txt
-D    Do use DNS enumeration
-S    Do use SMB enumeration
-L    Do use LDAP enumeration
-A    Use all enumeration options
--SSL Do use SSL
-t    Specify target IP
-u    Specify username
-p    Specify password
-d    Specify domain
```

## Usage

```txt
Enumerate ldap anonymously                         ad-enumerator.py -t 10.10.10.10 -L
Enumerate SMB anonymously                          ad-enumerator.py -t 10.10.10.10 -S
Enumerate DNS anonymously                          ad-enumerator.py -t 10.10.10.10 -D -d <domain>
Enumerate everything anonymously                   ad-enumerator.py -t 10.10.10.10 -A
Enumerate everything using credentials and domain  ad-enumerator.py -t 10.10.10.10 -A -U <username> -p <password> -d <domain>
Using credentials                                  ad-enumerator.py -t 10.10.10.10 -<protocol> -u <username> -p <password>
```

