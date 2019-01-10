#!/usr/bin/python
import re
import os
import uuid
import subprocess
import shlex

ldif = """dn: {dn}
changetype: modify
replace: ms-Mcs-AdmPwdExpirationTime
ms-Mcs-AdmPwdExpirationTime: {expire}
-
replace: ms-Mcs-AdmPwd
ms-Mcs-AdmPwd: {new_pass}"""

def set_admin_password(krb5_cache, dn, new_pass, expire):
    server = dig_ad_listings()
    cmd = ['ldapadd', '-h', server[0]]
    with open(os.devnull, 'w') as devnull:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=devnull, stderr=devnull, env={'KRB5CCNAME': krb5_cache})
        proc.communicate(ldif.format(dn=dn, new_pass=new_pass, expire=expire))
    os.remove(krb5_cache)
    return bool(proc.returncode == 0)

def get_admin_password(dn):
    server = dig_ad_listings()
    cmd = ['ldapsearch', '-h', server[0], '-b', dn, 'ms-Mcs-AdmPwd']
    with open(os.devnull, 'w') as devnull:
        proc = subprocess.Popen(cmd)
        out,error=proc.communicate()
    if error is not None:
        print error

def get_computer_credentials():
    cmd = ['security', 'find-generic-password', '-s', '/Active Directory/AD', '-g', '/Library/Keychains/System.keychain'] 
    cmd2 = ['security', 'find-generic-password', '-s', '/Active Directory/AD', '-w', '/Library/Keychains/System.keychain']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    password = proc2.communicate()
    metadata = proc.communicate()
    acct=re.search(r'^\s+"acct"\<blob\>="(.*)"$', metadata[0], re.MULTILINE).group(1)
    if not metadata or not password:
        return False
    return (acct, password[0])

def gen_krb5_cache(creds):
    cred_cache = '/tmp/cred_cache_{}'.format(uuid.uuid4())
    cmd2 = ['kinit', '-c', cred_cache, '--password-file=/dev/stdin', creds[0]]
    cmd1 = ['echo', creds[1]]
    proc1=subprocess.Popen(cmd1,stdout=subprocess.PIPE)
    proc2=subprocess.Popen(cmd2, stdin=proc1.stdout, stdout=subprocess.PIPE)
    proc1.stdout.close()
    out,error=proc2.communicate()
    if error is None:
        return cred_cache
    return None

def do_kinit(user,out):
    cmd2 = ['kinit', '--password-file=/dev/stdin', user + '@AD.CORP.APPNEXUS.COM']
    cmd1 = ['echo', out]
    proc1=subprocess.Popen(cmd1,stdout=subprocess.PIPE)
    proc2=subprocess.Popen(cmd2, stdin=proc1.stdout, stdout=subprocess.PIPE)
    proc1.stdout.close()
    out,error=proc2.communicate()
    if error is None:
      return True
    return False

def dig_ad_listings():
    cmd="dig SRV _ldap._tcp.ad.corp.foobar.com +short"
    cmd2="awk '{print $4}'"
    proc1=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
    proc2=subprocess.Popen(shlex.split(cmd2), stdin=proc1.stdout, stdout=subprocess.PIPE)
    proc1.stdout.close()
    out,err=proc2.communicate()
    server=filter(None,out.split('\n'))
    return server

def get_computer_dn(krb5_cache, computer_name):
    server=dig_ad_listings()
    if len(server) > 0:
        cmd = ['ldapsearch', '-Q', '-o', 'ldif-wrap=no', '-h', server[0], '-b', 'dc=ad,dc=corp,dc=foobar,dc=com', '(samaccountname={})'.format(computer_name), 'dn']
        output = subprocess.check_output(cmd, env={'KRB5CCNAME': krb5_cache})
        return re.search(r'^dn:\s(.*)$', output, re.MULTILINE).group(1)

