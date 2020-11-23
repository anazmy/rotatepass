#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 Ahmed Nazmy.
# This file is part of passrotate
# (see https://github.com/anazmy/rotatepass).

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

# Meta
__license__ = "AGPLv3"
__author__ = 'Ahmed Nazmy'
__version__ = '2.0'

import crypt
import random
import string
import sys
import os
import gettext
import math
import argparse
import re
import subprocess
import shlex
from multiprocessing.pool import ThreadPool
from multiprocessing import TimeoutError
import time
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import AlreadyFinalized, UnsupportedAlgorithm, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import uuid


#####Configurable vars#####

# Length of password, 24 or higher recommended.
pass_length = 24

# How many hosts will be processed in parallel
# If the count of hosts are less than forks the hosts count will be used.
forks = 30

# Full path of file to save servers and passwords in
# content format is: server.example.com   password
# data is AES encrypted
hosts_file = "host_pass.enc"

# The user targted for password reset
user = "root"

# User to be used for ssh, should have sudo access to reset passwords, valid values are,
# - "None", no sudo user, ssh as root to target hosts.
# - <username>, use provided username to ssh to target hosts, user should have sudo privs
sudo_user = "passadmin"

# Boolean, whether sudo needs a passwod or not, valid values are True or False.
# Value "True" is valid only when sudo_user is set to something else other than None
# Note: avoid using a sudo password that contains ":" for the script to work properly
sudo_need_password = True

# In case a custom ssh port is used
ssh_port = "22"

# Timeout for ssh connection
ssh_timeout = 3

# Timeout for password reset execution, should be higher than ssh_timeout
fork_timeout = 10
############################


def create_contet():
    content = {'currnet_pass': "",
               'new_pass': "", 'out': "", 'err': "", 'errcode': ""}
    return content


parser = argparse.ArgumentParser(
    description="This script mass generates and resets a user password on hostnames specified, and saves them to a file.")
parser.add_argument(
    "-f",
    "--forks",
    action="store",
    dest='forks',
    default=forks,
    help="Number of parallel runs, the higher the value, the faster the passwords reset. Keep an eye on load.",
    required=False)
parser.add_argument(
    "-p",
    "--plain",
    action="store_true",
    dest='plain',
    default=False,
    required=False,
    help="Save the hosts' file in plaintext.\nWARNING: Secure handling of the file is the user's responsibility")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "-u",
    "--updateall",
    action='store_true',
    dest="updateall",
    default=False,
    required=False,
    help="This will reset passwords on all servers")
group.add_argument(
    "-t",
    "--target",
    action='store',
    dest="host",
    default=None,
    required=False,
    help="Reset password on the target host and update the servers' file.")
group.add_argument(
    "-d",
    "--decrypt",
    action='store_true',
    dest="decrypt",
    required=False,
    help="Decrypt hosts' file and print it to stdout")
group.add_argument(
    "-i",
    "--init",
    action='store',
    dest="init_list",
    default=None,
    required=False,
    help="Initial hosts' file, expects path to a plaintext file with one IP/FQDN per line.\nWARNING: existing hosts file will be overwritten")

group.add_argument(
    "-l",
    "--list",
    action='store',
    dest="list",
    default=None,
    required=False,
    help="List of hosts to process, expects path to a plaintext file with one IP/FQDN per line.\
         New entries will be added to existing hosts file.")


def main(argv):
    args = parser.parse_args()
    updateall = args.updateall
    decrypt = args.decrypt
    host = args.host  # pylint: disable=unused-variable
    plain = args.plain  # pylint: disable=unused-variable
    forks = args.forks
    init_list = args.init_list
    file_list = args.list

    if not plain:
        file_password = getpass.getpass(
            "Enter password of encrypted hosts file: ")

        if (len(file_password) < 3):
            sys.stderr.write('\033[31m' + 'Password to encrypt/decrypt hosts file is too short. Password should be 8 or more chars' +
                             "\n" + '\033[0m')
            exit(1)

    if (sudo_need_password and not decrypt and sudo_user != None):
        try:
            sudo_password = getpass.getpass(  # pylint: disable=unused-variable
                "Enter remote user sudo password: ")
        except Exception as e:
            sys.stderr.write('\033[31m' + 'Error getting sudo password: ' + str(e) +
                             "\n" + '\033[0m')
            exit(1)
        helper_script = create_helper_script(sudo_password)

    else:
        sudo_password = None
        helper_script = None

    if init_list:

        if os.path.exists(hosts_file):
            overwrite = raw_input(  # pylint: disable=undefined-variable
                'Hosts file %s already exists, do you want to overwrite? (y/n): ' % hosts_file)
            if overwrite in ['yes', 'Yes', 'y', 'Y']:
                os.remove(hosts_file)
            else:
                exit(0)

        init_hosts_dict = load_hosts(init_list)
        serversdict = threader(
            init_hosts_dict, fork_timeout, forks, sudo_password, helper_script)
        if os.path.exists(helper_script):
            os.remove(helper_script)

        if not plain:
            encrypt_file(serversdict, file_password)
        else:
            save_dict2file(serversdict)
            sys.stdout.write('\033[33m' + "Ensure secure handling of " + hosts_file +
                             "!!\n" + '\033[0m')

    elif updateall:
        if os.path.exists(hosts_file):
            if not plain:
                serversdict = decrypt_file(
                    hosts_file, file_password, print_stdout=False)
            else:
                serversdict = read_plain_dictfile(hosts_file)
        else:
            sys.stderr.write('\033[31m' + "Encrypted file " + hosts_file +
                             " doesn't exist" + '\033[0m')
            exit(1)

        threader(serversdict, fork_timeout, forks,
                 sudo_password, helper_script)
        if os.path.exists(helper_script):
            os.remove(helper_script)
        if not plain:
            encrypt_file(serversdict, file_password)
        else:
            save_dict2file(serversdict)

    elif file_list:
        if os.path.exists(hosts_file):
            if not plain:
                serversdict = decrypt_file(
                    hosts_file, file_password, print_stdout=False)
            else:
                serversdict = read_plain_dictfile(hosts_file)
        else:
            sys.stderr.write('\033[31m' + "Encrypted file " + hosts_file +
                             " doesn't exist" + '\033[0m')
            exit(1)

        hosts_to_update = load_hosts(file_list)
        updated_hosts = threader(
            hosts_to_update, fork_timeout, forks, sudo_password, helper_script)
        if os.path.exists(helper_script):
            os.remove(helper_script)
        for host in updated_hosts:
            # Do not add new entries with empty passwords
            if updated_hosts[host]['currnet_pass'] != '':
                serversdict[host] = updated_hosts[host]

        if not plain:
            encrypt_file(serversdict, file_password)
        else:
            save_dict2file(serversdict)

    elif host:
        if os.path.exists(hosts_file):
            if not plain:
                serversdict = decrypt_file(
                    hosts_file, file_password, False)
            else:
                serversdict = read_plain_dictfile(hosts_file)
        else:
            sys.stderr.write('\033[31m' + "Encrypted file " + hosts_file +
                             " doesn't exist" + '\033[0m')
            exit(1)

        singlehost = {}
        singlehost[host] = create_contet()
        singlehost[host]['host'] = host
        updated_host = threader(singlehost, fork_timeout,
                                forks, sudo_password, helper_script)

        if os.path.exists(helper_script):
            os.remove(helper_script)

        for host in updated_host:
            # Do not add new entries with empty passwords
            if updated_host[host]['currnet_pass'] != '':
                serversdict[host] = updated_host[host]

        if not plain:
            encrypt_file(serversdict, file_password)
        else:
            save_dict2file(serversdict)

    elif decrypt:
        decrypt_file(hosts_file, file_password, print_stdout=True)


def threader(serversdict, fork_timeout, forks, sudo_password, helper_script):

    #  Use the smaller count between number of servers, and number of forks.
    pool = ThreadPool(processes=min(len(serversdict), forks))
    async_results = {}
    for host, _ in serversdict.items():
        async_results[host] = {
            'update': pool.apply_async(set_pass, (host,  sudo_password, helper_script)), 'timelimit': time.time() + fork_timeout}

    # done with forks
    pool.close()

    # wait for forks and get results
    while async_results:
        for host in async_results:
            res = async_results[host]['update']
            if res.ready():
                if res.successful():
                    output = res.get()
                    if output['errcode'] == 0:
                        serversdict[host]['out'] = output['out']
                        serversdict[host]['err'] = output['err']
                        serversdict[host]['errcode'] = output['errcode']
                        serversdict[host]['new_pass'] = output['new_pass']
                        serversdict[host]['currnet_pass'] = output['new_pass']
                        serversdict[host]['success'] = True
                        sys.stdout.write("Successfuly reset %s's password on %s\n" %
                                         (user, host))
                    else:
                        serversdict[host]['out'] = output['out']
                        serversdict[host]['err'] = output['err']
                        serversdict[host]['errcode'] = output['errcode']
                        serversdict[host]['success'] = False
                        sys.stderr.write("Error while resetting password on server %s, errcode: %s, errmsg: %s\n" % (
                            host, output['errcode'], str(output['err']).strip()))
                else:
                    sys.stderr.write("Generic error while resetting password on server %s\n" % (
                        host))
                    # Errored so leave current_password as is
                    serversdict[host]['success'] = False
                    serversdict[host]['err'] = "Generic error while changing password"
                del async_results[host]
                break
            elif time.time() > async_results[host]['timelimit']:
                sys.stderr.write(
                    "Timeout error while resetting password on %s !!\n" % host)
                serversdict[host]['success'] = False
                serversdict[host]['err'] = "timeout error while changing password"
                del async_results[host]
                break
        else:
            # avoid cpu churn
            time.sleep(0.1)

    failedservers = {}
    for host in serversdict:
        if serversdict[host]['success'] == False:
            failedservers[host] = serversdict[host]

    if len(failedservers) > 0:
        sys.stderr.write(
            '\033[33m' + '=== List of failed servers ====' + "\n" + '\033[0m')
        for host in serversdict:
            if serversdict[host]['success'] == False:
                sys.stderr.write(
                    '\033[31m' + host + ", err: " + str(failedservers[host]['err']).strip() + "\n" + '\033[0m')

        sys.stderr.write(
            '\033[33m' + '=== End of failed servers ====' + "\n" + '\033[0m')

    else:
        sys.stdout.write(
            '\033[32m' + 'All passwords changed successfully' + "\n" + '\033[0m')
    return serversdict


def load_hosts(hosts_file):
    hostsdict = {}
    try:
        with open(hosts_file) as afile:
            for line in afile:
                hostname = line.strip()
                hostsdict[hostname] = create_contet()
                hostsdict[hostname]['host'] = hostname
    except IOError:
        sys.stderr.write("Error opennig file %s" % hosts_file)
        exit(1)

    return hostsdict


def read_plain_dictfile(filename):
    serversdict = {}
    try:
        with open(filename) as afile:
            for line in afile:
                try:
                    hostname, current_pass = line.split()
                    serversdict[hostname] = create_contet()
                    serversdict[hostname]['host'] = hostname
                    serversdict[hostname]['currnet_pass'] = current_pass
                except ValueError as e:
                    sys.stderr.write(
                        '\033[31m' + "Error parsing file, " + repr(e) + "\n" + '\033[0m')
    except IOError:
        sys.stderr.write('\033[31m' + "Error opennig file %s" %
                         hosts_file + "\n" + '\033[0m')
        exit(1)
    return serversdict


def save_dict2file(dict):
    try:
        file_content = "\n".join("%s   %s" % (key, val['currnet_pass'])
                                 for (key, val) in sorted(dict.iteritems()))
    except KeyError as e:
        sys.stderr.write(
            '\033[31m' + "Error parsing hosts dict, " + repr(e) + "\n" + '\033[0m')
        exit(1)

    try:
        with open(hosts_file, 'wb') as output_file:
            output_file.write(file_content)

        os.chmod(hosts_file, 0o600)

    except Exception as e:
        sys.stderr.write('\033[31m' + 'Error writing hosts file : %s' +
                         "\n" + '\033[0m' % str(e))
        exit(1)


def encrypt_file(dict, password):

    # Convert dict to a multiline string
    # with format of: server.example.com   password
    try:

        plain_text = "\n".join("%s   %s" % (key, val['currnet_pass'])
                               for (key, val) in sorted(dict.iteritems()))
    except KeyError as e:
        sys.stderr.write(
            '\033[31m' + "Error parsing hosts dict, " + repr(e) + "\n" + '\033[0m')
        exit(1)
    try:
        password_bytes = password.encode('utf-8')
        plain_text_bytes = plain_text.encode('utf-8')
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(salt=salt, length=32, iterations=100000,
                         algorithm=hashes.SHA512, backend=default_backend())
        key = kdf.derive(password_bytes)
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce),
                           backend=default_backend()).encryptor()

        ciphertext = encryptor.update(plain_text_bytes) + encryptor.finalize()
        token = salt + nonce + encryptor.tag + ciphertext

        # Write to file
        with open(hosts_file, 'wb') as output_file:
            output_file.write(token)

    except (UnsupportedAlgorithm, AlreadyFinalized, InvalidTag):
        sys.stderr.write('\033[31m' + "File encryption failed" + '\033[0m')


def decrypt_file(filename, password, print_stdout):
    password_bytes = password.encode('utf-8')
    with open(filename, 'rb') as f:
        cipher_text = f.read()

        salt = cipher_text[:16]
        nonce = cipher_text[16:28]
        tag = cipher_text[28:44]
        ciphertext = cipher_text[44:]

        kdf = PBKDF2HMAC(salt=salt, length=32, iterations=100000,
                         algorithm=hashes.SHA512, backend=default_backend())
        key = kdf.derive(password_bytes)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()).decryptor()

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except (UnsupportedAlgorithm, AlreadyFinalized, InvalidTag):
            sys.stderr.write(
                '\033[31m' + "File decryption failed, verify the password is correct\n" + '\033[0m')
            exit(1)

        if print_stdout:
            for line in plaintext.splitlines():
                sys.stdout.write(line+"\n")
            exit(0)
        else:
            serversdict = {}

            for line in plaintext.splitlines():
                try:
                    hostname, current_pass = line.split()
                    serversdict[hostname] = create_contet()
                    serversdict[hostname]['host'] = hostname
                    serversdict[hostname]['currnet_pass'] = current_pass
                except ValueError as e:
                    sys.stderr.write(
                        '\033[31m' + "Error parsing decrypted file, " + repr(e) + "\n" + '\033[0m')
            return serversdict


def copy_file(user, host, filename):
    my_env = os.environ.copy()
    cmd = """/usr/bin/scp -P %s %s %s@%s:~/%s """ % (ssh_port, filename,
                                                     user, host, filename)
    out, err, errcode = run_cmd(cmd, my_env)
    return out, err, errcode


def create_helper_script(sudo_passwd):
    randombits = str(uuid.uuid4())
    filename = randombits + "-helper.sh"
    try:
        helper_file = open(filename, "w")
        helper_file.write("#!/bin/bash\n")
        helper_file.write("echo %s\n" % sudo_passwd)
        # Self destruct
        helper_file.write('rm -- "$0"')
        helper_file.close()
    except Exception as e:
        sys.stderr.write('\033[31m' + 'Error writing helper script : %s' +
                         "\n" + '\033[0m' % str(e))

    try:
        os.chmod(filename, 0o700)
    except Exception as e:
        sys.stderr.write('\033[31m' + 'Error chmod helper script : %s' +
                         "\n" + '\033[0m' % str(e))

    return filename


def set_pass(host, sudo_password, helper_script=None):
    """
    This is the threaded function that runs against every host
    """
    new_password = generate_password(min_len=pass_length)
    pass_hash = hash_password(new_password)
    # Piggybacking on LC_NAME var to deliver the password
    # so it's not visible on command line
    my_env = os.environ.copy()
    my_env["LC_NAME"] = user + ":" + pass_hash
    # sudo user without pass
    if (sudo_user != None and not sudo_need_password):
        cmd = """/usr/bin/ssh -o SendEnv=LC_NAME -o BatchMode=yes -o ConnectTimeout=%s -p %s %s@%s \
        'echo $LC_NAME|sudo -A  timeout %s chpasswd -e' """ % (ssh_timeout,
                                                               ssh_port, sudo_user, host, fork_timeout)
    # sudo user with pass
    elif (sudo_user != None and sudo_need_password):
        # FIXME: there might other homedirs other than /home to consider
        helper_script_path = "/home/" + sudo_user + "/" + helper_script
        # We have copy file + cmd run here, which require increasing the timeout to handle both
        copy_file(sudo_user, host, helper_script)
        cmd = """/usr/bin/ssh -o SendEnv=LC_NAME -o BatchMode=yes -o ConnectTimeout=%s -p %s %s@%s \
        'export SUDO_ASKPASS=%s ;echo $LC_NAME|sudo -A timeout %s chpasswd -e' """ % (ssh_timeout,
                                                                                      ssh_port, sudo_user, host, helper_script_path, fork_timeout)

    # root access
    else:
        cmd = """/usr/bin/ssh -o SendEnv=LC_NAME -o BatchMode=yes -o ConnectTimeout=%s -p %s root@%s \
        'echo $LC_NAME|timeout %s chpasswd -e' """ % (ssh_timeout,
                                                      ssh_port, host, fork_timeout)
    out, err, errcode = run_cmd(cmd, my_env)
    output = {'host': host, 'new_pass': new_password, 'out': out, 'err': err,
              'errcode': errcode}
    return output


def run_cmd(cmd, my_env):
    try:
        args = shlex.split(cmd)
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
        out, err = process.communicate()
        errcode = process.returncode
    except Exception as e:
        sys.stderr.write('\033[31m' + 'Error running command : %s' +
                         "\n" + '\033[0m' % str(e))

    return out, err, errcode


def generate_password(entropy_bits=128, uppercase=1, lowercase=1, digits=1,
                      special=None, min_len=24):
    """
    Copied from freeipa code.

    Values specify minimal number of characters from given
    character class.
    Value None prevents given character from appearing in the password.
    """

    special_chars = '!$%&()*+,-./:;<>?@[]^_{|}~'
    pwd_charsets = {
        'uppercase': {
            'chars': string.ascii_uppercase,
            'entropy': math.log(len(string.ascii_uppercase), 2)
        },
        'lowercase': {
            'chars': string.ascii_lowercase,
            'entropy': math.log(len(string.ascii_lowercase), 2)
        },
        'digits': {
            'chars': string.digits,
            'entropy': math.log(len(string.digits), 2)
        },
        'special': {
            'chars': special_chars,
            'entropy': math.log(len(special_chars), 2)
        },
    }
    req_classes = dict(
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        special=special
    )
    # 'all' class is used when adding entropy to too-short tokens
    # it contains characters from all allowed classes
    pwd_charsets['all'] = {
        'chars': ''.join([
            charclass['chars'] for charclass_name, charclass
            in pwd_charsets.items()
            if req_classes[charclass_name] is not None
        ])
    }
    pwd_charsets['all']['entropy'] = math.log(
        len(pwd_charsets['all']['chars']), 2)
    rnd = random.SystemRandom()

    todo_entropy = entropy_bits
    password = u''
    # Generate required character classes:
    # The order of generated characters is fixed to comply with check in
    # NSS function sftk_newPinCheck() in nss/lib/softoken/fipstokn.c.
    for charclass_name in ['digits', 'uppercase', 'lowercase', 'special']:
        charclass = pwd_charsets[charclass_name]
        todo_characters = req_classes[charclass_name]
        if todo_characters is None:
            continue
        while todo_characters > 0:
            password += rnd.choice(charclass['chars'])
            todo_entropy -= charclass['entropy']
            todo_characters -= 1

    # required character classes do not provide sufficient entropy
    # or does not fulfill minimal length constraint
    allchars = pwd_charsets['all']
    while todo_entropy > 0 or len(password) < min_len:
        password += rnd.choice(allchars['chars'])
        todo_entropy -= allchars['entropy']

    return password


def _crypt_salt(length=16):
    random.seed()
    salt_chars = string.ascii_letters + string.digits + './'
    # $6$: SHA-512
    return '$6$' + ''.join(
        (random.choice(salt_chars) for _ in range(length)))


def hash_password(password):
    hashed_password = crypt.crypt(password, _crypt_salt())
    return hashed_password


if __name__ == "__main__":
    main(sys.argv)
