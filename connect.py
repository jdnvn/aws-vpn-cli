import psutil
if "acvc-openvpn" in (p.name() for p in psutil.process_iter()):
  print("VPN already running!")
  exit(1)

import os
import re
import time
import socket
import pexpect
import secrets
import subprocess
from dotenv import load_dotenv

load_dotenv()

VPN_HOST = os.environ.get('VPN_HOST')
AWS_VPN_PATH = os.environ.get('AWS_VPN_PATH')
OVPN_CONF_PATH = os.environ.get('OVPN_CONF_PATH')
UPDATED_CONF_PATH = 'vpn-config.ovpn'
PORT = 443
PROTO = "udp"

# clean vpn config file if not already
if not os.path.isfile(UPDATED_CONF_PATH):
  with open(OVPN_CONF_PATH, "r") as f:
    config_lines = f.readlines()

  excluded_strings = ['auth-user-pass', 'auth-federate', 'auth-retry interact', 'remote']
  updated_config_lines = [line for line in config_lines if not any(excluded_str in line for excluded_str in excluded_strings)]

  with open(UPDATED_CONF_PATH, 'w') as f:
    f.writelines(updated_config_lines)

# cleanup old run
pexpect.run('rm -f saml_pass.txt')

# create random hostname prefix for the vpn gw
rand = secrets.token_hex(12)

# resolve hostname to IP, as we have to keep persistent IP address
ip = socket.gethostbyname(f"{rand}.{VPN_HOST}")

# start vpn with dummy password to get link and sid
process = pexpect.spawn(f"{AWS_VPN_PATH} --config {UPDATED_CONF_PATH} --verb 3 --proto {PROTO} --remote {ip} {PORT} --auth-user-pass pass.txt")
process.expect(r"AUTH_FAILED,CRV1.+")
ovpn_response = process.after.decode()
process.close()

saml_link = re.search(r"https://.+", ovpn_response).group(0)
vpn_sid = ovpn_response.split(':')[2]

# start temporary server for auth callback
server = pexpect.spawn("go run server.go")
time.sleep(2) # give it time to boot
pexpect.run(f"open {saml_link}")
server.expect("SAMLResponse")
server.close()

saml_response = os.popen('cat saml-response.txt').read()
os.system(f"echo 'N/A\nCRV1::{vpn_sid}::{saml_response}' >> saml_pass.txt")

print("Connecting...")
subprocess.run(["sudo", "bash", "-c", f"""{AWS_VPN_PATH} --config {UPDATED_CONF_PATH} --verb 3 --auth-nocache --inactive 3600 --proto {PROTO} --remote {ip} {PORT} --script-security 2 --route-up '/usr/bin/env rm saml-response.txt' --auth-user-pass saml_pass.txt"""])
