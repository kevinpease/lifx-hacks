#!/usr/bin/env python3
#
# Author: Tim Serong <tim@wirejunkie.com>
# Contributor: Nadezhda Vyasova <nadyamcg@proton.me>, SSL fix, --security flag, AP auto-detect
#
# usage: ./onboard.py <ssid> <password> [--security TYPE]
#
# this will send an onboarding packet to a virgin LIFX bulb, telling it to
# connect to your local WiFi network using the SSID and password provided
# as command line arguments. there is no error checking, so if it breaks
# you get to keep both pieces.
#
# IMPORTANT NOTES:
# - only use this if you're connected to a virgin LIFX bulb's AP.
#   the bulb AP is usually named "LIFX <model> <suffix>" and will assign
#   you an IP in the 172.16.0.x range. this script checks for that before
#   sending, and warns you if it can't see the right subnet.
# - use --security to specify your network's security type (default: wpa2_aes).
# - this script has been tested on: LIFX Original, LIFX Color 1000, LIFX A19.
#   use at your own risk on other models.
# - on Python 3.12+/OpenSSL 3.x you will get an SSL error from the bulb's
#   ancient TLS stack. the fix is ssl.OP_LEGACY_SERVER_CONNECT (already applied
#   below). older advice of setting MinProtocol = TLSv1.0 in
#   /etc/ssl/openssl.cnf does NOT fix this specific error
#   (UNSAFE_LEGACY_RENEGOTIATION_DISABLED).
#
# SECURITY TYPES:
#   open       - no security
#   wep        - WEP PSK (allegedly not supported by bulbs)
#   wpa_tkip   - WPA TKIP PSK
#   wpa_aes    - WPA AES PSK
#   wpa2_aes   - WPA2 AES PSK  (default, most common)
#   wpa2_tkip  - WPA2 TKIP PSK
#   wpa2_mixed - WPA2 mixed PSK
#
# interesting commentary:
# - both LIFX original and LIFX Color 1000 bulbs seem happy to take the
#   onboarding packet ("SetAccessPoint") via an SSL connection to TCP port
#   56700.
# - the LIFX original bulbs can also be onboarded by sending the same packet
#   via UDP broadcast on port 56700. this is presumably wildly insecure,
#   what with not being encrypted and all. the LIFX Color 1000 bulbs seem to
#   ignore SetAccessPoint packets sent via this means.
# - once onboarded, the bulbs don't seem to accept TCP connections to port
#   56700 anymore.
#
import sys, socket, ssl, argparse

SECURITY_TYPES = {
    "open":       0x01,
    "wep":        0x02,
    "wpa_tkip":   0x03,
    "wpa_aes":    0x04,
    "wpa2_aes":   0x05,
    "wpa2_tkip":  0x06,
    "wpa2_mixed": 0x07,
}

LIFX_AP_IP   = "172.16.0.1"
LIFX_AP_PORT = 56700


def detect_lifx_ap():
    """return True if a local interface is in the 172.16.0.x range (LIFX AP subnet)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((LIFX_AP_IP, LIFX_AP_PORT))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip.startswith("172.16.0.")
    except OSError:
        return False


parser = argparse.ArgumentParser(
    description="onboard a virgin LIFX bulb to your WiFi network.")
parser.add_argument("ssid",     help="WiFi SSID to connect the bulb to")
parser.add_argument("password", help="WiFi password")
parser.add_argument(
    "--security",
    choices=list(SECURITY_TYPES.keys()),
    default="wpa2_aes",
    metavar="TYPE",
    help="WiFi security type: " + ", ".join(SECURITY_TYPES.keys()) + " (default: wpa2_aes)",
)
args = parser.parse_args()

ssid   = args.ssid[:32]
passwd = args.password[:64]
sec    = SECURITY_TYPES[args.security]

if not detect_lifx_ap():
    print("WARNING: no interface found in 172.16.0.x! you may not be connected to the LIFX AP.")
    print("         connect to the bulb's WiFi network first, then retry.")
    response = input("send anyway? [y/N] ")
    if not response or response[0] not in ['Y', 'y']:
        sys.exit(1)

print("will attempt to onboard using")
print(f"  ssid:     {ssid}")
print(f"  password: {passwd}")
print(f"  security: {args.security} (0x{sec:02x})")
response = input("continue? [y/N] ")
if not response or response[0] not in ['Y', 'y']:
    sys.exit(1)

onboard_packet  = b'\x86\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x31\x01\x00\x00\x02'
onboard_packet += ssid.ljust(32, '\x00').encode('utf-8')
onboard_packet += passwd.ljust(64, '\x00').encode('utf-8')
onboard_packet += bytes([sec])

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE
ctx.options       |= ssl.OP_LEGACY_SERVER_CONNECT  # required for Python 3.12+ / OpenSSL 3.x
sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((LIFX_AP_IP, LIFX_AP_PORT))
sock.write(onboard_packet)

print("LIFX bulb probably onboarded. if not, then you will have to edit the Python script manually.")
