#!/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import base64

#Globals
incident = 1 # keeps track of how many "incidents" have happened
ftp_users = []
ftp_passes = []

# This function decodes a string encoded using base64 encoding
# Returns: decoded string
def decode64(passwd):
    base64_bytes = passwd.encode('ascii')
    passwd_bytes = base64.b64decode(base64_bytes)
    human_readable = passwd_bytes.decode('ascii')
    return human_readable

# Finds user and pass combo sent via imap
# Returns: username:password string
def imap_passwdfind(payload):
    words = payload.split(" ")
    for w, word in enumerate(words):
        if word == "LOGIN":
            username = words[w + 1]
            password = words[w + 2]
            password = password.replace("\\r\\n", '')
            password = password.replace("\"", '')
            password = password.strip('\'')
            user_passwd = username + ":" + password
            return user_passwd

# Function finds the USER and PASS sent via FTP and 
# stores them in separate global stacks
def ftp_passwdfind(payload, user_or_pass):
    words = payload.split(" ")
    for w, word in enumerate(words):
        found = word.find(user_or_pass)
        # .find() returns -1 if the string is NOT a substring of payload
        if found != -1:
            if user_or_pass == "USER":
                user = words[w + 1]
                # Cleaning string 
                user = user.replace('\\r\\n', '')
                user = user.replace('\'', '')
                user = user.replace('\"', '')
                global ftp_users
                ftp_users.append(user)
            if user_or_pass == "PASS":
                passwd = words[w + 1]
                # Cleaning string
                passwd = passwd.replace('\\r\\n', '')
                passwd = passwd.replace('\'', '')
                passwd = passwd.replace('\"', '')
                global ftp_passes
                ftp_passes.append(passwd)




# This function finds the username:password pairing
# that is sent in a http authorization request
# Returns: username:password string
def http_passwdfind(http):
    # split http requests by lines
    lines = http.split("\\r\\n")
    for line in lines:
        # Search each line for authorizatoin field
        auth  = line.find("Authorization:")
        if auth != -1:
            # Split line into words and extract password
            words = line.split(" ")
            passwd = str(words[2])
            passwd_decoded = decode64(passwd)
            return passwd_decoded


def packetcallback(packet):
  try:

    global incident
    # Checking for a Xmas scan
    if packet[TCP].flags == 'FPU':
        print("ALERT #", incident, "Xmas scan is detected from", packet[IP].src, " (TCP)!")
        incident = incident + 1

    # Checking for a NULL scan
    if packet[TCP].flags == '':
        print("ALERT #", incident, "NULL scan is detected from", packet[IP].src, " (TCP)!")
        incident = incident + 1

    # Checking for a Fin Scan    
    if packet[TCP].flags == 'F':
        print("ALERT #", incident, "FIN scan is detected from", packet[IP].src, " (TCP)!")
        incident = incident + 1

    # Stringify the payload so we can search for passwords
    # and also nikto scans
    payload = str(packet.payload)

    # Checks for imap passwords sent in the clear
    if packet[TCP].dport == 143:
        user_passwd = imap_passwdfind(payload)
        if user_passwd != None:
            print("ALERT #", incident, "Usernames and passwords sent in the clear from", packet[IP].src, " (IMAP) (", user_passwd,")")
            incident = incident + 1

    # Checks for ftp passwords by checking if each packet
    # is sending either the username or password
    # and stores them on two separate stacks
    # and them pops from both of them when a password is found
    if packet[TCP].dport == 21:
        user = payload.find("USER")
        passwd = payload.find("PASS")
        # .find() returns -1 if the string is not a substring of payload
        if user != -1:
            ftp_passwdfind(payload, "USER")
        elif passwd != -1:
            ftp_passwdfind(payload, "PASS")
            global ftp_passes
            global ftp_users
            user = ftp_users.pop()
            passwd = ftp_passes.pop()
            user_passwd = user + ":" + passwd
            print("ALERT #", incident, "Usernames and passwords sent in the clear from", packet[IP].src, " (FPT) (", user_passwd,")")
            incident = incident + 1

    # Checking for nikto scans and http usernames and passwords
    if packet[TCP].dport == 80:
        auth = payload.find("Authorization: Basic")        
        nikto_scan = payload.find("Nikto")
        # .find() returns -1 if the string is not a substring of payload
        if nikto_scan != -1: 
            print("ALERT #", incident, "Nikto Scan detected from", packet[IP].src, " (HTTP)")
            incident = incident + 1
        if auth != -1:
            user_passwd = http_passwdfind(payload)
            print("ALERT #", incident, "Usernames and passwords sent in the clear from", packet[IP].src, " (HTTP) (", user_passwd,")")
            incident = incident + 1

        if packet[TCP].dport == 445 or packet[TCP].dport == 139:
            print("ALERT #", incident, "SMB Scan detected from", packect[IP].src, " (SMB)!")
            incident = incident + 1

  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback) 
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
