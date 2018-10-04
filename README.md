# SIPCracker

dusip: voip PBX users scanner by dictionry attack 

options:
  -d DICTIONARY, --dictionary=DICTIONARY
                        specify a dictionary file with possible extension
                        names
  -i DICTIONARY, --iplist=DICTIONARY
                        specify a dictionary file with possible ips
  -m OPTIONS, --method=OPTIONS
                        specify a request method. The default is REGISTER.
                        Other possible methods are OPTIONS and INVITE
  --force               Force scan, ignoring initial sanity checks.
  --maximumtime=MAXIMUMTIME
                        Maximum time in seconds to keep sending requests
                        without receiving a response back
  --domain=DOMAIN       force a specific domain name for the SIP message, eg.
                        -d example.org
  --debug               Print SIP messages received
  --port=PORT           port SIP target to send


examples:
  dusip.py -d dictionary.txt 127.0.0.1
  dusip.py -d dictionary.txt -i iplist.txt -m INVITE --debug
