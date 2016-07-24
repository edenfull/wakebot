import logging # for the following line
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # suppress IPV6 warning on startup
from scapy.all import * # for sniffing for the ARP packets
from subprocess import call
import getData, datetime

# it takes a minute for the scapy sniffing to initialize, so I print this to know when it's actually ready to go
print('Init done.')

lastCalled = datetime.datetime(2016,1,1,1,1,1,1)

def arp_display(pkt):
  global lastCalled
  if pkt[ARP].op == 1: #who-has (request)
    if (pkt[ARP].psrc == '0.0.0.0') and (datetime.datetime.now() - lastCalled > datetime.timedelta(minutes=1)): # ARP Probes will match this
        weather = getData.getWeather()
        subway = getData.getSubway()

        if pkt[ARP].hwsrc == 'f0:27:2d:86:7b:bf':
            lastCalled = datetime.datetime.now()
            call(['flite', '-voice', 'slt', getData.getDateTime()])
            call(['flite', '-voice', 'slt', weather['morning']])
            call(['flite', '-voice', 'slt', weather['day']])
            call(['flite', '-voice', 'slt', weather['evening']])
            call(['flite', '-voice', 'slt', subway['ace']])
            call(['flite', '-voice', 'slt', subway['nqr']])
            call(['flite', '-voice', 'slt', subway['oneTwoThree']])
        else:
            print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print(sniff(prn=arp_display, filter="arp", store=0))
