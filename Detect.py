# *********************************************#
# Module: Detect
# Purpose: Detect network entities and
# create XML files with features of Entity
# Main FCN: Discover
# *********************************************#

import os
import subprocess
import xml.etree.ElementTree as ET


# ************************#
# Function: Discover
# Purpose: Discover network entities parse information
# store parsed information in an XML file
# Input: Program - Name of program desired to be used to discover the network entities
# Output: Success - States that the program has completed
# ************************#

def Discover(Program):
    # Calls the NMap Program and pipes the result into a file called infosearch.txt
    # -O means look for possible Operating systems. To do this it will scan for open ports as well
    # if Program == "Nmap":
        # os.system('"C:\\Program Files\\Nmap\\nmap.exe" -O 192.168.120.0/24 > infosearch.txt')
    info = []
    y = -1
    timestamp = ' '
    filen = ''
    # Index will eventually be the master index XML file that will keep track of who is in the network
    Index = ET.Element('Index')
    # IP will eventually become the network entity XML
    IP = ET.Element('Address')
    # Begin to parse the infosearch file with the piped information from NMap
    for line in open('infosearch.txt', 'r'):
        if 'Starting' in line:
            k = line.split(' at ')
            timestamp = k[1]
        if 'scan report' in line:
            if y > -1:
                tree = ET.ElementTree(IP)
                tree.write(filen, "us-ascii", xml_declaration=None, default_namespace=None, method='xml')
                IP = IP.clear()
                IP = ET.Element('Address')
            k = line.split(' ')
            p = k[4].strip()
            filen = 'IP' + p + '.xml'
            IP.text = k[4].strip()
            ind = ET.SubElement(Index, 'IP')
            ind.text = k[4].strip()
            time = ET.SubElement(IP, 'TimeStamp')
            time.text = timestamp.strip()
            prog = ET.SubElement(IP, 'ProgramUsed')
            prog.text = 'Nmap 6.25'
            y = y + 1
        if 'MAC Address:' in line:
            k = line.split(' ')
            ma = ET.SubElement(IP, 'MacAddress')
            ma.text = k[2].strip()
        if 'open' in line:
            k = line.split('/')
            op = ET.SubElement(IP, 'OpenPort')
            op.text = k[0].strip()
        if 'Running' in line:
            k = line.split(':')
            k = k[1].split(',')
            for item in k:
                if 'or ' in item and item.index('or ') < 4:
                    h = item.split('or ')
                    OSGuess = ET.SubElement(IP, 'OSGuess')
                    OSGuess.text = h[1].strip()
                else:
                    OSGuess = ET.SubElement(IP, 'OSGuess')
                    OSGuess.text = item.strip()
    # Prints our master index list and the XML list to their respective files
    tree = ET.ElementTree(IP)
    tree.write(filen, "us-ascii", xml_declaration=None, default_namespace=None, method='xml')
    tree = ET.ElementTree(Index)
    tree.write('IPAddressIndex.xml', encoding='us-ascii')
    return 'Success'
