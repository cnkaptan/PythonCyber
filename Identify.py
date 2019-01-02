# *********************************************#
# Module: Identify
# Purpose: Go through each Network Entity and
# determine if a state exists
# Main FCN: IdStates()
# *********************************************#

import xml.etree.ElementTree as ET
from datetime import datetime


# *********************************************#
# Function: IsEqual
# Purpose: Compares an exploit list against a single IP  address to determine if a state exists
# Input: a - exploit vector that looks like:
# ['A', ['OSGuess', 'Linux 2.6.X'], ['OpenPort', '80']]
# ["Name of Vulnerability", [Vector of Aspect followed by specifics], etc..]
# b - pointer to the XML of a single IP address
# Output: matching- vector containing the name of vulnerability
# and if each thing checked were true or false. Will look like:
# ['A', False, False]
# *********************************************#
def IsEqual(a, b, ip):
    matching = []
    matching.append(a[0])
    # check for matching ports
    ports = b.findall('OpenPort')
    check = []
    for p in ports:
        u = p.text.strip()
        check.append(u)
    counter = 0
    ans = False
    for y in a:
        if counter > 0:
            if y[0].strip() == 'OpenPort':
                for i in y:
                    for u in check:
                        if i == u:
                            ans = True
        counter = counter + 1
    matching.append(ans)

    # check for matching OSs
    osg = b.findall('OSGuess')
    check = []
    for os in osg:
        u = os.text.strip()
        check.append(u)

    counter = 0
    ans = False
    for y in a:
        if counter > 0:
            if y[0].strip() == 'OSGuess':
                for i in y:
                    for u in check:
                        if i in u:
                            ans = True
        counter = counter + 1
    matching.append(ans)
    print ip + "\t" + matching.__str__() + "\t" + check.__str__() + "\n"
    return matching


# *********************************************#
# Function: GetExploits
# Purpose: pulls the entire exploit xml and makes
# it a vector we can use to compare to the IP address
# Input: None
# Output: exploit list vector contains a list of exploits and vectors for
# for the various aspects. Looks like:
# [['A', ['OSGuess', 'Linux 2.6.X'], ['OpenPort', '80']],
# ['B', ['OSGuess', 'Microsoft Windows 2000|XP', 'Windows XP SP2'], ['OpenPort','3389', '6667', '7000']]]
# *********************************************#
def GetExploits():
    tree = ET.parse('Exploits.xml')
    root = tree.getroot()
    exploitlist = []
    l = 0
    for Vul in root.iter('Vulnerability'):
        y = []
        exploitlist.append([Vul.text.strip()])
        for Asp in Vul.iter('Aspect'):
            y.append(Asp.text.strip())
            for Sp in Asp.iter('Spec'):
                y.append(Sp.text.strip())
            exploitlist[l].append(y)
            y = []
        l = l + 1
    return exploitlist


# *********************************************#
# Function: GetIPAddresses
# Purpose: pulls all IP addresses from the master list and returns a vector with them
# Input: None
# Output: vector list of IP addresses
# Looks like: ['192.168.120.3', '192.168.120.4', '192.168.120.10', '192.168.120.150']
# *********************************************#

def GetIPAddresses():
    tree = ET.parse('IPAddressIndex.xml')
    root = tree.getroot()
    IPAddList = []
    for IP in root.iter('IP'):
        IPAddList.append(IP.text.strip())
    return IPAddList


# *********************************************#
# Function: IdStates
# Purpose: uses other functions to create queries, test if they are true
# and then updates the network entity xml to reflect that a state exisits or not
# Input: None
# Output: "Success" to let the GUI know that Identify completed correctly
# *********************************************#

def IdStates():
    elist = GetExploits()
    ilist = GetIPAddresses()

    for add in ilist:
        filen = 'IP' + add + '.xml'
        tree = ET.parse(filen)
        root = tree.getroot()
        t = datetime.now().strftime("%Y-%m-%d %I:%M%p")
        for ex in elist:
            ans = IsEqual(ex, root, filen)
            if all(ans):
                state = ET.SubElement(root, 'State')
                state.text = 'State 0'
                Vul = ET.SubElement(state, 'Vulnerability')
                Vul.text = ans[0].strip()
                Time = ET.SubElement(state, 'TimeStamp')
                Time.text = t.strip() + " Pacific Daylight Time"
        tree.write(filen, 'us-ascii')
    return 'Success'


if __name__ == '__main__':
    IdStates()
