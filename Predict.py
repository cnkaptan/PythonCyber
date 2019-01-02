# *********************************************#
# Module: Predict
# Purpose: Go through each Network Entity, find if a state
# exists, make a recommendation for an attack for that state
# provide expected probability of success
# Main FCN: Predict()
# *********************************************#

import xml.etree.ElementTree as ET
from datetime import datetime


# *********************************************#
# Function: GetRecommendations()
# Purpose: Opens exploits.xml, calculates recommended exploits
# and percentages
# Input: None
# Output: list of exploits and probabilities. Looks like:
# [['A', ['MiTM-Ettercap', 0.625, 'B'], ['MoTS-Cain and Able', 0.428]]]
# *********************************************#
def GetRecommendations():
    tree = ET.parse('Exploits.xml')
    root = tree.getroot()
    exploitlist = []
    l = 0
    for Vul in root.iter('Vulnerability'):
        y = []
        exploitlist.append([Vul.text.strip()])
        for Rec in Vul.iter('Recommend'):
            y.append(Rec.text.strip())
            for Pr in Rec.iter('Prob'):
                v = Pr.text.strip()
                v = v.split(':')
                n = float(v[0]) / float(v[1])
                y.append(n)
        for Rq in Rec.iter('Requires'):
            y.append(Rq.text.strip())
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
# Function: MakeRec
# Purpose: given a vector of found vulnerabilities choose the
# one with the highest prob and return it
# Input: r. List of exploits.
# Looks like: [['A', ['MiTM-Ettercap', 0.625, 'B'], ['MoTS-Cain and Able', 0.428]]]
# General form is Name of Vulnerability, [Name of attack, probability, additional requirements], etc
# Output: Exploit with recommended attack and probability and any other requirements
# Looks like: ['MiTM-Ettercap', 0.625, 'B']
# Note: most future work with Predict would be in here
# *********************************************#
def MakeRec(r):
    y = [' ', 0]
    counter = 0
    for a in r:
        if counter > 0:
            if a[1] > y[1]:
                y = a
        counter = counter + 1
    return y


# *********************************************#
# Function: Predict
# Purpose: Go through network entities, see if a state 0 exists, if it does find
# the recommended exploit, update the entity xml to reflect this
# Input: None
# Output: Success to indicate the module has run correctly
# *********************************************#
def Predict():
    rlist = GetRecommendations()
    ilist = GetIPAddresses()
    t = datetime.now().strftime("%Y-%m-%d %I:%M%p")
    for add in ilist:
        filen = 'IP' + add + '.xml'
        tree = ET.parse(filen)
        root = tree.getroot()
        for st in root.iter("State"):
            if st.text == "State 0":
                for vul in st.iter('Vulnerability'):
                    for r in rlist:
                        if r[0].strip() == vul.text.strip():
                            z = MakeRec(r)
                            RElem = ET.SubElement(root, 'Recommend')
                            RElem.text = z[0].strip()
                            TElem = ET.SubElement(RElem, 'Timestamp')
                            TElem.text = t.strip()
                            PElem = ET.SubElement(RElem, 'Prob')
                            PElem.text = str(z[1]).strip()
                            if len(z) > 2:
                                QElem = ET.SubElement(RElem, 'Requires')
                                QElem.text = z[2].strip()
        tree.write(filen, 'us-ascii')
    return 'Success'


if __name__ == '__main__':
    Predict()
