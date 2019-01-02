import Tkinter as tk
from Tkinter import *
import tkMessageBox
import Detect
import Identify
import Predict
import React

# *********************************************#
# Module: GUI
# Purpose: Step through each module, allow input from user
# to update the exploit xml, display steps
# Main FCN: WalkThroughSequence
# *********************************************#

top = Tk()
top.title("DIPR Automated Cyber Penetration System")
top.geometry("200x250")


# *********************************************#
# Function: WalkThroughSequence
# Purpose: Walks through each module, Builds the GUI
# Input: None
# Output: v - Success or failure of the entire walk through
# *********************************************#
def WalkThroughSequence():
    text = Text(top, width=25, height=9, wrap=WORD)
    text.insert(INSERT, 'Starting... \n')
    text.grid(row=1, column=0)
    y = Detect.Discover("NMap")
    if y == 'Success':
        text.insert(END, 'Dectect Successful \n')
        z = Identify.IdStates()  # runs identify module
        if z == 'Success':
            text.insert(END, 'Identify Successful \n')
            w = Predict.Predict()  # runs predict module
            if w == 'Success':
                text.insert(END, 'Predict Successful \n')
                (v, vul, atk) = React.React()  # runs React Module
                if v == 'Success':
                    text.insert(END, 'React Successful.\n Please view Wireshark \n')
                    C = Button(top, text='Success?', command=lambda: React.UpdateSuccess(vul, atk))
                    D = Button(top, text='Failure?', command=lambda: React.UpdateFailure(vul, atk))
                    C.grid(row=2, column=0)
                    D.grid(row=3, column=0)
    return v


B = Button(top, text="Start Sequence", command=WalkThroughSequence)
B.grid(row=0, column=0)  # puts the button into our window
#
top.mainloop()
