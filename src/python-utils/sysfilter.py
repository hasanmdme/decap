import sys
import os
import util
import re
import subprocess

class sysFilter:
    def __init__(self, binaryPath, sysfilterPath, logger):
        self.binaryPath = binaryPath
        self.sysfilterPath = sysfilterPath
        self.logger = logger

    def getSyscalls(self):
        binPath = self.binaryPath
        syscallList = self.runSysfilter(binPath)
        return syscallList

    def runSysfilter(self, binPath):
        if (not os.path.exists(self.sysfilterPath)):
                self.logger.error("Sysfilter path %s doesn't exist", self.sysfilterPath)
        cmd = self.sysfilterPath + " " +  binPath
        returnCode, out, Er = self.runCommand(cmd)
        if returnCode!=0:
            self.logger.error("Unable to extract system call using sysfilter for binary %s", self.binaryPath)
            return [-1]
        out = out[1:-2]
        out= [int(s) for s in out.split(',') if s.isdigit()]
        return out
    
    def runCommand(self,cmd):
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = proc.communicate()
        outStr = str(out.decode("utf-8"))
        errStr = str(err.decode("utf-8"))
        return (proc.returncode, outStr, errStr)
