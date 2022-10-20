import sys
import os
import util
import re

class BinaryAnalysis:
    """
    This class can be used to extract direct system calls and possibly other information from a binary
    """
    def __init__(self, binaryPath, logger):
        self.binaryPath = binaryPath
        self.logger = logger
    
    def extractDirectSyscalls(self, SysAdminSyscallNumbers):
        objDumpSuccess = True
        #Dump binary to tmp file
        dumpFileName = self.binaryPath + ".dump"
        if ( "/" in dumpFileName ):
            dumpFileName = dumpFileName[dumpFileName.rindex("/")+1:]
        dumpFilePath = "/tmp/" + dumpFileName
        cmd = "objdump -d {} > " + dumpFilePath
        if ( os.path.isfile(self.binaryPath) ):
            cmd = cmd.format(self.binaryPath)
            returncode, out, err = util.runCommand(cmd)
            if (returncode != 0 ):
                self.logger.error("Couldn't create dump file for: %s with err: %s", self.binaryPath, dumpFilePath)
                return (set(), -1, -1, dict(), False)
            #Find direct syscalls and arguments
            #Specify how many were found successfully and how many were not
            syscallSet, successCount, failedCount, syscallToArgumentValMap = self.parseObjdump(dumpFilePath, SysAdminSyscallNumbers)
            #Return syscall list along with number of not found syscalls
            os.unlink(dumpFilePath)
            return (syscallSet, successCount, failedCount,
                    syscallToArgumentValMap, objDumpSuccess)
        else:
            self.logger.error("Binary path doesn't exist: %s", self.binaryPath)
            return (set(), -1, -1, dict(), False)


    def binaryDumpPath(self):
        #Dump binary to tmp file
        dumpFileName = self.binaryPath + ".dump"
        if ( "/" in dumpFileName ):
            dumpFileName = dumpFileName[dumpFileName.rindex("/")+1:]
        dumpFilePath = "/tmp/" + dumpFileName
        cmd = "objdump -d {} > " + dumpFilePath
        if ( os.path.isfile(self.binaryPath) ):
            cmd = cmd.format(self.binaryPath)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                #self.logger.error("Couldn't create dump file for: %s with err: %s", self.binaryPath, dumpFilePath)
                return (None, -1, -1)
            return dumpFilePath
        else:
            self.logger.error("binary path doesn't exist: %s", self.binaryPath)
            return (None, -1, -1)


    def extractArgumentVal(self, syscallNum, syscallMap):
        #Dump binary to tmp file
        dumpFileName = self.binaryPath + ".dump"
        if ( "/" in dumpFileName ):
            dumpFileName = dumpFileName[dumpFileName.rindex("/")+1:]
        dumpFilePath = "/tmp/" + dumpFileName
        cmd = "objdump -d {} > " + dumpFilePath
        if ( os.path.isfile(self.binaryPath) ):
            cmd = cmd.format(self.binaryPath)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                #self.logger.error("Couldn't create dump file for: %s with err: %s", self.binaryPath, dumpFilePath)
                return (None, -1, -1)
            #Find argument values of a syscall
            argumentVal = self.parseObjdumpForArgument(dumpFilePath, syscallNum, syscallMap)
            os.unlink(dumpFilePath)
            return (argumentVal)
        else:
            self.logger.error("binary path doesn't exist: %s", self.binaryPath)
            return (None)

    def parentFunctionSearch(self, fnName, wrapper, syscallNum, FnNameBodyMap):
        argumentVal = set()
        for parentName in FnNameBodyMap:
            pBody = FnNameBodyMap[parentName]
            for line_no in range(len(pBody)):
                lineVal = pBody[line_no]
                if (fnName in lineVal and "e8" in lineVal) or (fnName in lineVal and "e9" in lineVal):
                    tmpY = line_no - 1
                    sys_flag_val = self.extractFlag(pBody[tmpY], wrapper, syscallNum)
                    while ( sys_flag_val == -1 and (line_no - tmpY) < 15 and tmpY > 0 ):
                        tmpY = tmpY - 1
                        sys_flag_val = self.extractFlag(pBody[tmpY], wrapper, syscallNum)
                    argumentVal.add(sys_flag_val)
        return argumentVal;

    def parseObjdumpForArgument(self, outputFileName, syscallNum, syscallMap):
        FnNameBodyMap = {}
        FnSysCallMap = {}
        f = open(outputFileName)
        fnName = ""
        for line in f:
            if "<" in line and ">:" in line:
                namesplit = line.split()
                fnName = self.sanitizeFnName(namesplit[1])
                FnNameBodyMap[fnName] = []
                FnSysCallMap[fnName] = []
                continue
            if fnName != "":
                FnNameBodyMap[fnName].append(line)
        f.close()

        argumentVal = set()
        for fnName in FnNameBodyMap:
            sys_num=-1
            body = FnNameBodyMap[fnName]
            for i in range(len(body)):
                line = body[i]
                if (syscallMap[syscallNum]+"@plt" in line and "e8" in
                    line) or (syscallMap[syscallNum]+"@plt" in line and "e9" in line):
                    argumentVal = argumentVal | self.iterateFuncBodyForArgumentVal(i, syscallNum, body,
                            fnName, True, FnNameBodyMap, argumentVal);

        return argumentVal

    def iterateFuncBodyForArgumentVal(self, i, syscallNum, body, fnName,
            isLibcWrapper, FnNameBodyMap, argumentVal):
        tmpI = i-1
        flag_val = self.extractFlag(body[tmpI], isLibcWrapper, syscallNum)
        while ( flag_val == -1 and (i - tmpI) < 15 and tmpI > 0 ):
            tmpI = tmpI - 1
            flag_val = self.extractFlag(body[tmpI], isLibcWrapper, syscallNum)
        if (flag_val == -1 and tmpI < 15):
            argumentVal = argumentVal | self.parentFunctionSearch(fnName, isLibcWrapper, syscallNum, FnNameBodyMap)
        else:
            argumentVal.add(flag_val)
        return argumentVal

    def extractFlag(self, ins, isLibcWrapper, sys_num):
        sys_flag_val = -1
        first_arg_edi_rdi_reg = {157, 101, 179, 160} #when wrapper, if no wrapper then esi rsi
        second_arg_esi_rsi_reg = {16, 31, 71} #when wrapper, if no wrapper then edx rdx
        third_arg_edx_rdx_reg = {56, 28} #when wrapper, if no wrapper then ecx rcx
        forth_arg_ecx_rcx_reg = {265} #when wrapper, if no wrapper then r8
        split = ins.split()
        for i in range(len(split)):
            if split[i] == "mov":
                # Next token should be src,dest
                srcdst = split[i+1].split(",")
                src = srcdst[0]
                dst = srcdst[1]
                if isLibcWrapper:
                    if (sys_num in second_arg_esi_rsi_reg) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in first_arg_edi_rdi_reg) and (dst == "%edi" or dst == "%rdi"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in third_arg_edx_rdx_reg) and (dst == "%edx" or dst == "%rdx"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in forth_arg_ecx_rcx_reg) and (dst == "%ecx"
                            or dst == "%rcx"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)

                else:
                    if (sys_num == 250) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num == 317) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num == 251) and (dst == "%ecx" or dst == "%rcx"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in second_arg_esi_rsi_reg) and (dst == "%edx" or dst == "%rdx"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in first_arg_edi_rdi_reg) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in third_arg_edx_rdx_reg) and (dst == "%ecx" or dst == "%rcx"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)
                    elif (sys_num in forth_arg_ecx_rcx_reg) and (dst == "%r8"):
                        sys_flag_val = src
                        sys_flag_val = self.sanitizeFlag(sys_flag_val)

            elif split[i] == "xor":
                # Next token should be src,dest
                srcdst = split[i+1].split(",")
                src = srcdst[0]
                dst = srcdst[1]
                if isLibcWrapper:
                    if (sys_num in second_arg_esi_rsi_reg) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in first_arg_edi_rdi_reg) and (dst == "%edi" or dst == "%rdi"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in third_arg_edx_rdx_reg) and (dst == "%edx" or dst == "%rdx"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in forth_arg_ecx_rcx_reg) and (dst == "%ecx"
                            or dst == "%rcx"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                else:
                    if (sys_num == 250) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num == 317) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num == 251) and (dst == "%ecx" or dst == "%rcx"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in second_arg_esi_rsi_reg) and (dst == "%edx" or dst == "%rdx"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in first_arg_edi_rdi_reg) and (dst == "%esi" or dst == "%rsi"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in third_arg_edx_rdx_reg) and (dst == "%ecx" or dst == "%rcx"):
                        sys_flag_val = self.xorFlagreturn(dst,src)
                    elif (sys_num in forth_arg_ecx_rcx_reg) and (dst == "%r8"):
                        sys_flag_val = self.xorFlagreturn(dst,src)

        return sys_flag_val

    def xorFlagreturn(self, dst,src):
        if dst == src:
            sys_flag_val = '$0x0'
            sys_flag_val = self.sanitizeFlag(sys_flag_val)
        else:
            sys_flag_val = '$0x-1'
            sys_flag_val = self.sanitizeFlag(sys_flag_val)
        return sys_flag_val

    
    def sanitizeFlag(self, sys_flag_val):
        if sys_flag_val[0] == "$":
            #print(sys_flag_val)
            sys_flag_val = sys_flag_val[3:]
        return sys_flag_val

    def sanitizeFnName(self, instr):
        outstr = ""
        for s in instr:
            if s == "<":
                continue
            if s == ">":
                continue
            if s == ":":
                continue
            outstr += s
        return outstr

    def decimalify(self, token):
        number = ""
        intnum = -1
        #print('$$  ',token)
        if token[0] == "$":
            number = token[1:]
        try:
            intnum = int(number, 16)
        except ValueError:
            #self.logger.debug("can't convert: %s", token)
            #print('$$ $$')
            pass
        return intnum
    
    def extractNum(self, ins, wrapper):
        num = -1
        #print(wrapper)
        split = ins.split()
        for i in range(len(split)):
            if split[i] == "mov":
                # Next token should be src,dest
                srcdst = split[i+1].split(",")
                src = srcdst[0]
                dst = srcdst[1]
                if wrapper and (dst == "%edi" or dst == "%rdi"):
                    num = self.decimalify(src)
                elif (wrapper == False) and (dst == "%rax" or dst == "%eax" or dst == "%rcx" or dst == "%ecx"):# or dst == "%edi" or dst == "%rdi":
                    #self.logger.debug("src: %s", src)
                    num = self.decimalify(src)
             
        return num
    
    
    def parseObjdump(self, outputFileName, SysAdminSyscallNumbers):
        FnNameBodyMap = {}
        FnSysCallMap = {}
        failCount = 0
        successCount = 0
        f = open(outputFileName)
        fnName = ""
        for line in f:
            if "<" in line and ">:" in line:
                # Most likely new function start
                namesplit = line.split()
                fnName = self.sanitizeFnName(namesplit[1])
                FnNameBodyMap[fnName] = []
                FnSysCallMap[fnName] = []
                continue
            if fnName != "":
                FnNameBodyMap[fnName].append(line)
        f.close()
    
        # For each function
        syscallSet = set()
        syscallToArgumentValMap = dict()
        for fnName in FnNameBodyMap:
            body = FnNameBodyMap[fnName]
            wrapper = False
            for i in range(len(body)):
                line = body[i]
                if ("syscall" in line and "0f 05" in line):# ("syscall" in line and "e8" in line) or ("syscall" in line and "e9" in line):
                    # Check the past three lines for the value of the rax register
                    tmpI = i-1
                    num = self.extractNum(body[tmpI], wrapper)
                    while ( num == -1 and (i - tmpI) < 15 and tmpI > 0 ):
                        tmpI = tmpI - 1
                        num = self.extractNum(body[tmpI], wrapper)
                    if num == -1:
                        failCount += 1
                        #self.logger.error("Can't reason about syscall in function: %s in line: %s", fnName, line)
                    else:
                        successCount += 1
                        # Extract argument values for the system calls responsible for CAP_SYS_ADMIN
                        if (num in SysAdminSyscallNumbers):
                            argumentVal = set()
                            argumentVal = self.iterateFuncBodyForArgumentVal(i, num, body, fnName, False, FnNameBodyMap, argumentVal)
                            if (num in syscallToArgumentValMap):
                                syscallToArgumentValMap[num] = syscallToArgumentValMap[num] | argumentVal
                            else:
                                syscallToArgumentValMap[num] = argumentVal

                        syscallSet.add(num)
                elif ("syscall" in line and "e8" in line) or ("syscall" in line and "e9" in line):
                    # Check the past three lines for the value of the rax register
                    wrapper = True
                    tmpI = i-1
                    num = self.extractNum(body[tmpI], wrapper)
                    while ( num == -1 and (i - tmpI) < 15 and tmpI > 0 ):
                        tmpI = tmpI - 1
                        num = self.extractNum(body[tmpI], wrapper)
                    if num == -1:
                        failCount += 1
                        #self.logger.error("Can't reason about syscall in function: %s in line: %s", fnName, line)
                    else:
                        successCount += 1
                        # Extract argument values for the system calls responsible for CAP_SYS_ADMIN
                        if (num in SysAdminSyscallNumbers):
                            argumentVal = set()
                            argumentVal = self.iterateFuncBodyForArgumentVal(i, num, body, fnName, False, FnNameBodyMap, argumentVal)
                            if (num in syscallToArgumentValMap):
                                syscallToArgumentValMap[num] = syscallToArgumentValMap[num] | argumentVal
                            else:
                                syscallToArgumentValMap[num] = argumentVal
                        syscallSet.add(num)

        return (syscallSet, successCount, failCount, syscallToArgumentValMap)
