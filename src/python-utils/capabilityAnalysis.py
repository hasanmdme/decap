import os, sys, subprocess, signal
import logging

import graph
import syscall
import binaryAnalysis
import syscallToCapabilityMapping
import sysfilter
import util
import pexpect

class CapabilityAnalysis:
    
    def __init__(self, binaryName, binaryPath, logger, sysfilterPath):
        self.binaryName = binaryName
        self.binaryPath = binaryPath
        self.sysfilterPath = sysfilterPath
        self.logger = logger

    def addCapsToBinary(self, capToAdd):
        self.logger.info("Deprivileging setuid binary and enforcing only the required capabilities to the binary")
        
        # removing setuid privilege from binary
        privCmd = "sudo chmod u-s {}"
        removePrivilegeCmd = privCmd.format(self.binaryPath)
        returncode, out, err = util.runCommand(removePrivilegeCmd)
        if ( returncode != 0 ):
            logging.error("Error removing setuid bit of binary: %s", err)
            return

        # Add the required capabilities to the binary
        if (len(capToAdd) == 0):
                return
        capToAdd = ','.join(capToAdd)
        cmd = "sudo setcap '{}=+ep' {}"
        finalCmd = cmd.format(capToAdd, self.binaryPath)
        self.logger.debug("Modifyng capabilities with the cmd: %s", finalCmd)
        returncode, out, err = util.runCommand(finalCmd)
        if ( returncode != 0 ):
            logging.error("Error modifying capability set of binary: %s", err)
        return


    def ioctlFlags(self):
        ioctl_flags = {'40045201','40085203', '5204', '5206', '5207', '5457',
                '541d', '540e', '540c', '1269', '125f', '401870c8', '401070c9',
                '401070ca', '401870cb', '401070cd', '1261', '125d', '40081271',
                '1262', '1264', 'c0185879', '50009403', 'd0009411', 'c0709411',
                'd0009412', '5000940f', '50009402', '40309410', '5000940a',
                '5000940b', '5000943a', '40089413', 'c400941b', '941c',
                'c400941d', 'c4089434', 'ca289435', 'c0389424', 'c038943b',
                'c4009420', '40049421', '84009422', 'c0109428', '40189429',
                '4010942a', '8030942b', '4040942c', '8040942d', '40309439',
                '6611', '8004587d', '6880', 'c0045877', 'c0045878', 'c0185879',
                '40106e80', '40086e81', '40786e88', '40086e8b', '40106e8c',
                '40186e8d', 'c038586b', '4058587a', '4048587b', 'c0205866',
                'c0205865', 'c0205867', 'c0105872', '80105873', '8004587d',
                '40085874', '40085875', '8080583a', 'c0484e41'}
        return ioctl_flags

    def quotactlFlags(self):
        quotactl_flags = {'800002', '800003', '800006', '800007', '800008',
                '5801', '5802', '5803', '5804'} 
        return quotactl_flags

    def libcSensitiveSysToParentMap(self):
        sensitiveMap = {"setrlimit" : "vlimit", "shmctl": "__monstartup"}
        return sensitiveMap;

    def hexToBinFlag(self, argVal):
        scale = 16 ## equals to hexadecimal
        num_of_bits = 32
        binFlag = bin(int(argVal, scale))[2:].zfill(num_of_bits)
        return binFlag


    def findCapSysAdminRequirement(self, syscallNum, argVal):
        sysAdminRequired = True
        binFlag = bin(int('0', 16))[2:].zfill(32)
        for items in argVal:
            try:
                if (items == "removeTrue"):
                    return True;
                if (items == "removeFalse"):
                    return False;
                if (items == -1):
                    return False
                temp = self.hexToBinFlag(str(items))
                #doing bitwise or on string on temp and binFlag
                binFlag = ''.join(map(max, binFlag, temp))
            except:
                #print('$$not a hex value but a register')
                sysAdminRequired = False
        
        bitList = list(binFlag)
        if syscallNum == 56: #clone
            sys_admin_flag = {8000000, 40000000, 20000, 20000000, 4000000}
            adminFlag = bin(int('0', 16))[2:].zfill(32)
            for items in sys_admin_flag:
                temp = self.hexToBinFlag(str(items))
                adminFlag = ''.join(map(max, adminFlag, temp))
            adminList = list(adminFlag)
            sysAdminRequired = True
            for index, val in enumerate(adminList):
                if val == 1:
                    if bitList[index] == 1:
                        sysAdminRequired = False
        elif syscallNum == 157: #prctl
            sys_admin_flag1 = '16' #hex value
            sys_admin_flag2 = '2' #hex value
            if sys_admin_flag1 not in argVal:
                sysAdminRequired = True
            else:
                sysAdminRequired = False
        elif syscallNum == 28: #madvise decimal value
            advice_flag = '64' #advice flags hex value
            if advice_flag in argVal:
                sysAdminRequired = False
        elif syscallNum == 31: #shmctl decimal value
            IPC_SET = '1' #flags hex value
            IPC_RMID = '0'
            if IPC_SET in argVal or IPC_RMID in argVal:
                sysAdminRequired = False
        elif syscallNum == 16: #ioctl decimal value
            ioctl_flags = self.ioctlFlags() #request flags hex value for sys_admin
            for it in argVal:
                if it in ioctl_flags:
                    sysAdminRequired = False
                    #break
        elif syscallNum == 250: #keyctl decimal value
            KEYCTL_CHOWN = '4' #flags hex value
            KEYCTL_SETPERM = '5'
            if KEYCTL_CHOWN in argVal or KEYCTL_SETPERM in argVal:
                sysAdminRequired = False
        elif syscallNum == 101: #ptrace decimal value
            PTRACE_SECCOMP_GET_FILTER = '420c' #flags hex value
            PTRACE_SETOPTIONS = '4200'
            if PTRACE_SECCOMP_GET_FILTER in argVal or PTRACE_SETOPTIONS in argVal:
                sysAdminRequired = False
        elif syscallNum == 179: #quotactl decimal value
            quotactl_flags = self.quotactlFlags() #cmd flags hex value
            for it in argVal:
                size = len(it)
                # Slice string to remove last 2 characters from it
                it = it[:size - 2]
                if it in quotactl_flags:
                    sysAdminRequired = False
        elif syscallNum == 71: #msgctl decimal value
            IPC_SET = '1' #flags hex value
            IPC_RMID = '0'
            if IPC_SET in argVal or IPC_RMID in argVal:
                sysAdminRequired = False
        elif syscallNum == 317: #seccomp decimal value
            SECCOMP_SET_MODE_FILTER = '1' #flags hex value
            if SECCOMP_SET_MODE_FILTER in argVal:
                sysAdminRequired = False
        elif syscallNum == 251: #ioprio_set decimal value
            IOPRIO_PRIO_CLASS = '1' #flags hex value
            if IOPRIO_PRIO_CLASS in argVal:
                sysAdminRequired = False
        elif syscallNum == 160: #setrlimit decimal value
            RLIMIT_NPROC1 = '6' #flags hex value
            RLIMIT_NPROC2 = '7' #flags hex value
            RLIMIT_NPROC3 = '8' #flags hex value
            if RLIMIT_NPROC1 in argVal or RLIMIT_NPROC2 in argVal or RLIMIT_NPROC3 in argVal:
                sysAdminRequired = False

        return sysAdminRequired


    def findArgumentsForImportedFunctions(self, syscallNumber, funcName,
                            importedFunctionListFromBinary, importedFunctionListFromLibraries, syscallNumberToNameMap,
                            sysToParentMap, glibcGraph, pathToFunctionMap):
        argumentVal = {'0000'};

        # System call name and imported function name are name
        if syscallNumberToNameMap[syscallNumber] == funcName or funcName == '__' + syscallNumberToNameMap[syscallNumber]:
            # Check if the imported function is coming from binary
            if funcName in importedFunctionListFromBinary:
                argumentAnalysis = binaryAnalysis.BinaryAnalysis(self.binaryPath, None)
                argumentVal = argumentAnalysis.extractArgumentVal(syscallNumber, syscallNumberToNameMap)
            elif funcName in importedFunctionListFromLibraries:
                for libPath, fNames in pathToFunctionMap.items():
                    if funcName in pathToFunctionMap[libPath] and libPath != '/lib/x86_64-linux-gnu/libc.so.6':
                        argumentAnalysis = binaryAnalysis.BinaryAnalysis(libPath, None)
                        argumentVal = argumentVal | argumentAnalysis.extractArgumentVal(syscallNumber, syscallNumberToNameMap)
        # System call name is different from imported function name; we get
        # system call from another libc function. Ex., clone system call is
        # coming from fork libc wrapper
        elif syscallNumberToNameMap[syscallNumber] != funcName and funcName != '__' + syscallNumberToNameMap[syscallNumber]:
            parent = sysToParentMap[syscallNumber]
            if (parent == '__' + syscallNumberToNameMap[syscallNumber]):
                parent = glibcGraph.getParent(funcName, parent)
            argumentVal = {'removeTrue'}
            for syscallName, parentFunc in self.libcSensitiveSysToParentMap().items():
                if syscallName == syscallNumberToNameMap[syscallNumber] and parentFunc == parent:
                    argumentVal = {'removeFalse'}
                    return argumentVal
        
        return argumentVal
    
    def getDirectSyscalls(self, canBeRemovedSyscallList, cannotBeRemovedSyscallList, syscallNumberToNameMap, SysAdminSyscallNumbers, blackListedLibraries):
        # Extract direct system calls from binary
        binAnalysisForBinary = binaryAnalysis.BinaryAnalysis(self.binaryPath, self.logger)
        directSyscallSetFromBinary, successCount, failCount, syscallToArgumentValMapBinary, success = binAnalysisForBinary.extractDirectSyscalls(SysAdminSyscallNumbers)

        if (not success):
            return (set(), success)

        # Analyze argument values for the system calls that are responsible for CAP_SYS_ADMIN
        if (syscallToArgumentValMapBinary != None):
            for syscallNumber, argumentVal in syscallToArgumentValMapBinary.items():
                sysAdminRequired = self.findCapSysAdminRequirement(syscallNumber, argumentVal)
                if sysAdminRequired:
                    canBeRemovedSyscallList.append(syscallNumber)
                else:
                    cannotBeRemovedSyscallList.append(syscallNumber)
        
        # Extract direct system calls from libraries
        directSyscallSetFromLibraries = set()
        libraries = util.readLibrariesWithLdd(self.binaryPath)
        for name, libraryPath in libraries.items():
            #direct system calls from shared libraries
            if name not in blackListedLibraries:
                binAnalysisForLibrary = binaryAnalysis.BinaryAnalysis(libraryPath, None)
                directSyscallsSet, successCount, failCount, syscallToArgumentValMapLibraries, success = binAnalysisForLibrary.extractDirectSyscalls(SysAdminSyscallNumbers)

                if (not success):
                    return (set(), success)

                for syscallNumber, argumentVal in syscallToArgumentValMapLibraries.items():
                    sysAdminRequired = self.findCapSysAdminRequirement(syscallNumber, argumentVal)
                    if sysAdminRequired:
                        canBeRemovedSyscallList.append(syscallNumber)
                    else:
                        cannotBeRemovedSyscallList.append(syscallNumber)

                directSyscallSetFromLibraries = directSyscallSetFromLibraries | directSyscallsSet


        directSyscallsSet = directSyscallSetFromBinary | directSyscallSetFromLibraries
        return (directSyscallsSet, True)


    def getSyscallsFromImportedFunctions(self, canBeRemovedSyscallList,
            cannotBeRemovedSyscallList, syscallNumberToNameMap,
            SysAdminSyscallNumbers, blackListedLibraries):
        syscallsSetFromImportedFunctions = set()
        
        # Extract imported functions from binary
        importedFunctionListFromBinary = util.extractImportedFunctions(self.binaryPath)

        # Extract imported functions from libraries
        libraries = util.readLibrariesWithLdd(self.binaryPath)
        importedFunctionListFromLibraries = []
        pathToFunctionMap = {}

        for name, libraryPath in libraries.items():
            if name not in blackListedLibraries:
                pathToFunctionMap[libraryPath] = util.extractImportedFunctions(libraryPath)
                importedFunctionListFromLibraries = importedFunctionListFromLibraries + pathToFunctionMap[libraryPath]
        
        allImportedFunctions = set(importedFunctionListFromBinary + importedFunctionListFromLibraries)

        # Extract system calls from imported functions using glibc callgraph
        glibcGraph = graph.Graph(self.logger)
        glibcGraph.createGraphFromInput("libc-callgraphs/glibc.callgraph", ":")

        for funcName in allImportedFunctions:
            syscallsSet, sysToParentMap = glibcGraph.getSyscallFromStartNode(funcName)
            for syscallNumber in syscallsSet:
                if syscallNumber in SysAdminSyscallNumbers:
                    # Find argument values for the system calls responsible
                    # for CAP_SYS_ADMIN
                    argumentVal = self.findArgumentsForImportedFunctions(syscallNumber, funcName,
                            importedFunctionListFromBinary, importedFunctionListFromLibraries, syscallNumberToNameMap,
                            sysToParentMap, glibcGraph, pathToFunctionMap);
                    # Find if CAP_SYS_ADMIN is required
                    sysAdminRequired = self.findCapSysAdminRequirement(syscallNumber, argumentVal)
                    if sysAdminRequired:
                        canBeRemovedSyscallList.append(syscallNumber)
                    else:
                        cannotBeRemovedSyscallList.append(syscallNumber)
            syscallsSetFromImportedFunctions = syscallsSetFromImportedFunctions | syscallsSet

        return syscallsSetFromImportedFunctions

    def getSyscallsFromSysfilter(self):
        numOfSysfilterSyscalls = 0
        sysfilterAnalysis = sysfilter.sysFilter(self.binaryPath, self.sysfilterPath, self.logger)
        allSyscallsFromSysfilter = sysfilterAnalysis.getSyscalls();
        
        if len(allSyscallsFromSysfilter) == 1 and allSyscallsFromSysfilter[0] == -1:
            numOfSysfilterSyscalls = 0
        else:
            numOfSysfilterSyscalls = len(allSyscallsFromSysfilter)

        return allSyscallsFromSysfilter, numOfSysfilterSyscalls

    def getSyscallNameFromSyscallNumber(self, syscallNumbers, syscallNumberToNameMap):
        syscallNameList = []
        i = 0
        while i < 400:
            if ( i in syscallNumbers and syscallNumberToNameMap.get(i, None)):
                    syscallNameList.append(syscallNumberToNameMap[i])
            i += 1
        #print ('\nExtracted syscall Names intersected: ', syscallNameList, '\n')
        return syscallNameList
    
    def removeCapSysAdmin(self, canBeRemovedSyscallList, cannotBeRemovedSyscallList,
            capToAdd, syscallsResponsibleForSysAdmin, syscallNumberToNameMap):
        removeSyscallList = set(canBeRemovedSyscallList) - set(cannotBeRemovedSyscallList)
        removeSyscallNameList = self.getSyscallNameFromSyscallNumber(removeSyscallList, syscallNumberToNameMap)

        diff = []
        isRemovable = ''
        if len(syscallsResponsibleForSysAdmin) != 0:
            diff = list(set(syscallsResponsibleForSysAdmin) - set(removeSyscallNameList))
            # remove CAP_SYS_ADMIN only when all of the syscalls responsible
            # are removable. Note: we don't remove the syscall itself since a
            # syscall can be responsible for other capabilities also. We just
            # remove the CAP_SYS_ADMIN capability
            if len(diff) == 0:
                isRemovable = 'Yes'
                capToAdd.remove('CAP_SYS_ADMIN')
                self.logger.info("... removing CAP_SYS_ADMIN")

            else:
                isRemovable = 'No'
                self.logger.info("... CAP_SYS_ADMIN can not be removed")
        
        return capToAdd, isRemovable


    def runCapabilityAnalysis(self):
        self.logger.info("Starting analysis for binary: %s ...\n", self.binaryName)

        successfullyAnalyzed = True
        canBeRemovedSyscallList = []
        cannotBeRemovedSyscallList = []
        syscallMapper = syscall.Syscall(self.logger)
        syscallNumberToNameMap = syscallMapper.createMap()
        SysAdminSyscallNumbers = {56,16, 28, 157,31,250,101,179, 71, 317,
                251, 160}
        blackListedLibraries = ["ld", "libc", "libdl", "libnss_compat", "libnsl", "libnss_files", "libnss_nis", "libm", "libresolv", "librt", "libnss_dns", "gosu"]

        self.logger.info("Starting system call extraction ...")
        # Extracting system calls using Confine
        self.logger.info("Extracting system calls using Confine and performing argument analysis for the system calls responsible for CAP_SYS_ADMIN ...")
        
        # Handle direct syscalls
        directSyscalls, successfullyAnalyzed = self.getDirectSyscalls(canBeRemovedSyscallList,
                cannotBeRemovedSyscallList, syscallNumberToNameMap, SysAdminSyscallNumbers, blackListedLibraries)
        
        # Handle imported functions
        syscallsFromImportedFunctions = self.getSyscallsFromImportedFunctions(canBeRemovedSyscallList, cannotBeRemovedSyscallList, syscallNumberToNameMap, SysAdminSyscallNumbers, blackListedLibraries)
        
        allSyscallsFromConfine = directSyscalls | syscallsFromImportedFunctions
        
        allSyscallsFromConfine = list(allSyscallsFromConfine)
        allSyscallsFromConfine.sort()
        numOfConfineSyscalls = len(allSyscallsFromConfine)
        #print('num of syscall confine', numOfConfineSyscalls)
        #print ('\nAll syscall Numbers: ', allSyscallsFromConfine, len(allSyscallsFromConfine))
        
        # Extracting system calls using Sysfilter
        self.logger.info("Extracting system calls using Sysfilter ...") 
        allSyscallsFromSysfilter, numOfSysfilterSyscalls = self.getSyscallsFromSysfilter()


        # Take intersection of Confine and Sysfilter
        self.logger.info("Generating final system call list ...")
        intersectedSyscallSet = allSyscallsFromConfine
        if (numOfSysfilterSyscalls != 0):
            intersectedSyscallSet = list(set(allSyscallsFromConfine) & set(allSyscallsFromSysfilter))
            intersectedSyscallSet.sort()
        
        numofIntersectedSyscalls = len(intersectedSyscallSet)
        #print('num of syscalls intersected', numofIntersectedSyscalls)
        self.logger.info("... System call extraction done!")
        self.logger.info("Total number of extracted system calls : %d\n", numofIntersectedSyscalls)

        # Extract names of the syscalls from syscall numbers
        syscallNameList = self.getSyscallNameFromSyscallNumber(intersectedSyscallSet, syscallNumberToNameMap)


        # Extract required capabilities from system calls
        self.logger.info("Finding required capabilities for the extracted system calls ...")
        capabilities = syscallToCapabilityMapping.Mappings(syscallNameList)
        capToAdd, syscallsResponsibleForSysAdmin = capabilities.requiredCapabilities()

        # Remove CAP_SYS_ADMIN using argument analysis
        self.logger.info("Checking if CAP_SYS_ADMIN is required based on the argument analysis ...")
        capToAdd, isRemovable = self.removeCapSysAdmin(canBeRemovedSyscallList, cannotBeRemovedSyscallList, capToAdd, syscallsResponsibleForSysAdmin, syscallNumberToNameMap);
        self.logger.info("Total num of capabilties to add : %d", len(capToAdd))
        
        # Add capabilities to binary
        self.addCapsToBinary(capToAdd)

        return syscallsResponsibleForSysAdmin, isRemovable, capToAdd, numOfConfineSyscalls, numOfSysfilterSyscalls, numofIntersectedSyscalls, successfullyAnalyzed
