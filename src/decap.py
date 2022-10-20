import os, sys, subprocess, signal
import optparse
import logging
sys.path.insert(0, './python-utils/')

import capabilityAnalysis
import util
import pandas as pd
import json
import pexpect

def isValidOpts(opts):
    if ( not options.input) or (not options.sysfilterpath):
        parser.error("Options --input and --sysfilterpath should be provided")
        return False

    return True

if __name__ == '__main__':
    usage = "Usage: %prog --input <InputFile.json> --sysfilterpath <SysfilterPath>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-i", "--input", dest="input", default=None, nargs=1,
                      help="Input file containing list of setuid binaries for capability analysis")

    parser.add_option("-s", "--sysfilterpath", dest="sysfilterpath",
            default=None, nargs=1,
                      help="Path of the sysfilter_extract executable")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = util.setLogPath("../log/Capability.log", options)

        # 1. parse input JSON
        try:
            inputJsonFile = open(options.input, 'r')
            inputJsonStr = inputJsonFile.read()
            inputJson = json.loads(inputJsonStr)
            #print(inputJson)
        except Exception as e:
            rootLogger.error("Trying to load input json from: %s, but doesn't exist: %s", options.input, str(e))
            rootLogger.error("Exiting...")
            sys.exit(-1)

        CapStat = pd.DataFrame(columns
                =['app_name','syscalls_responsible_for_SYS_ADMIN', 'SYS_ADMIN removed?', 'total_capabilities', 'total_cap_count',
                    'number_of_syscalls_from_Confine','number_of_syscalls_from_Sysfilter','number_of_intersected_syscalls']) #final dataframe to get the statistics of capability

        for binaryName, Values in inputJson.items():
            binaryPath = Values.get("binary-path", None)
            capAnalysis = capabilityAnalysis.CapabilityAnalysis(binaryName, binaryPath, rootLogger, options.sysfilterpath)
            syscallsResponsibleForSysAdmin, isRemovable, capToAdd, numOfConfineSyscalls, numOfSysfilterSyscalls, numofIntersectedSyscalls, success  = capAnalysis.runCapabilityAnalysis()
            if (not success):
                rootLogger.info("Couldn't successfully analyze binary %s!", binaryName)
            else:
                rootLogger.info("Done capability analysis for %s!", binaryName)
                added_cap_count = len(capToAdd)
                CapStat = CapStat.append({'app_name' : binaryName, 'syscalls_responsible_for_SYS_ADMIN' : syscallsResponsibleForSysAdmin, 'SYS_ADMIN removed?' : isRemovable, 'total_capabilities' : capToAdd, 'total_cap_count' : added_cap_count, 'number_of_syscalls_from_Confine' : numOfConfineSyscalls, 'number_of_syscalls_from_Sysfilter' : numOfSysfilterSyscalls , 'number_of_intersected_syscalls' : numofIntersectedSyscalls}, ignore_index = True)
            rootLogger.info("----------------------------------------------------------------\n")
            
            
        CapStat.to_csv('Output_Stat.csv')

