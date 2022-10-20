import os, sys
import subprocess
import logging

def runCommand(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    outStr = str(out.decode("utf-8"))
    errStr = str(err.decode("utf-8"))
    return (proc.returncode, outStr, errStr)


def readLibrariesWithLdd(elfPath):
    cmd = "ldd " + elfPath
    (returncode, out, err) = runCommand(cmd)
    if ( returncode != 0 ):
        logging.critical("ldd error for %s", elfPath)
        return dict()

    loadings = dict()

    # Read all imports and exports per each library
    for lib in out.split('\n\t'):
        # Exclude a virtual dynamically linked shared object(VDSO) and a dynamic loader(DL)
        if 'linux-vdso' not in lib and 'ld-linux' not in lib:
            try:
                libname, libpath = lib.split(" => ")
                libname = libname.split(".")[0]         # Library name only w/o version
                libpath = libpath.split("(")[0].strip() # Discard the address
                if libpath!='not found':
                    loadings[libname] = libpath

            except:
                logging.critical("Parsing Error with %s outcome!" % ("ldd"))

    return loadings


def extractImportedFunctions(fileName, libcOnly=False): #removed logger from the parameter
    if ( libcOnly ):
        cmd = "objdump -T " + fileName + " | grep \"UND\" | grep -i libc | awk '{print $5,$6}'"
    else:
        cmd = "objdump -T " + fileName + " | grep \"UND\" | awk '{print $5,$6}'"
    """
    if ( logger ):
        logger.debug("Running command: %s", cmd)
    """
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting imported functions: %s", err)
        return None
    functionList = []
    splittedOut = out.splitlines()
    for line in splittedOut:
        if ( len(line.split()) > 1 ):
            line = line.split()[1]
        functionList.append(line.strip())
    #print ("File ",fileName, "\n");
    #print ("Functionlist: ",functionList,"\n");
    return functionList

def setLogPath(logPath, options):
    """
    Set the property of the logger: path, config, and format
    :param logPath:
    :return:
    """
    if os.path.exists(logPath):
        os.remove(logPath)

    rootLogger = logging.getLogger("coverage")
    if options.debug:
        logging.basicConfig(filename=logPath, level=logging.DEBUG)
        rootLogger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(filename=logPath, level=logging.INFO)
        rootLogger.setLevel(logging.INFO)

    consoleHandler = logging.StreamHandler()
    rootLogger.addHandler(consoleHandler)
    return rootLogger
