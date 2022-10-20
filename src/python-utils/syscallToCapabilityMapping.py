import sys
import os
import util
import re
from collections import ChainMap

class Mappings:
    """
    This class is used to find required capability
    """
    def __init__(self, syscallNameList):
        self.syscallNameList = syscallNameList

    def requiredCapabilities(self):
        capList = set()
        syscallResponsibleForSysAdmin = []
        syscallList = self.syscallNameList
        for sysCall in syscallList:
            caps = self.sysToCapMap(sysCall)
            if caps != None:
                for capName, value in caps:
                    if capName == "CAP_SYS_ADMIN":
                        syscallResponsibleForSysAdmin.append(sysCall)
                    capList.add(capName)
                    
        #print('\nsyscall responsible for SYS_ADMIN:', syscallResponsibleForSysAdmin)
        capListFinal = set()

        for capName in capList:
            parentCap = self.capHierarchy(capName)
            if parentCap != None:
                if parentCap not in capList:
                    capListFinal.add(capName)
            else:
                capListFinal.add(capName)
        #print('Final-----',capListFinal)

        return capListFinal, syscallResponsibleForSysAdmin

    def sysToCapMap(self, sysCall):
        d = {"ioctl": [
                ('CAP_SYS_ADMIN',0), 
                ('CAP_FOWNER',0), 
                ('CAP_KILL',0), 
                ('CAP_LINUX_IMMUTABLE',0), 
                ('CAP_NET_ADMIN',0), 
                ('CAP_SYS_RESOURCE',0), 
                ('CAP_SYS_TTY_CONFIG',0)
                ], 
            "open" : [
                ('CAP_FOWNER',0), 
                ('CAP_DAC_OVERRIDE',0), 
                ('CAP_DAC_READ_SEARCH',0)
                ],
             "openat" : [
                 ('CAP_FOWNER',0),
                 ('CAP_DAC_OVERRIDE',0),
                 ('CAP_DAC_READ_SEARCH',0)
                 ],

             "openat2" : [
                 ('CAP_FOWNER',0),
                 ('CAP_DAC_OVERRIDE',0),
                 ('CAP_DAC_READ_SEARCH',0)
                 ],

             "open_by_handle_at": [
                 ('CAP_DAC_READ_SEARCH',1)
                 ],
             "chmod": [
                 ('CAP_FOWNER',0), 
                 ('CAP_FSETID',0)
                 ],
             "fchmod": [
                 ('CAP_FOWNER',0), 
                 ('CAP_FSETID',0)
                 ],
             "fchmodat": [
                 ('CAP_FOWNER',0), 
                 ('CAP_FSETID',0)
                 ],
             "kill": [
                 ('CAP_KILL',1)
                 ],
             "sendto":[
                 ('CAP_AUDIT_CONTROL',0),('CAP_SYS_RESOURCE',0),
                 ('CAP_AUDIT_WRITE',0)
                 ],
             "send":[
                 ('CAP_AUDIT_CONTROL',0),('CAP_SYS_RESOURCE',0)
                 ],
             "sendmsg":[
                 ('CAP_AUDIT_CONTROL',0),('CAP_SYS_RESOURCE',0)
                 ],
              "recvmsg":[('CAP_AUDIT_CONTROL',0)],
             "recv":[('CAP_AUDIT_CONTROL',0)],
             "recvfrom":[('CAP_AUDIT_CONTROL',0)],
             "epoll_ctl":[('CAP_BLOCK_SUSPEND',0)],
             "bpf":[('CAP_SYS_ADMIN',1)],
             "clone":[('CAP_SYS_ADMIN',0), ('CAP_SETFCAP',0)],
             "perf_event_open":[('CAP_SYS_ADMIN',1)],
             "syslog":[('CAP_SYSLOG',1)],
             "mount":[('CAP_SYS_ADMIN',1)],
             "umount":[('CAP_SYS_ADMIN',1)],
             "pivot_root":[('CAP_SYS_ADMIN',1)],
             "swapon":[('CAP_SYS_ADMIN',1)],
             "swapoff":[('CAP_SYS_ADMIN',1)],
             "sethostname":[('CAP_SYS_ADMIN',1)],
             "setdomainname":[('CAP_SYS_ADMIN',1)],
             "quotactl":[('CAP_SYS_ADMIN',0)],
             "vm86":[('CAP_SYS_ADMIN',1)],
             "lookup_dcookie":[('CAP_SYS_ADMIN',1)],
             "io_submit":[('CAP_SYS_ADMIN',1)],
             "msgctl":[('CAP_SYS_ADMIN',0), ('CAP_IPC_OWNER',0),('CAP_SYS_RESOURCE',0)],
             "setrlimit":[('CAP_SYS_ADMIN',0),('CAP_SYS_RESOURCE',0)],
             "shmctl":[('CAP_SYS_ADMIN',0),('CAP_IPC_OWNER',0)],
             "ioprio_set":[('CAP_SYS_ADMIN',0), ('CAP_SYS_NICE',0)],
             "setns":[('CAP_SYS_ADMIN',1), ('CAP_SYS_CHROOT',0)],
             "fanotify_init":[('CAP_SYS_ADMIN',1)],
             "keyctl":[('CAP_SYS_ADMIN',0),('CAP_SETUID',0)],
             "madvise":[('CAP_SYS_ADMIN',0)],
             "nfsservctl":[('CAP_SYS_ADMIN',1)],
             "bdflush":[('CAP_SYS_ADMIN',1)],
             "unshare":[('CAP_SYS_ADMIN',1)],
             "seccomp":[('CAP_SYS_ADMIN',0)],
             "ptrace":[('CAP_SYS_ADMIN',0), ('CAP_SYS_PTRACE',1)],
             "chown":[('CAP_CHOWN',1)],
             "fchown":[('CAP_CHOWN',1)],
             "lchown":[('CAP_CHOWN',1)],
             "fchownat":[('CAP_CHOWN',1)],
             "linkat":[('CAP_DAC_READ_SEARCH',0)],
             "utime":[('CAP_DAC_OVERRIDE',0), ('CAP_FOWNER',0)],
             "utimensat":[('CAP_DAC_OVERRIDE',0), ('CAP_FOWNER',0)],
             "utimes":[('CAP_DAC_OVERRIDE',0), ('CAP_FOWNER',0)],
             "unlink":[('CAP_FOWNER',0)],
             "unlinkat":[('CAP_FOWNER',0)],
             "fcntl":[('CAP_FOWNER',0), ('CAP_LEASE',0), ('CAP_SYS_RESOURCE',0)],
             "rename":[('CAP_FOWNER',0)],
             "renameat":[('CAP_FOWNER',0)],
             "renameat2":[('CAP_FOWNER',0),('CAP_MKNOD',0)],
             "rmdir":[('CAP_FOWNER',0)],
             "mlock":[('CAP_IPC_LOCK',1)],
             "mlock2":[('CAP_IPC_LOCK',1)],
             "mlockall":[('CAP_IPC_LOCK',1)],
             "mmap":[('CAP_IPC_LOCK',0)],
             "memfd_create":[('CAP_IPC_LOCK',0)],
             "msgget":[('CAP_IPC_OWNER',0)],
             "msgrcv":[('CAP_IPC_OWNER',0)],
             "semop":[('CAP_IPC_OWNER',1)],
             "semtimedop":[('CAP_IPC_OWNER',1)],
             "shmat":[('CAP_IPC_OWNER',1)],
             "shmdt":[('CAP_IPC_OWNER',1)],
             "msgsnd":[('CAP_IPC_OWNER',0)],
             "mknod":[('CAP_MKNOD',0)],
             "mknodat":[('CAP_MKNOD',0)],
             "setsockopt":[('CAP_NET_ADMIN',0)],
             "bind":[('CAP_NET_BIND_SERVICE',0), ('CAP_AUDIT_READ',0)],
             "socket":[('CAP_NET_RAW',0), ('CAP_MAC_OVERRIDE',0)],
             "setgroups":[('CAP_SETGID',1)],
             "setfsgid":[('CAP_SETGID',1)],
             "setgid":[('CAP_SETGID',0)],
             "setregid":[('CAP_SETGID',0)],
             "setresgid":[('CAP_SETGID',0)],
             "prctl":[('CAP_SETPCAP',0), ('CAP_SYS_RESOURCE',0), ('CAP_SYS_ADMIN',0)],
             "capset":[('CAP_SETPCAP',1)],
             "setuid":[('CAP_SETUID',0)],
             "setreuid":[('CAP_SETUID',1)],
             "setresuid":[('CAP_SETUID',1)],
             "setfsuid":[('CAP_SETUID',1)],
             "reboot":[('CAP_SYS_BOOT',1)],
             "kexec_load":[('CAP_SYS_BOOT',1)],
             "kexec_file_load":[('CAP_SYS_BOOT',1)],
             "chroot":[('CAP_SYS_CHROOT',1)],
             "nice":[('CAP_SYS_NICE',0)],
             "setpriority":[('CAP_SYS_NICE',0)],
             "sched_setscheduler":[('CAP_SYS_NICE',1)],
             "sched_setparam":[('CAP_SYS_NICE',1)],
             "sched_setattr":[('CAP_SYS_NICE',1)],
             "sched_setaffinity":[('CAP_SYS_NICE',0)],
             "migrate_pages":[('CAP_SYS_NICE',1)],
             "move_pages":[('CAP_SYS_NICE',0)],
             "spu_create":[('CAP_SYS_NICE',0)],
             "mbind":[('CAP_SYS_NICE',0)],
             "acct":[('CAP_SYS_PACCT',1)],
             "set_robust_list":[('CAP_SYS_PTRACE',1)],
             "process_vm_readv":[('CAP_SYS_PTRACE',1)],
             "process_vm_writev":[('CAP_SYS_PTRACE',1)],
             "userfaultfd":[('CAP_SYS_PTRACE',1)],
             "kcmp":[('CAP_SYS_PTRACE',1)],
             "iopl":[('CAP_SYS_RAWIO',1)],
             "ioperm":[('CAP_SYS_RAWIO',0)],
             "prlimit":[('CAP_SYS_RESOURCE',0)],
             "mq_open":[('CAP_SYS_RESOURCE',0)],
             "settimeofday":[('CAP_SYS_TIME',1)],
             "stime":[('CAP_SYS_TIME',1)],
             "adjtimex":[('CAP_SYS_TIME',0)],
             "clock_adjtime":[('CAP_SYS_TIME',0)],
             "ntp_adjtime":[('CAP_SYS_TIME',0)],
             "vhangup":[('CAP_SYS_TTY_CONFIG',1)],
             "timer_create":[('CAP_WAKE_ALARM',0)],
             "timerfd_settime":[('CAP_WAKE_ALARM',0)],
             "finit_module":[('CAP_SYS_MODULE'),0],
             "init_module":[('CAP_SYS_MODULE',0)],
             "create_module":[('CAP_SYS_MODULE',0)],
             "delete_module":[('CAP_SYS_MODULE',0)],
             "setxattr":[('CAP_MAC_ADMIN',0)],
             "lsetxattr":[('CAP_MAC_ADMIN',0)],
             "fsetxattr":[('CAP_MAC_ADMIN',0)]
             }
             
        caps = d.get(sysCall)
        return caps

    def capHierarchy (self, cap):
        CH = {"CAP_AUDIT_READ": "CAP_AUDIT_CONTROL",
              "CAP_AUDIT_WRITE":"CAP_AUDIT_CONTROL",
              "CAP_BPF":"CAP_SYS_ADMIN",
              "CAP_CHECKPOINT_RESTORE":"CAP_SYS_ADMIN",
              "CAP_PERFMON":"CAP_SYS_ADMIN",
              "CAP_SYSLOG":"CAP_SYS_ADMIN"
              }
        parent = CH.get(cap)
        return parent



