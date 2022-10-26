# Decap
Decap is a binary code analysis tool that automatically deprivileges programs by identifying the subset of capabilities they require based on the system calls they may invoke. This is made possible by our systematic effort in deriving a complete mapping between all Linux system calls related to privileged operations and the corresponding capabilities on which they depend. We suggest reading our [paper](https://www3.cs.stonybrook.edu/~mdhasan/papers/decap.raid22.pdf) for more details.

<img style="display: block; margin-left: auto; margin-right: auto;"
     src="https://hasanmdme.github.io/decap/website/images/DecapOverview.png"
     alt="Decap overview figure" />

### System call - Capability Mapping
We performed a thorough investigation of all available Linux capabilities and the system calls they affect, to derive a detailed and complete mapping between all system calls related to privileged operations and their respective capabilities. The complete mapping can be found [here](https://hasanmdme.github.io/decap/website/syscall-capabilitymappingtable.html), and a visual representation of the mapping is available [here](https://hasanmdme.github.io/decap/website/syscall-capabilitymapping.html). 

<img style="display: block; margin-left: auto; margin-right: auto;"
     src="https://hasanmdme.github.io/decap/website/images/mapping.png"
     alt="Mapping figure" />
     
### System call Identification and Capability Enforcement
The first step in deprivileging a setuid program is to identify its required system calls. Decap performs static binary code analysis of a target program and its libraries to extract the set of all possible system calls it may invoke, and then to derive and enforce the corresponding set of required capabilities. Decap relies on both [Confine](https://www3.cs.stonybrook.edu/~sghavamnia/papers/confine.raid20.pdf) and [Sysfilter](https://cs.brown.edu/~vpk/papers/sysfilter.raid20.pdf) to identify the system calls required by a given application. Also, CAP_SYS_ADMIN capability is required by multiple system calls but only when invoked with a limited set of specific argument values. Therefore, once the set of required system calls has been extracted, Decap performs argumentlevel analysis for those system calls that conditionally require CAP_SYS_ADMIN, and attempts to extract the concrete values passed to the arguments that determine whether CAP_SYS_ADMIN is required, across all their call sites.  Decap identifies the required capabilities for an application based on the system call analysis and the previously generated mapping. Finally, it reduces the privileges by first deprivileging the target application entirely by removing its setuid bit, and then granting only the capabilities that the program actually requires.

## Step by Step Guide
This section shows the step by step guide for running Decap to generate capability profile of setuid binaries. [Read more...](https://hasanmdme.github.io/decap/website/stepbystepguide.html)

## Academic Publication
Please use the following citation for [Decap](https://www3.cs.stonybrook.edu/~mdhasan/papers/decap.raid22.pdf).
```
@inproceedings{decapraid22,
     title = {Decap: Deprivileging Programs by Reducing Their Capabilities},
     author = {Hasan, Md Mehedi and Ghavamnia, Seyedhamed and Polychronakis, Michalis},
     booktitle = {Proceedings of the International Conference on Research in Attacks, 
     Intrusions, and Defenses (RAID)},
     year = {2022}
}
```
