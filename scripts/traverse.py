#!/usr/bin/python
import sys
from collections import defaultdict

entryExits = defaultdict(set)
entryTypes = defaultdict(set)
shouldLink = defaultdict(str)
globalFuncs = set([])
for line in sys.stdin:
    line_split = line.strip().split("\t")
    entryType = line_split[0].strip()
    entryFunc = line_split[1].strip()
    exitFuncs = line_split[2].strip().split(" ")

    entryTypes[entryFunc].add(entryType)
    if exitFuncs[0] == "(has-no-body)":
        realName = entryFunc[entryFunc.rfind('/') + 1:]
        shouldLink[entryFunc] = realName
    elif not entryExits.has_key(entryFunc):
        entryExits[entryFunc] = set(exitFuncs)
        if entryType == "global":
            globalFuncs.add(entryFunc)
    elif not entryTypes.has_key(entryType):
        continue
    else:
        warnStr = "WARNING: multiple definition of " + entryFunc
        if len(exitFuncs) >= len(entryExits[entryFunc]):
            entryExits[entryFunc] = set(exitFuncs)
            if entryType == "global":
                globalFuncs.add(entryFunc)
            warnStr += " (overwritten)"
        else:
            warnStr += " (ignored)"
        print sys.stderr, warnStr

for entryFunc in shouldLink.keys():
    if not shouldLink[entryFunc] in globalFuncs:
        print sys.stderr, "WARNING: No definition of " + shouldLink[entryFunc]
    else:
        entryExits[entryFunc] = entryExits[shouldLink[entryFunc]]

shouldExpand = defaultdict(set)
for entryFunc in entryExits.keys():
    for exitFunc in entryExits[entryFunc]:
        if exitFunc in globalFuncs:
            shouldExpand[entryFunc].add(exitFunc)

for entryFunc in shouldExpand.keys():
    expanded = shouldExpand[entryFunc]
    completed = entryExits[entryFunc] - expanded
    passed = set([entryFunc])
    while len(expanded) != 0:
        MoreExpanded = set([])
        for nextEntryFunc in expanded:
            if nextEntryFunc in passed:
                continue
            if nextEntryFunc in globalFuncs:
                MoreExpanded |= shouldExpand[nextEntryFunc]
                passed.add(nextEntryFunc)
            if entryExits.has_key(nextEntryFunc):
                completed |= entryExits[nextEntryFunc] - shouldExpand[nextEntryFunc]
        expanded = MoreExpanded
    entryExits[entryFunc] = completed

for entryFunc in entryTypes.keys():
    if entryFunc in globalFuncs:
        continue
    exitStr = ""
    for exitFunc in entryExits[entryFunc]:
        exitStr += exitFunc + " "
    exitStr = exitStr[:-1]
    for entryType in entryTypes[entryFunc]:
        if entryType != "global":
            print entryType + "\t" + entryFunc + "\t" + exitStr

