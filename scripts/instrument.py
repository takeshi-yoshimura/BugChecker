#!/usr/bin/python
import sys, os, shutil
from collections import defaultdict

target_struct = ["pci_driver", "dev_pm_ops", "pci_error_handlers", "platform_driver", "i2c_driver"]

pm_callback_prefix = "wrapper_pm_"
pm_callbacks = {
"prepare": ["int", ["struct device *", "dev"]],
"complete": ["void", ["struct device *", "dev"]],
"suspend": ["int", ["struct device *", "dev"]],
"resume": ["int", ["struct device *", "dev"]],
"freeze": ["int", ["struct device *", "dev"]],
"thaw": ["int", ["struct device *", "dev"]],
"poweroff": ["int", ["struct device *", "dev"]],
"restore": ["int", ["struct device *", "dev"]],
"suspend_late": ["int", ["struct device *", "dev"]],
"resume_early": ["int", ["struct device *", "dev"]],
"freeze_late": ["int", ["struct device *", "dev"]],
"thaw_early": ["int", ["struct device *", "dev"]],
"poweroff_late": ["int", ["struct device *", "dev"]],
"restore_early": ["int", ["struct device *", "dev"]],
"suspend_noirq": ["int", ["struct device *", "dev"]],
"resume_noirq": ["int", ["struct device *", "dev"]],
"freeze_noirq": ["int", ["struct device *", "dev"]],
"thaw_noirq": ["int", ["struct device *", "dev"]],
"poweroff_noirq": ["int", ["struct device *", "dev"]],
"restore_noirq": ["int", ["struct device *", "dev"]],
}
pci_callback_prefix = "wrapper_pci_driver_"
pci_callbacks = {
"probe": ["int", ["struct pci_dev *", "dev"], ["const struct pci_device_id *", "id"]],
"remove": ["void", ["struct pci_dev *", "dev"]],
"suspend": ["int", ["struct pci_dev *", "dev"], ["pm_message_t", "state"]],
"suspend_late": ["int", ["struct pci_dev *", "dev"], ["pm_message_t", "state"]],
"resume_early": ["int", ["struct pci_dev *", "dev"]],
"resume": ["int", ["struct pci_dev *", "dev"]],
"shutdown": ["void", ["struct pci_dev *", "dev"]],
#"sriov_configure": ["int", ["struct pci_dev *", "dev"], ["int", "num_vfs"]],
}
pci_error_handlers_callback_prefix = "wrapper_pci_error_handlers_"
pci_error_handlers_callbacks = {
"error_detected": ["pci_ers_result_t", ["struct pci_dev *", "dev"], ["pci_channel_state_t", "error"]],
"mmio_enabled": ["pci_ers_result_t", ["struct pci_dev *", "dev"]],
"link_reset": ["pci_ers_result_t", ["struct pci_dev *", "dev"]],
"slot_reset": ["pci_ers_result_t", ["struct pci_dev *", "dev"]],
"resume": ["void", ["struct pci_dev *", "dev"]],
}

platform_callback_prefix = "wrapper_platform_driver_"
platform_callbacks = {
"probe": ["int", ["struct platform_device *", "dev"]],
"remove": ["void", ["struct platform_device *", "dev"]],
"suspend": ["int", ["struct platform_device *", "dev"], ["pm_message_t", "state"]],
"resume": ["int", ["struct platform_device *", "dev"]],
"shutdown": ["void", ["struct platform_device *", "dev"]],
}

i2c_callback_prefix = "wrapper_i2c_driver_"
i2c_callbacks = {
"probe": ["int", ["struct i2c_client *", "cl"], ["const struct i2c_device_id *", "id"]],
"remove": ["void", ["struct i2c_client *", "cl"]],
"shutdown": ["void", ["struct i2c_client *", "cl"]],
}


def printStructFunc(callbacks, opsForFile, prefix):
    outStr = ""
    for structFunc in callbacks.keys():
        retType = callbacks[structFunc][0]
        args = callbacks[structFunc][1:]
        declStr = "static " + retType + " " + prefix + structFunc + "("
        for arg in args[:-1]:
            declStr += arg[0] + " " + arg[1] + ", "
        declStr += args[-1][0] + " " + args[-1][1] + ")"

        outStr += declStr + " {\n"
        if opsForFile.has_key(structFunc):
            callStr = opsForFile[structFunc] + "("
            for arg in args[:-1]:
                callStr += arg[1] + ", "
            callStr += args[-1][1] + ");"
            if callbacks[structFunc][0] != "void":
                outStr += "\treturn " + callStr + "\n"
            else:
                outStr += "\t" + callStr + "\n"
        elif structFunc == "shutdown" and opsForFile.has_key("remove"):
            callStr = opsForFile["remove"] + "("
            for arg in args[:-1]:
                callStr += args[1] + ", "
            callStr += args[-1][1] + ");"
            outStr += "\t" + callStr + "\n"
        else:
            if callbacks[structFunc][0] != "void":
                outStr += "\treturn 0;\n"
        outStr += "}\n"
    return outStr




if len(sys.argv) != 4:
    print "specify (linux dir) (driver_life.c) (getentryexit subdir)"
    exit(1)

linux_dir = sys.argv[1]
model_file = sys.argv[2]
output_dir = sys.argv[3]

f = open(output_dir + "/traverse.txt")
lines = f.readlines()
f.close()

pci_drivers = defaultdict(dict)
dev_pm_ops = defaultdict(dict)
pci_error_handlers = defaultdict(dict)
platform_drivers = defaultdict(dict)
i2c_drivers = defaultdict(dict)

files = set([])

for line in lines:
    line_split = line.strip().split('\t')
    type = line_split[0]
    func = line_split[1]
    
    if type.find("argof(") != -1:
        continue
    elif type == "rhs" or type == "init":
        continue
    
    struct = type[:type.find("::")]
    structFunc = type[type.find("::") + 2:]
    
    if not struct in target_struct:
        continue
    
    file = linux_dir + "/" + func[:func.rfind("/")] + ".c"
    callback = func[func.rfind("/") + 1:]

    files.add(file)
    if struct == "pci_driver":
        pci_drivers[file][structFunc] = callback
    elif struct == "dev_pm_ops":
        dev_pm_ops[file][structFunc] = callback
    elif struct == "pci_error_handlers":
        pci_error_handlers[file][structFunc] = callback
    elif struct == "platform_driver":
        platform_drivers[file][structFunc] = callback
    elif struct == "i2c_driver":
        i2c_drivers[file][structFunc] = callback

f = open(model_file, "r")
scenarioStr = f.read()
f.close()

f2 = open(output_dir + "/build_target.txt", "w")
for file in files:
    defineStr = ""
    outStr = ""
    if pci_drivers.has_key(file):
        defineStr += "#define TEST_PCI_DRIVER\n"
        outStr += printStructFunc(pci_callbacks, pci_drivers[file], pci_callback_prefix)
        if dev_pm_ops.has_key(file):
            defineStr += "#define TEST_PM\n"
            outStr += printStructFunc(pm_callbacks, dev_pm_ops[file], pm_callback_prefix)
        if pci_error_handlers.has_key(file):
            defineStr += "#define TEST_PCI_ERROR_HANDLERS\n"
            outStr += printStructFunc(pci_error_handlers_callbacks, pci_error_handlers[file], pci_error_handlers_callback_prefix)
    if platform_drivers.has_key(file):
        defineStr += "#define TEST_PLATFORM_DRIVER\n"
        outStr += printStructFunc(platform_callbacks, platform_drivers[file], platform_callback_prefix)
    if i2c_drivers.has_key(file):
        defineStr += "#define TEST_I2C_DRIVER\n"
        outStr += printStructFunc(i2c_callbacks, i2c_drivers[file], i2c_callback_prefix)

    f = open(file, "a")
    f.write("\n/* the below section is automatically added by instrument.py */\n\n")
    f.write("#ifdef __clang_analyzer__\n\n")
    f.write(defineStr + "\n")
    f.write(scenarioStr + "\n")
    f.write(outStr + "\n")
    f.write("\n#endif /* __clang_analyzer__*/")
    f.close()

    f2.write(file[:file.rfind(".c")] + ".o\n")
f2.close()
