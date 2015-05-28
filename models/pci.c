/* NOTE: do not call functions defined here more than twice.
 * each function must be called only once due to clang static analyzer limitation...
 */

extern int random();

#ifdef TEST_PCI_DRIVER
static int  wrapper_pci_driver_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void wrapper_pci_driver_remove(struct pci_dev *dev);
static int  wrapper_pci_driver_suspend(struct pci_dev *dev, pm_message_t state);
static int  wrapper_pci_driver_suspend_late(struct pci_dev *dev, pm_message_t state);
static int  wrapper_pci_driver_resume_early(struct pci_dev *dev);
static int  wrapper_pci_driver_resume(struct pci_dev *dev);
static void wrapper_pci_driver_shutdown(struct pci_dev *dev);
//static int  wrapper_pci_driver_sriov_configure(struct pci_dev *dev, int num_vfs);

enum TEST_PCI_STATE {
	PCI_STATE_PROBED = 0, PCI_STATE_REMOVED, PCI_STATE_DEAD,
};
enum TEST_PCI_EVENT {
	PCI_EVENT_REMOVE = 0, PCI_EVENT_PM, PCI_EVENT_ERROR, PCI_EVENT_IDLE,
};

#endif /* TEST_PCI_DRIVER */

static int  wrapper_pm_prepare(struct device *dev);
static void wrapper_pm_complete(struct device *dev);
static int  wrapper_pm_suspend(struct device *dev);
static int  wrapper_pm_resume(struct device *dev);
static int  wrapper_pm_freeze(struct device *dev);
static int  wrapper_pm_thaw(struct device *dev);
static int  wrapper_pm_poweroff(struct device *dev);
static int  wrapper_pm_restore(struct device *dev);
static int  wrapper_pm_suspend_late(struct device *dev);
static int  wrapper_pm_resume_early(struct device *dev);
static int  wrapper_pm_freeze_late(struct device *dev);
static int  wrapper_pm_thaw_early(struct device *dev);
static int  wrapper_pm_poweroff_late(struct device *dev);
static int  wrapper_pm_restore_early(struct device *dev);
static int  wrapper_pm_suspend_noirq(struct device *dev);
static int  wrapper_pm_resume_noirq(struct device *dev);
static int  wrapper_pm_freeze_noirq(struct device *dev);
static int  wrapper_pm_thaw_noirq(struct device *dev);
static int  wrapper_pm_poweroff_noirq(struct device *dev);
static int  wrapper_pm_restore_noirq(struct device *dev);
/* currently runtime pm is not supported */
//static int  wrapper_pm_runtime_suspend(struct device *dev) { return 0; }
//static int  wrapper_pm_runtime_resume(struct device *dev) { return 0; }
//static int  wrapper_pm_runtime_idle(struct device *dev) { return 0; }

/* simplified version of hibernate() in kernel/power/hibernate.c
 * return 0 if hibernation succeeded.
 * return -1 if hibernation failed and the system should not restore.
 */
static int simple_hibernate(struct device *dev) {
/* in hibernation_snapshot() */
	if (wrapper_pm_prepare(dev) < 0) { /* = dpm_prepare(PMSG_FREEZE) */
		wrapper_pm_complete(dev); /* = dpm_complete(PMSG_RECOVER) */
		return -1;
	}
	if (wrapper_pm_freeze(dev) < 0) { /* = dpm_suspend(PMSG_FREEZE) */
		wrapper_pm_thaw(dev); /* = dpm_resume(msg) (msg = PMSG_RECOVER here) */
		wrapper_pm_complete(dev); /* = dpm_complete(msg) */
		return -1;
	}

/* call create_image() */
/* call dpm_suspend_end(PMSG_FREEZE) */
	if (wrapper_pm_freeze_late(dev) < 0) { /* = dpm_suspend_late(PMSG_FREEZE) */
		/* return from create_image(), in hibernation_snapshot() */
		wrapper_pm_thaw(dev);/* = dpm_resume(msg) (msg = PMSG_RECOVER here) */
		wrapper_pm_complete(dev); /* = dpm_complete(msg) */
		return -1;
	}
	if (wrapper_pm_freeze_noirq(dev) < 0) { /* = dpm_suspend_noirq(PMSG_FREEZE) */
		wrapper_pm_thaw_early(dev); /* = dpm_resume_early(resume_event(PMSG_FREEZE)) */
		/* return from create_image(), in hibernation_snapshot() */
		wrapper_pm_thaw(dev); /* = dpm_resume(msg) (msg = PMSG_RECOVER here) */
		wrapper_pm_complete(dev); /* dpm_complete(msg) */
		return -1;
	}
	/* hibernation aborts if *any* device fails to hibernate */
	if (random() % 2) {
		/* call dpm_resume_start(PMSG_RECOVER or PMSG_THAW) */
		wrapper_pm_thaw_noirq(dev); /* = dpm_resume_noirq(PMSG_RECOVER or PMSG_THAW) */
		wrapper_pm_thaw_early(dev); /* = dpm_resume_early(PMSG_RECOVER or PMSG_THAW) */
		/* return from create_image(), in hibernation_snapshot() */
		wrapper_pm_thaw(dev); /* = dpm_resume(msg) (msg = PMSG_RECOVER or PMSG_THAW here) */
		wrapper_pm_complete(dev); /* dpm_complete(msg) */
		return -1;
	}

	/* Now the system snapshot is held.
	 * However, we need to restore them before power off in order to provide ->poweroff()
	 * on the other hand, ->resume*() assumes resuming the state here, so bifurcate to emulate both situations
	 */

	if (random() % 2) {
		/* call dpm_resume_start(PMSG_RESTORE) */
		wrapper_pm_restore_noirq(dev); /* = dpm_resume_noirq(PMSG_RESTORE) */
		wrapper_pm_restore_early(dev); /* = dpm_resume_early(PMSG_RESTORE) */
		/* return from create_image(), in hibernation_snapshot() */
		wrapper_pm_restore(dev); /* = dpm_resume(msg) (msg = PMSG_RESTORE here) */
		wrapper_pm_complete(dev); /* dpm_complete(msg) */
		/* return from hibernation_snapshot(), in hibernate() */
		/* call hibernation_platform_enter() */
		/* call dpm_suspend_start(PMSG_HIBERNATE) */ /* call dpm_suspend_end(PMSG_HIBERNATE) */
		if (wrapper_pm_prepare(dev) < 0 || wrapper_pm_poweroff(dev) || wrapper_pm_poweroff_late(dev) ) {
		/* = dpm_prepare(PMSG_HIBERNATE) */ /* = dpm_suspend(PMSG_HIBERNATE) */ /* dpm_suspend_late(PMSG_HIBERNATE) */
			/* looks like operating normal restore procedures */
			return 0;
		}
		if (wrapper_pm_poweroff_noirq(dev) < 0) { /* dpm_suspend_noirq(PMSG_HIBERNATE) */
			wrapper_pm_restore_early(dev); /* = dpm_resume_early(resume_event(PMSG_FREEZE)) */
			/* looks like operating normal restore procedures */
			return 0;
		}
		/* call power_down() */
	}

	/* the system's power is down */

	return 0;
}

/* emulate a situation after restoring system state from a hibernation image */
static void simple_restore(struct device *dev) {
	/* resume from the middle of create_image() (at the 'snapshot is held' comment) */
	/* call dpm_resume_start(PMSG_RESTORE) */
	wrapper_pm_restore_noirq(dev); /* = dpm_resume_noirq(PMSG_RESTORE) */
	wrapper_pm_restore_early(dev); /* = dpm_resume_early(PMSG_RESTORE) */
	/* return from create_image(), in hibernation_snapshot() */
	wrapper_pm_restore(dev); /* = dpm_resume(msg) (msg = PMSG_RESTORE here) */
	wrapper_pm_complete(dev); /* dpm_complete(msg) */
	/* return from hibernation_snapshot(), in hibernate() */
}

/*  simplified version of suspend_devices_and_enter in kernel/power/suspend.c */
static int simple_suspend(struct device *dev) {
/* call dpm_suspend_start(PMSG_SUSPEND) */
	if (wrapper_pm_prepare(dev) < 0 || wrapper_pm_suspend(dev) < 0) { /* = dpm_prepare(PMSG_SUSPEND) */
		/* call dpm_resume_end(PMSG_RESUME) */
		wrapper_pm_resume(dev); /* = dpm_resume(PMSG_RESUME) */
		wrapper_pm_complete(dev); /* = dpm_complete(PMSG_RESUME) */
		return -1;
	}
/* call suspend_enter() */
	/* call dpm_suspend_end(PMSG_SUSPEND)*/
	if (wrapper_pm_suspend_late(dev) < 0) { /* = dpm_suspend_late(PMSG_SUSPEND) */
		/* call dpm_resume_end(PMSG_RESUME) */
		wrapper_pm_resume(dev); /* = dpm_resume(PMSG_RESUME) */
		wrapper_pm_complete(dev); /* = dpm_complete(PMSG_RESUME) */
		return -1;
	}
	if (wrapper_pm_suspend_noirq(dev) < 0) { /* = dpm_suspend_noirq(PMSG_SUSPEND) */
		wrapper_pm_resume_early(dev); /* dpm_resume_early(resume_event(PMSG_SUSPEND)) */
		/* call dpm_resume_end(PMSG_RESUME) */
		wrapper_pm_resume(dev); /* = dpm_resume(PMSG_RESUME) */
		wrapper_pm_complete(dev); /* = dpm_complete(PMSG_RESUME) */
		return -1;
	}

	/* suspend may abort due to fail to suspend misc devices.
	 * But that's the same as normal resume procedure so we don't explicitly write it
	 */
	return 0;
}

static void simple_resume(struct device *dev) {
	/* call dpm_resume_start(PMSG_RESUME) */
	wrapper_pm_resume_noirq(dev);
	wrapper_pm_resume_early(dev);

	/* call dpm_resume_end(PMSG_RESUME) */
	wrapper_pm_resume(dev); /* = dpm_resume(PMSG_RESUME) */
	wrapper_pm_complete(dev); /* = dpm_complete(PMSG_RESUME) */
}

/* common pm interfaces. see Documentation/power/pci.txt */
static void pci_pm_state_transition(struct pci_dev *pdev, enum TEST_PCI_STATE *state) {
	struct device *dev = &pdev->dev;
	switch (random() % 3) {
	case 0: /* suspend & resume */
		if (simple_suspend(dev) < 0) {
			break;
		}

#ifdef TEST_PCI_DRIVER
		/* suspended devices may be removed */
		if (random() % 2) {
			wrapper_pci_driver_remove(pdev);
			*state = PCI_STATE_REMOVED;
			break;
		}
#endif /* TEST_PCI_DRIVER */
		simple_resume(dev);
		break;
	case 1: /* hibernation & restore */
		if (simple_hibernate(dev) < 0) {
			break;
		}

#ifdef TEST_PCI_DRIVER
		/* hibernated devices may be removed */
		if (random() % 2) {
			wrapper_pci_driver_remove(pdev);
			*state = PCI_STATE_REMOVED;
			break;
		}
#endif /* TEST_PCI_DRIVER */

		simple_restore(dev);
		break;
	case 2: /* runtime suspend & resume */
		/* currently runtime pm is not supported */
		break;
	}
}


#ifdef TEST_PCI_DRIVER

#ifndef TEST_PM

/* see drivers/pci/pci-driver.c */
static int wrapper_pm_prepare(struct device *dev) {
	return 0;
}
static int wrapper_pm_suspend(struct device *dev) {
	return wrapper_pci_driver_suspend(to_pci_dev(dev), PMSG_SUSPEND);
}
static int wrapper_pm_suspend_noirq(struct device *dev) {
	return wrapper_pci_driver_suspend_late(to_pci_dev(dev), PMSG_SUSPEND);
}
static int wrapper_pm_resume_noirq(struct device *dev) {
	return wrapper_pci_driver_resume_early(to_pci_dev(dev));
}
static int wrapper_pm_resume(struct device *dev) {
	return wrapper_pci_driver_resume(to_pci_dev(dev));
}
static int wrapper_pm_freeze(struct device *dev) {
	return wrapper_pci_driver_suspend(to_pci_dev(dev), PMSG_FREEZE);
}
static int wrapper_pm_freeze_noirq(struct device *dev) {
	return wrapper_pci_driver_suspend_late(to_pci_dev(dev), PMSG_FREEZE);
}
static int wrapper_pm_thaw_noirq(struct device *dev) {
	return wrapper_pci_driver_resume_early(to_pci_dev(dev));
}
static int wrapper_pm_thaw(struct device *dev) {
	return wrapper_pci_driver_resume(to_pci_dev(dev));
}
static int wrapper_pm_poweroff(struct device *dev) {
	return wrapper_pci_driver_suspend(to_pci_dev(dev), PMSG_HIBERNATE);
}
static int wrapper_pm_poweroff_noirq(struct device *dev) {
	return wrapper_pci_driver_suspend_late(to_pci_dev(dev), PMSG_HIBERNATE);
}
static int wrapper_pm_restore_noirq(struct device *dev) {
	return wrapper_pci_driver_resume_early(to_pci_dev(dev));
}
static int wrapper_pm_restore(struct device *dev) {
	return wrapper_pci_driver_resume(to_pci_dev(dev));
}
static void wrapper_pm_complete(struct device *dev) {
}
static int  wrapper_pm_suspend_late(struct device *dev) {
	return 0;
}
static int  wrapper_pm_resume_early(struct device *dev) {
	return 0;
}
static int  wrapper_pm_freeze_late(struct device *dev) {
	return 0;
}
static int  wrapper_pm_thaw_early(struct device *dev) {
	return 0;
}
static int  wrapper_pm_poweroff_late(struct device *dev) {
	return 0;
}
static int  wrapper_pm_restore_early(struct device *dev) {
	return 0;
}
#endif


#ifdef TEST_PCI_ERROR_HANDLERS
static pci_ers_result_t wrapper_pci_error_handlers_error_detected(struct pci_dev *dev, pci_channel_state_t error);
static pci_ers_result_t wrapper_pci_error_handlers_mmio_enabled(struct pci_dev *dev);
static pci_ers_result_t wrapper_pci_error_handlers_link_reset(struct pci_dev *dev);
static pci_ers_result_t wrapper_pci_error_handlers_slot_reset(struct pci_dev *dev);
static void wrapper_pci_error_handlers_resume(struct pci_dev *dev);

/* see Documentation/PCI/pci-error-recovery.txt */
static void pci_error_handlers_state_transition(struct pci_dev *pdev, enum TEST_PCI_STATE *state) {
	/* STEP 1: Notification */
	switch(wrapper_pci_error_handlers_error_detected(pdev, random() % 3 + 1)) {
	case PCI_ERS_RESULT_CAN_RECOVER:
		if (random() % 2)
			goto mmio_enable; /* If **all** drivers on the segment/slot return PCI_ERS_RESULT_CAN_RECOVER */
		goto slot_reset; /* If **any** driver requested a slot reset (by returning PCI_ERS_RESULT_NEED_RESET) */
	case PCI_ERS_RESULT_NEED_RESET:
		goto slot_reset;
	case PCI_ERS_RESULT_DISCONNECT:
		goto permanent_failure;
	default:
		goto not_implemented;
	}
mmio_enable: /* STEP 2: MMIO Enable */
	switch(wrapper_pci_error_handlers_mmio_enabled(pdev)) {
	case PCI_ERS_RESULT_RECOVERED:
		if (random() % 2)
			goto link_reset; /* link reset operations will probably be ignored */
		goto slot_reset; /* If **any** driver returned PCI_ERS_RESULT_NEED_RESET */
	case PCI_ERS_RESULT_NEED_RESET:
		goto slot_reset;
	case PCI_ERS_RESULT_DISCONNECT:
		goto permanent_failure;
	default:
		goto resume_operation;
	}
link_reset: /* STEP 3: Link Reset */
	switch(wrapper_pci_error_handlers_link_reset(pdev)) {
	case PCI_ERS_RESULT_RECOVERED:
		goto resume_operation;
	case PCI_ERS_RESULT_NEED_RESET:
		goto slot_reset;
	case PCI_ERS_RESULT_DISCONNECT:
		goto permanent_failure;
	default:
		goto resume_operation;
	}
slot_reset: /* STEP 4: Slot Reset */
	switch(wrapper_pci_error_handlers_slot_reset(pdev)) {
	case PCI_ERS_RESULT_RECOVERED:
		if (random() % 2)
			goto resume_operation;
		goto permanent_failure;
	case PCI_ERS_RESULT_DISCONNECT:
		goto permanent_failure;
	default:
		goto resume_operation;
	}
resume_operation: /* STEP 5: Resume Operation */
	wrapper_pci_error_handlers_resume(pdev);
	return;
permanent_failure: /* STEP 6: Permanent Failure */
	wrapper_pci_error_handlers_error_detected(pdev, pci_channel_io_perm_failure);
	*state = PCI_STATE_DEAD;
not_implemented:/* PCI error recovery is not implemented */
	;
}
#else
static void pci_error_handlers_state_transition(struct pci_dev *dev, enum TEST_PCI_STATE *state) {}
#endif /* TEST_PCI_ERROR_HANDLERS */



static void idle_pci_driver(struct pci_dev *pdev) { }

static void TestPCIDriver(struct pci_dev *pdev, const struct pci_device_id *id) {
	int loop = 0;
	enum TEST_PCI_STATE state;
reprobe:
	if (wrapper_pci_driver_probe(pdev, id)) {
		return;
	}
	state = PCI_STATE_PROBED;

normal_operation:
	switch(random() % 4) {
	case PCI_EVENT_PM:
		pci_pm_state_transition(pdev, &state);
		break;
	case PCI_EVENT_ERROR:
		pci_error_handlers_state_transition(pdev, &state);
		break;
	case PCI_EVENT_REMOVE:
		wrapper_pci_driver_remove(pdev);
		state = PCI_STATE_REMOVED;
		if (random() % 2 && loop++ < 10) {
			goto reprobe;
		}
		break;
	default:
		idle_pci_driver(pdev);
	}
	if (random() % 2 && loop++ < 10 && state == PCI_STATE_PROBED) {
		goto normal_operation;
	}

	wrapper_pci_driver_shutdown(pdev);
}

#endif /* TEST_PCI_DRIVER */
