// SPDX-License-Identifier: GPL-2.0+
/*
 * Sunway PCI Express Hot Plug Controller Driver
 */

#define dev_fmt(fmt) "sunway_pciehp: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pm_runtime.h>
#include <linux/pci.h>
#include <asm/sw64io.h>

#include "sunway_pciehp.h"
#include "../pci.h"

/* The following routines constitute the bulk of the
 * hotplug controller logic
 */

#define SAFE_REMOVAL	 true
#define SURPRISE_REMOVAL false

static void set_slot_off(struct controller *ctrl)
{
	/*
	 * Turn off slot, turn on attention indicator, turn off power
	 * indicator
	 */
	if (POWER_CTRL(ctrl)) {
		sunway_pciehp_power_off_slot(ctrl);

		/*
		 * After turning power off, we must wait for at least 1 second
		 * before taking any action that relies on power having been
		 * removed from the slot/adapter.
		 */
		msleep(1000);
	}

	sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_OFF,
			PCI_EXP_SLTCTL_ATTN_IND_ON);
}

/**
 * board_added - Called after a board has been added to the system.
 * @ctrl: PCIe hotplug controller where board is added
 *
 * Turns power on for the board.
 * Configures board.
 */
static int board_added(struct controller *ctrl)
{
	int retval = 0;
	struct pci_bus *parent = ctrl->pci_dev->subordinate;

	if (POWER_CTRL(ctrl)) {
		/* Power on slot */
		retval = sunway_pciehp_power_on_slot(ctrl);
		if (retval)
			return retval;
	}

	sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_BLINK,
			INDICATOR_NOOP);

	/* Check link training status */
	retval = sunway_pciehp_check_link_status(ctrl);
	if (retval)
		goto err_exit;

	/* Check for a power fault */
	if (ctrl->power_fault_detected || sunway_pciehp_query_power_fault(ctrl)) {
		ctrl_err(ctrl, "Slot(%s): Power fault\n", slot_name(ctrl));
		retval = -EIO;
		goto err_exit;
	}

	retval = sunway_pciehp_configure_device(ctrl);
	if (retval) {
		if (retval != -EEXIST) {
			ctrl_err(ctrl, "Cannot add device at %04x:%02x:00\n",
				 pci_domain_nr(parent), parent->number);
			goto err_exit;
		}
	}

	sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_ON,
			PCI_EXP_SLTCTL_ATTN_IND_OFF);
	return 0;

err_exit:
	set_slot_off(ctrl);
	return retval;
}

/**
 * remove_board - Turn off slot and Power Indicator
 * @ctrl: PCIe hotplug controller where board is being removed
 * @safe_removal: whether the board is safely removed (versus surprise removed)
 */
static void remove_board(struct controller *ctrl, bool safe_removal)
{
	sunway_pciehp_unconfigure_device(ctrl, safe_removal);

	if (POWER_CTRL(ctrl)) {
		sunway_pciehp_power_off_slot(ctrl);

		/*
		 * After turning power off, we must wait for at least 1 second
		 * before taking any action that relies on power having been
		 * removed from the slot/adapter.
		 */
		msleep(1000);

		/* Ignore link or presence changes caused by power off */
		atomic_and(~(PCI_EXP_SLTSTA_DLLSC | PCI_EXP_SLTSTA_PDC),
			   &ctrl->pending_events);
	}

	/* turn off Green LED */
	sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_OFF,
			INDICATOR_NOOP);
}

static int sunway_pciehp_enable_slot(struct controller *ctrl);
static int sunway_pciehp_disable_slot(struct controller *ctrl, bool safe_removal);

void sunway_pciehp_request(struct controller *ctrl, int action)
{
	atomic_or(action, &ctrl->pending_events);
	if (!sunway_pciehp_poll_mode)
		irq_wake_thread(ctrl->pci_dev->irq, ctrl);
}

void sunway_pciehp_queue_pushbutton_work(struct work_struct *work)
{
	struct controller *ctrl = container_of(work, struct controller,
			button_work.work);

	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case BLINKINGOFF_STATE:
		sunway_pciehp_request(ctrl, DISABLE_SLOT);
		break;
	case BLINKINGON_STATE:
		sunway_pciehp_request(ctrl, PCI_EXP_SLTSTA_PDC);
		break;
	default:
		break;
	}
	mutex_unlock(&ctrl->state_lock);
}

void sunway_pciehp_handle_button_press(struct controller *ctrl)
{
	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case OFF_STATE:
	case ON_STATE:
		if (ctrl->state == ON_STATE) {
			ctrl->state = BLINKINGOFF_STATE;
			ctrl_info(ctrl, "Slot(%s): Powering off due to button press\n",
				  slot_name(ctrl));
		} else {
			ctrl->state = BLINKINGON_STATE;
			ctrl_info(ctrl, "Slot(%s) Powering on due to button press\n",
				  slot_name(ctrl));
		}
		/* blink power indicator and turn off attention */
		sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_BLINK,
				PCI_EXP_SLTCTL_ATTN_IND_OFF);
		schedule_delayed_work(&ctrl->button_work, 5 * HZ);
		break;
	case BLINKINGOFF_STATE:
	case BLINKINGON_STATE:
		/*
		 * Cancel if we are still blinking; this means that we
		 * press the attention again before the 5 sec. limit
		 * expires to cancel hot-add or hot-remove
		 */
		ctrl_info(ctrl, "Slot(%s): Button cancel\n", slot_name(ctrl));
		cancel_delayed_work(&ctrl->button_work);
		if (ctrl->state == BLINKINGOFF_STATE) {
			ctrl->state = ON_STATE;
			sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_ON,
					PCI_EXP_SLTCTL_ATTN_IND_OFF);
		} else {
			ctrl->state = OFF_STATE;
			sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_OFF,
					PCI_EXP_SLTCTL_ATTN_IND_OFF);
		}
		ctrl_info(ctrl, "Slot(%s): Action canceled due to button press\n",
			  slot_name(ctrl));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Ignoring invalid state %#x\n",
			 slot_name(ctrl), ctrl->state);
		break;
	}
	mutex_unlock(&ctrl->state_lock);
}

void sunway_pciehp_handle_disable_request(struct controller *ctrl)
{
	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case BLINKINGON_STATE:
	case BLINKINGOFF_STATE:
		cancel_delayed_work(&ctrl->button_work);
		break;
	}
	ctrl->state = POWEROFF_STATE;
	mutex_unlock(&ctrl->state_lock);

	ctrl->request_result = sunway_pciehp_disable_slot(ctrl, SAFE_REMOVAL);
}

void sunway_pciehp_save_rc_piu(struct controller *ctrl)
{
	struct pci_dev *pdev = ctrl->pci_dev;

	save_rc_piu(pdev);
}

void sunway_pciehp_start(struct hotplug_slot *hotplug_slot)
{
	struct controller *ctrl = to_ctrl(hotplug_slot);
	struct pci_dev *pdev = ctrl->pci_dev;
	struct pci_bus *bus = pdev->bus;
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	unsigned long piu_value;
	bool hardware_auto = true;
	u16 slot_ctrl;
	void __iomem *piu_ior0_base;
	void __iomem *piu_ior1_base;

	piu_ior0_base = hose->piu_ior0_base;
	piu_ior1_base = hose->piu_ior1_base;

	switch (ctrl->state) {
	case OFF_STATE:
		if (sunway_pciehp_poll_mode) {
			ctrl_dbg(ctrl, "%s: poll mode\n", __func__);
			pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
			/* poll mode */
			slot_ctrl &= ~PCI_EXP_SLTCTL_HPIE;
			pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

			sunway_pciehp_request(ctrl, SW64_POLL_ENABLE_SLOT);
		} else {
			pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
			/* interrupt mode */
			if (hardware_auto) {
				ctrl_dbg(ctrl, "%s: hardware auto enable\n", __func__);
				slot_ctrl &= ~(PCI_EXP_SLTCTL_ABPE |
						PCI_EXP_SLTCTL_MRLSCE |
						PCI_EXP_SLTCTL_PDCE |
						PCI_EXP_SLTCTL_CCIE);
				slot_ctrl |= (PCI_EXP_SLTCTL_PFDE |
						PCI_EXP_SLTCTL_HPIE |
						PCI_EXP_SLTCTL_DLLSCE);
			} else {
				ctrl_dbg(ctrl, "%s: hardware auto disable\n", __func__);
				slot_ctrl &= ~(PCI_EXP_SLTCTL_ABPE | PCI_EXP_SLTCTL_MRLSCE);
				slot_ctrl |= (PCI_EXP_SLTCTL_PFDE |
						PCI_EXP_SLTCTL_PDCE |
						PCI_EXP_SLTCTL_CCIE |
						PCI_EXP_SLTCTL_HPIE |
						PCI_EXP_SLTCTL_DLLSCE);
			}
			pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

			sunway_pciehp_set_indicators(ctrl, INDICATOR_NOOP,
					PCI_EXP_SLTCTL_ATTN_IND_BLINK);

			writeq(HP_CTRL_INSERT, (piu_ior0_base + HP_CTRL));
		}
		break;
	case ON_STATE:
		sunway_pciehp_save_rc_piu(ctrl);
		if (sunway_pciehp_poll_mode) {
			ctrl_dbg(ctrl, "%s: poll mode\n", __func__);
			pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
			/* poll mode */
			slot_ctrl &= ~PCI_EXP_SLTCTL_HPIE;
			pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

			sunway_pciehp_request(ctrl, SW64_POLL_DISABLE_SLOT);
		} else {
			ctrl_dbg(ctrl, "%s: int mode\n", __func__);
			pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
			/* interrupt mode */
			slot_ctrl &= ~(PCI_EXP_SLTCTL_ABPE | PCI_EXP_SLTCTL_MRLSCE);
			slot_ctrl |= (PCI_EXP_SLTCTL_PFDE |
					PCI_EXP_SLTCTL_PDCE |
					PCI_EXP_SLTCTL_CCIE |
					PCI_EXP_SLTCTL_HPIE |
					PCI_EXP_SLTCTL_DLLSCE);
			pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

			sunway_pciehp_set_indicators(ctrl, INDICATOR_NOOP,
					PCI_EXP_SLTCTL_ATTN_IND_BLINK);
			sunway_pciehp_link_disable(ctrl);

			while (1) {
				piu_value = readq(piu_ior1_base + NEWLTSSMSTATE0);
				piu_value &= 0xff;

				if (piu_value == 0x19)
					break;

				udelay(10);
			}

			writeq(HP_CTRL_REMOVE, (piu_ior0_base + HP_CTRL));

			sunway_pciehp_request(ctrl, DISABLE_SLOT);
		}
		break;
	default:
		break;
	}
}

void sunway_pciehp_restore_rc_piu(struct controller *ctrl)
{
	struct pci_dev *pdev = ctrl->pci_dev;

	restore_rc_piu(pdev);
}

void sunway_pciehp_end(struct controller *ctrl, bool insert)
{
	struct pci_dev *pdev = ctrl->pci_dev;
	struct pci_bus *bus = pdev->bus;
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	unsigned long piu_value;
	u16 slot_ctrl;
	void __iomem *piu_ior0_base;
	void __iomem *piu_ior1_base;

	piu_ior0_base = hose->piu_ior0_base;
	piu_ior1_base = hose->piu_ior1_base;

	if (insert) {
		writeq(HP_CTRL_FINISH, (piu_ior0_base + HP_CTRL));
	} else {
		sunway_pciehp_set_indicators(ctrl, INDICATOR_NOOP,
				PCI_EXP_SLTCTL_ATTN_IND_OFF);
		sunway_pciehp_link_enable(ctrl);

		mdelay(100);

		while (1) {
			piu_value = readq(piu_ior1_base + NEWLTSSMSTATE0);
			piu_value &= 0xff;

			if (piu_value == 0x0)
				break;

			udelay(10);
		}

		writeq(HP_ENABLE_INTD_CORE0, (piu_ior0_base + HPINTCONFIG));

		pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
		slot_ctrl |= (PCI_EXP_SLTCTL_PFDE |
				PCI_EXP_SLTCTL_PDCE |
				PCI_EXP_SLTCTL_CCIE |
				PCI_EXP_SLTCTL_HPIE |
				PCI_EXP_SLTCTL_PCC |
				PCI_EXP_SLTCTL_DLLSCE);
		pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

		writeq(HP_CTRL_FINISH, (piu_ior0_base + HP_CTRL));
	}
}

void sunway_pciehp_handle_presence_or_link_change(struct controller *ctrl, u32 events)
{
	int present, link_active;

	/*
	 * If the slot is on and presence or link has changed, turn it off.
	 * Even if it's occupied again, we cannot assume the card is the same.
	 */
	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case BLINKINGOFF_STATE:
		cancel_delayed_work(&ctrl->button_work);
		fallthrough;
	case ON_STATE:
		ctrl->state = POWEROFF_STATE;
		mutex_unlock(&ctrl->state_lock);
		if (events & PCI_EXP_SLTSTA_DLLSC)
			ctrl_info(ctrl, "Slot(%s): Link Down\n",
					slot_name(ctrl));
		if (events & PCI_EXP_SLTSTA_PDC)
			ctrl_info(ctrl, "Slot(%s): Card not present\n",
					slot_name(ctrl));
		sunway_pciehp_disable_slot(ctrl, SURPRISE_REMOVAL);
		break;
	default:
		mutex_unlock(&ctrl->state_lock);
		break;
	}

	/* Turn the slot on if it's occupied or link is up */
	mutex_lock(&ctrl->state_lock);
	present = sunway_pciehp_card_present(ctrl);
	link_active = sunway_pciehp_check_link_active(ctrl);
	if (present <= 0 && link_active <= 0) {
		sunway_pciehp_end(ctrl, false);
		mutex_unlock(&ctrl->state_lock);
		return;
	}

	switch (ctrl->state) {
	case BLINKINGON_STATE:
		cancel_delayed_work(&ctrl->button_work);
		fallthrough;
	case OFF_STATE:
		ctrl->state = POWERON_STATE;
		mutex_unlock(&ctrl->state_lock);
		if (present)
			ctrl_info(ctrl, "Slot(%s): Card present\n",
				  slot_name(ctrl));
		if (link_active)
			ctrl_info(ctrl, "Slot(%s): Link Up\n",
				  slot_name(ctrl));
		ctrl->request_result = sunway_pciehp_enable_slot(ctrl);
		sunway_pciehp_end(ctrl, true);
		break;
	default:
		mutex_unlock(&ctrl->state_lock);
		break;
	}
}

static int __sunway_pciehp_enable_slot(struct controller *ctrl)
{
	u8 getstatus = 0;

	if (MRL_SENS(ctrl)) {
		sunway_pciehp_get_latch_status(ctrl, &getstatus);
		if (getstatus) {
			ctrl_info(ctrl, "Slot(%s): Latch open\n",
				  slot_name(ctrl));
			return -ENODEV;
		}
	}

	if (POWER_CTRL(ctrl)) {
		sunway_pciehp_get_power_status(ctrl, &getstatus);
		if (getstatus) {
			ctrl_info(ctrl, "Slot(%s): Already enabled\n",
				  slot_name(ctrl));
			return 0;
		}
	}

	return board_added(ctrl);
}

static int sunway_pciehp_enable_slot(struct controller *ctrl)
{
	int ret;

	pm_runtime_get_sync(&ctrl->pci_dev->dev);
	ret = __sunway_pciehp_enable_slot(ctrl);
	if (ret && ATTN_BUTTN(ctrl))
		/* may be blinking */
		sunway_pciehp_set_indicators(ctrl, PCI_EXP_SLTCTL_PWR_IND_OFF,
				INDICATOR_NOOP);
	pm_runtime_put(&ctrl->pci_dev->dev);

	mutex_lock(&ctrl->state_lock);
	ctrl->state = ret ? OFF_STATE : ON_STATE;
	mutex_unlock(&ctrl->state_lock);

	return ret;
}

static int __sunway_pciehp_disable_slot(struct controller *ctrl, bool safe_removal)
{
	u8 getstatus = 0;

	if (POWER_CTRL(ctrl)) {
		sunway_pciehp_get_power_status(ctrl, &getstatus);
		if (!getstatus) {
			ctrl_info(ctrl, "Slot(%s): Already disabled\n",
				  slot_name(ctrl));
			return -EINVAL;
		}
	}

	remove_board(ctrl, safe_removal);
	return 0;
}

static int sunway_pciehp_disable_slot(struct controller *ctrl, bool safe_removal)
{
	int ret;

	pm_runtime_get_sync(&ctrl->pci_dev->dev);
	ret = __sunway_pciehp_disable_slot(ctrl, safe_removal);
	pm_runtime_put(&ctrl->pci_dev->dev);

	mutex_lock(&ctrl->state_lock);
	ctrl->state = OFF_STATE;
	mutex_unlock(&ctrl->state_lock);

	return ret;
}

int sunway_pciehp_sysfs_enable_slot(struct hotplug_slot *hotplug_slot)
{
	struct controller *ctrl = to_ctrl(hotplug_slot);

	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case BLINKINGON_STATE:
	case OFF_STATE:
		mutex_unlock(&ctrl->state_lock);
		/*
		 * The IRQ thread becomes a no-op if the user pulls out the
		 * card before the thread wakes up, so initialize to -ENODEV.
		 */
		ctrl->request_result = -ENODEV;
		sunway_pciehp_request(ctrl, PCI_EXP_SLTSTA_PDC);

		wait_event(ctrl->requester,
			   !atomic_read(&ctrl->pending_events) &&
			   !ctrl->ist_running);

		sunway_pciehp_start(hotplug_slot);
		return ctrl->request_result;
	case POWERON_STATE:
		ctrl_info(ctrl, "Slot(%s): Already in powering on state\n",
			  slot_name(ctrl));
		break;
	case BLINKINGOFF_STATE:
	case ON_STATE:
	case POWEROFF_STATE:
		ctrl_info(ctrl, "Slot(%s): Already enabled\n",
			  slot_name(ctrl));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Invalid state %#x\n",
			 slot_name(ctrl), ctrl->state);
		break;
	}
	mutex_unlock(&ctrl->state_lock);

	return -ENODEV;
}

int sunway_pciehp_sysfs_disable_slot(struct hotplug_slot *hotplug_slot)
{
	struct controller *ctrl = to_ctrl(hotplug_slot);

	mutex_lock(&ctrl->state_lock);
	switch (ctrl->state) {
	case BLINKINGOFF_STATE:
	case ON_STATE:
		sunway_pciehp_start(hotplug_slot);

		mutex_unlock(&ctrl->state_lock);
		wait_event(ctrl->requester,
			   !atomic_read(&ctrl->pending_events) &&
			   !ctrl->ist_running);

		return ctrl->request_result;
	case POWEROFF_STATE:
		ctrl_info(ctrl, "Slot(%s): Already in powering off state\n",
			  slot_name(ctrl));
		break;
	case BLINKINGON_STATE:
	case OFF_STATE:
	case POWERON_STATE:
		ctrl_info(ctrl, "Slot(%s): Already disabled\n",
			  slot_name(ctrl));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Invalid state %#x\n",
			 slot_name(ctrl), ctrl->state);
		break;
	}
	mutex_unlock(&ctrl->state_lock);

	return -ENODEV;
}
