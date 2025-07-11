// SPDX-License-Identifier: GPL-2.0-only
/*
 * Core driver for the pin muxing portions of the pin control subsystem
 *
 * Copyright (C) 2011-2012 ST-Ericsson SA
 * Written on behalf of Linaro for ST-Ericsson
 * Based on bits of regulator core, gpio core and clk core
 *
 * Author: Linus Walleij <linus.walleij@linaro.org>
 *
 * Copyright (C) 2012 NVIDIA CORPORATION. All rights reserved.
 */
#define pr_fmt(fmt) "pinmux core: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinmux.h>
#include "core.h"
#include "pinmux.h"
#include <linux/mutex.h>

int pinmux_check_ops(struct pinctrl_dev *pctldev)
{
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	unsigned nfuncs;
	unsigned selector = 0;

	/* Check that we implement required operations */
	if (!ops ||
	    !ops->get_functions_count ||
	    !ops->get_function_name ||
	    !ops->get_function_groups ||
	    !ops->set_mux) {
		dev_err(pctldev->dev, "pinmux ops lacks necessary functions\n");
		return -EINVAL;
	}
	/* Check that all functions registered have names */
	nfuncs = ops->get_functions_count(pctldev);
	while (selector < nfuncs) {
		const char *fname = ops->get_function_name(pctldev,
							   selector);
		if (!fname) {
			dev_err(pctldev->dev, "pinmux ops has no name for function%u\n",
				selector);
			return -EINVAL;
		}
		selector++;
	}

	return 0;
}

int pinmux_validate_map(const struct pinctrl_map *map, int i)
{
	if (!map->data.mux.function) {
		pr_err("failed to register map %s (%d): no function given\n",
		       map->name, i);
		return -EINVAL;
	}

	return 0;
}

/**
 * pinmux_can_be_used_for_gpio() - check if a specific pin
 *	is either muxed to a different function or used as gpio.
 *
 * @pctldev: the associated pin controller device
 * @pin: the pin number in the global pin space
 *
 * Controllers not defined as strict will always return true,
 * menaning that the gpio can be used.
 */
bool pinmux_can_be_used_for_gpio(struct pinctrl_dev *pctldev, unsigned pin)
{
	struct pin_desc *desc = pin_desc_get(pctldev, pin);
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	bool can;

	/* Can't inspect pin, assume it can be used */
	if (!desc || !ops)
		return true;

	mutex_lock(&desc->mux_lock);
	if (ops->strict && desc->mux_usecount) {
		mutex_unlock(&desc->mux_lock);
		return false;
	}

	can = !(ops->strict && !!desc->gpio_owner);
	mutex_unlock(&desc->mux_lock);
	return can;
}

/**
 * pin_request() - request a single pin to be muxed in, typically for GPIO
 * @pctldev: the associated pin controller device
 * @pin: the pin number in the global pin space
 * @owner: a representation of the owner of this pin; typically the device
 *	name that controls its mux function, or the requested GPIO name
 * @gpio_range: the range matching the GPIO pin if this is a request for a
 *	single GPIO pin
 */
static int pin_request(struct pinctrl_dev *pctldev,
		       int pin, const char *owner,
		       struct pinctrl_gpio_range *gpio_range)
{
	struct pin_desc *desc;
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	int status = -EINVAL;

	desc = pin_desc_get(pctldev, pin);
	if (desc == NULL) {
		dev_err(pctldev->dev,
			"pin %d is not registered so it cannot be requested\n",
			pin);
		goto out;
	}

	dev_dbg(pctldev->dev, "request pin %d (%s) for %s\n",
		pin, desc->name, owner);

	mutex_lock(&desc->mux_lock);
	if ((!gpio_range || ops->strict) &&
	    desc->mux_usecount && strcmp(desc->mux_owner, owner)) {
		dev_err(pctldev->dev,
			"pin %s already requested by %s; cannot claim for %s\n",
			desc->name, desc->mux_owner, owner);
		mutex_unlock(&desc->mux_lock);
		goto out;
	}

	if ((gpio_range || ops->strict) && desc->gpio_owner) {
		dev_err(pctldev->dev,
			"pin %s already requested by %s; cannot claim for %s\n",
			desc->name, desc->gpio_owner, owner);
		mutex_unlock(&desc->mux_lock);
		goto out;
	}

	if (gpio_range) {
		desc->gpio_owner = owner;
	} else {
		desc->mux_usecount++;
		if (desc->mux_usecount > 1) {
			mutex_unlock(&desc->mux_lock);
			return 0;
		}

		desc->mux_owner = owner;
	}
	mutex_unlock(&desc->mux_lock);

	/* Let each pin increase references to this module */
	if (!try_module_get(pctldev->owner)) {
		dev_err(pctldev->dev,
			"could not increase module refcount for pin %d\n",
			pin);
		status = -EINVAL;
		goto out_free_pin;
	}

	/*
	 * If there is no kind of request function for the pin we just assume
	 * we got it by default and proceed.
	 */
	if (gpio_range && ops->gpio_request_enable)
		/* This requests and enables a single GPIO pin */
		status = ops->gpio_request_enable(pctldev, gpio_range, pin);
	else if (ops->request)
		status = ops->request(pctldev, pin);
	else
		status = 0;

	if (status) {
		dev_err(pctldev->dev, "request() failed for pin %d\n", pin);
		module_put(pctldev->owner);
	}

out_free_pin:
	if (status) {
		mutex_lock(&desc->mux_lock);
		if (gpio_range) {
			desc->gpio_owner = NULL;
		} else {
			desc->mux_usecount--;
			if (!desc->mux_usecount)
				desc->mux_owner = NULL;
		}
		mutex_unlock(&desc->mux_lock);
	}
out:
	if (status)
		dev_err(pctldev->dev, "pin-%d (%s) status %d\n",
			pin, owner, status);

	return status;
}

/**
 * pin_free() - release a single muxed in pin so something else can be muxed
 * @pctldev: pin controller device handling this pin
 * @pin: the pin to free
 * @gpio_range: the range matching the GPIO pin if this is a request for a
 *	single GPIO pin
 *
 * This function returns a pointer to the previous owner. This is used
 * for callers that dynamically allocate an owner name so it can be freed
 * once the pin is free. This is done for GPIO request functions.
 */
static const char *pin_free(struct pinctrl_dev *pctldev, int pin,
			    struct pinctrl_gpio_range *gpio_range)
{
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	struct pin_desc *desc;
	const char *owner;

	desc = pin_desc_get(pctldev, pin);
	if (desc == NULL) {
		dev_err(pctldev->dev,
			"pin is not registered so it cannot be freed\n");
		return NULL;
	}

	mutex_lock(&desc->mux_lock);
	if (!gpio_range) {
		/*
		 * A pin should not be freed more times than allocated.
		 */
		if (WARN_ON(!desc->mux_usecount)) {
			mutex_unlock(&desc->mux_lock);
			return NULL;
		}
		desc->mux_usecount--;
		if (desc->mux_usecount) {
			mutex_unlock(&desc->mux_lock);
			return NULL;
		}
	}
	mutex_unlock(&desc->mux_lock);

	/*
	 * If there is no kind of request function for the pin we just assume
	 * we got it by default and proceed.
	 */
	if (gpio_range && ops->gpio_disable_free)
		ops->gpio_disable_free(pctldev, gpio_range, pin);
	else if (ops->free)
		ops->free(pctldev, pin);

	mutex_lock(&desc->mux_lock);
	if (gpio_range) {
		owner = desc->gpio_owner;
		desc->gpio_owner = NULL;
	} else {
		owner = desc->mux_owner;
		desc->mux_owner = NULL;
		desc->mux_setting = NULL;
	}
	mutex_unlock(&desc->mux_lock);

	module_put(pctldev->owner);

	return owner;
}

/**
 * pinmux_request_gpio() - request pinmuxing for a GPIO pin
 * @pctldev: pin controller device affected
 * @pin: the pin to mux in for GPIO
 * @range: the applicable GPIO range
 * @gpio: number of requested GPIO
 */
int pinmux_request_gpio(struct pinctrl_dev *pctldev,
			struct pinctrl_gpio_range *range,
			unsigned pin, unsigned gpio)
{
	const char *owner;
	int ret;

	/* Conjure some name stating what chip and pin this is taken by */
	owner = kasprintf(GFP_KERNEL, "%s:%d", range->name, gpio);
	if (!owner)
		return -ENOMEM;

	ret = pin_request(pctldev, pin, owner, range);
	if (ret < 0)
		kfree(owner);

	return ret;
}

/**
 * pinmux_free_gpio() - release a pin from GPIO muxing
 * @pctldev: the pin controller device for the pin
 * @pin: the affected currently GPIO-muxed in pin
 * @range: applicable GPIO range
 */
void pinmux_free_gpio(struct pinctrl_dev *pctldev, unsigned pin,
		      struct pinctrl_gpio_range *range)
{
	const char *owner;

	owner = pin_free(pctldev, pin, range);
	kfree(owner);
}

/**
 * pinmux_gpio_direction() - set the direction of a single muxed-in GPIO pin
 * @pctldev: the pin controller handling this pin
 * @range: applicable GPIO range
 * @pin: the affected GPIO pin in this controller
 * @input: true if we set the pin as input, false for output
 */
int pinmux_gpio_direction(struct pinctrl_dev *pctldev,
			  struct pinctrl_gpio_range *range,
			  unsigned pin, bool input)
{
	const struct pinmux_ops *ops;
	int ret;

	ops = pctldev->desc->pmxops;

	if (ops->gpio_set_direction)
		ret = ops->gpio_set_direction(pctldev, range, pin, input);
	else
		ret = 0;

	return ret;
}

static int pinmux_func_name_to_selector(struct pinctrl_dev *pctldev,
					const char *function)
{
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	unsigned nfuncs = ops->get_functions_count(pctldev);
	unsigned selector = 0;

	/* See if this pctldev has this function */
	while (selector < nfuncs) {
		const char *fname = ops->get_function_name(pctldev, selector);

		if (!strcmp(function, fname))
			return selector;

		selector++;
	}

	return -EINVAL;
}

int pinmux_map_to_setting(const struct pinctrl_map *map,
			  struct pinctrl_setting *setting)
{
	struct pinctrl_dev *pctldev = setting->pctldev;
	const struct pinmux_ops *pmxops = pctldev->desc->pmxops;
	char const * const *groups;
	unsigned num_groups;
	int ret;
	const char *group;

	if (!pmxops) {
		dev_err(pctldev->dev, "does not support mux function\n");
		return -EINVAL;
	}

	ret = pinmux_func_name_to_selector(pctldev, map->data.mux.function);
	if (ret < 0) {
		dev_err(pctldev->dev, "invalid function %s in map table\n",
			map->data.mux.function);
		return ret;
	}
	setting->data.mux.func = ret;

	ret = pmxops->get_function_groups(pctldev, setting->data.mux.func,
					  &groups, &num_groups);
	if (ret < 0) {
		dev_err(pctldev->dev, "can't query groups for function %s\n",
			map->data.mux.function);
		return ret;
	}
	if (!num_groups) {
		dev_err(pctldev->dev,
			"function %s can't be selected on any group\n",
			map->data.mux.function);
		return -EINVAL;
	}
	if (map->data.mux.group) {
		group = map->data.mux.group;
		ret = match_string(groups, num_groups, group);
		if (ret < 0) {
			dev_err(pctldev->dev,
				"invalid group \"%s\" for function \"%s\"\n",
				group, map->data.mux.function);
			return ret;
		}
	} else {
		group = groups[0];
	}

	ret = pinctrl_get_group_selector(pctldev, group);
	if (ret < 0) {
		dev_err(pctldev->dev, "invalid group %s in map table\n",
			map->data.mux.group);
		return ret;
	}
	setting->data.mux.group = ret;

	return 0;
}

void pinmux_free_setting(const struct pinctrl_setting *setting)
{
	/* This function is currently unused */
}

int pinmux_enable_setting(const struct pinctrl_setting *setting)
{
	struct pinctrl_dev *pctldev = setting->pctldev;
	const struct pinctrl_ops *pctlops = pctldev->desc->pctlops;
	const struct pinmux_ops *ops = pctldev->desc->pmxops;
	int ret = 0;
	const unsigned *pins = NULL;
	unsigned num_pins = 0;
	int i;
	struct pin_desc *desc;

	if (pctlops->get_group_pins)
		ret = pctlops->get_group_pins(pctldev, setting->data.mux.group,
					      &pins, &num_pins);

	if (ret) {
		const char *gname;

		/* errors only affect debug data, so just warn */
		gname = pctlops->get_group_name(pctldev,
						setting->data.mux.group);
		dev_warn(pctldev->dev,
			 "could not get pins for group %s\n",
			 gname);
		num_pins = 0;
	}

	/* Try to allocate all pins in this group, one by one */
	for (i = 0; i < num_pins; i++) {
		ret = pin_request(pctldev, pins[i], setting->dev_name, NULL);
		if (ret) {
			const char *gname;
			const char *pname;

			desc = pin_desc_get(pctldev, pins[i]);
			pname = desc ? desc->name : "non-existing";
			gname = pctlops->get_group_name(pctldev,
						setting->data.mux.group);
			dev_err(pctldev->dev,
				"could not request pin %d (%s) from group %s "
				" on device %s\n",
				pins[i], pname, gname,
				pinctrl_dev_get_name(pctldev));
			goto err_pin_request;
		}
	}

	/* Now that we have acquired the pins, encode the mux setting */
	for (i = 0; i < num_pins; i++) {
		desc = pin_desc_get(pctldev, pins[i]);
		if (desc == NULL) {
			dev_warn(pctldev->dev,
				 "could not get pin desc for pin %d\n",
				 pins[i]);
			continue;
		}
		mutex_lock(&desc->mux_lock);
		desc->mux_setting = &(setting->data.mux);
		mutex_unlock(&desc->mux_lock);
	}

	ret = ops->set_mux(pctldev, setting->data.mux.func,
			   setting->data.mux.group);

	if (ret)
		goto err_set_mux;

	return 0;

err_set_mux:
	for (i = 0; i < num_pins; i++) {
		desc = pin_desc_get(pctldev, pins[i]);
		if (desc) {
			mutex_lock(&desc->mux_lock);
			desc->mux_setting = NULL;
			mutex_unlock(&desc->mux_lock);
		}
	}
err_pin_request:
	/* On error release all taken pins */
	while (--i >= 0)
		pin_free(pctldev, pins[i], NULL);

	return ret;
}

void pinmux_disable_setting(const struct pinctrl_setting *setting)
{
	struct pinctrl_dev *pctldev = setting->pctldev;
	const struct pinctrl_ops *pctlops = pctldev->desc->pctlops;
	int ret = 0;
	const unsigned *pins = NULL;
	unsigned num_pins = 0;
	int i;
	struct pin_desc *desc;
	bool is_equal;

	if (pctlops->get_group_pins)
		ret = pctlops->get_group_pins(pctldev, setting->data.mux.group,
					      &pins, &num_pins);
	if (ret) {
		const char *gname;

		/* errors only affect debug data, so just warn */
		gname = pctlops->get_group_name(pctldev,
						setting->data.mux.group);
		dev_warn(pctldev->dev,
			 "could not get pins for group %s\n",
			 gname);
		num_pins = 0;
	}

	/* Flag the descs that no setting is active */
	for (i = 0; i < num_pins; i++) {
		desc = pin_desc_get(pctldev, pins[i]);
		if (desc == NULL) {
			dev_warn(pctldev->dev,
				 "could not get pin desc for pin %d\n",
				 pins[i]);
			continue;
		}
		mutex_lock(&desc->mux_lock);
		is_equal = (desc->mux_setting == &(setting->data.mux));
		mutex_unlock(&desc->mux_lock);

		if (is_equal) {
			pin_free(pctldev, pins[i], NULL);
		} else {
			const char *gname;

			gname = pctlops->get_group_name(pctldev,
						setting->data.mux.group);
			dev_warn(pctldev->dev,
				 "not freeing pin %d (%s) as part of "
				 "deactivating group %s - it is already "
				 "used for some other setting",
				 pins[i], desc->name, gname);
		}
	}
}

#ifdef CONFIG_DEBUG_FS

/* Called from pincontrol core */
static int pinmux_functions_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev = s->private;
	const struct pinmux_ops *pmxops = pctldev->desc->pmxops;
	unsigned nfuncs;
	unsigned func_selector = 0;

	if (!pmxops)
		return 0;

	mutex_lock(&pctldev->mutex);
	nfuncs = pmxops->get_functions_count(pctldev);
	while (func_selector < nfuncs) {
		const char *func = pmxops->get_function_name(pctldev,
							  func_selector);
		const char * const *groups;
		unsigned num_groups;
		int ret;
		int i;

		ret = pmxops->get_function_groups(pctldev, func_selector,
						  &groups, &num_groups);
		if (ret) {
			seq_printf(s, "function %s: COULD NOT GET GROUPS\n",
				   func);
			func_selector++;
			continue;
		}

		seq_printf(s, "function: %s, groups = [ ", func);
		for (i = 0; i < num_groups; i++)
			seq_printf(s, "%s ", groups[i]);
		seq_puts(s, "]\n");

		func_selector++;
	}

	mutex_unlock(&pctldev->mutex);

	return 0;
}

static int pinmux_pins_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev = s->private;
	const struct pinctrl_ops *pctlops = pctldev->desc->pctlops;
	const struct pinmux_ops *pmxops = pctldev->desc->pmxops;
	unsigned i, pin;

	if (!pmxops)
		return 0;

	seq_puts(s, "Pinmux settings per pin\n");
	if (pmxops->strict)
		seq_puts(s,
		 "Format: pin (name): mux_owner|gpio_owner (strict) hog?\n");
	else
		seq_puts(s,
		"Format: pin (name): mux_owner gpio_owner hog?\n");

	mutex_lock(&pctldev->mutex);

	/* The pin number can be retrived from the pin controller descriptor */
	for (i = 0; i < pctldev->desc->npins; i++) {
		struct pin_desc *desc;
		bool is_hog = false;

		pin = pctldev->desc->pins[i].number;
		desc = pin_desc_get(pctldev, pin);
		/* Skip if we cannot search the pin */
		if (desc == NULL)
			continue;

		mutex_lock(&desc->mux_lock);
		if (desc->mux_owner &&
		    !strcmp(desc->mux_owner, pinctrl_dev_get_name(pctldev)))
			is_hog = true;

		if (pmxops->strict) {
			if (desc->mux_owner)
				seq_printf(s, "pin %d (%s): device %s%s",
					   pin, desc->name, desc->mux_owner,
					   is_hog ? " (HOG)" : "");
			else if (desc->gpio_owner)
				seq_printf(s, "pin %d (%s): GPIO %s",
					   pin, desc->name, desc->gpio_owner);
			else
				seq_printf(s, "pin %d (%s): UNCLAIMED",
					   pin, desc->name);
		} else {
			/* For non-strict controllers */
			seq_printf(s, "pin %d (%s): %s %s%s", pin, desc->name,
				   desc->mux_owner ? desc->mux_owner
				   : "(MUX UNCLAIMED)",
				   desc->gpio_owner ? desc->gpio_owner
				   : "(GPIO UNCLAIMED)",
				   is_hog ? " (HOG)" : "");
		}

		/* If mux: print function+group claiming the pin */
		if (desc->mux_setting)
			seq_printf(s, " function %s group %s\n",
				   pmxops->get_function_name(pctldev,
					desc->mux_setting->func),
				   pctlops->get_group_name(pctldev,
					desc->mux_setting->group));
		else
			seq_putc(s, '\n');
		mutex_unlock(&desc->mux_lock);
	}

	mutex_unlock(&pctldev->mutex);

	return 0;
}

void pinmux_show_map(struct seq_file *s, const struct pinctrl_map *map)
{
	seq_printf(s, "group %s\nfunction %s\n",
		map->data.mux.group ? map->data.mux.group : "(default)",
		map->data.mux.function);
}

void pinmux_show_setting(struct seq_file *s,
			 const struct pinctrl_setting *setting)
{
	struct pinctrl_dev *pctldev = setting->pctldev;
	const struct pinmux_ops *pmxops = pctldev->desc->pmxops;
	const struct pinctrl_ops *pctlops = pctldev->desc->pctlops;

	seq_printf(s, "group: %s (%u) function: %s (%u)\n",
		   pctlops->get_group_name(pctldev, setting->data.mux.group),
		   setting->data.mux.group,
		   pmxops->get_function_name(pctldev, setting->data.mux.func),
		   setting->data.mux.func);
}

DEFINE_SHOW_ATTRIBUTE(pinmux_functions);
DEFINE_SHOW_ATTRIBUTE(pinmux_pins);

void pinmux_init_device_debugfs(struct dentry *devroot,
			 struct pinctrl_dev *pctldev)
{
	debugfs_create_file("pinmux-functions", S_IFREG | S_IRUGO,
			    devroot, pctldev, &pinmux_functions_fops);
	debugfs_create_file("pinmux-pins", S_IFREG | S_IRUGO,
			    devroot, pctldev, &pinmux_pins_fops);
}

#endif /* CONFIG_DEBUG_FS */

#ifdef CONFIG_GENERIC_PINMUX_FUNCTIONS

/**
 * pinmux_generic_get_function_count() - returns number of functions
 * @pctldev: pin controller device
 */
int pinmux_generic_get_function_count(struct pinctrl_dev *pctldev)
{
	return pctldev->num_functions;
}
EXPORT_SYMBOL_GPL(pinmux_generic_get_function_count);

/**
 * pinmux_generic_get_function_name() - returns the function name
 * @pctldev: pin controller device
 * @selector: function number
 */
const char *
pinmux_generic_get_function_name(struct pinctrl_dev *pctldev,
				 unsigned int selector)
{
	struct function_desc *function;

	function = radix_tree_lookup(&pctldev->pin_function_tree,
				     selector);
	if (!function)
		return NULL;

	return function->name;
}
EXPORT_SYMBOL_GPL(pinmux_generic_get_function_name);

/**
 * pinmux_generic_get_function_groups() - gets the function groups
 * @pctldev: pin controller device
 * @selector: function number
 * @groups: array of pin groups
 * @num_groups: number of pin groups
 */
int pinmux_generic_get_function_groups(struct pinctrl_dev *pctldev,
				       unsigned int selector,
				       const char * const **groups,
				       unsigned * const num_groups)
{
	struct function_desc *function;

	function = radix_tree_lookup(&pctldev->pin_function_tree,
				     selector);
	if (!function) {
		dev_err(pctldev->dev, "%s could not find function%i\n",
			__func__, selector);
		return -EINVAL;
	}
	*groups = function->group_names;
	*num_groups = function->num_group_names;

	return 0;
}
EXPORT_SYMBOL_GPL(pinmux_generic_get_function_groups);

/**
 * pinmux_generic_get_function() - returns a function based on the number
 * @pctldev: pin controller device
 * @selector: function number
 */
struct function_desc *pinmux_generic_get_function(struct pinctrl_dev *pctldev,
						  unsigned int selector)
{
	struct function_desc *function;

	function = radix_tree_lookup(&pctldev->pin_function_tree,
				     selector);
	if (!function)
		return NULL;

	return function;
}
EXPORT_SYMBOL_GPL(pinmux_generic_get_function);

/**
 * pinmux_generic_add_function() - adds a function group
 * @pctldev: pin controller device
 * @name: name of the function
 * @groups: array of pin groups
 * @num_groups: number of pin groups
 * @data: pin controller driver specific data
 */
int pinmux_generic_add_function(struct pinctrl_dev *pctldev,
				const char *name,
				const char **groups,
				const unsigned int num_groups,
				void *data)
{
	struct function_desc *function;
	int selector;

	if (!name)
		return -EINVAL;

	selector = pinmux_func_name_to_selector(pctldev, name);
	if (selector >= 0)
		return selector;

	selector = pctldev->num_functions;

	function = devm_kzalloc(pctldev->dev, sizeof(*function), GFP_KERNEL);
	if (!function)
		return -ENOMEM;

	function->name = name;
	function->group_names = groups;
	function->num_group_names = num_groups;
	function->data = data;

	radix_tree_insert(&pctldev->pin_function_tree, selector, function);

	pctldev->num_functions++;

	return selector;
}
EXPORT_SYMBOL_GPL(pinmux_generic_add_function);

/**
 * pinmux_generic_remove_function() - removes a numbered function
 * @pctldev: pin controller device
 * @selector: function number
 *
 * Note that the caller must take care of locking.
 */
int pinmux_generic_remove_function(struct pinctrl_dev *pctldev,
				   unsigned int selector)
{
	struct function_desc *function;

	function = radix_tree_lookup(&pctldev->pin_function_tree,
				     selector);
	if (!function)
		return -ENOENT;

	radix_tree_delete(&pctldev->pin_function_tree, selector);
	devm_kfree(pctldev->dev, function);

	pctldev->num_functions--;

	return 0;
}
EXPORT_SYMBOL_GPL(pinmux_generic_remove_function);

/**
 * pinmux_generic_free_functions() - removes all functions
 * @pctldev: pin controller device
 *
 * Note that the caller must take care of locking. The pinctrl
 * functions are allocated with devm_kzalloc() so no need to free
 * them here.
 */
void pinmux_generic_free_functions(struct pinctrl_dev *pctldev)
{
	struct radix_tree_iter iter;
	void __rcu **slot;

	radix_tree_for_each_slot(slot, &pctldev->pin_function_tree, &iter, 0)
		radix_tree_delete(&pctldev->pin_function_tree, iter.index);

	pctldev->num_functions = 0;
}

#endif /* CONFIG_GENERIC_PINMUX_FUNCTIONS */
