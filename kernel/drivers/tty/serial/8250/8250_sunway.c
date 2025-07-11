// SPDX-License-Identifier: GPL-2.0+
/*
 * Synopsys SUNWAY 8250 driver.
 *
 * Copyright 2011 Picochip, Jamie Iles.
 * Copyright 2013 Intel Corporation
 *
 * The Synopsys SUNWAY 8250 has an extra feature whereby it detects if the
 * LCR is written whilst busy.  If it is, then a busy detect interrupt is
 * raised, the LCR needs to be rewritten and the uart status register read.
 */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/serial_8250.h>
#include <linux/serial_reg.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include <linux/pm_runtime.h>

#include <asm/byteorder.h>

#include "8250.h"

/* Offsets for the DesignWare specific registers */
#define SUNWAY_UART_USR	0x1f /* UART Status Register */
#define SUNWAY_UART_DLF	0xc0 /* Divisor Latch Fraction Register */
#define SUNWAY_UART_CPR	0xf4 /* Component Parameter Register */
#define SUNWAY_UART_UCV	0xf8 /* UART Component Version */

/* Component Parameter Register bits */
#define SUNWAY_UART_CPR_ABP_DATA_WIDTH	(3 << 0)
#define SUNWAY_UART_CPR_AFCE_MODE		(1 << 4)
#define SUNWAY_UART_CPR_THRE_MODE		(1 << 5)
#define SUNWAY_UART_CPR_SIR_MODE		(1 << 6)
#define SUNWAY_UART_CPR_SIR_LP_MODE		(1 << 7)
#define SUNWAY_UART_CPR_ADDITIONAL_FEATURES	(1 << 8)
#define SUNWAY_UART_CPR_FIFO_ACCESS		(1 << 9)
#define SUNWAY_UART_CPR_FIFO_STAT		(1 << 10)
#define SUNWAY_UART_CPR_SHADOW		(1 << 11)
#define SUNWAY_UART_CPR_ENCODED_PARMS	(1 << 12)
#define SUNWAY_UART_CPR_DMA_EXTRA		(1 << 13)
#define SUNWAY_UART_CPR_FIFO_MODE		(0xff << 16)
/* Helper for fifo size calculation */
#define SUNWAY_UART_CPR_FIFO_SIZE(a)	(((a >> 16) & 0xff) * 16)

/* DesignWare specific register fields */
#define SUNWAY_UART_MCR_SIRE		BIT(6)

struct sunway8250_data {
	u8			usr_reg;
	u8			dlf_size;
	int			line;
	int			msr_mask_on;
	int			msr_mask_off;
	struct clk		*clk;
	struct clk		*pclk;
	struct reset_control	*rst;
	struct uart_8250_dma	dma;

	unsigned int		skip_autocfg:1;
	unsigned int		uart_16550_compatible:1;
};

static inline u32 sunway8250_readl_ext(struct uart_port *p, int offset)
{
	if (p->iotype == UPIO_MEM32BE)
		return ioread32be(p->membase + offset);
	return readl(p->membase + offset);
}

static inline void sunway8250_writel_ext(struct uart_port *p, int offset, u32 reg)
{
	if (p->iotype == UPIO_MEM32BE)
		iowrite32be(reg, p->membase + offset);
	else
		writel(reg, p->membase + offset);
}

static inline int sunway8250_modify_msr(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	/* Override any modem control signals if needed */
	if (offset == UART_MSR) {
		value |= d->msr_mask_on;
		value &= ~d->msr_mask_off;
	}

	return value;
}

static void sunway8250_force_idle(struct uart_port *p)
{
	struct uart_8250_port *up = up_to_u8250p(p);

	serial8250_clear_and_reinit_fifos(up);
	(void)p->serial_in(p, UART_RX);
}

static void sunway8250_check_lcr(struct uart_port *p, int value)
{
	void __iomem *offset = p->membase + (UART_LCR << p->regshift);
	int tries = 1000;

	/* Make sure LCR write wasn't ignored */
	while (tries--) {
		unsigned int lcr = p->serial_in(p, UART_LCR);

		if ((value & ~UART_LCR_SPAR) == (lcr & ~UART_LCR_SPAR))
			return;

		sunway8250_force_idle(p);

#ifdef CONFIG_64BIT
		if (p->type == PORT_OCTEON)
			__raw_writeq(value & 0xff, offset);
		else
#endif
		if (p->iotype == UPIO_MEM32)
			writel(value, offset);
		else if (p->iotype == UPIO_MEM32BE)
			iowrite32be(value, offset);
		else
			writeb(value, offset);
	}
	/*
	 * FIXME: this deadlocks if port->lock is already held
	 * dev_err(p->dev, "Couldn't set LCR to %d\n", value);
	 */
}

/* Returns once the transmitter is empty or we run out of retries */
static void sunway8250_tx_wait_empty(struct uart_port *p)
{
	unsigned int tries = 20000;
	unsigned int delay_threshold = tries - 1000;
	unsigned int lsr;

	while (tries--) {
		lsr = readb(p->membase + (UART_LSR << p->regshift));
		if (lsr & UART_LSR_TEMT)
			break;

		/*
		 * The device is first given a chance to empty without delay,
		 * to avoid slowdowns at high bitrates. If after 1000 tries
		 * the buffer has still not emptied, allow more time for low-
		 * speed links.
		 */
		if (tries < delay_threshold)
			udelay(1);
	}
}

static void sunway8250_serial_out38x(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	/* Allow the TX to drain before we reconfigure */
	if (offset == UART_LCR)
		sunway8250_tx_wait_empty(p);

	writeb(value, p->membase + (offset << p->regshift));

	if (offset == UART_LCR && !d->uart_16550_compatible)
		sunway8250_check_lcr(p, value);
}


static void sunway8250_serial_out(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	writeb(value, p->membase + (offset << p->regshift));

	if (offset == UART_LCR && !d->uart_16550_compatible)
		sunway8250_check_lcr(p, value);
}

static unsigned int sunway8250_serial_in(struct uart_port *p, int offset)
{
	unsigned int value = readb(p->membase + (offset << p->regshift));

	return sunway8250_modify_msr(p, offset, value);
}

#ifdef CONFIG_64BIT
static unsigned int sunway8250_serial_inq(struct uart_port *p, int offset)
{
	unsigned int value;

	value = (u8)__raw_readq(p->membase + (offset << p->regshift));

	return sunway8250_modify_msr(p, offset, value);
}

static void sunway8250_serial_outq(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	value &= 0xff;
	__raw_writeq(value, p->membase + (offset << p->regshift));
	/* Read back to ensure register write ordering. */
	__raw_readq(p->membase + (UART_LCR << p->regshift));

	if (offset == UART_LCR && !d->uart_16550_compatible)
		sunway8250_check_lcr(p, value);
}
#endif /* CONFIG_64BIT */

static void sunway8250_serial_out32(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	writel(value, p->membase + (offset << p->regshift));

	if (offset == UART_LCR && !d->uart_16550_compatible)
		sunway8250_check_lcr(p, value);
}

static unsigned int sunway8250_serial_in32(struct uart_port *p, int offset)
{
	unsigned int value = readl(p->membase + (offset << p->regshift));

	return sunway8250_modify_msr(p, offset, value);
}

static void sunway8250_serial_out32be(struct uart_port *p, int offset, int value)
{
	struct sunway8250_data *d = p->private_data;

	iowrite32be(value, p->membase + (offset << p->regshift));

	if (offset == UART_LCR && !d->uart_16550_compatible)
		sunway8250_check_lcr(p, value);
}

static unsigned int sunway8250_serial_in32be(struct uart_port *p, int offset)
{
	unsigned int value = ioread32be(p->membase + (offset << p->regshift));

	return sunway8250_modify_msr(p, offset, value);
}


static int sunway8250_handle_irq(struct uart_port *p)
{
	struct uart_8250_port *up = up_to_u8250p(p);
	struct sunway8250_data *d = p->private_data;
	unsigned int iir = p->serial_in(p, UART_IIR);
	unsigned int status;
	unsigned long flags;

	/*
	 * There are ways to get Designware-based UARTs into a state where
	 * they are asserting UART_IIR_RX_TIMEOUT but there is no actual
	 * data available.  If we see such a case then we'll do a bogus
	 * read.  If we don't do this then the "RX TIMEOUT" interrupt will
	 * fire forever.
	 *
	 * This problem has only been observed so far when not in DMA mode
	 * so we limit the workaround only to non-DMA mode.
	 */
	if (!up->dma && ((iir & 0x3f) == UART_IIR_RX_TIMEOUT)) {
		spin_lock_irqsave(&p->lock, flags);
		status = p->serial_in(p, UART_LSR);

		if (!(status & (UART_LSR_DR | UART_LSR_BI)))
			(void) p->serial_in(p, UART_RX);

		spin_unlock_irqrestore(&p->lock, flags);
	}

	if (serial8250_handle_irq(p, iir))
		return 1;

	if ((iir & UART_IIR_BUSY) == UART_IIR_BUSY) {
		/* Clear the USR */
		(void)p->serial_in(p, d->usr_reg);

		return 1;
	}

	return 0;
}

static void
sunway8250_do_pm(struct uart_port *port, unsigned int state, unsigned int old)
{
	if (!state)
		pm_runtime_get_sync(port->dev);

	serial8250_do_pm(port, state, old);

	if (state)
		pm_runtime_put_sync_suspend(port->dev);
}

static void sunway8250_set_termios(struct uart_port *p, struct ktermios *termios,
			       struct ktermios *old)
{
	unsigned int baud = tty_termios_baud_rate(termios);
	struct sunway8250_data *d = p->private_data;
	long rate;
	int ret;

	if (IS_ERR(d->clk))
		goto out;

	clk_disable_unprepare(d->clk);
	rate = clk_round_rate(d->clk, baud * 16);
	if (rate < 0)
		ret = rate;
	else if (rate == 0)
		ret = -ENOENT;
	else
		ret = clk_set_rate(d->clk, rate);
	clk_prepare_enable(d->clk);

	if (!ret)
		p->uartclk = rate;

out:
	p->status &= ~UPSTAT_AUTOCTS;
	if (termios->c_cflag & CRTSCTS)
		p->status |= UPSTAT_AUTOCTS;

	serial8250_do_set_termios(p, termios, old);
}

static void sunway8250_set_ldisc(struct uart_port *p, struct ktermios *termios)
{
	struct uart_8250_port *up = up_to_u8250p(p);
	unsigned int mcr = p->serial_in(p, UART_MCR);

	if (up->capabilities & UART_CAP_IRDA) {
		if (termios->c_line == N_IRDA)
			mcr |= SUNWAY_UART_MCR_SIRE;
		else
			mcr &= ~SUNWAY_UART_MCR_SIRE;

		p->serial_out(p, UART_MCR, mcr);
	}
	serial8250_do_set_ldisc(p, termios);
}

/*
 * sunway8250_fallback_dma_filter will prevent the UART from getting just any free
 * channel on platforms that have DMA engines, but don't have any channels
 * assigned to the UART.
 *
 * REVISIT: This is a work around for limitation in the DMA Engine API. Once the
 * core problem is fixed, this function is no longer needed.
 */
static bool sunway8250_fallback_dma_filter(struct dma_chan *chan, void *param)
{
	return false;
}

static bool sunway8250_idma_filter(struct dma_chan *chan, void *param)
{
	return param == chan->device->dev;
}

/*
 * divisor = div(I) + div(F)
 * "I" means integer, "F" means fractional
 * quot = div(I) = clk / (16 * baud)
 * frac = div(F) * 2^dlf_size
 *
 * let rem = clk % (16 * baud)
 * we have: div(F) * (16 * baud) = rem
 * so frac = 2^dlf_size * rem / (16 * baud) = (rem << dlf_size) / (16 * baud)
 */
static unsigned int sunway8250_get_divisor(struct uart_port *p,
				       unsigned int baud,
				       unsigned int *frac)
{
	unsigned int quot, rem, base_baud = baud * 16;
	struct sunway8250_data *d = p->private_data;

	quot = p->uartclk / base_baud;
	rem = p->uartclk % base_baud;
	*frac = DIV_ROUND_CLOSEST(rem << d->dlf_size, base_baud);

	return quot;
}

static void sunway8250_set_divisor(struct uart_port *p, unsigned int baud,
			       unsigned int quot, unsigned int quot_frac)
{
	sunway8250_writel_ext(p, SUNWAY_UART_DLF, quot_frac);
	serial8250_do_set_divisor(p, baud, quot, quot_frac);
}

static void sunway8250_quirks(struct uart_port *p, struct sunway8250_data *data)
{
	if (p->dev->of_node) {
		struct device_node *np = p->dev->of_node;
		int id;

		/* get index of serial line, if found in DT aliases */
		id = of_alias_get_id(np, "serial");
		if (id >= 0)
			p->line = id;
#ifdef CONFIG_64BIT
		if (of_device_is_compatible(np, "cavium,octeon-3860-uart")) {
			p->serial_in = sunway8250_serial_inq;
			p->serial_out = sunway8250_serial_outq;
			p->flags = UPF_SKIP_TEST | UPF_SHARE_IRQ | UPF_FIXED_TYPE;
			p->type = PORT_OCTEON;
			data->usr_reg = 0x27;
			data->skip_autocfg = true;
		}
#endif
		if (of_device_is_big_endian(p->dev->of_node)) {
			p->iotype = UPIO_MEM32BE;
			p->serial_in = sunway8250_serial_in32be;
			p->serial_out = sunway8250_serial_out32be;
		}
		if (of_device_is_compatible(np, "marvell,armada-38x-uart"))
			p->serial_out = sunway8250_serial_out38x;

	} else if (acpi_dev_present("APMC0D08", NULL, -1)) {
		p->iotype = UPIO_MEM32;
		p->regshift = 2;
		p->serial_in = sunway8250_serial_in32;
		data->uart_16550_compatible = true;
	}

	/* Platforms with iDMA 64-bit */
	if (platform_get_resource_byname(to_platform_device(p->dev),
					 IORESOURCE_MEM, "lpss_priv")) {
		data->dma.rx_param = p->dev->parent;
		data->dma.tx_param = p->dev->parent;
		data->dma.fn = sunway8250_idma_filter;
	}
}

static void sunway8250_setup_port(struct uart_port *p)
{
	struct uart_8250_port *up = up_to_u8250p(p);
	u32 reg;

	/*
	 * If the Component Version Register returns zero, we know that
	 * ADDITIONAL_FEATURES are not enabled. No need to go any further.
	 */
	reg = sunway8250_readl_ext(p, SUNWAY_UART_UCV);
	if (!reg)
		return;

	dev_dbg(p->dev, "Designware UART version %c.%c%c\n",
		(reg >> 24) & 0xff, (reg >> 16) & 0xff, (reg >> 8) & 0xff);

	sunway8250_writel_ext(p, SUNWAY_UART_DLF, ~0U);
	reg = sunway8250_readl_ext(p, SUNWAY_UART_DLF);
	sunway8250_writel_ext(p, SUNWAY_UART_DLF, 0);

	if (reg) {
		struct sunway8250_data *d = p->private_data;

		d->dlf_size = fls(reg);
		p->get_divisor = sunway8250_get_divisor;
		p->set_divisor = sunway8250_set_divisor;
	}

	reg = sunway8250_readl_ext(p, SUNWAY_UART_CPR);
	if (!reg)
		return;

	/* Select the type based on fifo */
	if (reg & SUNWAY_UART_CPR_FIFO_MODE) {
		p->type = PORT_16550A;
		p->flags |= UPF_FIXED_TYPE;
		p->fifosize = SUNWAY_UART_CPR_FIFO_SIZE(reg);
		up->capabilities = UART_CAP_FIFO;
	}

	if (reg & SUNWAY_UART_CPR_AFCE_MODE)
		up->capabilities |= UART_CAP_AFE;

	if (reg & SUNWAY_UART_CPR_SIR_MODE)
		up->capabilities |= UART_CAP_IRDA;
}

static int sunway8250_probe(struct platform_device *pdev)
{
	struct uart_8250_port uart = {};
	struct resource *regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	int irq = platform_get_irq(pdev, 0);
	struct uart_port *p = &uart.port;
	struct device *dev = &pdev->dev;
	struct sunway8250_data *data;
	int err;
	u32 val;

	if (!regs) {
		dev_err(dev, "no registers defined\n");
		return -EINVAL;
	}

	if (irq < 0) {
		if (irq != -EPROBE_DEFER)
			dev_err(dev, "cannot get irq\n");
		irq = 0; // Set serial poll mode
	}

	spin_lock_init(&p->lock);
	p->mapbase	= regs->start;
	p->irq		= irq;
	p->handle_irq	= sunway8250_handle_irq;
	p->pm		= sunway8250_do_pm;
	p->type		= PORT_8250;
	p->flags	= UPF_SHARE_IRQ | UPF_FIXED_PORT;
	p->dev		= dev;
	p->iotype	= UPIO_MEM;
	p->serial_in	= sunway8250_serial_in;
	p->serial_out	= sunway8250_serial_out;
	p->set_ldisc	= sunway8250_set_ldisc;
	p->set_termios	= sunway8250_set_termios;

	p->membase = devm_ioremap(dev, regs->start, resource_size(regs));
	if (!p->membase)
		return -ENOMEM;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dma.fn = sunway8250_fallback_dma_filter;
	data->usr_reg = SUNWAY_UART_USR;
	p->private_data = data;

	data->uart_16550_compatible = device_property_read_bool(dev,
						"snps,uart-16550-compatible");

	err = device_property_read_u32(dev, "reg-shift", &val);
	if (!err)
		p->regshift = val;

	err = device_property_read_u32(dev, "reg-io-width", &val);
	if (!err && val == 4) {
		p->iotype = UPIO_MEM32;
		p->serial_in = sunway8250_serial_in32;
		p->serial_out = sunway8250_serial_out32;
	}

	if (device_property_read_bool(dev, "dcd-override")) {
		/* Always report DCD as active */
		data->msr_mask_on |= UART_MSR_DCD;
		data->msr_mask_off |= UART_MSR_DDCD;
	}

	if (device_property_read_bool(dev, "dsr-override")) {
		/* Always report DSR as active */
		data->msr_mask_on |= UART_MSR_DSR;
		data->msr_mask_off |= UART_MSR_DDSR;
	}

	if (device_property_read_bool(dev, "cts-override")) {
		/* Always report CTS as active */
		data->msr_mask_on |= UART_MSR_CTS;
		data->msr_mask_off |= UART_MSR_DCTS;
	}

	if (device_property_read_bool(dev, "ri-override")) {
		/* Always report Ring indicator as inactive */
		data->msr_mask_off |= UART_MSR_RI;
		data->msr_mask_off |= UART_MSR_TERI;
	}

	/* Always ask for fixed clock rate from a property. */
	device_property_read_u32(dev, "clock-frequency", &p->uartclk);

	/* If there is separate baudclk, get the rate from it. */
	data->clk = devm_clk_get(dev, "baudclk");
	if (IS_ERR(data->clk) && PTR_ERR(data->clk) != -EPROBE_DEFER)
		data->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(data->clk) && PTR_ERR(data->clk) == -EPROBE_DEFER)
		return -EPROBE_DEFER;
	if (!IS_ERR_OR_NULL(data->clk)) {
		err = clk_prepare_enable(data->clk);
		if (err)
			dev_warn(dev, "could not enable optional baudclk: %d\n",
				 err);
		else
			p->uartclk = clk_get_rate(data->clk);
	}

	/* If no clock rate is defined, fail. */
	if (!p->uartclk) {
		dev_err(dev, "clock rate not defined\n");
		err = -EINVAL;
		goto err_clk;
	}

	data->pclk = devm_clk_get(dev, "apb_pclk");
	if (IS_ERR(data->pclk) && PTR_ERR(data->pclk) == -EPROBE_DEFER) {
		err = -EPROBE_DEFER;
		goto err_clk;
	}
	if (!IS_ERR(data->pclk)) {
		err = clk_prepare_enable(data->pclk);
		if (err) {
			dev_err(dev, "could not enable apb_pclk\n");
			goto err_clk;
		}
	}

	data->rst = devm_reset_control_get_optional_exclusive(dev, NULL);
	if (IS_ERR(data->rst)) {
		err = PTR_ERR(data->rst);
		goto err_pclk;
	}
	reset_control_deassert(data->rst);

	sunway8250_quirks(p, data);

	/* If the Busy Functionality is not implemented, don't handle it */
	if (data->uart_16550_compatible)
		p->handle_irq = NULL;

	if (!data->skip_autocfg)
		sunway8250_setup_port(p);

	/* If we have a valid fifosize, try hooking up DMA */
	if (p->fifosize) {
		data->dma.rxconf.src_maxburst = p->fifosize / 4;
		data->dma.txconf.dst_maxburst = p->fifosize / 4;
		uart.dma = &data->dma;
	}

	data->line = serial8250_register_8250_port(&uart);
	if (data->line < 0) {
		err = data->line;
		goto err_reset;
	}

	platform_set_drvdata(pdev, data);

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	return 0;

err_reset:
	reset_control_assert(data->rst);

err_pclk:
	if (!IS_ERR(data->pclk))
		clk_disable_unprepare(data->pclk);

err_clk:
	if (!IS_ERR(data->clk))
		clk_disable_unprepare(data->clk);

	return err;
}

static int sunway8250_remove(struct platform_device *pdev)
{
	struct sunway8250_data *data = platform_get_drvdata(pdev);

	pm_runtime_get_sync(&pdev->dev);

	serial8250_unregister_port(data->line);

	reset_control_assert(data->rst);

	if (!IS_ERR(data->pclk))
		clk_disable_unprepare(data->pclk);

	if (!IS_ERR(data->clk))
		clk_disable_unprepare(data->clk);

	pm_runtime_disable(&pdev->dev);
	pm_runtime_put_noidle(&pdev->dev);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int sunway8250_suspend(struct device *dev)
{
	struct sunway8250_data *data = dev_get_drvdata(dev);

	serial8250_suspend_port(data->line);

	return 0;
}

static int sunway8250_resume(struct device *dev)
{
	struct sunway8250_data *data = dev_get_drvdata(dev);

	serial8250_resume_port(data->line);

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_PM
static int sunway8250_runtime_suspend(struct device *dev)
{
	struct sunway8250_data *data = dev_get_drvdata(dev);

	if (!IS_ERR(data->clk))
		clk_disable_unprepare(data->clk);

	if (!IS_ERR(data->pclk))
		clk_disable_unprepare(data->pclk);

	return 0;
}

static int sunway8250_runtime_resume(struct device *dev)
{
	struct sunway8250_data *data = dev_get_drvdata(dev);

	if (!IS_ERR(data->pclk))
		clk_prepare_enable(data->pclk);

	if (!IS_ERR(data->clk))
		clk_prepare_enable(data->clk);

	return 0;
}
#endif

static const struct dev_pm_ops sunway8250_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(sunway8250_suspend, sunway8250_resume)
	SET_RUNTIME_PM_OPS(sunway8250_runtime_suspend, sunway8250_runtime_resume, NULL)
};

static const struct of_device_id sunway8250_of_match[] = {
	{ .compatible = "sw6,sunway-apb-uart" },
	{ .compatible = "cavium,octeon-3860-uart" },
	{ .compatible = "marvell,armada-38x-uart" },
	{ .compatible = "renesas,rzn1-uart" },
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(of, sunway8250_of_match);

static const struct acpi_device_id sunway8250_acpi_match[] = {
	{ "INT33C4", 0 },
	{ "INT33C5", 0 },
	{ "INT3434", 0 },
	{ "INT3435", 0 },
	{ "80860F0A", 0 },
	{ "8086228A", 0 },
	{ "APMC0D08", 0},
	{ "AMD0020", 0 },
	{ "AMDI0020", 0 },
	{ "BRCM2032", 0 },
	{ "HISI0031", 0 },
	{ "SUNW0009", 0},
	{ },
};
MODULE_DEVICE_TABLE(acpi, sunway8250_acpi_match);

static struct platform_driver sunway8250_platform_driver = {
	.driver = {
		.name		= "sunway-apb-uart",
		.pm		= &sunway8250_pm_ops,
		.of_match_table	= sunway8250_of_match,
		.acpi_match_table = ACPI_PTR(sunway8250_acpi_match),
	},
	.probe			= sunway8250_probe,
	.remove			= sunway8250_remove,
};

module_platform_driver(sunway8250_platform_driver);

MODULE_AUTHOR("Jamie Iles");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Synopsys DesignWare 8250 serial port driver");
MODULE_ALIAS("platform:sunway-apb-uart");
