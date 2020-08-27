#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define DRIVER_VERSION "v0.1"
#define DRIVER_AUTHOR "Ali Kaan TURKMEN <turkmenalikaan@gmail.com>"
#define DRIVER_DESC "Virtual TTY driver"
#define DRIVER_LICENCE "GPL"

/* Module information */
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE(DRIVER_LICENCE);

#define SHA_256_HASHED_OUTPUT
#define CUSTOM_SHA256

#define ENABLE_VTTY_TIMER
//#define REFRESH_VTTY_TIMER_PERIOD
#define VTTY_TIMER_PERIOD		(HZ * 1)	/* 2 seconds per character */

#define TINY_TTY_MAJOR		240	/* experimental range */
#define TINY_TTY_MINORS		4	/* only have 4 devices */

static unsigned char input_data_buf[500];
static unsigned char output_data_buf[500];

#ifdef SHA_256_HASHED_OUTPUT

#ifdef CUSTOM_SHA256
/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
static void c_sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void c_sha256_init(SHA256_CTX *ctx)
{
	pr_info("%s - ", __func__);

	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

static void c_sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	pr_info("%s - ", __func__);

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			c_sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

static void c_sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	pr_info("%s - ", __func__);

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		c_sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	c_sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

static void c_sha256_hash(char *data, int data_size)
{
	SHA256_CTX ctx;
	BYTE tbuf[(SHA256_BLOCK_SIZE * 2) + 1 ];
	char *pch = &output_data_buf[0];
	int i;			

	pr_info("%s - ", __func__);

	c_sha256_init(&ctx);
	c_sha256_update(&ctx, data, data_size);
	c_sha256_final(&ctx, tbuf);

	pr_info("%ld", strlen(tbuf));

	for (i = 0; i < SHA256_BLOCK_SIZE ; i++)
	{		
		pch += sprintf(pch,"%x",tbuf[i]);			
	}	

	pr_info("%ld", strlen(output_data_buf));

	pch++;
	*pch = 0x00;
}

#else

#include <linux/sha256.h>
#include <linux/crypto.h>
#include <linux/export.h>

EXPORT_SYMBOL(sha256_init);
EXPORT_SYMBOL(sha256_update);
EXPORT_SYMBOL(sha256_final);

static void sha256_hash(char *data, int data_size)
{
	struct sha256_state *sctx;
	char tbuf[100];
	char *pch = output_data_buf;
	int i;
	int hashed_data_size = 0;

	pr_info("%s - ", __func__);

	sha256_init(sctx);
	sha256_update(sctx, data, data_size);
	sha256_final(sctx, tbuf);
	for (i = 0; i < strlen(tbuf); i++)
	{
		hashed_data_size += sprintf(pch,"%x",tbuf[i]);		
		pch += hashed_data_size;
	}	
}
#endif

#endif

struct tiny_serial {
	struct tty_struct	*tty;		/* pointer to the tty for this device */
	int			open_count;	/* number of times this port has been opened */
	struct mutex	mutex;		/* locks this structure */
	struct timer_list	timer;

	/* for tiocmget and tiocmset functions */
	int			msr;		/* MSR shadow */
	int			mcr;		/* MCR shadow */

	/* for ioctl fun */
	struct serial_struct	serial;
	wait_queue_head_t	wait;
	struct async_icount	icount;
};

static struct tiny_serial *tiny_table[TINY_TTY_MINORS];	/* initially all NULL */
static struct tty_port tiny_tty_port[TINY_TTY_MINORS];

static void vtty_send_data(struct tty_port *port, char *data, int data_size)
{	
	/* send the data to the tty layer for users to read.  This doesn't
	 * actually push the data through unless tty->low_latency is set */
	int i;

	pr_info("%s - ", __func__);

	for (i = 0; i < data_size; ++i) {
		if (!tty_buffer_request_room(port, 1))
			tty_flip_buffer_push(port);
		tty_insert_flip_char(port, data[i], TTY_NORMAL);
	}
	tty_flip_buffer_push(port);
}

#ifdef ENABLE_VTTY_TIMER
static void tiny_timer(struct timer_list *t)
{	
	struct tiny_serial *tiny = from_timer(tiny, t, timer);
	struct tty_struct *tty;
	struct tty_port *port;	

	char data[400];
	//int data_size = sprintf(data, "%s\r\n", DRIVER_AUTHOR);		
	int data_size = sprintf(data, "\r\nWelcome to virtual tty port!");
	data_size += sprintf(data + data_size, "\r\nEnter input, then press enter, you will see hashed output");
	data_size += sprintf(data + data_size, "\r\nTo reset input values press '*'\r\n");
	pr_info("%s - ", __func__);

	if (!tiny)
		return;

	tty = tiny->tty;
	port = tty->port;
	
	vtty_send_data(port, data, data_size);
#ifdef REFRESH_VTTY_TIMER_PERIOD
	/* resubmit the timer again */
	tiny->timer.expires = jiffies + VTTY_TIMER_PERIOD;
	add_timer(&tiny->timer);
#endif
}

#endif

static int tiny_open(struct tty_struct *tty, struct file *file)
{	
	struct tiny_serial *tiny;
	int index;

	pr_info("%s - ", __func__);
	/* Clean input and output data buf*/
	memset(input_data_buf, 0, sizeof(input_data_buf));
	memset(output_data_buf, 0, sizeof(output_data_buf));
	/* initialize the pointer in case something fails */
	tty->driver_data = NULL;

	/* get the serial object associated with this tty pointer */
	index = tty->index;
	tiny = tiny_table[index];
	if (tiny == NULL) {
		/* first time accessing this device, let's create it */
		tiny = kmalloc(sizeof(*tiny), GFP_KERNEL);
		if (!tiny)
			return -ENOMEM;

		mutex_init(&tiny->mutex);
		tiny->open_count = 0;

		tiny_table[index] = tiny;
	}

	mutex_lock(&tiny->mutex);

	/* save our structure within the tty structure */
	tty->driver_data = tiny;
	tiny->tty = tty;

	++tiny->open_count;
	if (tiny->open_count == 1) {
		/* this is the first time this port is opened */
		/* do any hardware initialization needed here */

#ifdef ENABLE_VTTY_TIMER
		/* create our timer and submit it */
		timer_setup(&tiny->timer, tiny_timer, 0);
		tiny->timer.expires = jiffies + VTTY_TIMER_PERIOD;
		add_timer(&tiny->timer);
#endif
	}

	mutex_unlock(&tiny->mutex);
	return 0;
}

static void do_close(struct tiny_serial *tiny)
{
	pr_info("%s - ", __func__);
	
	mutex_lock(&tiny->mutex);

	if (!tiny->open_count) {
		/* port was never opened */
		goto exit;
	}

	--tiny->open_count;
	if (tiny->open_count <= 0) {
		/* The port is being closed by the last user. */
		/* Do any hardware specific stuff here */

#ifdef ENABLE_VTTY_TIMER
		/* shut down our timer */
		del_timer(&tiny->timer);
#endif		

	}
exit:
	mutex_unlock(&tiny->mutex);
}

static void tiny_close(struct tty_struct *tty, struct file *file)
{	
	struct tiny_serial *tiny = tty->driver_data;

	pr_info("%s - ", __func__);

	if (tiny)
		do_close(tiny);
}

static int tiny_write(struct tty_struct *tty,
		      const unsigned char *buffer, int count)
{		
	
	struct tiny_serial *tiny = tty->driver_data;
	struct tty_port *port = tty->port;
	int i;
	int retval = -EINVAL;		
	char tbuf[50];
	int tbuf_size;
	static char *pch = &input_data_buf[0];

	pr_info("%s - ", __func__);

	if (!tiny)
		return -ENODEV;

	mutex_lock(&tiny->mutex);

	if (!tiny->open_count)
		/* port was not opened */
		goto exit;

	/* fake sending the data out a hardware port by
	 * writing it to the kernel debug log.
	 */
	pr_debug("%s - ", __func__);
	for (i = 0; i < count; ++i)
	{
		if(buffer[i] == '*')
		{
			/* Clean input and output data buf*/
			memset(input_data_buf, 0, sizeof(input_data_buf));
			memset(output_data_buf, 0, sizeof(output_data_buf));
			pch = &input_data_buf[0];
			pr_info("Reset");			
			vtty_send_data(port, "Reset\r\n", 7);			
		}
		else if(buffer[i] == 0x0D) {			
			*pch = 0x00;

			pr_info("got enter");
			pr_info("input val : %s", input_data_buf);			
#ifdef SHA_256_HASHED_OUTPUT

	#ifdef CUSTOM_SHA256
			c_sha256_hash(input_data_buf, strlen(input_data_buf));	
	#else
			sha256_hash(input_data_buf, strlen(input_data_buf));	
	#endif		
			pr_info("hashed output val : %s", output_data_buf);
			tbuf_size = sprintf(tbuf, "\r\ninput : ");
			vtty_send_data(port, tbuf, tbuf_size);
			vtty_send_data(port, input_data_buf, strlen(input_data_buf));
			
			tbuf_size = sprintf(tbuf, "\r\noutput : ");
			vtty_send_data(port, tbuf, tbuf_size);
			vtty_send_data(port, output_data_buf, strlen(output_data_buf));
#else
			vtty_send_data(port, input_data_buf, strlen(input_data_buf));
#endif						
			pch = &input_data_buf[0];
		}
		else{
			*pch++ = buffer[i];
			pr_info("input data : %c , input data hex : %02x, input data size : %d ", buffer[i], buffer[i], count);		
		}		
	}
	
	mutex_unlock(&tiny->mutex);
	return count;
	pr_info("\n");
	
exit:
	mutex_unlock(&tiny->mutex);		
	return retval;	
}

static int tiny_write_room(struct tty_struct *tty)
{	
	struct tiny_serial *tiny = tty->driver_data;
	int room = -EINVAL;

	pr_info("%s - ", __func__);

	if (!tiny)
		return -ENODEV;

	mutex_lock(&tiny->mutex);

	if (!tiny->open_count) {
		/* port was not opened */
		goto exit;
	}

	/* calculate how much room is left in the device */
	room = 255;

exit:
	mutex_unlock(&tiny->mutex);
	return room;
}

#define RELEVANT_IFLAG(iflag) ((iflag) & (IGNBRK|BRKINT|IGNPAR|PARMRK|INPCK))

static void tiny_set_termios(struct tty_struct *tty, struct ktermios *old_termios)
{	
	unsigned int cflag;

	pr_info("%s - ", __func__);

	cflag = tty->termios.c_cflag;

	/* check that they really want us to change something */
	if (old_termios) {
		if ((cflag == old_termios->c_cflag) &&
		    (RELEVANT_IFLAG(tty->termios.c_iflag) ==
		     RELEVANT_IFLAG(old_termios->c_iflag))) {
			pr_debug(" - nothing to change...\n");
			return;
		}
	}

	/* get the byte size */
	switch (cflag & CSIZE) {
	case CS5:
		pr_debug(" - data bits = 5\n");
		break;
	case CS6:
		pr_debug(" - data bits = 6\n");
		break;
	case CS7:
		pr_debug(" - data bits = 7\n");
		break;
	default:
	case CS8:
		pr_debug(" - data bits = 8\n");
		break;
	}

	/* determine the parity */
	if (cflag & PARENB)
		if (cflag & PARODD)
			pr_debug(" - parity = odd\n");
		else
			pr_debug(" - parity = even\n");
	else
		pr_debug(" - parity = none\n");

	/* figure out the stop bits requested */
	if (cflag & CSTOPB)
		pr_debug(" - stop bits = 2\n");
	else
		pr_debug(" - stop bits = 1\n");

	/* figure out the hardware flow control settings */
	if (cflag & CRTSCTS)
		pr_debug(" - RTS/CTS is enabled\n");
	else
		pr_debug(" - RTS/CTS is disabled\n");

	/* determine software flow control */
	/* if we are implementing XON/XOFF, set the start and
	 * stop character in the device */
	if (I_IXOFF(tty) || I_IXON(tty)) {
		unsigned char stop_char  = STOP_CHAR(tty);
		unsigned char start_char = START_CHAR(tty);

		/* if we are implementing INBOUND XON/XOFF */
		if (I_IXOFF(tty))
			pr_debug(" - INBOUND XON/XOFF is enabled, "
				"XON = %2x, XOFF = %2x", start_char, stop_char);
		else
			pr_debug(" - INBOUND XON/XOFF is disabled");

		/* if we are implementing OUTBOUND XON/XOFF */
		if (I_IXON(tty))
			pr_debug(" - OUTBOUND XON/XOFF is enabled, "
				"XON = %2x, XOFF = %2x", start_char, stop_char);
		else
			pr_debug(" - OUTBOUND XON/XOFF is disabled");
	}

	/* get the baud rate wanted */
	pr_debug(" - baud rate = %d", tty_get_baud_rate(tty));
}

/* Our fake UART values */
#define MCR_DTR		0x01
#define MCR_RTS		0x02
#define MCR_LOOP	0x04
#define MSR_CTS		0x08
#define MSR_CD		0x10
#define MSR_RI		0x20
#define MSR_DSR		0x40

static int tiny_tiocmget(struct tty_struct *tty)
{	
	struct tiny_serial *tiny = tty->driver_data;

	unsigned int result = 0;
	unsigned int msr = tiny->msr;
	unsigned int mcr = tiny->mcr;

	pr_info("%s - ", __func__);

	result = ((mcr & MCR_DTR)  ? TIOCM_DTR  : 0) |	/* DTR is set */
		((mcr & MCR_RTS)  ? TIOCM_RTS  : 0) |	/* RTS is set */
		((mcr & MCR_LOOP) ? TIOCM_LOOP : 0) |	/* LOOP is set */
		((msr & MSR_CTS)  ? TIOCM_CTS  : 0) |	/* CTS is set */
		((msr & MSR_CD)   ? TIOCM_CAR  : 0) |	/* Carrier detect is set*/
		((msr & MSR_RI)   ? TIOCM_RI   : 0) |	/* Ring Indicator is set */
		((msr & MSR_DSR)  ? TIOCM_DSR  : 0);	/* DSR is set */

	return result;
}

static int tiny_tiocmset(struct tty_struct *tty, unsigned int set,
			 unsigned int clear)
{	
	struct tiny_serial *tiny = tty->driver_data;
	unsigned int mcr = tiny->mcr;

	pr_info("%s - ", __func__);

	if (set & TIOCM_RTS)
		mcr |= MCR_RTS;
	if (set & TIOCM_DTR)
		mcr |= MCR_RTS;

	if (clear & TIOCM_RTS)
		mcr &= ~MCR_RTS;
	if (clear & TIOCM_DTR)
		mcr &= ~MCR_RTS;

	/* set the new MCR value in the device */
	tiny->mcr = mcr;
	return 0;
}

static int tiny_proc_show(struct seq_file *m, void *v)
{	
	struct tiny_serial *tiny;
	int i;

	pr_info("%s - ", __func__);

	seq_printf(m, "tinyserinfo:1.0 driver:%s\n", DRIVER_VERSION);
	for (i = 0; i < TINY_TTY_MINORS; ++i) {
		tiny = tiny_table[i];
		if (tiny == NULL)
			continue;

		seq_printf(m, "%d\n", i);
	}

	return 0;
}

#define tiny_ioctl tiny_ioctl_tiocgserial
static int tiny_ioctl(struct tty_struct *tty, unsigned int cmd,
		      unsigned long arg)
{	
	struct tiny_serial *tiny = tty->driver_data;

	pr_info("%s - ", __func__);

	if (cmd == TIOCGSERIAL) {
		struct serial_struct tmp;

		if (!arg)
			return -EFAULT;

		memset(&tmp, 0, sizeof(tmp));

		tmp.type		= tiny->serial.type;
		tmp.line		= tiny->serial.line;
		tmp.port		= tiny->serial.port;
		tmp.irq			= tiny->serial.irq;
		tmp.flags		= ASYNC_SKIP_TEST | ASYNC_AUTO_IRQ;
		tmp.xmit_fifo_size	= tiny->serial.xmit_fifo_size;
		tmp.baud_base		= tiny->serial.baud_base;
		tmp.close_delay		= 5*HZ;
		tmp.closing_wait	= 30*HZ;
		tmp.custom_divisor	= tiny->serial.custom_divisor;
		tmp.hub6		= tiny->serial.hub6;
		tmp.io_type		= tiny->serial.io_type;

		if (copy_to_user((void __user *)arg, &tmp, sizeof(struct serial_struct)))
			return -EFAULT;
		return 0;
	}
	return -ENOIOCTLCMD;
}
#undef tiny_ioctl

#define tiny_ioctl tiny_ioctl_tiocmiwait
static int tiny_ioctl(struct tty_struct *tty, unsigned int cmd,
		      unsigned long arg)
{	
	struct tiny_serial *tiny = tty->driver_data;

	pr_info("%s - ", __func__);
	if (cmd == TIOCMIWAIT) {
		DECLARE_WAITQUEUE(wait, current);
		struct async_icount cnow;
		struct async_icount cprev;

		cprev = tiny->icount;
		while (1) {
			add_wait_queue(&tiny->wait, &wait);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			remove_wait_queue(&tiny->wait, &wait);

			/* see if a signal woke us up */
			if (signal_pending(current))
				return -ERESTARTSYS;

			cnow = tiny->icount;
			if (cnow.rng == cprev.rng && cnow.dsr == cprev.dsr &&
			    cnow.dcd == cprev.dcd && cnow.cts == cprev.cts)
				return -EIO; /* no change => error */
			if (((arg & TIOCM_RNG) && (cnow.rng != cprev.rng)) ||
			    ((arg & TIOCM_DSR) && (cnow.dsr != cprev.dsr)) ||
			    ((arg & TIOCM_CD)  && (cnow.dcd != cprev.dcd)) ||
			    ((arg & TIOCM_CTS) && (cnow.cts != cprev.cts))) {
				return 0;
			}
			cprev = cnow;
		}

	}
	return -ENOIOCTLCMD;
}
#undef tiny_ioctl

#define tiny_ioctl tiny_ioctl_tiocgicount
static int tiny_ioctl(struct tty_struct *tty, unsigned int cmd,
		      unsigned long arg)
{	
	struct tiny_serial *tiny = tty->driver_data;

	pr_info("%s - ", __func__);

	if (cmd == TIOCGICOUNT) {
		struct async_icount cnow = tiny->icount;
		struct serial_icounter_struct icount;

		icount.cts	= cnow.cts;
		icount.dsr	= cnow.dsr;
		icount.rng	= cnow.rng;
		icount.dcd	= cnow.dcd;
		icount.rx	= cnow.rx;
		icount.tx	= cnow.tx;
		icount.frame	= cnow.frame;
		icount.overrun	= cnow.overrun;
		icount.parity	= cnow.parity;
		icount.brk	= cnow.brk;
		icount.buf_overrun = cnow.buf_overrun;

		if (copy_to_user((void __user *)arg, &icount, sizeof(icount)))
			return -EFAULT;
		return 0;
	}
	return -ENOIOCTLCMD;
}
#undef tiny_ioctl

/* the real tiny_ioctl function.  The above is done to get the small functions in the book */
static int tiny_ioctl(struct tty_struct *tty, unsigned int cmd,
		      unsigned long arg)
{
	pr_info("%s - ", __func__);

	switch (cmd) {
	case TIOCGSERIAL:
		return tiny_ioctl_tiocgserial(tty, cmd, arg);
	case TIOCMIWAIT:
		return tiny_ioctl_tiocmiwait(tty, cmd, arg);
	case TIOCGICOUNT:
		return tiny_ioctl_tiocgicount(tty, cmd, arg);
	}

	return -ENOIOCTLCMD;
}


static const struct tty_operations serial_ops = {
	.open = tiny_open,
	.close = tiny_close,
	.write = tiny_write,
	.write_room = tiny_write_room,
	.set_termios = tiny_set_termios,
	.proc_show = tiny_proc_show,
	.tiocmget = tiny_tiocmget,
	.tiocmset = tiny_tiocmset,
	.ioctl = tiny_ioctl,
};

static struct tty_driver *virtual_tty_driver;

static int __init virtual_tty_init(void)
{	
	int retval;
	int i;

	pr_info("%s - ", __func__);

	/* allocate the tty driver */
	pr_alert("Welcome to virtual tty driver!");
	pr_info("Welcome to virtual tty driver!");
	virtual_tty_driver = alloc_tty_driver(TINY_TTY_MINORS);
	if (!virtual_tty_driver)
		return -ENOMEM;

	/* initialize the tty driver */
	virtual_tty_driver->owner = THIS_MODULE;
	virtual_tty_driver->driver_name = "virtual_tty";
	virtual_tty_driver->name = "vtty";
	virtual_tty_driver->major = TINY_TTY_MAJOR,
	virtual_tty_driver->type = TTY_DRIVER_TYPE_SERIAL,
	virtual_tty_driver->subtype = SERIAL_TYPE_NORMAL,
	virtual_tty_driver->flags = TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV,
	virtual_tty_driver->init_termios = tty_std_termios;
	virtual_tty_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	tty_set_operations(virtual_tty_driver, &serial_ops);
	for (i = 0; i < TINY_TTY_MINORS; i++) {
		tty_port_init(tiny_tty_port + i);
		tty_port_link_device(tiny_tty_port + i, virtual_tty_driver, i);
	}

	/* register the tty driver */
	retval = tty_register_driver(virtual_tty_driver);
	if (retval) {
		pr_err("failed to register virtual tty driver");
		put_tty_driver(virtual_tty_driver);
		return retval;
	}

	for (i = 0; i < TINY_TTY_MINORS; ++i)
		tty_register_device(virtual_tty_driver, i, NULL);

	pr_info( "succesfully registered virtual tty driver");
	pr_info(DRIVER_DESC " " DRIVER_VERSION);
	return retval;
}

static void __exit virtual_tty_exit(void)
{	
	struct tiny_serial *tiny;
	int i;

	pr_info("%s - good bye from virtual tty driver!", __func__);
	pr_alert("%s - good bye from virtual tty driver!", __func__);
	
	for (i = 0; i < TINY_TTY_MINORS; ++i)
		tty_unregister_device(virtual_tty_driver, i);
	tty_unregister_driver(virtual_tty_driver);

	/* shut down all of the timers and free the memory */
	for (i = 0; i < TINY_TTY_MINORS; ++i) {
		tiny = tiny_table[i];
		if (tiny) {
			/* close the port */
			while (tiny->open_count)
				do_close(tiny);

			/* shut down our timer and free the memory */
#ifdef ENABLE_VTTY_TIMER
			del_timer(&tiny->timer);
#endif
			mutex_destroy(&tiny->mutex);
			kfree(tiny);
			tiny_table[i] = NULL;
		}
	}
	put_tty_driver(virtual_tty_driver);
}

module_init(virtual_tty_init);
module_exit(virtual_tty_exit);
