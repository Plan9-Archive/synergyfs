#include <u.h>
#include <stdio.h>
#include <libc.h>
#include <bio.h>
#include <auth.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>
#include <draw.h>

typedef struct Keyboard Keyboard;
typedef struct Mouse Mouse;
typedef struct Queue Queue;
typedef struct Msg Msg;
typedef struct Snarfbuf Snarfbuf;

enum 
{
	Qdir,
	Qcons,
	Qmouse,
	Qsnarf,
	Nqid,
};

/* Mouse.ctl */
enum
{
	Mnone		= 0,
	Mxy			= (1<<0),
	Mxyrelative	= (1<<1),
	Mclearbuttons	= (1<<2),
	Msetbuttons	= (1<<3),
	Mresetbuttons	= (1<<4),
	Mresized		= (1<<5),
	Mmove		= (1<<6),
	Mlocal		= (1<<7),
	Mlocalwrite	= (1<<8),
};

/* Keyboard.ctl */
enum
{
	Knone		= 0,
	Kup			= 1,
	Kdown		= 2,
	Krepeat		= 3,
	Ksend		= 4,
};

enum
{
	Ftext,
	Fbmp,
	Fhtml,
	Fmax,
};

struct Snarfbuf
{
	int			len;
	char			*buf;
};

struct Keyboard
{
	int			ctl;

	int			key;
	int			mod;
	int			button;
	int			repeat;

	int			send;
};

struct Mouse
{
	int			ctl;

	Point			xy;
	int			buttons;
};

struct Queue
{
	Lock			lock;
	Req			*head;
	Req			**tail;
};

struct Msg
{
	uchar		*p;
	uchar		*e;
};

static char *synergyaddr = nil;

static int mousefd;
static Channel *mousechan;

static int consfd;
static Channel *conschan;
static int kbdinfd;

static Queue qmouse;
static Queue qcons;

static Lock snarflock;
static int snarfversion = 0;
static Snarfbuf snarfbuf;
static int snarfchange = 0;

static int screenchange = 0;
static Point screenmouse;

static int packmsg(Msg *msg, char *fmt, ...);
static int packfmtlen(char *fmt, ...);
static int unpackmsg(Msg *msg, char *fmt, ...);

static int
vpackmsglen(char *fmt, va_list arg)
{
	int n, q;
	char *vas;
	int vai;

	n = 0;
	while(*fmt){
		if(*fmt!='%'){
			n++;
			fmt++;
			continue;
		}
		fmt++;
		q = 0;
		if((*fmt >= '0') && (*fmt <= '9')){
			q = *(fmt++)-'0';
		}
		switch(*fmt){
		case 'i':
			vai = va_arg(arg, int);
			USED(vai);
			n += q;
			break;
		case 's':
			vas = va_arg(arg, char*);
			n += (4 + strlen(vas));
			break;
		}
		fmt++;
	}
	return n;
}

static int
packmsglen(char *fmt, ...)
{
	va_list arg;
	int n;

	va_start(arg, fmt);
	n = vpackmsglen(fmt, arg);
	va_end(arg);
	return n;
}

static int
vunpackmsg(Msg *msg, char *fmt, va_list arg)
{
	int *vai;
	char **vas;

	int n, q, i;

	n = 0;
	while(*fmt){
		if(*fmt!='%'){
			if(msg->p >= msg->e)
				return n;
			msg->p++;
			fmt++;
			continue;
		}
		fmt++;

		q = 0;
		if((*fmt>='0') && (*fmt<='9')){
			q = *fmt-'0';
			fmt++;
		}
		switch(*fmt){
		default:
			return n;
		case 'i':
			if(msg->p+q > msg->e)
				return n;
			if(vai = va_arg(arg, int*)){
				switch(q){
				default:
					return n;
				case 1:
					*vai = 	(int)msg->p[0];
					break;
				case 2:
					*vai = 	((int)msg->p[0])<<8 | 
							((int)msg->p[1]);
					break;
				case 4:
					*vai = 	((int)msg->p[0])<<24 | 
							((int)msg->p[1])<<16 | 
							((int)msg->p[2])<<8 | 
							((int)msg->p[3]);
					break;
				}
			}
			msg->p+=q;
			break;
		case 's':
			vas = va_arg(arg, char**);
			if(msg->p+4 > msg->e)
				return n;
			q = ((int)msg->p[0]) << 24 |
				((int)msg->p[1]) << 16 |
				((int)msg->p[2]) << 8 |
				((int)msg->p[3]);
			msg->p += 4;
			if(msg->p+q > msg->e)
				return n;
			if(vas == nil){
				msg->p += q;
				break;
			}
			*vas = malloc(1 + q);
			(*vas)[q] = '\0';
			for(i = 0; i < q; i++){
				(*vas)[i] = *msg->p;
				msg->p++;
			}
			break;
		}

		n++;
		fmt++;
	}
	return n;
}

static int
vpackmsg(Msg *msg, char *fmt, va_list arg)
{
	int vai;
	char *vas;

	int n, q;

	n = 0;
	while(*fmt){
		if(*fmt!='%'){
			if(msg->p >= msg->e)
				return n;
			*msg->p++ = *fmt++;
			continue;
		}
		fmt++;

		q = 0;
		if((*fmt >= '0') && (*fmt <= '9')){
			q = *(fmt++)-'0';
		}
		switch(*fmt){
		default:
			return n;
		case 'i':
			if(msg->p+q > msg->e)
				return n;
			vai = va_arg(arg, int);
			switch(q){
			default:
				return n;
			case 1:
				msg->p[0] = vai		& 0xff;
				break;
			case 2:
				msg->p[0] = vai>>8		& 0xff;
				msg->p[1] = vai		& 0xff;
				break;
			case 4:
				msg->p[0] = (vai>>24)	& 0xff;
				msg->p[1] = (vai>>16)	& 0xff;
				msg->p[2] = (vai>>8)	& 0xff;
				msg->p[3] = vai		& 0xff;
				break;
			}
			msg->p += q;
			break;
		case 's':
			vas = va_arg(arg, char*);
			q = strlen(vas);
			if(msg->p + 4 + q > msg->e)
				return n;
			packmsg(msg, "%4i", q);
			if(q > 0)
				memcpy(msg->p, vas, q);
			msg->p += q;
			break;
		}
		n++;
		fmt++;
	}
	return n;
}

static int
unpackmsg(Msg *msg, char *fmt, ...)
{
	va_list arg;
	int n;

	va_start(arg, fmt);
	n = vunpackmsg(msg, fmt, arg);
	va_end(arg);
	return n;
}

static int
packmsg(Msg *msg, char *fmt, ...)
{
	va_list arg;
	int n;

	va_start(arg, fmt);
	n = vpackmsg(msg, fmt, arg);
	va_end(arg);
	return n;
}

static int
writemsg(int fd, char *fmt, ...)
{
	va_list arg;
	uchar *buf;
	Msg m;
	int n, l;

	va_start(arg, fmt);
	l = vpackmsglen(fmt, arg);
	buf = emalloc9p(l+4);
	m.p = buf+4;
	m.e = m.p + l;
	n = vpackmsg(&m, fmt, arg);
	va_end(arg);
	m.p = buf;
	packmsg(&m, "%4i", l);
	if(write(fd, buf, l+4)!=l+4){
		free(buf);
		return -1;
	}
	free(buf);
	return n;
}

static void
initqueue(Queue *q)
{
	q->head = nil;
	q->tail = &(q->head);
}

static void
enqueuereq(Queue *q, Req *x)
{
	lock(&q->lock);
	x->aux = nil;
	*(q->tail) = x;
	q->tail = &x->aux;
	unlock(&q->lock);
}

static Req*
dequeuereq(Queue *q, Req *x)
{
	Req **r;

	lock(&q->lock);
	if(x==nil)
		x = q->head;
	for(r=&(q->head); *r; r=(Req**)&((*r)->aux)){
		if(*r != x)
			continue;
		if((*r = x->aux) == nil)
			q->tail = r;
		x->aux = nil;
		unlock(&q->lock);
		return x;
	}
	unlock(&q->lock);
	return nil;
}

static int
sendqueue(Queue *q, void *buf, int len)
{
	Req *r;

	if(r = dequeuereq(q, nil)){
		if(r->ifcall.count < len){
			respond(r, "buffer too small");
			return 0;
		}
		r->ofcall.count = len;
		memcpy(r->ofcall.data, buf, len);
		respond(r, nil);
		return 1;
	} else {
		return 0;
	}
}

static void
mousereadproc(void *)
{
	for(;;){
		char buf[50];
		Mouse mouse;
		char c;
		int x, y, b;

		if(readn(mousefd, buf, 49)!=49){
			fprint(2, "error reading mouse\n");
			exits("readmouse");
		}
		buf[49] = '\0';
		sscanf(buf, "%c%11d %11d %11d", &c, &x, &y, &b);

		mouse.ctl = Mlocal | Mxy | Mclearbuttons | Msetbuttons;
		if(c == 'r'){
       		        if(getwindow(display, Refnone) < 0)
          		           sysfatal("resize failed: %r");
			mouse.ctl |= Mresized;
		}
		mouse.xy.x = x;
		mouse.xy.y = y;
		mouse.buttons = b;
		send(mousechan, &mouse);
	}
}

static void
mousewrite(Req *req)
{
	Mouse mouse;
	char buf[50];
	int x, y;

	if(req->ifcall.count >= sizeof(buf)){
		respond(req, "buffer too big");
		return;
	}
	memcpy(buf, req->ifcall.data, req->ifcall.count);
	buf[req->ifcall.count] = '\0';	
	if(sscanf(buf, "m%d %d", &x, &y)!=2){
		respond(req, "bad data");
		return;
	}
	req->ofcall.count = req->ifcall.count;
	respond(req, nil);
	mouse.ctl = Mlocalwrite | Mmove | Mxy;
	mouse.xy.x = x;
	mouse.xy.y = y;

	send(mousechan, &mouse);
}

static void
consreadproc(void *)
{
	Keyboard k;

	for(;;){
		uchar b[1];

		if(readn(consfd, b, sizeof(b))!=sizeof(b)){
			fprint(2, "error reading cons\n");
			exits("readcons");
		}

		k.ctl = Ksend;
		k.send = b[0];
		send(conschan, &k);
	}
}

static void
screensaver(int on)
{
	if(on){
		int fd;

		sleep(200);
		fd = open("#v/vgactl", OWRITE);
		if(fd < 0)
			return;
		fprint(fd, "blank");
		close(fd);
	} else {
		Mouse m;
		m.ctl = Mmove;
		send(mousechan, &m);
	}
}

/* synergy protocol handling */

static void
synergyproc(void *)
{
	int clip[2];

	int fd;
	uchar *buf = nil;
	int buflen = 0;
	int oldsnarfversion;
	int ignoremove;

	ignoremove = 0;
	oldsnarfversion = snarfversion;
	fd = -1;
reconnect:
	if(fd >= 0)
		close(fd);
	fd = dial(synergyaddr, 0, 0, 0);
	if(fd < 0) {
		sleep(10000);
		goto reconnect;
	}
	for(;;){
		Mouse mouse;
		Keyboard keyboard;
		int i, x, y, seq, on, key, btn, rep, mod, major, minjor, cfmt;
		ulong msgid;

		Msg m;
		int l;

		if(snarfchange){
			snarfchange = 0;
			for(i=0; i<2; i++){
				clip[i] = 1;
				if(writemsg(fd, "CCLP%1i%4i", i, seq)!=2)
					goto reconnect;
			}
		}
		if(screenchange){
			screenchange = 0;
			if(writemsg(fd, "DINF%2i%2i%2i%2i%2i%2i%2i", 
				screen->r.min.x,
				screen->r.min.y,
				screen->r.max.x,
				screen->r.max.y,
				0,			/* size of warp zone (obsolete) */
				screenmouse.x, 
				screenmouse.y		/* current mouse position */
			)!=7){
				goto reconnect;
			}
			ignoremove = 1;
		}

		if(buflen < 4){
			buflen = 256;
			buf = erealloc9p(buf, buflen);
		}

		if(readn(fd, buf, 4)!=4){
			fprint(2,"read msg size failed: %r\n");
			goto reconnect;
		}
		m.p = buf;
		m.e = m.p + buflen;
		unpackmsg(&m, "%4i", &l);
		if(l<4 || l>1024*1024){
			fprint(2, "invalid msg size\n");
			goto reconnect;
		}
		if(buflen < l){
			buflen = l;
			buf = erealloc9p(buf, buflen);
		}
		m.p = buf;
		m.e = m.p + buflen;
		if(readn(fd, m.p, l)!=l){
			fprint(2, "read msg failed: %r\n");
			goto reconnect;
		}

		m.e = m.p + l;
		unpackmsg(&m, "%4i", &msgid);

#define MSGID(c1,c2,c3,c4)	c1<<24|c2<<16|c3<<8|c4

		switch(msgid){
		default:
		unhandled:
			fprint(2, "unhandled: %c%c%c%c\n",
				(char)((msgid>>24)&0xFF),
				(char)((msgid>>16)&0xFF),
				(char)((msgid>>8)&0xFF),
				(char)((msgid>>0)&0xFF));
			break;

		case MSGID('Q','I','N','F'):	/* query info from server */
			screenchange = 1;
			break;

		case MSGID('S','y','n','e'):	/* hello from server */
			if(unpackmsg(&m, "rgy%2i%2i", &major, &minjor)!=2)
				goto unhandled;
			if(writemsg(fd, "Synergy%2i%2i%s", 1, 3, sysname())!=3)
				goto reconnect;
			break;

		case MSGID('C','A','L','V'):
			/* Keep alive ping */
			if(writemsg(fd, "CALV")!=0)
				goto reconnect;
			break;

		case MSGID('C','N','O','P'):	/* nop */
			break;

		case MSGID('C','B','Y','E'):
			goto reconnect;

		case MSGID('C','I','A','K'):	/* info acknowledge */
			ignoremove = 0;
			break;

		case MSGID('C','I','N','N'):	/* enter */
			oldsnarfversion = snarfversion;
			if(unpackmsg(&m, "%2i%2i%4i%2i", &x, &y, &seq, &mod)!=4)
				goto unhandled;
			mouse.xy.x = x;
			mouse.xy.y = y;
			mouse.ctl = Mxy | Mmove | Mclearbuttons;
			send(mousechan, &mouse);
			break;

		case MSGID('C','C','L','P'):	/* grab clipboard */
			if(unpackmsg(&m, "%1i", &i)!=1)
				goto unhandled;
			clip[i] = 0;
			break;

		case MSGID('C','O','U','T'):	/* leave */
			lock(&snarflock);
			if(snarfversion>oldsnarfversion && snarfbuf.len>0){
				Msg om;
				uchar *buf;
				int l;
				char fmt[] = "%4iDCLP%1i%4i%4i%4i%4i%4i";

				l = packmsglen(fmt, 0,0,0,0,0,0,0);
				buf = emalloc9p(l);

				for(i=0; i<2; i++){
					/* ignore the clipboards we dont own */
					if(clip[i]==0)
						continue;

					om.p = buf;
					om.e = buf + l;
					packmsg(&om, fmt,
						(l - 4) + snarfbuf.len,// message length
						i,				// clipboard id
						seq,				// sequence number from CINN
						4+4+4+snarfbuf.len,	// size of clipboard data
						1,				// num of clipboard records
						Ftext,			// 1st record type
						snarfbuf.len);		// 1st record size
					if(write(fd, buf, l)!=l){
						free(buf);
						unlock(&snarflock);
						goto reconnect;
					}
					if(write(fd, snarfbuf.buf, snarfbuf.len)!=snarfbuf.len){
						free(buf);
						unlock(&snarflock);
						goto reconnect;
					}
				}

				free(buf);
			}
			unlock(&snarflock);
			break;

		case MSGID('C','R','O','P'):	/* reset options */
			break;

		case MSGID('C','S','E','C'):	/* screensaver */
			if(unpackmsg(&m, "%1i", &on)!=1)
				goto unhandled;
			screensaver(on);
			break;

		case MSGID('D','C','L','P'):	/* clipboard data */
			if(unpackmsg(&m, "%1i%4i%4i", nil, nil, nil)!=3)
				goto unhandled;

			/*
			 * this can fail if number of formats is 0, so we
			 * just break out
			 */
			if(unpackmsg(&m, "%4i%4i%4i",
				nil,		// number of formats
				&cfmt,	// 1st format type
				&buflen	// 1st format size
			)!=3)
				break;

			/* we only handle HTML and Text */
			if((cfmt!=Ftext) && (cfmt!=Fhtml))
				break;

			/* check remaining data length */
			if((m.e-m.p) < buflen)
				buflen = (m.e-m.p);
			if(buflen <= 0)
				break;

			lock(&snarflock);
			snarfbuf.buf = erealloc9p(snarfbuf.buf, buflen+1);
			snarfbuf.len = buflen;
			memcpy(snarfbuf.buf, m.p, buflen);
			snarfbuf.buf[buflen] = '\0';
			snarfversion++; 
			oldsnarfversion = snarfversion;
			unlock(&snarflock);
			break;

		case MSGID('D','K','D','N'):	/* keydown */
			if(unpackmsg(&m, "%2i%2i%2i", &key, &mod, &btn)!=3)
				goto unhandled;
			keyboard.ctl = Kdown;
			keyboard.key = key;
			keyboard.mod = mod;
			keyboard.button = btn;
			send(conschan, &keyboard);
			break;

		case MSGID('D','K','U','P'):	/* keyup */
			if(unpackmsg(&m, "%2i%2i%2i", &key, &mod, &btn)!=3)
				goto unhandled;
			keyboard.ctl = Kup;
			keyboard.key = key;
			keyboard.mod = mod;
			keyboard.button = btn;
			send(conschan, &keyboard);
			break;

		case MSGID('D','K','R','P'):	/* keyrepeat */
			if(unpackmsg(&m, "%2i%2i%2i%2i", &key, &mod, &rep, &btn)!=4)
				goto unhandled;
			keyboard.ctl = Krepeat;
			keyboard.key = key;
			keyboard.mod = mod;
			keyboard.button = btn;
			keyboard.repeat = rep;
			send(conschan, &keyboard);
			break;

		case MSGID('D','M','D','N'):	/* mousedown */
			if(unpackmsg(&m, "%1i", &btn)!=1)
				goto unhandled;
			mouse.buttons = (1<<(btn-1));
			mouse.ctl = Msetbuttons;
			send(mousechan, &mouse);
			break;

		case MSGID('D','M','U','P'):	/* mouseup */
			if(unpackmsg(&m, "%1i", &btn)!=1)
				goto unhandled;
			mouse.buttons = (1<<(btn-1));
			mouse.ctl = Mresetbuttons;
			send(mousechan, &mouse);
			break;

		case MSGID('D','M','M','V'):	/* mousemove */
			if(ignoremove)
				break;
			if(unpackmsg(&m, "%2i%2i", &x, &y)!=2)
				goto unhandled;
			mouse.xy.x = x;
			mouse.xy.y = y;
			mouse.ctl = Mxy | Mmove;
			send(mousechan, &mouse);
			break;

		case MSGID('D','M','R','M'):	/* mousemove relative */
			if(ignoremove)
				break;
			if(unpackmsg(&m, "%2i%2i", &x, &y)!=2)
				goto unhandled;
			mouse.xy.x = x;
			mouse.xy.y = y;
			mouse.ctl = Mxyrelative | Mmove;
			send(mousechan, &mouse);
			break;

		case MSGID('D', 'M', 'W', 'M'): /* mouse wheel */
			if(unpackmsg(&m, "%2i%2i", &x, &y) != 2)
				goto unhandled;
			x = (x<<16)>>16;
			y = (y<<16)>>16;
			mouse.ctl = Msetbuttons;
			if(y > 0)
				mouse.buttons = 1<<3;
			else
				mouse.buttons = 1<<4;
			send(mousechan, &mouse);
			mouse.ctl = Mresetbuttons;
			send(mousechan, &mouse);
			break;

		case MSGID('D','S','O','P'):	/* ??? */
			break;
		}
	}
}

static void
mousechangeproc(void *)
{
	int resized;
	int ignorelocal;
	int ignoremove;

	Mouse mouse;
	Mouse m;

	resized = 0;
	ignorelocal = 0;
	ignoremove = 0;

	// initial mouse state
	mouse.buttons = mouse.xy.x = mouse.xy.y = 0;

	while(recv(mousechan, &m) > 0){
		vlong msec;
		char buf[50];

		if(m.ctl & Mresized){
			if(m.ctl & Mxy){
				screenmouse.x = m.xy.x;
				screenmouse.y = m.xy.y;
			}
			screenchange = 1;
			resized = 1;
		}

		if(m.ctl & Mlocalwrite){
			if(m.ctl & Mxy){
				screenmouse.x = m.xy.x;
				screenmouse.y = m.xy.y;
			}
			screenchange = 1;
		}

		// ignore local mouse events
		if(!resized && ignorelocal && ignorelocal-- && (m.ctl&Mlocal))
			continue;

		if(m.ctl & Mxy) {
			mouse.xy.x = m.xy.x;
			mouse.xy.y = m.xy.y;
		}
		if(m.ctl & Mxyrelative){
			mouse.xy.x += m.xy.x;
			mouse.xy.y += m.xy.y;
		}
	
		if(m.ctl & Mclearbuttons)
			mouse.buttons = 0;
		if(m.ctl & Msetbuttons)
			mouse.buttons |= m.buttons;
		if(m.ctl & Mresetbuttons)
			mouse.buttons &= ~m.buttons;

		msec = nsec()/1000000LL;

		snprint(buf, sizeof(buf), "%c%11d %11d %11d %11lud ",
			resized ? 'r' : 'm',
			mouse.xy.x, 
			mouse.xy.y, 
			mouse.buttons,
			(ulong)msec);

		if((!ignoremove && (m.ctl&Mmove)) || resized) {
			// writing mousefd to set cursor causes a read in mousereadproc()
			// that has local button values, so we ignore any Mlocal in the 
			// next 4 mousec recv()s that are not Mresized
			ignorelocal = 6;
			write(mousefd, buf, 49);
		}

		/*
		 * while we processing this message (write to /dev/mouse to set cursor pos), 
		 * maybe synergyproc has already send a Mmove-message to mousechan, so we just
		 * ignore the next Mmove message. we just dont want the cursor
		 * to jump arround :-)
		 */
		ignoremove = 0;
		if(m.ctl&Mlocalwrite)
			ignoremove = 1;

		if(sendqueue(&qmouse, buf, 49)){
			// only reset resized state if we are able to notify the client
			resized = 0;
		}
	}
}

static int map[][5] = {
{0xef08,	1,	0x08, 0x00, 0x00},	// del
{0xef09,	1,	0x09, 0x00, 0x00},	// tab?
{0xef0d,	1,	0x0a, 0x00, 0x00},	// enter
{0xef1b,	1,	0x1b, 0x00, 0x00},	// esc
{0xef50,	3,	0xef, 0x80, 0x8d},	// home
{0xef51,	3,	0xef, 0x80, 0x91},	// left
{0xef52,	3,	0xef, 0x80, 0x8e},	// up
{0xef53,	3,	0xef, 0x80, 0x92},	// right
{0xef54,	3,	0xef, 0xa0, 0x80},	// down
{0xef55,	3,	0xef, 0x80, 0x8f},	// page up
{0xef56,	3,	0xef, 0x80, 0x93},	// page down
{0xef57,	3,	0xef, 0x80, 0x98},	// end
{0xef63,	3,	0xef, 0x80, 0x94},	// ins
{0xefff,	1,	0x7f, 0x00, 0x00},	// del
{0x0000,	0,	0x00, 0x00, 0x00},
};

static void
conschangeproc(void *)
{
	Keyboard k;

	while(recv(conschan, &k) > 0){
		uchar b[3];
		int n;
		int i;
		int r;

		n = 0;
		switch(k.ctl){
		default:
			k.repeat = 0;
			break;

		case Ksend:
			n = 1;
			b[0] = k.send&0xFF;
			k.repeat = 1;
			k.ctl = Kdown;
			break;

		case Kdown:
			k.repeat = 1;
		case Krepeat:
			// we dont want to loop that long
			if(k.repeat > 20)
				k.repeat = 20;
			for(i=0; map[i][0]; i++){
				if(map[i][0]<k.key)
					continue;
				if(map[i][0]==k.key){
					n = map[i][1];
					//fprint(2, "n=%d\n", n);
					switch(n){
					case 3:
						b[0] = map[i][2]&0xff;
						b[1] = map[i][3]&0xff;
						b[2] = map[i][4]&0xff;
						break;
					case 2:
						b[0] = map[i][2]&0xff;
						b[1] = map[i][3]&0xff;
						break;
					case 1:
						b[0] = map[i][2]&0xff;
						break;
					}
				} else {
					//fprint(2, "no match 0x%x\n", k.key);
					if(k.key&~0x7F){
						n = 0;
						break;
					}
					n = 1;
					if(k.mod == 2) {
						switch(k.key) {
						case 'h':
							b[0] = 0x08;
							break;
						case 'u':
							b[0] = 0x15;
							break;
						case 'w':
							b[0] = 0x17;
							break;
						case 'd':
							b[0] = 0x04;
							break;
						case 'a':
							b[0] = 0x01;
							break;
						case 'e':
							b[0] = 0x05;
							break;
						default:
							b[0] = k.key&0x7F;
						}
					}else
						b[0] = k.key&0x7F;
				}
				break;
			}
			break;
		}

		if(n!=0){
			for(r=0; r<k.repeat; r++){
				write(kbdinfd, b, n);
			}
		}
	}
}

int
fillstat(ulong qid, Dir *d)
{
	memset(d, 0, sizeof(Dir));

	d->uid = "synergy";
	d->gid = "synergy";
	d->muid = "";
	d->qid = (Qid){qid, 0, 0};
	d->atime = time(0);

	switch(qid) {
	case Qdir:
		d->name = "/";
		d->qid.type = QTDIR;
		d->mode = DMDIR|0777;
		break;
	case Qcons:
		d->name = "cons";
		d->mode = 0666;
		break;
	case Qmouse:
		d->name = "mouse";
		d->mode = 0666;
		break;
	case Qsnarf:
		d->qid.vers = snarfversion;
		d->name = "snarf";
		d->mode = 0666;
		break;
	}
	return 1;
}


int
readtopdir(Fid*, uchar *buf, long off, int cnt, int blen)
{
	int i, m, n;
	long pos;
	Dir d;

	n = 0;
	pos = 0;
	for (i = 1; i < Nqid; i++){
		fillstat(i, &d);
		m = convD2M(&d, &buf[n], blen-n);
		if(off <= pos){
			if(m <= BIT16SZ || m > cnt)
				break;
			n += m;
			cnt -= m;
		}
		pos += m;
	}
	return n;
}

static void
fsattach(Req *r)
{
	char *spec;

	spec = r->ifcall.aname;
	if(spec && spec[0]) {
		respond(r, "invalid attach specifier");
		return;
	}

	r->fid->qid = (Qid){Qdir, 0, QTDIR};
	r->ofcall.qid = r->fid->qid;
	respond(r, nil);
}

static void
fsstat(Req *r)
{
	fillstat((ulong)r->fid->qid.path, &r->d);

	r->d.name = estrdup9p(r->d.name);
	r->d.uid = estrdup9p(r->d.uid);
	r->d.gid = estrdup9p(r->d.gid);
	r->d.muid = estrdup9p(r->d.muid);

	respond(r, nil);
}

static char*
fswalk1(Fid *fid, char *name, Qid *qid)
{
	switch((ulong)fid->qid.path) {
	case Qdir:
		if (strcmp(name, "..") == 0) {
			*qid = (Qid){Qdir, 0, QTDIR};
			fid->qid = *qid;
			return nil;
		}
		if (strcmp(name, "cons") == 0) {
			*qid = (Qid){Qcons, 0, 0};
			fid->qid = *qid;
			return nil;
		}
		if (strcmp(name, "mouse") == 0) {
			*qid = (Qid){Qmouse, 0, 0};
			fid->qid = *qid;
			return nil;
		}
		if (strcmp(name, "snarf") == 0) {
			*qid = (Qid){Qsnarf, 0, 0};
			qid->vers = snarfversion;
			fid->qid = *qid;
			return nil;
		}
		return "file not found";
		
	default:
		return "walk in non-directory";
	}
}


static void
fsopen(Req *r)
{
	int omode;
	Fid *fid;
	ulong path;

	fid = r->fid;
	path = (ulong)fid->qid.path;
	omode = r->ifcall.mode;
	
	switch(path) {
	case Qdir:
		if (omode == OREAD)
			respond(r, nil);
		else
			respond(r, "permission denied");
		return;
	default:
		switch(path) {
		case Qcons:
		case Qmouse:
			goto permok;
		case Qsnarf:
			// create a temporary Snarfbuf if opend writable and attach it
			// to fid->aux
			omode &= OMASK;
			if((omode==OWRITE) || (omode==ORDWR)){
				Snarfbuf *b;

				b = emalloc9p(sizeof(Snarfbuf));
				b->len = 0;
				b->buf = nil;
				fid->aux = b;
			} else {
				fid->aux = nil;
			}
			goto permok;
		}
		respond(r, "permission denied");
		return;
permok:
		/*  handle open */
		respond(r, nil);
		return;
	}
}

static void
fsread(Req *r)
{
	uchar *buf;
	long count;
	vlong offset;

	offset = r->ifcall.offset;
	count = r->ifcall.count;
	buf = (uchar*)r->ofcall.data;

	switch((ulong)r->fid->qid.path) {
	case Qdir:
		r->ofcall.count = readtopdir(r->fid, buf, offset, count, count);
		respond(r, nil);
		return;

	case Qcons:
		enqueuereq(&qcons, r);
		break;

	case Qmouse:
		enqueuereq(&qmouse, r);
		break;

	case Qsnarf:
		lock(&snarflock);
		if(snarfbuf.len - offset < count)
			count = snarfbuf.len - offset;
		if(count < 0)
			count = 0;
		if(count > 0)
			memcpy(buf, snarfbuf.buf + offset, count);
		r->ofcall.count = count;
		unlock(&snarflock);

		respond(r, nil);
		break;
	}
}

static void
fswrite(Req *r)
{
	char e[ERRMAX];
	int c;

	switch((ulong)r->fid->qid.path) {
	default:
		respond(r, "bug in fs");
		break;

	case Qcons:
		if((c = write(consfd, r->ifcall.data, r->ifcall.count)) < 0){
			rerrstr(e, sizeof(e));
			respond(r, e);
		}
		r->ofcall.count = c;
		respond(r, nil);
		break;

	case Qmouse:
		mousewrite(r);
		break;

	case Qsnarf:
		/*
		 * if snarf was opend writable, we had attached a temporary 
		 * Snarfbuf* to fid->aux
		 */
		if(r->fid->aux){
			int count;

			if((count = r->ifcall.count) > 0){
				Snarfbuf *b;
				char *p;

				b = r->fid->aux;
				p = erealloc9p(b->buf, b->len + count + 1);
				memcpy(p + b->len, r->ifcall.data, count);
				b->buf = p;
				b->len += count;
				b->buf[b->len] = '\0';
			}
			r->ofcall.count = count;
			respond(r, nil);
		} else {
			// something wrong in fsopen
			respond(r, "bug in fs");
		}
		break;
	}
}

static void
fsflush(Req *r)
{
	switch((ulong)r->oldreq->fid->qid.path) {
	case Qcons:
		if(dequeuereq(&qcons, r->oldreq)){
			respond(r->oldreq, "interrupted");
		}
		break;
	case Qmouse:
		if(dequeuereq(&qmouse, r->oldreq)){
			respond(r->oldreq, "interrupted");
		}
		break;
	}
	respond(r, nil);
}

static void
fsdestroyfid(Fid *fid)
{
	switch((ulong)fid->qid.path){
	case Qsnarf:
		if(fid->aux){
			Snarfbuf *b;

			b = fid->aux;
			fid->aux = nil;

			if((b->len > 0) && b->buf){

				lock(&snarflock);
				if(snarfbuf.buf)
					free(snarfbuf.buf);
				snarfbuf.buf = b->buf;
				snarfbuf.len = b->len;
				snarfversion++;

				// this fires the CCLP message in synergyproc
				snarfchange = 1;
				unlock(&snarflock);

				b->buf = nil;
				b->len = 0;
			}
			free(b);
		}
		break;
	}
}

Srv fs = {
	.attach=			fsattach,
	.walk1=			fswalk1,
	.open=			fsopen,
	.read=			fsread,
	.write=			fswrite,
	.stat=			fsstat,
	.flush=			fsflush,
	.destroyfid=		fsdestroyfid,
};

void
usage(void)
{
	fprint(2, "usage: synergyfs [-m mntpnt] [net!]server!24800\n");
	exits("usage");
}

void
threadmain(int argc, char** argv)
{
	char* mtpt = "/dev";

	ARGBEGIN{
	case 'm':
		mtpt = EARGF(usage());
		break;
	default:
		usage();
	}ARGEND
	
	if(initdraw(nil, nil, argv[0]) < 0){
		fprint(2, "stats: initdraw failed: %r\n");
		exits("initdraw");
	}

	synergyaddr = argv[argc-1];

	if(synergyaddr==nil)
		usage();

	snarfbuf.buf = nil;
	snarfbuf.len = 0;

	screenmouse.x = 0;
	screenmouse.y = 0;

	mousechan = chancreate(sizeof(Mouse), 0);
	conschan = chancreate(sizeof(Keyboard), 0);

	if((mousefd = open("/dev/mouse", ORDWR)) < 0){
		fprint(2, "error open mouse: %r\m");
		exits("open");
	}
//	if((consfd = open("/dev/consctl", OWRITE)) < 0){
//		fprint(2, "error open consctl: %r\m");
//		exits("open");
//	}
//	fprint(consfd, "rawon");
	// leave consctl open to keep rawon
	if((consfd = open("/dev/cons", ORDWR)) < 0){
		fprint(2, "error open cons: %r\m");
		exits("open");
	}
	if((kbdinfd = open("/dev/kbdin", OWRITE)) < 0){
		fprint(2, "error open kbdin: %r\m");
		exits("open");
	}

	initqueue(&qcons);
	initqueue(&qmouse);

	proccreate(mousereadproc, nil, 8192);
	proccreate(mousechangeproc, nil, 8192);
	proccreate(consreadproc, nil, 8192);
	proccreate(conschangeproc, nil, 8192);
	proccreate(synergyproc, nil, 8192);

	threadpostmountsrv(&fs, "synergy", mtpt, MBEFORE);
}
