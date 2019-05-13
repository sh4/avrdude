/*
 * avrdude - A Downloader/Uploader for AVR device programmers
 * Copyright (C) 2003-2004  Theodore A. Roth  <troth@openavr.org>
 * Copyright (C) 2006 Joerg Wunsch <j@uriah.heep.sax.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* $Id: ser_posix.c 1365 2015-12-09 22:45:57Z joerg_wunsch $ */

/*
 * Posix serial interface for avrdude.
 */

#if !defined(WIN32NATIVE)


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "avrdude.h"
#include "libavrdude.h"

#include "native-lib.h"

long serial_recv_timeout = 5000; /* ms */

static int ser_setspeed(union filedescriptor *fd, long baud)
{
  UsbSerialPort_SetParameters((UsbSerialPortHandle)fd->pfd, baud, 8, 1, 0);
  return 0;
}

static int ser_set_dtr_rts(union filedescriptor *fdp, int is_on)
{
  UsbSerialPort_SetDTR((UsbSerialPortHandle)fdp->pfd, is_on);
  UsbSerialPort_SetRTS((UsbSerialPortHandle)fdp->pfd, is_on);
  return 0;
}

static void ser_close(union filedescriptor *fd)
{
  /*
   * restore original termios settings from ser_open
   */

  UsbSerialPort_Close((UsbSerialPortHandle)fd->pfd); 
}

static int ser_open(char * port, union pinfo pinfo, union filedescriptor *fdp)
{
  int rc;

  /*
   * open the serial port
   */
  UsbSerialPortHandle handle = (UsbSerialPortHandle)port;

  if (!handle) {
    avrdude_message(MSG_INFO, "%s: ser_open(): can't open device \"%s\": %s\n",
            progname, port, strerror(errno));
    return -1;
  }

  fdp->pfd = handle;

  /*
   * set serial line attributes
   */
  rc = ser_setspeed(fdp, pinfo.baud);
  if (rc) {
    avrdude_message(MSG_INFO, "%s: ser_open(): can't set attributes for device \"%s\": %s\n",
                    progname, port, strerror(-rc));
    ser_close(fdp);
    return -1;
  }
  return 0;
}

static int ser_send(union filedescriptor *fd, const unsigned char * buf, size_t buflen)
{
  int rc;
  const unsigned char * p = buf;
  size_t len = buflen;

  if (!len)
    return 0;

  if (verbose > 3)
  {
      avrdude_message(MSG_TRACE, "%s: Send: ", progname);

      while (buflen) {
        unsigned char c = *buf;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE, ". ");
        }
        avrdude_message(MSG_TRACE, "[%02x] ", c);

        buf++;
        buflen--;
      }

      avrdude_message(MSG_TRACE, "\n");
  }

  while (len) {
    rc = UsbSerialPort_Write((UsbSerialPortHandle)fd->pfd, p, (len > 1024) ? 1024 : len, 0);
    if (rc < 0) {
      avrdude_message(MSG_INFO, "%s: ser_send(): write error: %s\n",
              progname, strerror(errno));
      return -1;
    }
    p += rc;
    len -= rc;
  }

  return 0;
}


static int ser_recv(union filedescriptor *fd, unsigned char * buf, size_t buflen)
{
  int rc;
  unsigned char * p = buf;
  size_t len = 0;

  while (len < buflen) {
    rc = UsbSerialPort_Read((UsbSerialPortHandle)fd->pfd, p, (buflen - len > 1024) ? 1024 : buflen - len, serial_recv_timeout);
    if (rc < 0) {
      avrdude_message(MSG_INFO, "%s: ser_recv(): read error: %s\n",
              progname, strerror(errno));
      return -1;
    }
    p += rc;
    len += rc;
  }

  p = buf;

  if (verbose > 3)
  {
      avrdude_message(MSG_TRACE, "%s: Recv: ", progname);

      while (len) {
        unsigned char c = *p;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE, ". ");
        }
        avrdude_message(MSG_TRACE, "[%02x] ", c);

        p++;
        len--;
      }
      avrdude_message(MSG_TRACE, "\n");
  }

  return 0;
}


static int ser_drain(union filedescriptor *fd, int display)
{
  int rc;
  unsigned char buf;

  if (display) {
    avrdude_message(MSG_INFO, "drain>");
  }

  while (1) {
    rc = UsbSerialPort_Read((UsbSerialPortHandle)fd->pfd, &buf, 1, 250);
    if (rc == 0) {
      if (display) {
        avrdude_message(MSG_INFO, "<drain\n");
      }
      break;
    }
    if (rc < 0) {
      avrdude_message(MSG_INFO, "%s: ser_drain(): read error: %s\n",
              progname, strerror(errno));
      return -1;
    }
    if (display) {
      avrdude_message(MSG_INFO, "%02x ", buf);
    }
  }

  return 0;
}

struct serial_device serial_serdev =
{
  .open = ser_open,
  .setspeed = ser_setspeed,
  .close = ser_close,
  .send = ser_send,
  .recv = ser_recv,
  .drain = ser_drain,
  .set_dtr_rts = ser_set_dtr_rts,
  .flags = SERDEV_FL_CANSETSPEED,
};

struct serial_device *serdev = &serial_serdev;

#endif  /* WIN32NATIVE */
