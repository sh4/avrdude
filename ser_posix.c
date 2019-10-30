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

/* $Id$ */

/*
 * Posix serial interface for avrdude.
 */

#if !defined(WIN32NATIVE)

#include "ac_cfg.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "avrdude.h"
#include "libavrdude.h"

long serial_recv_timeout = 5000; /* ms */

enum Command {
  CMD_NOOP = 0,
  CMD_CLOSE,
  CMD_READ,
  CMD_WRITE,
  CMD_SET_PARAMETERS,
  CMD_GET_CD,
  CMD_GET_CTS,
  CMD_GET_DSR,
  CMD_GET_DTR,
  CMD_GET_RI,
  CMD_GET_RTS ,
  CMD_SET_DTR,
  CMD_SET_RTS,
  CMD_GET_LAST_ERROR,
};

enum LastErrorResult {
  LAST_ERR_OK = 0,
  LAST_GENERIC_ERR = -1024,
  LAST_ERR_EMPTY = LAST_GENERIC_ERR - 1,
  LAST_ERR_BUFFER_SIZE_INEFFICIENT = LAST_GENERIC_ERR - 2,
  LAST_ERR_BUFFER_NULL = LAST_GENERIC_ERR - 3,
};

static int read_full(int fd, uint8_t* buf, int count) {
  int read_bytes = 0;
  while (count > 0) {
    int rc = read(fd, buf + read_bytes, count);
    if (rc < 0) {
      return rc;
    }
    read_bytes += rc;
    count -= rc;
  }
  return read_bytes;
}

static int write_full(int fd, const uint8_t* buf, int count) {
  int written_bytes = 0;
  while (count > 0) {
    int rc = write(fd, buf + written_bytes, count);
    if (rc < 0) {
      return rc;
    }
    written_bytes += rc;
    count -= rc;
  }
  return written_bytes;
}

// Java OutputStream bitness is big-endian 

static int32_t cmd_io_read_int(int fd) {
  uint8_t buf[sizeof(int32_t)];
  int rc = read_full(fd, buf, sizeof(buf));
  if (rc != sizeof(buf)) {
    return rc;
  }
  int32_t value = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
  avrdude_message(MSG_TRACE, "cmd_io_read_int: fd=%d, value=%d\n", fd, value);
  return value;
}

static int cmd_io_write_int(int fd, int32_t value) {
  uint32_t v = value;
  uint8_t buf[] = { (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v&0xff };
  avrdude_message(MSG_TRACE, "cmd_io_write_int: fd=%d, value=%d\n", fd, value);
  return write_full(fd, buf, sizeof(buf));
}

static uint8_t cmd_io_read_byte(int fd) {
  uint8_t buf;
  int rc = read(fd, &buf, sizeof(buf));
  if (rc != sizeof(buf)) {
    return rc;
  }
  return rc;
}

static uint8_t cmd_io_write_byte(int fd, uint8_t value) {
  return write(fd, &value, sizeof(value));  
}

static int cmd_send(int fd, enum Command cmd) {
  avrdude_message(MSG_TRACE, "cmd_send: fd=%d, cmd=%d\n", fd, cmd);  
  int rc = write_full(fd, (const uint8_t *)&cmd, sizeof(uint8_t));
  return rc;
}

static int execute_cmd_noop(int read_fd, int write_fd) {
  int rc = cmd_send(write_fd, CMD_NOOP);
  if (rc < 0) {
    return rc;
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_close(int read_fd, int write_fd) {
  int rc = cmd_send(write_fd, CMD_CLOSE);
  if (rc < 0) {
    return rc;
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_read(int read_fd, int write_fd, uint8_t* buf, int count, int timeout_miliesconds) {
  int rc;
  rc = cmd_send(write_fd, CMD_READ);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_write_int(write_fd, count);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_write_int(write_fd, timeout_miliesconds);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_read_int(read_fd);
  if (rc < 0) {
    return rc;
  }
  return read_full(read_fd, buf, rc);
}

static int execute_cmd_write(int read_fd, int write_fd, const uint8_t* buf, int count) {
  int rc;
  rc = cmd_send(write_fd, CMD_WRITE);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_write_int(write_fd, count);
  if (rc < 0) {
    return rc;
  }
  rc = write_full(write_fd, buf, count);
  if (rc < 0) {
    return rc;
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_set_parameters(int read_fd, int write_fd, int baud_rate, int data_bits, int stop_bits, int parity) {
  int rc;
  rc = cmd_send(write_fd, CMD_SET_PARAMETERS);
  if (rc < 0) {
    return rc;
  }
  int params[] = { baud_rate, data_bits, stop_bits, parity };
  avrdude_message(MSG_TRACE, "baud_rate=%d, data_bits=%d, stop_bits=%d, parity=%d\n",
    baud_rate, data_bits, stop_bits, parity);
  for (int i = 0; i < sizeof(params)/sizeof(int); i++) {
    rc = cmd_io_write_int(write_fd, params[i]);
    if (rc < 0) {
      return rc;
    }
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_set_dtr(int read_fd, int write_fd, int enable) {
  int rc;
  rc = cmd_send(write_fd, CMD_SET_DTR);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_write_byte(write_fd, enable ? 1 : 0);
  if (rc < 0) {
    return rc;
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_set_rts(int read_fd, int write_fd, int enable) {
  int rc;
  rc = cmd_send(write_fd, CMD_SET_RTS);
  if (rc < 0) {
    return rc;
  }
  rc = cmd_io_write_byte(write_fd, enable ? 1 : 0);
  if (rc < 0) {
    return rc;
  }
  return cmd_io_read_int(read_fd);
}

static int execute_cmd_get_last_error(int read_fd, int write_fd, char* buf, int* length) {
  int rc;
  assert(length && *length >= 1);
  rc = cmd_send(write_fd, CMD_GET_LAST_ERROR);
  if (rc < 0) { // last error is empty
    *length = 0;
    return rc;
  }
  rc = cmd_io_write_int(write_fd, *length - 1);
  if (rc < 0) { // client buffer size is inefficient 
    int buffer_size = cmd_io_read_int(read_fd);
    if (buffer_size <= 0) {
      *length = buffer_size;
      return rc;
    }
    *length = buffer_size + 1; // +1: null temrinate char
    return rc;
  }
  int error_length = cmd_io_read_int(read_fd);
  if (error_length <= 0) {
    *length = 0;
    return LAST_ERR_EMPTY;
  }
  if (!buf) {
    *length = error_length + 1;
    return LAST_ERR_BUFFER_NULL;
  }
  rc = read_full(read_fd, (uint8_t *)buf, error_length);
  if (rc < 0) {
    *length = 0;
    return rc;
  }
  buf[error_length] = '\0';
  *length = error_length;
  return LAST_ERR_OK;
}

static int ser_setspeed(union filedescriptor *fd, long baud)
{
  int rc;
  rc = execute_cmd_set_parameters(STDIN_FILENO, STDOUT_FILENO, baud, 8, 1, 0);
  if (rc < 0) {
    avrdude_message(MSG_INFO, "%s: ser_setspeed(): execute_cmd_set_parameters() failed\n",
            progname);
    return -errno;
  }
  return 0;
}

static int ser_set_dtr_rts(union filedescriptor *fd, int is_on)
{
  int rc;
  rc = execute_cmd_set_dtr(STDIN_FILENO, STDOUT_FILENO, is_on);
  if (rc < 0) {
    avrdude_message(MSG_INFO, "%s: ser_set_dtr_rts(): execute_cmd_set_dtr() failed\n",
            progname);
    return -errno;
  }
  rc = execute_cmd_set_rts(STDIN_FILENO, STDOUT_FILENO, is_on);
  if (rc < 0) {
    avrdude_message(MSG_INFO, "%s: ser_set_dtr_rts(): execute_cmd_set_rts() failed\n",
            progname);
    return -errno;
  }
  return 0;
}

static int ser_open(char * port, union pinfo pinfo, union filedescriptor *fdp)
{
  int rc;
  fdp->ifd = 0;

  /*
   * set serial line attributes
   */
  rc = ser_setspeed(fdp, pinfo.baud);
  if (rc) {
    avrdude_message(MSG_INFO, "%s: ser_open(): can't set attributes for device \"%s\": %s\n",
                    progname, port, strerror(-rc));
    return -1;
  }
  return 0;
}


static void ser_close(union filedescriptor *fd)
{
  execute_cmd_close(STDIN_FILENO, STDOUT_FILENO);
}


static int ser_send(union filedescriptor *fd, const unsigned char * send_buf, size_t buflen)
{
  int rc;
  const unsigned char * p = send_buf;
  size_t len = buflen;

  if (!len)
    return 0;

  if (verbose > 3)
  {
      avrdude_message(MSG_TRACE, "%s: Send: ", progname);

      while (buflen) {
        unsigned char c = *send_buf;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE, ". ");
        }
        avrdude_message(MSG_TRACE, "[%02x] ", c);

        send_buf++;
        buflen--;
      }

      avrdude_message(MSG_TRACE, "\n");
  }

  while (len) {
    rc = execute_cmd_write(STDIN_FILENO, STDOUT_FILENO, p, (len > 1024) ? 1024 : len);
    if (rc < 0) {
        avrdude_message(MSG_INFO, "%s: ser_send(): execute_cmd_write() error: %s\n",
                progname, strerror(errno));
        return -1;
    }
    p += rc;
    len -= rc;
  }

  return 0;
}


static int ser_recv(union filedescriptor *fd, unsigned char * send_buf, size_t buflen)
{
  int rc;
  unsigned char * p = send_buf;
  size_t len = 0;

  while (len < buflen) {
    rc = execute_cmd_read(STDIN_FILENO, STDOUT_FILENO, 
      p,
      (buflen - len > 1024) ? 1024 : buflen - len,
      serial_recv_timeout);
    if (rc < 0) {
      avrdude_message(MSG_INFO, "%s: ser_recv(): execute_cmd_read() error: %s\n",
                progname, strerror(errno));
      return -1;
    }
    p += rc;
    len += rc;
  }

  p = send_buf;

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
  unsigned char send_buf;

  if (display) {
    avrdude_message(MSG_INFO, "drain>");
  }

  while (1) {
    rc = execute_cmd_read(STDIN_FILENO, STDOUT_FILENO, &send_buf, 1, 250);
    if (rc < 0) {
        avrdude_message(MSG_INFO, "%s: ser_drain(): execute_cmd_read(): %s\n",
                progname, strerror(errno));
        return -1;
    } else if (rc == 0) {
      if (display) {
        avrdude_message(MSG_INFO, "<drain\n");
      }
      break;
    }
    if (display) {
      avrdude_message(MSG_INFO, "%02x ", send_buf);
    }
  }

  return 0;
}

struct serial_device android_serdev =
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

struct serial_device *serdev = &android_serdev;

#endif  /* WIN32NATIVE */
