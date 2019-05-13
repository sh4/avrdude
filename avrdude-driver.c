#include "ac_cfg.h"
#include "avrdude.h"
#include <stdio.h>
#include <stdarg.h>
#include <sys/param.h>
#include <android/log.h>

#include "native-lib.h"

char * progname = "avrdude";		/* name of program, for messages */
char progbuf[PATH_MAX] = "avrdude";		/* spaces same length as progname */

int ovsigck = 0;		/* override signature check (-F) */
int verbose = 1;		/* verbosity level (-v, -vv, ...) */
int quell_progress = 0;	/* quiteness level (-q, -qq) */

int avrdude_message(const int msglvl, const char *format, ...)
{
    int rc = 0;
    va_list ap;
    if (verbose >= msglvl) {
        va_start(ap, format);
        rc = __android_log_vprint(ANDROID_LOG_DEBUG, "avrdude", format, ap);
        va_end(ap);
    }
    
    if (rc > 0) {
        char buf[1024];
        int buflen = sizeof(buf);
        int written = 0;
        char* pbuf = buf;
        int allocated = 0;
        if (rc > sizeof(buf)) {
            pbuf = malloc(rc);
            buflen = rc;
            allocated = 1;
        }

        va_start(ap, format);
        written = vsnprintf(pbuf, buflen, format, ap);
        va_end(ap);

        if (written > 0) {
            UsbSerialPort_Log(msglvl, pbuf);
        }

        if (allocated) {
            free(pbuf);
            pbuf = NULL;
        }
    }

    return rc;
}