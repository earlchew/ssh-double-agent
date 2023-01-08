/**
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "err.h"
#include "fd.h"

#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <sys/event.h>

/******************************************************************************/
int signal_fd(pid_t aSignal)
{
    int rc = -1;

    int signalFd = -1;

    if (!aSignal) {
        errno = EINVAL;
        goto Finally;
    }

    signalFd = kqueue();
    if (-1 == signalFd)
        goto Finally;

    struct kevent kEvent;

    EV_SET(
        &kEvent, aSignal,
        EVFILT_SIGNAL, EV_ADD | EV_ENABLE,
        0, 0, 0);

    if (-1 == kevent(signalFd, &kEvent, 1, 0, 0, 0))
        goto Finally;

    rc = 0;

Finally:

    FINALLY({
        if (rc)
            signalFd = fd_close(signalFd);
    });

    return rc ? rc : signalFd;
}

/*----------------------------------------------------------------------------*/
int signal_fd_read(int aSignalFd)
{
    int rc = -1;

    int events = -1;

    struct kevent kEvent;

    struct timespec zeroTimeout = { 0, 0 };

    events = kevent(aSignalFd, 0, 0, &kEvent, 1, &zeroTimeout);
    if (-1 == events) {
        if (EINTR != errno)
            goto Finally;
        events = 0;
    }

    rc = 0;

Finally:

    return rc ? rc : events;
}

/******************************************************************************/
