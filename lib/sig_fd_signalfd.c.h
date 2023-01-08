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

#include <sys/signalfd.h>

/******************************************************************************/
int signal_fd(pid_t aSignal)
{
    int rc = -1;

    int signalFd = -1;

    if (!aSignal) {
        errno = EINVAL;
        goto Finally;
    }

    sigset_t sigMask;
    if (sigemptyset(&sigMask) || sigaddset(&sigMask, aSignal))
        goto Finally;

    signalFd = signalfd(-1, &sigMask, 0);
    if (-1 == signalFd)
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

    struct pollfd pollFd = {
        .fd = aSignalFd,
        .events = POLLIN,
    };

    int pollRd = poll(&pollFd, 1, 0);
    if (-1 == pollRd) {
        if (EINTR != errno)
            goto Finally;
        pollRd = 0;
    }

    events = 0;

    if (pollRd) {
        struct signalfd_siginfo sigInfo;

        ssize_t bytesRd = read(aSignalFd, &sigInfo, sizeof(sigInfo));
        if (-1 == bytesRd) {
            if (EINTR != errno)
                goto Finally;
            bytesRd = 0;
        }

        events = bytesRd ? 1 : 0;
    }

    rc = 0;

Finally:

    return rc ? rc : events;
}

/******************************************************************************/
