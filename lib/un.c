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

#include "un.h"

#include "err.h"

#include "macros.h"

#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

/******************************************************************************/
int
un_connect(const char *aPath)
{
    int rc = -1;

    int unFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == unFd)
        goto Finally;

    struct sockaddr_un sockAddr = { };

    sockAddr.sun_family = AF_UNIX;
    strncpy(sockAddr.sun_path, aPath, sizeof(sockAddr.sun_path));
    sockAddr.sun_path[sizeof(sockAddr.sun_path)-1] = 0;

    if (connect(unFd, (void *) &sockAddr, sizeof(sockAddr)))
        goto Finally;

    rc = 0;

Finally:

    FINALLY({
        if (rc) {
            if (-1 != unFd)
                close(unFd);
        }
    });

    return rc ? rc : unFd;
}

/*----------------------------------------------------------------------------*/
int
un_listen(const char *aPath)
{
    int rc = -1;

    int prevMask = -1;

    int unFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == unFd)
        goto Finally;

    struct sockaddr_un sockAddr = { };

    sockAddr.sun_family = AF_UNIX;
    strncpy(sockAddr.sun_path, aPath, sizeof(sockAddr.sun_path));
    sockAddr.sun_path[sizeof(sockAddr.sun_path)-1] = 0;

    prevMask = umask(0177);

    if (bind(unFd, (void *) &sockAddr, sizeof(sockAddr)))
        goto Finally;

    if (listen(unFd, 0))
        goto Finally;

    rc = 0;

Finally:

    FINALLY({
        if (rc) {
            if (-1 != unFd)
                close(unFd);
        }

        if (-1 != prevMask) {
            umask(prevMask);
        }
    });

    return rc ? rc : unFd;
}

/*----------------------------------------------------------------------------*/
int
un_accept(int aUnFd)
{
    int rc = -1;

    int clientFd = accept(aUnFd, 0, 0);
    if (-1 == clientFd)
        goto Finally;

    rc = 0;

Finally:

    return rc ? rc : clientFd;
}

/******************************************************************************/
