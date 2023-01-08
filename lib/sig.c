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

#include "sig.h"

#define SIG_FD_TYPE_NONE_   0
#define SIG_FD_TYPE_PIDFD_  1
#define SIG_FD_TYPE_KQUEUE_ 2

#if defined(__linux__)
#define SIG_FD_TYPE SIG_FD_TYPE_PIDFD_
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define SIG_FD_TYPE SIG_FD_TYPE_KQUEUE_
#endif

#ifndef SIG_FD_TYPE
#define SIG_FD_TYPE SIG_FD_TYPE_NONE_
#endif

/******************************************************************************/
#if SIG_FD_TYPE == SIG_FD_TYPE_PIDFD_
#include "sig_fd_signalfd.c.h"
#endif

#if SIG_FD_TYPE == SIG_FD_TYPE_KQUEUE_
#include "sig_fd_kqueue.c.h"
#endif

/******************************************************************************/
