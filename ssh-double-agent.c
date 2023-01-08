/**
 * Create an ssh agent using a pair of ssh agents
 *
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
#include "un.h"
#include "macros.h"
#include "proc.h"
#include "sig.h"

#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/wait.h>

/******************************************************************************/
static int optHelp;
static const char *argPrimaryPath;
static const char *argFallbackPath;
static const char *argDoubleAgentPath;

/******************************************************************************/
#define SSH_AGENT_FAILURE             5
#define SSH_AGENT_SUCCESS             6
#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER   12
#define SSH_AGENTC_SIGN_REQUEST       13
#define SSH_AGENT_SIGN_RESPONSE       14
#define SSH_AGENTC_LOCK               22
#define SSH_AGENTC_UNLOCK             23

/******************************************************************************/
struct Agent {
    size_t mPasswordLen;
    char  *mPassword;

    pid_t mParentPid;

    const char *mPrimaryPath;
    const char *mFallbackPath;
    const char *mDoubleAgentPath;

    int mPrimaryFd;
    int mFallbackFd;
    int mDoubleAgentFd;
};

/******************************************************************************/
struct Message {

    const char *mName;
    int mFd;

    /* Model the number of remaining bytes on the socket. This differs
     * from the known length of the payload because some or all of the
     * payload bytes might remain on the socket.
     */

    int mType;
    uint32_t mSize;

    /* When modelling the payload of the message, the content might
     * not available because it has not yet been read from the socket.
     */

    struct {
        int   mLength;
        char *mContent;
    } mPayload;
};

/******************************************************************************/
void
usage(void)
{
    static const char usageText[] =
        "[-d] [primary-path] fallback-path double-agent-path -- cmd ...\n"
        "\n"
        "Options:\n"
        "  -d --debug          Emit debug information\n"
        "\n"
        "Environment:\n"
        "  SSH_AUTH_SOCK       Default socket path for primary agent\n"
        "\n"
        "Arguments:\n"
        "  primary-path        Socket path for primary agent\n"
        "  fallback-path       Socket path for fallback agent\n"
        "  double-agent--path  Socket path to publish double agent\n"
        "  cmd ...             Program to monitor\n";

    help(usageText, optHelp);

    exit(EXIT_FAILURE);
}

/******************************************************************************/
static void
terminate(void)
{
    DEBUG("Terminating agent pgid %d", getpgid(0));

    signal(SIGTERM, SIG_IGN);
    killpg(0, SIGTERM);
    sleep(3);
    killpg(0, SIGKILL);
}

/******************************************************************************/
static int
stdio_pipe(void)
{
    int rc = -1;

    fd_close(0);
    fd_close(1);

    int stdioFd[2];
    if (-1 == pipe(stdioFd))
        goto Finally;

    rc = 0;

Finally:

    return rc;
}

/******************************************************************************/
static void
rd_uint32_t(const char *aBuf, uint32_t *aOut)
{
    uint32_t value = 0;

    value = (value << 8) | (unsigned char) aBuf[0];
    value = (value << 8) | (unsigned char) aBuf[1];
    value = (value << 8) | (unsigned char) aBuf[2];
    value = (value << 8) | (unsigned char) aBuf[3];

    if (aOut)
        *aOut = value;
}

/*----------------------------------------------------------------------------*/
static int
send_message(int aFd, int aType, const char *aMsg, size_t aMsgLen)
{
    int rc = -1;

    char header[] = {
        ((aMsgLen+1) >> 24) & 0xff,
        ((aMsgLen+1) >> 16) & 0xff,
        ((aMsgLen+1) >>  8) & 0xff,
        ((aMsgLen+1) >>  0) & 0xff,
        aType,
    };

    if (sizeof(header) != fd_write(aFd, header, sizeof(header)))
        goto Finally;

    if (aMsgLen != fd_write(aFd, aMsg, aMsgLen))
        goto Finally;

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
static int
send_response_success(int aFd)
{
    DEBUG("Sending response SSH_AGENT_SUCCESS");
    return send_message(aFd, SSH_AGENT_SUCCESS, 0, 0);
}

/*----------------------------------------------------------------------------*/
static int
send_response_failure(int aFd)
{
    DEBUG("Sending response SSH_AGENT_FAILURE");
    return send_message(aFd, SSH_AGENT_FAILURE, 0, 0);
}

/*----------------------------------------------------------------------------*/
static int
send_request_identities(int aFd)
{
    DEBUG("Sending request SSH_AGENTC_REQUEST_IDENTITIES");
    return send_message(aFd, SSH_AGENTC_REQUEST_IDENTITIES, 0, 0);
}

/*----------------------------------------------------------------------------*/
static int
transfer_response_bytes(int aSrcFd, int aDstFd, size_t aLen)
{
    int rc = -1;

    while (aLen) {
        size_t chunkLen = 7; //8 * 1024;
        if (chunkLen > aLen)
            chunkLen = aLen;

        char chunk[chunkLen];
        if (sizeof(chunk) != fd_read(aSrcFd, chunk, sizeof(chunk)))
            goto Finally;

        if (-1 != aDstFd &&
                sizeof(chunk) != fd_write(aDstFd, chunk, sizeof(chunk)))
            goto Finally;

        aLen -= sizeof(chunk);
    }

    rc = 0;

Finally:

    return rc;
}

/******************************************************************************/
struct Message *
message_close(struct Message *self)
{
    if (self)
        free(self->mPayload.mContent);

    return 0;
}

/*----------------------------------------------------------------------------*/
struct Message *
message_init(
    struct Message *self, int aFd, const char *aName)
{
    int rc = -1;

    self->mName = aName;
    self->mFd = aFd;
    self->mType = 0;
    self->mSize = 0;
    self->mPayload.mLength = 0;
    self->mPayload.mContent = 0;

    char msgHeader[5];
    if (sizeof(msgHeader) != fd_read(aFd, msgHeader, sizeof(msgHeader)))
        goto Finally;

    uint32_t msgLength;
    rd_uint32_t(msgHeader, &msgLength);

    DEBUG("Message length %" PRIu32, msgLength);

    if (1 > msgLength) {
        warn("%s - Message length %" PRIu32 " underflows threshold", self->mName, msgLength);
        errno = EINVAL;
        goto Finally;
    }

    if (32 * 1024 < msgLength) {
        warn("%s - Message length %" PRIu32 " overflows threshold", self->mName, msgLength);
        errno = ENOMEM;
        goto Finally;
    }

    int msgType = (unsigned char) msgHeader[4];

    DEBUG("Message type %d", msgType);

    self->mType = msgType;
    self->mSize = msgLength - 1;
    self->mPayload.mLength = self->mSize;

    rc = 0;

Finally:

    FINALLY({
        if (rc)
            self = message_close(self);
    });

    return rc ? 0 : self;
}

/*----------------------------------------------------------------------------*/
int
message_read_payload(struct Message *self)
{
    int rc = -1;

    char *content = 0;

    if (self->mPayload.mContent || !self->mPayload.mLength) {
        errno = EINVAL;
        goto Finally;
    }

    size_t length = self->mPayload.mLength;

    content = malloc(length);
    if (!content)
        goto Finally;

    ssize_t rdLen = fd_read(self->mFd, content, length);

    self->mSize -= rdLen;

    if (rdLen != length)
        goto Finally;

    self->mPayload.mContent = content;
    content = 0;

    rc = 0;

Finally:

    FINALLY({
        free(content);
    });

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_purge(struct Message *self)
{
    int rc = -1;

    DEBUG("%s - Purging %" PRIu32 " bytes", self->mName, self->mSize);
    if (self->mSize && transfer_response_bytes(self->mFd, -1, self->mSize))
        goto Finally;

    self->mSize = 0;

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_send(struct Message *self, int aFd)
{
    int rc = -1;

    if (!self->mPayload.mContent) {
        errno = EINVAL;
        goto Finally;
    }

    char header[5] = {
        ((self->mPayload.mLength+1) >> 24) & 0xff,
        ((self->mPayload.mLength+1) >> 16) & 0xff,
        ((self->mPayload.mLength+1) >>  8) & 0xff,
        ((self->mPayload.mLength+1) >>  0) & 0xff,
        self->mType,
    };

    if (sizeof(header) != fd_write(aFd, header, sizeof(header)))
        goto Finally;

    if (self->mPayload.mLength != fd_write(aFd, self->mPayload.mContent, self->mPayload.mLength))
        goto Finally;

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_transfer_payload(struct Message *self, int aFd)
{
    int rc = -1;

    if (self->mPayload.mContent) {
        if (self->mPayload.mLength != fd_write(aFd, self->mPayload.mContent, self->mPayload.mLength)) {
            goto Finally;
        }

        self->mSize -= self->mPayload.mLength;
    }

    if (transfer_response_bytes(self->mFd, aFd, self->mSize)) {
        goto Finally;
    }

    free(self->mPayload.mContent);
    self->mPayload.mContent = 0;
    self->mPayload.mLength = 0;
    self->mSize = 0;
    self->mType = 0;

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_transfer(struct Message *self, int aFd)
{
    int rc = -1;

    char header[5] = {
        ((self->mPayload.mLength+1) >> 24) & 0xff,
        ((self->mPayload.mLength+1) >> 16) & 0xff,
        ((self->mPayload.mLength+1) >>  8) & 0xff,
        ((self->mPayload.mLength+1) >>  0) & 0xff,
        self->mType,
    };

    if (sizeof(header) != fd_write(aFd, header, sizeof(header))) {
        goto Finally;
    }

    if (message_transfer_payload(self, aFd)) {
        goto Finally;
    }

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_peek_uint32_t(struct Message *self, uint32_t *aValue)
{
    int rc = -1;

    if (self->mPayload.mContent)
        goto Finally;

    char buf[4];

    if (sizeof(buf) > self->mPayload.mLength)
        goto Finally;

    if (sizeof(buf) != fd_read(self->mFd, buf, sizeof(buf)))
        goto Finally;

    self->mPayload.mLength -= sizeof(buf);
    self->mSize -= sizeof(buf);

    uint32_t value;
    rd_uint32_t(buf, &value);

    if (aValue)
        *aValue = value;

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_peek_bytes(struct Message *self, size_t *size, char **bytes)
{
    int rc = 0;

    char *buf = 0;

    uint32_t length;
    if (message_peek_uint32_t(self, &length))
        goto Finally;

    if (self->mPayload.mLength < length) {
        errno = EINVAL;
        goto Finally;
    }

    if (16 * 1024 < length) {

        if (transfer_response_bytes(self->mFd, -1, length))
            goto Finally;

    } else {
        buf = malloc(length ? length : 1);
        if (!buf)
            goto Finally;

        if (length != fd_read(self->mFd, buf, length))
            goto Finally;
    }

    self->mPayload.mLength -= length;
    self->mSize -= length;

    *size = length;
    *bytes = buf;
    buf = 0;

    rc = 0;

Finally:

    FINALLY({
        free(buf);
    });

    return rc;
}

/*----------------------------------------------------------------------------*/
int
message_fd(const struct Message* self)
{
    return self->mFd;
}

/*----------------------------------------------------------------------------*/
int
message_type(const struct Message* self)
{
    return self->mType;
}

/*----------------------------------------------------------------------------*/
int
message_length(const struct Message* self)
{
    return self->mPayload.mLength;
}

/*----------------------------------------------------------------------------*/
const char *
message_content(const struct Message* self)
{
    return self->mPayload.mContent;
}

/******************************************************************************/
static struct Message *
query_agent_identities(
    struct Message *self, const char *aRole, int aFd, uint32_t *aIdentities)
{
    int rc = -1;

    if (send_request_identities(aFd)) {
        warn("Unable to request identities from %s agent", aRole);
        goto Finally;
    }

    self = message_init(self, aFd, aRole);
    if (!self) {
        warn("Unable to read response from %s agent", aRole);
        goto Finally;
    }

    if (SSH_AGENT_IDENTITIES_ANSWER != message_type(self)) {
        warn("Unexpected response for %s agent", aRole);
        goto Finally;
    }

    uint32_t numIdentities;
    if (message_peek_uint32_t(self, &numIdentities)) {
        warn("Unable to read number of identities from %s agent", aRole);
        goto Finally;
    }

    if (aIdentities)
        *aIdentities = numIdentities;

    rc = 0;

Finally:

    FINALLY({
        if (rc) {
            if (self) {
                message_purge(self);
                self = message_close(self);
            }
        }
    });

    return rc ? 0 : self;
}

/*----------------------------------------------------------------------------*/
static int
agent_request_identities(struct Agent *self, struct Message *msg)
{
    int rc = -1;

    DEBUG("Request SSH_AGENTC_REQUEST_IDENTITIES");

    struct Message primaryMsg_, *primaryMsg = 0;
    struct Message fallbackMsg_, *fallbackMsg = 0;

    uint32_t primaryIdentities = 0;
    primaryMsg = query_agent_identities(
            &primaryMsg_, "primary", self->mPrimaryFd, &primaryIdentities);
    if (!primaryMsg)
        goto Finally;

    uint32_t fallbackIdentities = 0;
    fallbackMsg = query_agent_identities(
            &fallbackMsg_, "fallback", self->mFallbackFd, &fallbackIdentities);
    if (!fallbackMsg)
        goto Finally;

    uint32_t totalLength = 0;
    totalLength += message_length(primaryMsg);
    totalLength += message_length(fallbackMsg);

    uint32_t totalIdentities = 0;
    totalIdentities += primaryIdentities;
    totalIdentities += fallbackIdentities;

    DEBUG("Reporting a total of %" PRIu32 " identities", totalIdentities);

    uint32_t answerLength = totalLength + 5;

    int clientFd = message_fd(msg);

    char identitiesAnswer[] = {
        (answerLength >> 24) & 0xff,
        (answerLength >> 16) & 0xff,
        (answerLength >>  8) & 0xff,
        (answerLength >>  0) & 0xff,
        SSH_AGENT_IDENTITIES_ANSWER,
        (totalIdentities >> 24) & 0xff,
        (totalIdentities >> 16) & 0xff,
        (totalIdentities >>  8) & 0xff,
        (totalIdentities >>  0) & 0xff,
    };

    if (sizeof(identitiesAnswer) !=
            fd_write(clientFd, identitiesAnswer, sizeof(identitiesAnswer))) {
        warn("Unable to send response %d", SSH_AGENT_IDENTITIES_ANSWER);
        goto Finally;
    }

    if (message_transfer_payload(primaryMsg, clientFd)) {
        warn("Unable to send primary identities");
        goto Finally;
    }

    if (message_transfer_payload(fallbackMsg, clientFd)) {
        warn("Unable to send fallback identities");
        goto Finally;
    }

    rc = 0;

Finally:

    FINALLY({
        if (primaryMsg) {
            message_purge(primaryMsg);
            primaryMsg = message_close(primaryMsg);
        }
        if (fallbackMsg) {
            message_purge(fallbackMsg);
            fallbackMsg = message_close(fallbackMsg);
        }
    });

    return rc;
}

/*----------------------------------------------------------------------------*/
static int
agent_sign_request(
    struct Agent *self, struct Message *msg)
{
    int rc = -1;

    DEBUG("Request SSH_AGENTC_SIGN_REQUEST");

    struct Message responseMsg_, *responseMsg = 0;

    if (message_read_payload(msg)) {
        warn("Unable to read message");
        goto Finally;
    }

    struct {
        const char *mName;
        int mFd;
    } agents[] = {
        { "primary agent", self->mPrimaryFd },
        { "fallback agent", self->mFallbackFd },
    };

    for (int ax = 0; ax < NUMBEROF(agents); ++ax) {

        if (message_send(msg, agents[ax].mFd)) {
            warn("Unable to send sign request");
            goto Finally;
        }

        responseMsg = message_init(
            &responseMsg_, agents[ax].mFd, agents[ax].mName);
        if (!responseMsg) {
            warn("Unable to read sign response");
            goto Finally;
        }

        if (SSH_AGENT_SIGN_RESPONSE == message_type(responseMsg)) {

            if (message_transfer(responseMsg, message_fd(msg))) {
                warn("Unable to transfer sign response");
                goto Finally;
            }

            break;
        }

        message_purge(responseMsg);
        responseMsg = message_close(responseMsg);

    }

    if (!responseMsg) {
        if (send_response_failure(message_fd(msg)))
            goto Finally;
    }

    rc = 0;

Finally:

    FINALLY({
        if (responseMsg) {
            message_purge(responseMsg);
            responseMsg = message_close(responseMsg);
        }
    });

    return rc;
}

/*----------------------------------------------------------------------------*/
static int
agent_password_(
    struct Agent *self,
    struct Message *msg,
    int (*aAction)(struct Agent *, size_t, const char *))
{
    int rc = -1;

    int clientFd = message_fd(msg);
    size_t msgLen = message_length(msg);

    if (4 > msgLen)
        goto Finally;

    msgLen -= 4;

    size_t passwordLen;
    char *password = 0;

    if (message_peek_bytes(msg, &passwordLen, &password)) {
        warn("Unable to read password");
        goto Finally;
    }

    DEBUG("Password length %lu", (unsigned long) passwordLen);

    if (8 < passwordLen || !password) {

        if (send_response_failure(clientFd))
            goto Finally;

    } else {

        int result = aAction(self, passwordLen, password);

        if (-1 == result)
            goto Finally;

        if (result) {
            if (send_response_success(clientFd))
                goto Finally;
        } else {
            if (send_response_failure(clientFd))
                goto Finally;
        }

    }

    rc = 0;

Finally:

    return rc;
}

/*----------------------------------------------------------------------------*/
static int
agent_lock_(struct Agent *self, size_t aPasswordLen, const char *aPassword)
{
    int rc = -1;

    if (self->mPassword) {

        rc = 0;

    } else {

        self->mPassword = malloc(aPasswordLen ? aPasswordLen : 1);
        if (!self->mPassword)
            goto Finally;

        memcpy(self->mPassword, aPassword, aPasswordLen);
        self->mPasswordLen = aPasswordLen;

        rc = 1;
    }

Finally:

    return rc;
}

static int
agent_lock(struct Agent *self, struct Message *msg)
{
    DEBUG("Request SSH_AGENTC_LOCK");
    return agent_password_(self, msg, agent_lock_);
}

/*----------------------------------------------------------------------------*/
static int
agent_unlock_(struct Agent *self, size_t aPasswordLen, const char *aPassword)
{
    int rc = -1;

    if (!self->mPassword ||
            self->mPasswordLen != aPasswordLen ||
            memcmp(self->mPassword, aPassword, aPasswordLen)) {

        rc = 0;

    } else {

        free(self->mPassword);

        self->mPassword = 0;
        self->mPasswordLen = 0;

        rc = 1;
    }

    goto Finally;

Finally:

    return rc;
}

static int
agent_unlock(struct Agent *self, struct Message *msg)
{
    DEBUG("Request SSH_AGENTC_UNLOCK");
    return agent_password_(self, msg, agent_unlock_);
}

/*----------------------------------------------------------------------------*/
static int
agent_primary_request(struct Agent *self, struct Message *msg)
{
    int rc = -1;

    DEBUG("Request %d", message_type(msg));

    struct Message response_, *response = 0;

    if (message_transfer(msg, self->mPrimaryFd)) {
        warn("Unable to forward request to primary agent");
        goto Finally;
    }

    response = message_init(&response_, self->mPrimaryFd, "primary");
    if (!response) {
        warn("Unable to read response from primary agent");
        goto Finally;
    }

    if (message_transfer(response, message_fd(msg))) {
        warn("Unable to forward response from primary agent");
        goto Finally;
    }

    rc = 0;

Finally:

    FINALLY({
        message_purge(response);
        response = message_close(response);
    });

    return rc;
}

/******************************************************************************/
static int
process_double_agent_request(
    struct Agent *self,
    int aClientFd)
{
    int rc = -1;

    struct Message msg_, *msg;

    msg = message_init(&msg_, aClientFd, "double agent");
    if (!msg) {
        warn("Unable to initialise message");
        goto Finally;
    }

    switch (message_type(msg)) {

    case SSH_AGENTC_REQUEST_IDENTITIES:
        if (agent_request_identities(self, msg))
            goto Finally;
        break;

    case SSH_AGENTC_SIGN_REQUEST:
        if (agent_sign_request(self, msg))
            goto Finally;
        break;

    case SSH_AGENTC_LOCK:
        if (agent_lock(self, msg))
            goto Finally;
        break;

    case SSH_AGENTC_UNLOCK:
        if (agent_unlock(self, msg))
            goto Finally;
        break;

    default:
        if (agent_primary_request(self, msg))
            goto Finally;
        break;
    }

    if (message_purge(msg)) {
        warn("Unable to purge message");
        goto Finally;
    }

    rc = 0;

Finally:

    FINALLY({
        message_close(msg);
    });

    return rc;
}

/******************************************************************************/
static int
run_double_agent_connection(
    struct Agent *self,
    int aClientFd)
{
    int rc = -1;

    int fallbackFd = -1;
    int primaryFd = -1;

    fallbackFd = un_connect(self->mFallbackPath);
    if (-1 == fallbackFd) {
        die("Unable to open fallback path %s", self->mFallbackPath);
        goto Finally;
    }

    primaryFd = un_connect(self->mPrimaryPath);
    if (-1 == primaryFd) {
        die("Unable to open primary path %s", self->mPrimaryPath);
        goto Finally;
    }

    self->mFallbackFd = fallbackFd;
    self->mPrimaryFd = primaryFd;

    while (1) {

        DEBUG("Waiting for next message");

        int ready = fd_wait_rd(aClientFd, -1);
        if (-1 == ready) {
            if (EINTR != errno)
                goto Finally;
            break;
        }

        if (process_double_agent_request(self, aClientFd))
            goto Finally;
    }

    rc = 0;

Finally:

    FINALLY({
        primaryFd = fd_close(primaryFd);
        fallbackFd = fd_close(fallbackFd);

        self->mPrimaryFd = -1;
        self->mFallbackFd = -1;
    });

    return rc;
}

/******************************************************************************/
int
run_double_agent(struct Agent *self)
{
    int rc = -1;

    int exitcode = -1;

    int clientFd = -1;
    int signalFd = -1;
    int processFd = -1;

    signalFd = signal_fd(SIGCHLD);
    if (-1 == signalFd) {
        die("Unable to create descriptor to signal %d", SIGCHLD);
        goto Finally;
    }

    DEBUG("Parent pid %d\n", self->mParentPid);
    processFd = proc_fd(self->mParentPid);
    if (-1 == processFd) {
        die("Unable to create descriptor to pid %d", self->mParentPid);
        goto Finally;
    }

    int numConnections = 0;

    while (1) {

        DEBUG("Reaping processes");

        while (1) {

            pid_t waitedPid = waitpid(-1, 0, WNOHANG);
            if (-1 == waitedPid) {
                if (ECHILD != errno) {
                    die("Unable to wait for child processes");
                    goto Finally;
                }
                waitedPid = 0;
            }

            if (!waitedPid)
                break;

            DEBUG("Reaped process pid %d", waitedPid);
            --numConnections;
            DEBUG("Decreasing connection count %d", numConnections);
        }

        struct pollfd pollFds[3] = {
            { .fd = self->mDoubleAgentFd, .events = POLLIN },
            { .fd = signalFd,             .events = POLLIN },
            { .fd = processFd,            .events = POLLIN },
        };

        DEBUG("Polling for activity");

        int fds = poll(pollFds, NUMBEROF(pollFds), -1);
        if (-1 == fds) {
            if (EINTR != errno) {
                die("Unable to poll for activity");
                goto Finally;
            }
            fds = 0;
        }

        DEBUG("Polling signal activity");

        int signalEvent = signal_fd_read(signalFd);
        if (-1 == signalEvent) {
            die("Unable to read signal descriptor");
            goto Finally;
        }

        DEBUG("Polling process activity");

        int processEvent = proc_fd_read(processFd);
        if (-1 == processEvent) {
            die("Unable to read process descriptor");
            goto Finally;
        }

        if (processEvent)
            break;

        DEBUG("Polling connection activity");

        DEBUG("Agent waiting for next connection");

        clientFd = un_accept(self->mDoubleAgentFd);
        if (-1 == clientFd) {
            if (EINTR != errno && EWOULDBLOCK != errno) {
                die("Unable to accept client connection");
                goto Finally;
            }

            continue;
        }

        if (16 <= numConnections) {

            DEBUG("Connection count at limit %d", numConnections);

        } else {

            ++numConnections;
            DEBUG("Increasing connection count %d", numConnections);

            pid_t connectionPid = fork();
            if (-1 == connectionPid) {
                die("Unable to start process to run connection");
                goto Finally;
            }

            if (!connectionPid) {

                DEBUG("Agent connection opened");

                self->mDoubleAgentFd = fd_close(self->mDoubleAgentFd);
                run_double_agent_connection(self, clientFd);

                DEBUG("Agent connection closed %d", clientFd);

                exitcode = 0;
                break;
            }

        }

        clientFd = fd_close(clientFd);
    }

    rc = 0;

Finally:

    FINALLY({
        clientFd = fd_close(clientFd);
        signalFd = fd_close(signalFd);
        processFd = fd_close(processFd);

        if (exitcode >= 0)
            exit(exitcode);
    });

    return rc;
}

/******************************************************************************/
int
spawn_double_agent(
    const char *aFallbackPath,
    const char *aPrimaryPath,
    const char *aDoubleAgentPath)
{
    int rc = -1;

    DEBUG("Fallback path %s", aFallbackPath);
    DEBUG("Primary path %s", aPrimaryPath);
    DEBUG("Double agent path %s", aDoubleAgentPath);

    const char *removePath = 0;

    pid_t childPid = -1;

    int doubleAgentFd = -1;

    doubleAgentFd = un_listen(aDoubleAgentPath);
    if (-1 == doubleAgentFd) {
        die("Unable to create double agent path %s", aDoubleAgentPath);
        goto Finally;
    }

    if (-1 == fd_nonblock(doubleAgentFd)) {
        die("Unable to configure non-blocking socket");
        goto Finally;
    }

    if (setenv("SSH_AUTH_SOCK", aDoubleAgentPath, 1)) {
        die("Unable to set SSH_AUTH_SOCK");
        goto Finally;
    }

    pid_t selfPid = getpid();

    DEBUG("Agent parent pid %d", selfPid);

    childPid = fork();
    if (-1 == childPid) {
        die("Unable to create child process");
        goto Finally;
    }

    if (!childPid) {

        DEBUG("Agent pid %d", getpid());

        removePath = aDoubleAgentPath;

        if (-1 == setsid()) {
            die("Unable to create new session leader");
            goto Finally;
        }

        if (stdio_pipe()) {
            die("Unable to create stdio pipe");
            goto Finally;
        }

        struct Agent agent = {

            .mPrimaryPath = aPrimaryPath,
            .mFallbackPath = aFallbackPath,
            .mDoubleAgentPath = aDoubleAgentPath,

            .mParentPid = selfPid,

            .mDoubleAgentFd = doubleAgentFd,
            .mPrimaryFd = -1,
            .mFallbackFd = -1,
        };

        if (run_double_agent(&agent))
            goto Finally;

        DEBUG("Agent closed");

    }

    rc = 0;

Finally:
    FINALLY({
        if (removePath)
            remove(removePath);

        doubleAgentFd = fd_close(doubleAgentFd);

        if (!childPid)
            terminate();
    });

    return rc;
}

/******************************************************************************/
static char **
parse_options(int argc, char **argv)
{
    int rc = -1;

    static char shortOpts[] = "+hd";

    static struct option longOpts[] = {
        { "help",      no_argument,       0, 'h' },
        { "debug",     no_argument,       0, 'd' },
        { 0 },
    };

    while (1) {
        int ch = getopt_long(argc, argv, shortOpts, longOpts, 0);

        if (-1 == ch)
            break;

        switch (ch) {
        default:
            break;

        case 'h':
            optHelp = 1;
            goto Finally;

        case ':':
        case '?':
            goto Finally;

        case 'd':
            debug("%s", DebugEnable); break;

        }
    }

    if (argc >= optind && !strcmp("--", argv[optind-1]))
        goto Finally;

    if (argc > optind && strcmp("--", argv[optind])) {
        if (argc - optind > 3 && !strcmp("--", argv[optind+3]))
            argPrimaryPath = argv[optind++];
    }

    if (argc > optind && strcmp("--", argv[optind]))
        argFallbackPath = argv[optind++];
    else
        goto Finally;

    if (argc > optind && strcmp("--", argv[optind]))
        argDoubleAgentPath = argv[optind++];
    else
        goto Finally;

    if (argc > optind && !strcmp("--", argv[optind]))
        ++optind;

    if (argc > optind)
        rc = 0;

Finally:

    FINALLY({
        if (!rc) {
            argv += optind;
            argc -= optind;
        }
    });

    return rc ? 0 : argv;
}

/******************************************************************************/
int
main(int argc, char **argv)
{
    int exitCode = 255;

    srand(getpid());

    char **cmd = parse_options(argc, argv);
    if (!cmd || !cmd[0])
        usage();

    if (argPrimaryPath)
        DEBUG("Primary path %s", argPrimaryPath);
    else
        DEBUG("No primary path specified");
    DEBUG("Fallback path %s", argFallbackPath);
    DEBUG("Double agent path %s", argDoubleAgentPath);

    if (!argPrimaryPath)
        argPrimaryPath = getenv("SSH_AUTH_SOCK");
    if (!argPrimaryPath)
        die("Unable to find primary path via SSH_AUTH_SOCK");

    if (spawn_double_agent(argFallbackPath, argPrimaryPath, argDoubleAgentPath))
        goto Finally;

    if (execvp(cmd[0], cmd))
        die("Unable to execute %s", cmd[0]);

    exitCode = 0;

    goto Finally;

Finally:

    return exitCode;
}

/******************************************************************************/
