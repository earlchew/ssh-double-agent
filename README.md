# SSH Double Agent

**ssh-double-agent** orchestrates interactions between
an SSH client and two SSH agents: a readonly fallback agent,
and a primary agent. When run, **ssh-double-agent**
populates `SSH_AUTH_SOCK` to refer to itself before
starting a command, which is typically an SSH client.

## Description

The SSH client queries `SSH_AUTH_SOCK` to connect
to **ssh-double-agent**. Queries for available keys
are sent to both the primary, and fallback agents.
Requests for signatures are first passed to the
primary agent, and then to the fallback agent if
the primary agent was not successful. Other actions,
such as a request to add a key, are only performed by
the primary agent.

The **ssh-double-agent** is useful for scenarios
where the keys must be added to an agent, but
only retained for the duration of a session.
Rather than adding the key to the GUI
keyring, a **ssh-double-agent** can be used
to stage a transient agent, while also providing
readonly access to keys already loaded into the GUI
keyring.

## Getting Started

### Dependencies

**ssh-double-agent** is implemented entirely in Posix C,
with **libc** as its only dependency. The program is known
to compile on:
* Mac OS
* Linux

### Installing

**ssh-double-agent** is compiled from source using the accompanying `Makefile`.

### Executing program

Documentation is provided in the accompanying `ssh-double-agent.man` file
which is created from using `man` target in the `Makefile`.
