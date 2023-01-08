.PHONY:	all
all:	ssh-double-agent

.PHONY:	man
man:	ssh-double-agent.man

.PHONY:	lib
lib:	library.a

.PHONY:	clean
clean:
	$(RM) lib/*.o
	$(RM) library.a
	$(RM) ssh-double-agent

.PHONY:	check
check:	ssh-double-agent
	#
	# Configure GITKEY, GITREMOTE, GITREPO, and GITPASSWD so
	# that test_github_client can succeed.
	#
	VALGRIND='$(VALGRIND)' test/check

CFLAGS = -Wall -Werror -Wshadow -D_GNU_SOURCE -Ilib/
ssh-double-agent:	ssh-double-agent.c library.a

LIBOBJS = $(patsubst %.c,%.o,$(wildcard lib/*.c))
ARFLAGS = crvs
library.a:	$(foreach o,$(LIBOBJS),library.a($o))
.SECONDARY:

ssh-double-agent.man:	ssh-double-agent.1
	nroff -man $< >$@.tmp && mv $@.tmp $@
