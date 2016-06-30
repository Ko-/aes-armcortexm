.PHONY: all clean

DIRS=aes128 aes128ctr aes192ctr aes256ctr aes128ctrbs aes128ctrbsmasked
COMMONDIR=common

all clean:
	for dir in $(DIRS); do \
		$(MAKE) -C $$dir $@ ; \
	done; \
	if [ "$@" = "clean" ]; then \
		rm $(COMMONDIR)/*.o $(COMMONDIR)/*.d ; \
	fi
