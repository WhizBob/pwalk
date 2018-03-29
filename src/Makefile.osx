# For OSX ...

BINDIR=../bin/osx
PWALK_FLAGS=-lm -lpthread
PWALK_C = pwalk.c pwalk_onefs.c pwalk_report.c
PWALK_H = pwalk.h pwalk_onefs.h pwalk_report.h

all: pwalk hacls chexcmp touch3 mystat

# Every make forces a compile, because the binaries are NOT in this directory ...

pwalk: $(PWALK_C) $(PWALK_H)
	$(CC)	$(PWALK_C) -o $(BINDIR)/pwalk $(PWALK_FLAGS)

hacls: hacls.c pwalk_acls.h
	$(CC)	hacls.c -o $(BINDIR)/hacls

chexcmp: chexcmp.c
	$(CC)	chexcmp.c -o $(BINDIR)/chexcmp

touch3: touch3.c
	$(CC)	touch3.c -o $(BINDIR)/touch3

mystat: mystat.c
	$(CC)	mystat.c -o $(BINDIR)/mystat
