CC = g++
CFLAGS  = -g -Wall -std=c++11 -stdlib=libc++
SRCDIR = src
BUILDDIR = obj

#default target
.PHONY: all
all: directories merge

#Make the Directories
directories:
	@mkdir -pv $(BUILDDIR)

merge: $(BUILDDIR)/merge.o $(BUILDDIR)/test.o $(BUILDDIR)/main.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILDDIR)/merge.o:  $(SRCDIR)/merge.cpp $(SRCDIR)/list.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/test.o: $(SRCDIR)/test.cpp $(SRCDIR)/test.h $(SRCDIR)/list.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/main.o: $(SRCDIR)/main.cpp $(SRCDIR)/test.h $(SRCDIR)/list.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)
	rm -f merge

.PHONY: run
run:
	./merge
