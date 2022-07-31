SUBDIRS = src

dist_doc_DATA = doc/README_md2pdf.pdf

test_pcapdir = $(top_srcdir)/test_pcap
dist_test_pcap_DATA = test_pcap/README

debiandir = $(top_srcdir)/debian
dist_debian_DATA = \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/rules

EXTRA_DIST = \
	src/netinet_helper.h 	\
	src/utils.h 	  		\
	src/nf_defs.h 	  		\
	src/nf_export.h      	\
	src/nf_table.h			\
	src/hash_functions/hash_functions.h  \
	src/hash_functions/lookup3/lookup3.h \
	src/hash_functions/murmur3/murmur3.h
