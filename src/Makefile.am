lib_LTLIBRARIES = libcanute.la
libcanute_la_SOURCES = cnt_id.cc cnt_id_cache.cc cnt_net.cc cnt_smime_association.cc \
                      cnt_smime_cert.cc cnt_net_engine.cc cnt_net_libunbound.cc \
                      cnt_pgp_association.cc cnt_pgp_key.cc \
                      cnt_tbird.cc 

libcanute_la_LDFLAGS = $(LDFLAGS) -version-info $(libcanute_la_version_info) \
                      -L/usr/local/lib -L/opt/local/lib -lunbound -lssl -lcrypto 
libcanute_la_CXXFLAGS = $(CXXFLAGS) -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include

smgheaderdir = $(includedir)
smgheader_HEADERS = cnt_id.h cnt_id_cache.h cnt_net.h cnt_smime_association.h cnt_smime_cert.h \
                    cnt_net_engine.h cnt_net_libunbound.h cnt_tbird.h cnt_defs.h

noinst_PROGRAMS = test_cnt_smime_cert test_cnt_smime_association test_cnt_id test_cnt_net \
                  test_cnt_id_cache test_cnt_pgp_association test_cnt_pgp_key test_crypt_check_cnt_smime_cert
bin_PROGRAMS = smimeagen openpgpkeygen

if CNT_DEBUG
libcanute_la_CXXFLAGS += -D_CNT_DEBUG
endif

if CNT_GETDNS
libcanute_la_LDFLAGS += -lldns -lgetdns
libcanute_la_SOURCES += cnt_net_getdns.cc
smgheader_HEADERS += cnt_net_getdns.h
libcanute_la_CXXFLAGS += -D_CNT_GETDNS
endif

test_cnt_smime_cert_SOURCES = test_cnt_smime_cert.cc cnt_smime_cert.cc
test_cnt_smime_cert_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
test_cnt_smime_cert_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                               -I/opt/local/include $(CXXFLAGS)

test_cnt_smime_association_SOURCES = test_cnt_smime_association.cc cnt_smime_association.cc \
                                     cnt_smime_cert.cc
test_cnt_smime_association_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
test_cnt_smime_association_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                                      -I/opt/local/include $(CXXFLAGS)

test_cnt_id_SOURCES = test_cnt_id.cc cnt_id.cc cnt_smime_association.cc cnt_smime_cert.cc \
                      cnt_pgp_association.cc cnt_pgp_key.cc
test_cnt_id_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
test_cnt_id_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include $(CXXFLAGS)

test_cnt_net_SOURCES = test_cnt_net.cc cnt_net.cc cnt_net_engine.cc cnt_net_libunbound.cc cnt_id.cc \
                       cnt_smime_association.cc cnt_smime_cert.cc cnt_pgp_association.cc cnt_pgp_key.cc
test_cnt_net_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error -lunbound $(LDFLAGS)
test_cnt_net_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include  $(CXXFLAGS)
if CNT_GETDNS
test_cnt_net_SOURCES += cnt_net_getdns.cc
test_cnt_net_LDFLAGS += -lldns -lgetdns
test_cnt_net_CXXFLAGS += -D_CNT_GETDNS
endif

smimeagen_SOURCES = smimeagen.cc cnt_id.cc cnt_smime_association.cc cnt_smime_cert.cc cnt_pgp_association_stub.cc
smimeagen_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
smimeagen_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                     -I/opt/local/include $(CXXFLAGS) -D_CNT_NO_PGP

openpgpkeygen_SOURCES = openpgpkeygen.cc cnt_id.cc cnt_smime_association_stub.cc cnt_pgp_key.cc cnt_pgp_association.cc
openpgpkeygen_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
openpgpkeygen_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                     -I/opt/local/include $(CXXFLAGS) -D_CNT_NO_SMIME

test_cnt_id_cache_SOURCES = test_cnt_id_cache.cc cnt_id.cc cnt_id_cache.cc cnt_smime_association.cc \
                            cnt_smime_cert.cc cnt_pgp_association.cc cnt_pgp_key.cc
test_cnt_id_cache_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
test_cnt_id_cache_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS)

test_cnt_pgp_association_SOURCES = test_cnt_pgp_association.cc cnt_pgp_association.cc cnt_pgp_key.cc 
test_cnt_pgp_association_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lgpgme -lgpg-error $(LDFLAGS)
test_cnt_pgp_association_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS) -D_CNT_DEBUG

test_cnt_pgp_key_SOURCES = test_cnt_pgp_key.cc cnt_pgp_association.cc cnt_pgp_key.cc 
test_cnt_pgp_key_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lgpgme -lgpg-error $(LDFLAGS)
test_cnt_pgp_key_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS) -D_CNT_DEBUG

test_crypt_check_cnt_smime_cert_SOURCES = test_crypt_check_cnt_smime_cert.cc cnt_smime_cert.cc
test_crypt_check_cnt_smime_cert_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
test_crypt_check_cnt_smime_cert_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                               -I/opt/local/include $(CXXFLAGS)

