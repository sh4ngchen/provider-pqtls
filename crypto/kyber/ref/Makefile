CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -z noexecstack
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all shared clean

all: shared

shared: \
  lib/libpqcrystals_kyber512_ref.so \
  lib/libpqcrystals_kyber768_ref.so \
  lib/libpqcrystals_kyber1024_ref.so \
  lib/libpqcrystals_fips202_ref.so \

lib/libpqcrystals_fips202_ref.so: fips202.c fips202.h
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) fips202.c -o $@

lib/libpqcrystals_kyber512_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=2 $(SOURCES) symmetric-shake.c randombytes.c -o $@

lib/libpqcrystals_kyber768_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=3 $(SOURCES) symmetric-shake.c randombytes.c -o $@

lib/libpqcrystals_kyber1024_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=4 $(SOURCES) symmetric-shake.c randombytes.c -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test/test_kyber512
	-$(RM) -f test/test_kyber768
	-$(RM) -f test/test_kyber1024
	-$(RM) -f test/test_vectors512
	-$(RM) -f test/test_vectors768
	-$(RM) -f test/test_vectors1024
	-$(RM) -f test/test_speed512
	-$(RM) -f test/test_speed768
	-$(RM) -f test/test_speed1024
	-$(RM) -f nistkat/PQCgenKAT_kem512
	-$(RM) -f nistkat/PQCgenKAT_kem768
	-$(RM) -f nistkat/PQCgenKAT_kem1024
	-$(RM) -f nistkat/*.req
	-$(RM) -f nistkat/*.rsp
	-$(RM) -rf lib/

install: shared
	@echo "Installing Kyber libraries to system..."
	@mkdir -p $(DESTDIR)/usr/local/lib
	@mkdir -p $(DESTDIR)/usr/local/include/pqcrystals/kyber
	@install -m 0644 *.h $(DESTDIR)/usr/local/include/pqcrystals/kyber/
	@install -m 0755 lib/libpqcrystals_kyber512_ref.so $(DESTDIR)/usr/local/lib/
	@install -m 0755 lib/libpqcrystals_kyber768_ref.so $(DESTDIR)/usr/local/lib/
	@install -m 0755 lib/libpqcrystals_kyber1024_ref.so $(DESTDIR)/usr/local/lib/
	@install -m 0755 lib/libpqcrystals_fips202_ref.so $(DESTDIR)/usr/local/lib/
	@ldconfig
	@echo "Installation complete. Libraries installed to $(DESTDIR)/usr/local/lib"
	@echo "Headers installed to $(DESTDIR)/usr/local/include/pqcrystals/kyber"
