/*
 * Copyright (c) 2023, Tommi Leino <namhas@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __OpenBSD__
#define HAVE_PLEDGE
#define HAVE_EXPLICIT_BZERO
#endif

#include <openssl/sha.h>
#include <readpassphrase.h>

#ifdef HAVE_PLEDGE
#include <unistd.h>
#endif

#include <stdio.h>
#include <err.h>
#include <string.h>

#ifndef HAVE_EXPLICIT_BZERO
#define explicit_bzero(ptr, sz) memset(ptr, '\0', sz)
#endif

int
main(int argc, char **argv)
{
	const char *domain, *account, *version;
	char master[128], repeat[128];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char key[256];
	char symbols[26+26+10] = 
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	int bits, i;

#ifdef HAVE_PLEDGE
	if (pledge("stdio tty", NULL) == -1)
		err(1, "pledge");
#endif

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "Usage: %s DOMAIN ACCOUNT [VERSION]\n", *argv);
		return 1;
	}

	domain = *++argv;
	account = *++argv;
	version = "1";
	if (argc == 4)
		version = *++argv;

	if (readpassphrase("Master passphrase: ", master, sizeof(master),
	    RPP_REQUIRE_TTY | RPP_SEVENBIT) == NULL)
		errx(1, "unable to read passphrase");

	if (readpassphrase("Repeat master passphrase: ", repeat,
	    sizeof(repeat), RPP_REQUIRE_TTY | RPP_SEVENBIT) == NULL)
		errx(1, "unable to read passphrase");

#ifdef HAVE_PLEDGE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	if (strcmp(master, repeat) != 0)
		errx(1, "did not match");
	explicit_bzero(repeat, sizeof(repeat));

	if (snprintf(key, sizeof(key), "%s %s %s %s",
	    domain, account, version, master) >= sizeof(key))
		errx(1, "key truncated");
	explicit_bzero(master, sizeof(master));

	SHA256((unsigned char *) key, strlen(key), digest);
	explicit_bzero(key, sizeof(key));

	for (i = 0; i < 14; i++) {
		bits = digest[i*2];
		bits |= digest[i*2+1] << 8;
		putchar(symbols[bits % sizeof(symbols)]);
		if ((i+1) % 4 == 0)
			putchar('-');
	}
	putchar('\n');
	return 0;
}
