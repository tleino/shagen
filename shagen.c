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

#include <openssl/sha.h>

#ifdef HAVE_READPASSPHRASE
#include <readpassphrase.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <string.h>

void generate_passphrase(FILE *fp, const char *file, unsigned char *digest);

static int
usage(const char *prog)
{
	fprintf(stderr,
	    "usage: %s [-q] [-f wordlist] domain account [version]\n",
	    prog);
	return 1;
}

int
main(int argc, char **argv)
{
	const char *domain, *account, *version;
#ifdef HAVE_READPASSPHRASE
	char master[128], repeat[128];
#else
	char *masterp, *repeatp;
#endif
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char key[256];
	char symbols[26+26+10] = 
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	int bits, i;
	char ch;
	const char *prog, *file = NULL;
	FILE *fp = NULL;
	char qflag;
	SHA256_CTX ctx;

#ifdef HAVE_PLEDGE
	if (pledge("stdio rpath tty", NULL) == -1)
		err(1, "pledge");
#endif

	prog = *argv;
	while ((ch = getopt(argc, argv, "qf:")) != -1) {
		switch (ch) {
		case 'q':
			qflag = 1;
			break;
		case 'f':
			file = optarg;
			if ((fp = fopen(file, "r")) == NULL)
				err(1, "%s", file);
			break;
		default:
			return usage(prog);
		}
	}

#ifdef HAVE_PLEDGE
	if (pledge("stdio tty", NULL) == -1)
		err(1, "pledge");
#endif

	argc -= optind;
	argv += optind;

	if (argc < 2)
		return usage(prog);

	domain = *argv++;
	argc--;
	account = *argv++;
	argc--;
	version = "1";
	if (argc)
		version = *argv++;

#ifndef HAVE_READPASSPHRASE
	masterp = getpass("Master passphrase: ");
	if (!qflag)
		repeatp = getpass("Repeat master passphrase: ");
#else
	if (readpassphrase("Master passphrase: ", master, sizeof(master),
	    RPP_REQUIRE_TTY | RPP_SEVENBIT) == NULL)
		errx(1, "unable to read passphrase");
	if (!qflag)
		if (readpassphrase("Repeat master passphrase: ", repeat,
		    sizeof(repeat), RPP_REQUIRE_TTY | RPP_SEVENBIT) == NULL)
			errx(1, "unable to read passphrase");
	masterp = master;
	repeatp = repeat;
#endif

#ifdef HAVE_PLEDGE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	if (!qflag) {
		if (strcmp(masterp, repeatp) != 0)
			errx(1, "did not match");
#ifdef HAVE_READPASSPHRASE
		explicit_bzero(repeat, sizeof(repeat));
#endif
	}

	if (snprintf(key, sizeof(key), "%s %s %s %s",
	    domain, account, version, masterp) >= sizeof(key))
		errx(1, "key truncated");
#ifdef HAVE_READPASSPHRASE
	explicit_bzero(master, sizeof(master));
#endif

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, strlen(key));
	SHA256_Final(digest, &ctx);

#ifdef HAVE_READPASSPHRASE
	explicit_bzero(key, sizeof(key));
#endif

	for (i = 0; i < 14; i++) {
		bits = digest[i*2];
		bits |= digest[i*2+1] << 8;
		putchar(symbols[bits % sizeof(symbols)]);
		if ((i+1) % 4 == 0)
			putchar('-');
	}
	putchar('\n');

	if (!fp)
		return 0;

	generate_passphrase(fp, file, digest);
	fclose(fp);

	return 0;
}
