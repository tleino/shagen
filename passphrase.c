#include <err.h>
#include <stdio.h>

void
generate_passphrase(FILE *fp, const char *file, unsigned char *digest)
{
	int i;
	char word[32];

	for (i = 0; i < 6; i++) {
		uint32_t num;
		int j;

		rewind(fp);

		/* This uses 24 bytes from 32 bytes SHA256 */
		num = digest[(i*4)];
		num |= (digest[(i*4)+1] << 8);
		num |= (digest[(i*4)+2] << 16);
		num |= (digest[(i*4)+3] << 24);
		num %= 7776;

		j = 0;
		for (j = 0; j < num; j++) {
			if (fscanf(fp, "%*d %s", word) != 1) {
				if (feof(fp))
					errx(1, "%s: need %d words more",
					    file, 7776 - j);
				else if (ferror(fp))
					err(1, "%s", file);
				else
					errx(1, "%s:%d: format error",
					    file, j+1);
			}
		}
		if (i != 0)
			putchar(' ');
		printf("%s", word);
	}

	putchar('\n');
}
