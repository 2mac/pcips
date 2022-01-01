/*
 *  pcips - portable C IPS patch utility
 *  Copyright (C) 2022 David McMackins II
 *
 *  Redistributions, modified or unmodified, in whole or in part, must retain
 *  applicable notices of copyright or other legal privilege, these conditions,
 *  and the following license terms and disclaimer.  Subject to these
 *  conditions, each holder of copyright or other legal privileges, author or
 *  assembler, and contributor of this work, henceforth "licensor", hereby
 *  grants to any person who obtains a copy of this work in any form:
 *
 *  1. Permission to reproduce, modify, distribute, publish, sell, sublicense,
 *  use, and/or otherwise deal in the licensed material without restriction.
 *
 *  2. A perpetual, worldwide, non-exclusive, royalty-free, gratis, irrevocable
 *  patent license to make, have made, provide, transfer, import, use, and/or
 *  otherwise deal in the licensed material without restriction, for any and
 *  all patents held by such licensor and necessarily infringed by the form of
 *  the work upon distribution of that licensor's contribution to the work
 *  under the terms of this license.
 *
 *  NO WARRANTY OF ANY KIND IS IMPLIED BY, OR SHOULD BE INFERRED FROM, THIS
 *  LICENSE OR THE ACT OF DISTRIBUTION UNDER THE TERMS OF THIS LICENSE,
 *  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 *  A PARTICULAR PURPOSE, AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS,
 *  ASSEMBLERS, OR HOLDERS OF COPYRIGHT OR OTHER LEGAL PRIVILEGE BE LIABLE FOR
 *  ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN ACTION OF CONTRACT,
 *  TORT, OR OTHERWISE ARISING FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR
 *  THE USE OF OR OTHER DEALINGS IN THE WORK.
 */

#include <string.h>

#include "apply.h"
#include "common.h"
#include "err.h"

static long
unbuffer(const unsigned char *buf, int nmemb)
{
	long value = 0;
	int i;

	for (i = 0; i < nmemb; ++i)
	{
		value <<= 8;
		value |= buf[i];
	}

	return value;
}

int
pcips_apply_patch(FILE *src_file, FILE *dest_file, FILE *patch)
{
	int c;
	long offset, length, pos;
	unsigned int size;
	unsigned char buf[5];

	if (src_file != dest_file)
	{
		rewind(src_file);
		rewind(dest_file);

		while ((c = fgetc(src_file)) != EOF)
		{
			c = fputc(c, dest_file);
			if (EOF == c)
				return PCIPS_EIO;
		}

		if (!feof(src_file))
			return PCIPS_EIO;

	}
	else
	{
		fseek(src_file, 0L, SEEK_END);
	}

	length = ftell(src_file);

	clearerr(src_file);
	rewind(patch);

	size = fread(buf, 1, 5, patch);
	if (size != 5 || memcmp(buf, IPS_HEADER, 5) != 0)
		return PCIPS_EFILE;

	while ((size = fread(buf, 1, 5, patch)) == 5)
	{
		offset = unbuffer(buf, 3);
		size = unbuffer(&buf[3], 2);

		if (offset > length)
		{
			fseek(dest_file, 0L, SEEK_END);
			while (length++ < offset)
			{
				c = fputc(0x00, dest_file);
				if (EOF == c)
					return PCIPS_EIO;
			}
		}

		fseek(dest_file, offset, SEEK_SET);
		if (0 == size) /* RLE record */
		{
			size = fread(buf, 1, 2, patch);
			if (size != 2)
				return PCIPS_EFILE;

			size = unbuffer(buf, 2);
			c = fgetc(patch);
			if (EOF == c)
				return PCIPS_EIO;

			while (size--)
			{
				if (fputc(c, dest_file) == EOF)
					return PCIPS_EIO;
			}
		}
		else
		{
			while (size--)
			{
				c = fgetc(patch);
				if (EOF == c)
					return PCIPS_EIO;

				c = fputc(c, dest_file);
				if (EOF == c)
					return PCIPS_EIO;
			}
		}

		pos = ftell(dest_file);
		if (pos > length)
			length = pos;
	}

	if (size != 3 || memcmp(buf, IPS_FOOTER, 3) != 0)
		return PCIPS_EFILE;

	return 0;
}
