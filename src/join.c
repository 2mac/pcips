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

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "err.h"
#include "join.h"

#define RLE_EXTENSION (RLE_RECORD_SIZE - HEADER_SIZE)

int
pcips_join_patches(FILE *dest, const char * const *src_paths, int n)
{
	int rc, i, c;
	unsigned int size;
	unsigned char buf[HEADER_SIZE];

	rc = fputs(IPS_HEADER, dest);
	if (EOF == rc)
		return PCIPS_EIO;

	rc = 0;
	for (i = 0; i < n; ++i)
	{
		FILE *src = fopen(src_paths[i], "rb");
		if (!src)
		{
			rc = PCIPS_EARGS;
			break;
		}

		size = fread(buf, 1, HEADER_SIZE, src);
		if (size != HEADER_SIZE
			|| memcmp(buf, IPS_HEADER, HEADER_SIZE) != 0)
		{
			rc = PCIPS_EFILE;
			fclose(src);
			break;
		}

		while ((size = fread(buf, 1, HEADER_SIZE, src)) == HEADER_SIZE)
		{
			size = buf[IPS_OFFSET_SIZE];
			size <<= 8;
			size |= buf[IPS_OFFSET_SIZE + 1];

			c = fwrite(buf, HEADER_SIZE, 1, dest);
			if (c != 1)
			{
				rc = PCIPS_EIO;
				break;
			}

			if (0 == size) /* RLE record */
			{
				c = fread(buf, RLE_EXTENSION, 1, src);
				if (c != 1)
				{
					rc = PCIPS_EFILE;
					break;
				}

				c = fwrite(buf, RLE_EXTENSION, 1, dest);
				if (c != 1)
				{
					rc = PCIPS_EFILE;
					break;
				}

				continue;
			}

			while (size--)
			{
				c = fgetc(src);
				if (EOF == c)
				{
					rc = PCIPS_EFILE;
					break;
				}

				c = fputc(c, dest);
				if (EOF == c)
				{
					rc = PCIPS_EIO;
					break;
				}
			}
		}

		if (!rc && (size != FOOTER_SIZE
				|| memcmp(buf, IPS_FOOTER, FOOTER_SIZE) != 0))
			rc = PCIPS_EFILE;

		fclose(src);
		if (rc)
			break;
	}

	if (rc)
		return rc;

	rc = fputs(IPS_FOOTER, dest);
	if (EOF == rc)
		return PCIPS_EIO;

	return 0;
}
