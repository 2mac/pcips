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
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "create.h"
#include "err.h"

#define RLE_TRADEOFF_SIZE (HEADER_SIZE + RLE_RECORD_SIZE)

struct ips_record
{
	long offset;
	unsigned int size;
	unsigned int rle_size;
	unsigned char *data;
	int rle_data;
};

static int
write_record(FILE *f, const struct ips_record *rec)
{
	long offset;
	unsigned int size;
	unsigned char header[HEADER_SIZE];

	offset = rec->offset;
	header[0] = (offset & 0xFF0000L) >> 16;
	header[1] = (offset & 0x00FF00L) >> 8;
	header[2] = (offset & 0x0000FFL);

	size = rec->size;
	header[3] = (size & 0xFF00) >> 8;
	header[4] = (size & 0x00FF);

	if (fwrite(header, sizeof header, 1, f) != 1)
		return PCIPS_EIO;

	if (0 == size) /* RLE record */
	{
		unsigned char rle[RLE_EXTENSION];

		size = rec->rle_size;
		rle[0] = (size & 0xFF00) >> 8;
		rle[1] = (size & 0x00FF);
		rle[2] = rec->rle_data;

		if (fwrite(rle, sizeof rle, 1, f) != 1)
			return PCIPS_EIO;
	}
	else
	{
		if (fwrite(rec->data, sizeof rec->data[0], size, f) != size)
			return PCIPS_EIO;
	}

	return 0;
}

static int
strip_to_rle(FILE *f, struct ips_record *rec)
{
	int rc;

	rec->size -= rec->rle_size;
	if (rec->size != 0)
	{
		rc = write_record(f, rec);
		if (rc)
			return rc;
	}

	rec->offset += rec->size;
	rec->size = rec->rle_size;
	memset(rec->data, rec->rle_data, rec->rle_size);

	return 0;
}

static int
bail_to_rle(FILE *f, struct ips_record *rec)
{
	int rc = 0;

	rec->size -= rec->rle_size;
	if (rec->size != 0)
	{
		rc = write_record(f, rec);
		if (rc)
			return rc;
	}

	rec->offset += rec->size;
	rec->size = 0;
	rc = write_record(f, rec);

	rec->offset += rec->rle_size;

	return rc;
}

int
pcips_create_patch(FILE *src, FILE *modified, FILE *patch, long src_length)
{
	int rc = 0, c, src_c, mod_c, in_patch = 0;
	long pos = 0;
	unsigned char src_look_ahead[HEADER_SIZE], mod_look_ahead[HEADER_SIZE];
	struct ips_record rec;

	rewind(src);
	rewind(modified);

	rec.data = malloc(IPS_MAX_RECORD);
	if (!rec.data)
		return PCIPS_ENOMEM;

	c = fputs(IPS_HEADER, patch);
	if (EOF == c)
	{
		rc = PCIPS_EIO;
		goto end;
	}

	while ((mod_c = fgetc(modified)) != EOF)
	{
		int match = 0;

		if (pos < src_length)
		{
			src_c = fgetc(src);
			if (EOF == src_c)
			{
				rc = PCIPS_EIO;
				goto end;
			}

			match = mod_c == src_c;
		}

		if (!match)
		{
			if (!in_patch)
			{
				in_patch = 1;
				rec.offset = pos;
				rec.size = 0;
				rec.rle_size = 1;
				rec.rle_data = -1; /* prevent matching first
						      byte of patch */
			}

			if (mod_c == rec.rle_data)
			{
				++rec.rle_size;
			}
			else
			{
				/* is it cheaper to make an RLE record? */
				if (rec.rle_size > RLE_TRADEOFF_SIZE
					|| (rec.rle_size > RLE_RECORD_SIZE
						&& rec.rle_size == rec.size))
				{
					rc = bail_to_rle(patch, &rec);
					if (rc)
						goto end;
				}

				rec.rle_size = 1;
				rec.rle_data = mod_c;
			}

			rec.data[rec.size++] = mod_c;
			if (rec.size == IPS_MAX_RECORD)
			{
				if (rec.rle_size == rec.size)
				{
					rc = bail_to_rle(patch, &rec);
					in_patch = 0;
				}
				else if (rec.rle_size > RLE_RECORD_SIZE)
				{
					rc = strip_to_rle(patch, &rec);
				}
				else
				{
					rc = write_record(patch, &rec);
					in_patch = 0;
				}

				if (rc)
					goto end;
			}
		}
		else /* files match here */
		{
			if (in_patch)
			{
				int i, src_count, mod_count, n, rpt;
				unsigned int limit;

				limit = IPS_MAX_RECORD - rec.size - 1;
				if (limit > HEADER_SIZE)
					limit = HEADER_SIZE;
				else
					limit = 0;

				mod_count = fread(mod_look_ahead, 1, limit,
						modified);
				src_count = fread(src_look_ahead, 1, limit,
						src);

				n = src_count < mod_count ? src_count : mod_count;
				rpt = 1;
				for (i = 0; i < n; ++i)
				{
					if (mod_look_ahead[i] != mod_c)
						rpt = 0;
					if (mod_look_ahead[i]
						!= src_look_ahead[i])
						break;
				}

				/* will it cost more to start a new record? */
				if ((!rpt || mod_c != rec.rle_data)
					&& rec.rle_size > RLE_TRADEOFF_SIZE)
				{
					rc = bail_to_rle(patch, &rec);
					if (rc)
						goto end;

					rec.rle_size = 1;
					rec.rle_data = -1;

					pos += i;
					fseek(src, i - src_count, SEEK_CUR);
					fseek(modified, i - mod_count,
						SEEK_CUR);

					in_patch = 0;
				}
				else if (i != n || n < mod_count)
				{
					if (rpt)
					{
						if (mod_c == rec.rle_data)
						{
							rec.rle_size += i + 2;
						}
						else
						{
							rec.rle_data = mod_c;
							rec.rle_size = i + 2;
						}
					}
					else
					{
						rec.rle_size = 1;
						rec.rle_data =
							mod_look_ahead[i];
					}

					rec.data[rec.size++] = mod_c;

					memcpy(rec.data + rec.size,
						mod_look_ahead, i + 1);
					rec.size += i + 1;

					pos += i + 1;
					fseek(src, i - src_count + 1,
						SEEK_CUR);
					fseek(modified, i - mod_count + 1,
						SEEK_CUR);
				}
				else
				{
					if (rec.rle_size > RLE_RECORD_SIZE
						|| (rec.rle_size == rec.size
							&& rec.rle_size >
							(RLE_RECORD_SIZE - HEADER_SIZE)))
						rc = bail_to_rle(patch, &rec);
					else
						rc = write_record(patch, &rec);

					if (rc)
						goto end;

					in_patch = 0;
					pos += n;
				}
			}
		}

		++pos;
	}

	if (in_patch)
	{
		if (rec.rle_size > RLE_RECORD_SIZE
			|| (rec.rle_size > (RLE_RECORD_SIZE - HEADER_SIZE)
				&& rec.rle_size == rec.size))
			rc = bail_to_rle(patch, &rec);
		else
			rc = write_record(patch, &rec);

		if (rc)
			goto end;
	}

	c = fputs(IPS_FOOTER, patch);
	if (EOF == c)
		rc = PCIPS_EIO;

end:
	free(rec.data);
	return rc;
}
