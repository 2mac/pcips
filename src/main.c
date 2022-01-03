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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apply.h"
#include "common.h"
#include "create.h"
#include "join.h"
#include "err.h"

#define VERSION "0.0.2"
#define PROG_INFO "pcips " VERSION
#define USAGE "USAGE\n\
\tApply a patch:\n\
\t\tpcips [options] -a patch_file source_file [output_file]\n\n\
\tCreate a patch file:\n\
\t\tpcips -c patch_file source_file modified_file\n\n\
\tJoin multiple patch files into one:\n\
\t\tpcips -j output_file input1 [input2 ...]\n\n\
OPTIONS\n\
\t-f\n\
\t\tIgnore IPS file size limit of 16MB and apply patches anyway\n\n\
\t-i\n\
\t\tPatch source_file in place, overwriting it\n"

enum pcips_mode
{
	MODE_UNSET,
	MODE_APPLY,
	MODE_CREATE,
	MODE_JOIN
};

static long
file_length(FILE *f)
{
	long result;

	fseek(f, 0L, SEEK_END);
	result = ftell(f);

	rewind(f);
	clearerr(f);

	return result;
}

int
main(int argc, char *argv[])
{
	int rc = 0, c, ignore_limit = 0, in_place = 0, remaining_args;
	enum pcips_mode mode = MODE_UNSET;
	char *patch_path = NULL, *src_path, *dest_path;
	FILE *patch_file = NULL, *src_file = NULL, *dest_file = NULL;

	opterr = 0;
	while ((c = getopt(argc, argv, "a:c:fij")) != -1)
	{
		switch (c)
		{
		case 'a':
		case 'c':
			if (mode != MODE_UNSET)
			{
				fprintf(stderr,
					"Error: more than one processing mode selected.\n\n%s\n",
					USAGE);
				rc = PCIPS_EARGS;
				goto end;
			}

			mode = 'a' == c ? MODE_APPLY : MODE_CREATE;

			patch_path = malloc(strlen(optarg) + 1);
			if (!patch_path)
			{
				rc = PCIPS_ENOMEM;
				goto end;
			}

			strcpy(patch_path, optarg);
			break;

		case 'f':
			ignore_limit = 1;
			break;

		case 'i':
			in_place = 1;
			break;

		case 'j':
			if (mode != MODE_UNSET)
			{
				fprintf(stderr,
					"Error: more than one processing mode selected.\n\n%s\n",
					USAGE);
				rc = PCIPS_EARGS;
				goto end;
			}

			mode = MODE_JOIN;
			break;

		case '?':
			fprintf(stderr, "Invalid argument: -%c\n\n%s\n",
				optopt, USAGE);
			rc = PCIPS_EARGS;
			goto end;
			break;

		case ':':
			fprintf(stderr,
				"Option -%c requires an argument\n\n%s\n",
				optopt, USAGE);
			rc = PCIPS_EARGS;
			goto end;
			break;

		default:
			break;
		}
	}

	remaining_args = argc - optind;
	switch (mode)
	{
	case MODE_UNSET:
		fprintf(stderr, "%s\n\n%s\n", PROG_INFO, USAGE);
		break;

	case MODE_APPLY:
		if (0 == remaining_args || remaining_args > 2)
		{
			fprintf(stderr, "%s\n", USAGE);
			rc = PCIPS_EARGS;
			break;
		}

		src_path = argv[optind];
		if (2 == remaining_args)
			dest_path = argv[optind + 1];
		else
			dest_path = src_path;

		src_file = fopen(src_path, "rb+");
		if (!src_file)
		{
			fprintf(stderr, "Error opening %s: %s\n", src_path,
				strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		if (!ignore_limit && file_length(src_file) > IPS_MAX_OFFSET)
		{
			fprintf(stderr,
				"Source file %s exceeds max IPS offset of 16MB.\n",
				src_path);
			rc = PCIPS_EFILE;
			break;
		}

		patch_file = fopen(patch_path, "rb");
		if (!patch_file)
		{
			fprintf(stderr, "Error opening %s: %s\n", patch_path,
				strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		if (strcmp(src_path, dest_path) == 0)
		{
			if (!in_place)
			{
				fprintf(stderr,
					"Error: You must use -i to patch in place.\n");
				rc = PCIPS_EARGS;
				goto end;
			}

			rc = pcips_apply_patch(src_file, src_file, patch_file);
		}
		else
		{
			dest_file = fopen(dest_path, "wb+");
			if (!dest_file)
			{
				fprintf(stderr, "Error opening %s: %s\n",
					dest_path, strerror(errno));
				rc = PCIPS_EARGS;
				break;
			}

			rc = pcips_apply_patch(src_file, dest_file,
					patch_file);
		}

		if (rc)
		{
			fprintf(stderr, "Error applying patch: %s\n",
				pcips_strerror(rc));

			if (PCIPS_EARGS == rc)
				fprintf(stderr, "%s\n", USAGE);
		}
		break;

	case MODE_CREATE:
		if (remaining_args != 2)
		{
			fprintf(stderr, "%s\n", USAGE);
			rc = PCIPS_EARGS;
			break;
		}

		src_path = argv[optind];
		dest_path = argv[optind + 1];

		src_file = fopen(src_path, "rb");
		if (!src_file)
		{
			fprintf(stderr, "Error opening %s: %s\n", src_path,
				strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		if (file_length(src_file) > IPS_MAX_OFFSET)
		{
			fprintf(stderr,
				"Source file %s exceeds max IPS offset of 16MB.\n",
				src_path);
			rc = PCIPS_EFILE;
			break;
		}

		dest_file = fopen(dest_path, "rb");
		if (!dest_file)
		{
			fprintf(stderr, "Error opening %s: %s\n", dest_path,
				strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		if (file_length(dest_file) > IPS_MAX_OFFSET)
		{
			fprintf(stderr,
				"Modified file %s exceeds max IPS offset of 16MB.\n",
				dest_path);
			rc = PCIPS_EFILE;
			break;
		}

		patch_file = fopen(patch_path, "wb");
		if (!patch_file)
		{
			fprintf(stderr, "Error opening %s: %s\n", patch_path,
				strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		rc = pcips_create_patch(src_file, dest_file, patch_file,
					file_length(src_file));
		if (rc)
		{
			fprintf(stderr, "Error creating patch: %s\n",
				pcips_strerror(rc));

			if (PCIPS_EARGS == rc)
				fprintf(stderr, "%s\n", USAGE);
		}
		break;

	case MODE_JOIN:
		if (0 == remaining_args)
		{
			fprintf(stderr, "%s\n", USAGE);
			rc = PCIPS_EARGS;
			break;
		}

		if (1 == remaining_args)
		{
			fprintf(stderr, "Error: no inputs specified\n\n%s\n",
				USAGE);
			rc = PCIPS_EARGS;
			break;
		}

		dest_path = argv[optind];
		dest_file = fopen(dest_path, "wb");
		if (!dest_file)
		{
			fprintf(stderr, "Error opening %s: %s\n",
				dest_path, strerror(errno));
			rc = PCIPS_EARGS;
			break;
		}

		rc = pcips_join_patches(dest_file,
					(const char * const *)
					argv + optind + 1,
					remaining_args - 1);
		break;
	}

end:
	if (patch_path)
	{
		free(patch_path);
		if (patch_file)
			fclose(patch_file);
	}

	if (src_file)
		fclose(src_file);

	if (dest_file)
		fclose(dest_file);

	return rc;
}
