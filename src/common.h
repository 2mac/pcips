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

#ifndef PCIPS_COMMON_H
#define PCIPS_COMMON_H

#define IPS_HEADER "PATCH"
#define IPS_FOOTER "EOF"

#define IPS_MAX_OFFSET 0x00FFFFFFL
#define IPS_MAX_RECORD 0xFFFF

#define IPS_OFFSET_SIZE 3
#define IPS_SIZE_SIZE 2
#define HEADER_SIZE (IPS_OFFSET_SIZE + IPS_SIZE_SIZE)
#define FOOTER_SIZE 3
#define RLE_HEADER_SIZE (HEADER_SIZE + 2)
#define RLE_RECORD_SIZE (RLE_HEADER_SIZE + 1)
#define RLE_EXTENSION (RLE_RECORD_SIZE - HEADER_SIZE)

#endif
