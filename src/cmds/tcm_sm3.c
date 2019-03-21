/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005, 2006 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */
#include <limits.h>
#include <openssl/evp.h>
#include "tcm_tspi.h"
#include "tcm_utils.h"

static char in_filename[PATH_MAX] = "";
static TSM_HTCM hTpm;
static BOOL passUnicode = FALSE;
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logCmdOption("-i, --infile FILE",
		     _
		     ("Filename. Default is STDIN."));
	logCmdOption("-z, --well-known", _("Use TSM_WELL_KNOWN_SECRET as the SRK secret."));
	logCmdOption("-u, --unicode", _("Use TSM UNICODE encoding for the SRK password to comply with applications using TSM popup boxes"));

}

static int parse(const int aOpt, const char *aArg)
{
	int rc = -1;

	switch (aOpt) {
	case 'i':
		if (aArg) {
			strncpy(in_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'u':
		passUnicode = TRUE;
		rc = 0;
		break;
	case 'z':
		isWellKnown = TRUE;
		rc = 0;
		break;
	default:
		break;
	}
	return rc;

}

int main(int argc, char **argv)
{
	int iRc = -1;
	struct option opts[] =
	{ 
	   {"infile", required_argument, NULL, 'i'},
	   {"unicode", no_argument, NULL, 'u'},
	   {"well-known", no_argument, NULL, 'z'}
	};
	UINT32 maxLine = 0, lineLen = 0;
	unsigned char line[1024] = {0};
	BYTE hash[TCPA_SM3_256_HASH_LEN] = {0};
	BIO *bin = NULL;

	initIntlSys();

	if (genericOptHandler(argc, argv, "i:uz", opts, sizeof(opts) / sizeof(struct option), parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if ((bin = BIO_new(BIO_s_file())) == NULL) {
		logError(_("Unable to open input BIO\n"));
		goto out_close;
	}

	if (strlen(in_filename) == 0) 
		BIO_set_fp(bin, stdin, BIO_NOCLOSE);
	else if (!BIO_read_filename(bin, in_filename)) {
		logError(_("Unable to open input file: %s\n"),
			 in_filename);
		goto out_close;
	}

	if(sm3Start(hTpm, &maxLine) != TSM_SUCCESS)
		goto out_close;

	while ((lineLen = BIO_read(bin, line, (maxLine<1024?maxLine:1024))) > 0) {
		if(sm3Update(hTpm, lineLen, line) != TSM_SUCCESS)
			goto out_close;
	}

	if(sm3Complete(hTpm, lineLen, line, hash) != TSM_SUCCESS){
		logError(_("Unable to HASH input file by SM3: %s\n"),in_filename);
		goto out_close;
	}

	logHexEx(TCPA_SM3_256_HASH_LEN, hash);
	
	iRc = 0;
	logSuccess(argv[0]);

out_close:
	contextClose(hContext);

out:
	if (bin)
		BIO_free(bin);
	return iRc;
}
