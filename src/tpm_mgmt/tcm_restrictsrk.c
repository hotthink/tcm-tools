/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
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

#include "tcm_tspi.h"
#include "tcm_utils.h"
#include <getopt.h>

//controlled by input options
static BOOL bCheck = FALSE;
static BOOL bRestrict = FALSE;
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 'a':
		logDebug(_("Changing mode to allow SRK access using SRK auth\n"));
		bRestrict = FALSE;
		break;
	case 's':
		logDebug(_("Changing mode to check status.\n"));
		bCheck = TRUE;
		break;
	case 'r':
		logDebug(_("Changing mode to restrist SRK access\n"));
		bRestrict = TRUE;
		break;
	case 'z':
		logDebug(_("Using TSM_WELL_KNOWN_SECRET to authorize the TCM command\n"));
		isWellKnown = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}

static void help(const char *aCmd)
{

	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-a, --allow",
		     _("Allow SRK read access using SRK auth"));
	logCmdOption("-s, --status", _("Display current status"));
	logCmdOption("-r, --restrict",
		     _("Restrict SRK read to owner only"));
	logCmdOption("-z, --well-known",
		     _("Use 32 bytes of zeros (TSM_WELL_KNOWN_SECRET) as the TCM secret authorization data"));
}

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	int pswd_len;
	TSM_HPOLICY hTpmPolicy;
	TSM_HTCM hTpm;
	int iRc = -1;
	struct option opts[] = { {"allow", no_argument, NULL, 'a'},
	{"status", no_argument, NULL, 's'},
	{"restrict", no_argument, NULL, 'r'},
	{"well-known", no_argument, NULL, 'z'},
	};
	BYTE well_known[TCPA_SM3_256_HASH_LEN] = TSM_WELL_KNOWN_SECRET;

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "asrz", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	/* If no args are given, the default should be to give status */
	if (argc == 1)
		bCheck = TRUE;

	//Connect to TSM and TCM
	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if (isWellKnown) {
		szTpmPasswd = (char *)well_known;
		pswd_len = sizeof(well_known);
	} else {
		// Prompt for owner password
		szTpmPasswd = GETPASSWD(_("Enter owner password: "), &pswd_len, FALSE);
		if (!szTpmPasswd) {
			logMsg(_("Failed to get password\n"));
			goto out_close;
		}
	}
	if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
		goto out_close;

	if (policySetSecret
	    (hTpmPolicy, pswd_len, (BYTE *)szTpmPasswd) != TSM_SUCCESS)
		goto out_close;

	if (bCheck) {
		TSM_BOOL bValue;
		if (tpmGetStatus
		    (hTpm, TSM_TCMSTATUS_DISABLEPUBSRKREAD,
		     &bValue) != TSM_SUCCESS)
			goto out;
		logMsg(_("Storage Root Key readable with: %s\n"),
		       bValue ? _("owner auth") : _("SRK auth"));

	} else {
		if (tpmSetStatus(hTpm, TSM_TCMSTATUS_DISABLEPUBSRKREAD, bRestrict)
		    != TSM_SUCCESS)
			goto out_close;
	}

	iRc = 0;
	logSuccess(argv[0]);

      out_close:
	contextClose(hContext);

      out:
	if (szTpmPasswd && !isWellKnown)
		shredPasswd(szTpmPasswd);

	return iRc;

}
