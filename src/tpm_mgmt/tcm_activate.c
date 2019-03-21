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

//Controled by input options

#define STATUS_CHECK 0
#define ACTIVATE 1
#define DEACTIVATE 2
#define TEMP_DEACTIVATE 3

static int request = STATUS_CHECK;
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-s, --status", _("Report current state"));
	logCmdOption("-a, --active", _("Activate TCM, requires reboot"));
	logCmdOption("-i, --inactive", _("Deactivate TCM, requires reboot"));
	logCmdOption("-t, --temp",
		     _("Change state immediately but only for this boot.\n\t\tOnly valid in conjunction with the inactive parameter."));
	logCmdOption("-z, --well-known",
		     _("Use 32 bytes of zeros (TSM_WELL_KNOWN_SECRET) as the TCM secret authorization data"));
}

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 's':
		logDebug(_("Changing mode to check status.\n"));
		request = STATUS_CHECK;
		break;
	case 'a':
		logDebug(_("Changing mode to activate the TCM.\n"));
		request = ACTIVATE;
		break;
	case 'i':
		logDebug(_("Changing mode to deactivate the TCM.\n"));
		request = DEACTIVATE;
		break;
	case 't':
		logDebug(_("Changing mode to temporarily deactivate the TCM\n"));
		request = TEMP_DEACTIVATE;
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

/*
 * Affect: Change state of TCM between Active and Inactive
 * Default: report status
 * Requires: Physical presence unless --temp specified
*/
int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	int tpm_len;
	TSM_HTCM hTpm;
	TSM_HPOLICY hTpmPolicy;
	TSM_BOOL bValue;
	int iRc = -1;
	struct option opts[] = { {"active", no_argument, NULL, 'a'},
	{"inactive", no_argument, NULL, 'i'},
	{"temp", no_argument, NULL, 't'},
	{"status", no_argument, NULL, 's'},
	{"well-known", no_argument, NULL, 'z'},
	};
	BYTE well_known[] = TSM_WELL_KNOWN_SECRET;

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "aitsz", opts,
	     sizeof(opts) / sizeof(struct option), parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	switch(request) {
	case STATUS_CHECK:
		logInfo(_("Checking status:\n"));
		if (isWellKnown){
			szTpmPasswd = (char *)well_known;
			tpm_len = sizeof(well_known);
		} else {
			szTpmPasswd = GETPASSWD(_("Enter owner password: "), &tpm_len, FALSE);
			if (!szTpmPasswd) {
				logMsg(_("Failed to get password\n"));
				goto out_close;
			}
		}

		if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
			goto out_close;

		if (policySetSecret
		    (hTpmPolicy, tpm_len,
		     (BYTE *)szTpmPasswd) != TSM_SUCCESS)
			goto out_close;
		if (tpmGetStatus
		    (hTpm, TSM_TCMSTATUS_PHYSICALSETDEACTIVATED,
		     &bValue) != TSM_SUCCESS)
			goto out_close;
		logMsg(_("Persistent Deactivated Status: %s\n"),
		       logBool(mapTssBool(bValue)));

		if (tpmGetStatus
		    (hTpm, TSM_TCMSTATUS_SETTEMPDEACTIVATED, &bValue))
			goto out_close;
		logMsg(_("Volatile Deactivated Status: %s\n"),
		       logBool(mapTssBool(bValue)));
		break;
	case ACTIVATE:
		if (tpmSetStatus(hTpm, TSM_TCMSTATUS_PHYSICALSETDEACTIVATED, FALSE) != TSM_SUCCESS)
			goto out_close;
		logMsg(_("Action requires a reboot to take effect\n"));
		break;
	case DEACTIVATE:
		if (tpmSetStatus(hTpm, TSM_TCMSTATUS_PHYSICALSETDEACTIVATED, TRUE) != TSM_SUCCESS)
			goto out_close;
		logMsg(_("Action requires a reboot to take effect\n"));
		break;
	case TEMP_DEACTIVATE:
		if (tpmSetStatus(hTpm, TSM_TCMSTATUS_SETTEMPDEACTIVATED, TRUE) != TSM_SUCCESS)
			goto out_close;
		break;
	}

	//Command successful
	iRc = 0;
	logSuccess(argv[0]);
	//Cleanup
      out_close:
	if (szTpmPasswd && !isWellKnown)
		shredPasswd(szTpmPasswd);

	contextClose(hContext);

      out:
	return iRc;
}
