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

//Controlled by input options
#define STATUS_CHECK 0
#define ENABLE 1
#define DISABLE 2

static int request = STATUS_CHECK;
static TSM_FLAG fForce = TSM_TCMSTATUS_OWNERSETDISABLE;
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;
/*
 * Affect: Change TCM state between enabled and disabled
 * Default: Display current status
 * Requires: Owner auth unless force( physical presence ) is specified
 */
static void help(const char *cmd)
{

	logCmdHelp(cmd);
	logUnicodeCmdOption();
	logCmdOption("-s, --status", _("Display current state"));
	logCmdOption("-e, --enable", _("Enable TCM"));
	logCmdOption("-d, --disable", _("Disable TCM"));
	logCmdOption("-f, --force",
		     _("Use physical presence authorization."));
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
	case 'e':
		logDebug(_("Changing mode to enable the TCM\n"));
		request = ENABLE;
		break;
	case 'd':
		logDebug(_("Changing mode to disable the TCM\n"));
		request = DISABLE;
		break;
	case 'f':
		logDebug(_("Changing mode to use force authorization\n"));
		fForce = TSM_TCMSTATUS_PHYSICALDISABLE;
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

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	int pswd_len;
	TSM_HTCM hTpm;
	TSM_BOOL bValue;
	TSM_HPOLICY hTpmPolicy;
	int iRc = -1;
	struct option hOpts[] = { {"enable", no_argument, NULL, 'e'},
	{"disable", no_argument, NULL, 'd'},
	{"force", no_argument, NULL, 'f'},
	{"status", no_argument, NULL, 's'},
	{"well-known", no_argument, NULL, 'z'},
	};
	BYTE well_known[] = TSM_WELL_KNOWN_SECRET;

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "edfsz", hOpts,
	     sizeof(hOpts) / sizeof(struct option), parse, help) != 0)
		goto out;

	//Connect to TSM and TCM
	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if ( request == STATUS_CHECK) {
		logInfo( _("Checking current status:\n"));
		if (isWellKnown) {
			szTpmPasswd = (char *)well_known;
			pswd_len = sizeof(well_known);
		} else {
			szTpmPasswd = GETPASSWD(_("Enter owner password: "), &pswd_len, FALSE);
			if (!szTpmPasswd) {
				logMsg(_("Failed to get password\n"));
				goto out_close;
			}
		}
		if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
			goto out_close;

		if (policySetSecret
		    (hTpmPolicy, pswd_len,
		     (BYTE *)szTpmPasswd) != TSM_SUCCESS)
			goto out_close;
		if (tpmGetStatus
		    (hTpm, TSM_TCMSTATUS_DISABLED,
		     &bValue) != TSM_SUCCESS)
			goto out_close;
		logMsg(_("Disabled status: %s\n"), logBool(mapTssBool(bValue)));
	}else {
		if (fForce == TSM_TCMSTATUS_OWNERSETDISABLE) {
			if (isWellKnown) {
				szTpmPasswd = (char *)well_known;
				pswd_len = sizeof(well_known);
			} else {
				szTpmPasswd = GETPASSWD(_("Enter owner password: "), &pswd_len,
							FALSE);
				if (!szTpmPasswd) {
					logMsg(_("Failed to get password\n"));
					goto out_close;
				}
			}

			if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
				goto out_close;

			if (policySetSecret
			    (hTpmPolicy, pswd_len,
			     (BYTE *)szTpmPasswd) != TSM_SUCCESS)
				goto out_close;
			}

		//Setup complete.  Attempt the command
		if (tpmSetStatus(hTpm, fForce, (request == ENABLE) ? FALSE : TRUE ) != TSM_SUCCESS)
			goto out_close;
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
