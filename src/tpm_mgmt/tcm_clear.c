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
static BOOL bValue = FALSE;	//If true FORCE CLEAR
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static inline TSM_RESULT tpmClearOwner(TSM_HTCM a_hTpm, BOOL a_bValue)
{

	TSM_RESULT result = Tspi_TCM_ClearOwner(a_hTpm, a_bValue);
	tspiResult("Tspi_TCM_ClearOwner", result);

	return result;

}

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-f, --force", _("Use physical presence authorization."));
	logCmdOption("-z, --well-known",
		     _("Use 32 bytes of zeros (TSM_WELL_KNOWN_SECRET) as the TCM secret authorization data"));
}

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 'f':
		logDebug(_("Changing mode to use force authorization\n"));
		bValue = TRUE;
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
	TSM_HPOLICY hTpmPolicy;
	int iRc = -1;
	struct option opts[] = {
			{"force", no_argument, NULL, 'f'},
			{"well-known", no_argument, NULL, 'z'},
	};
	BYTE well_known[] = TSM_WELL_KNOWN_SECRET;

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "fz", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if (!bValue) {
		if (isWellKnown){
			szTpmPasswd = (char *)well_known;
			pswd_len = sizeof(well_known);
		}else{
			szTpmPasswd = GETPASSWD(_("Enter owner password: "), &pswd_len, FALSE);
			if (!szTpmPasswd) {
				logMsg(_("Failed to get password\n"));
				goto out_close;
			}
		}

		if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
			goto out_close;

		if (policySetSecret(hTpmPolicy, pswd_len,
				    (BYTE *)szTpmPasswd) != TSM_SUCCESS)
			goto out_close;
	}
	//Setup complete attempt command
	if (tpmClearOwner(hTpm, bValue) != TSM_SUCCESS)
		goto out_close;

	//Command successful
	iRc = 0;
	logSuccess(argv[0]);

	logMsg( _("TCM Successfuly Cleared.  You need to reboot to complete this operation.  After reboot the TCM will be in the default state: unowned, disabled and inactive.\n") );

	//Cleanup
      out_close:
	if (szTpmPasswd && !isWellKnown)
		shredPasswd(szTpmPasswd);

	contextClose(hContext);

      out:
	return iRc;
}
