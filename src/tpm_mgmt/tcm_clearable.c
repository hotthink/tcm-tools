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

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-s, --status",
		     _("Report current status."));
	logCmdOption("-o, --owner",
		     _("Remove ability of the owner to clear TCM."));
	logCmdOption("-f, --force",
		     _("Remove ability to clear TCM with physical presence.\n\t\tThis action is not persistent"));
	logCmdOption("-z, --well-known",
		      _("Use 32 bytes of zeros (TSM_WELL_KNOWN_SECRET) as the TCM secret authorization data"));
}

enum {
	owner = 0,
	force
};

struct physFlag {
	const char *name;
	const TSM_FLAG property;
	BOOL disable;
};

//Controlled by input options
static struct physFlag flags[] = { {N_("Owner Clear"),
				    TSM_TCMSTATUS_DISABLEOWNERCLEAR},
{N_("Force Clear"),
 TSM_TCMSTATUS_DISABLEFORCECLEAR},
{0, 0, 0}
};
static BOOL bCheck = FALSE;
static BOOL bChangeRequested = FALSE;
static BOOL isWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 's':
		bCheck = TRUE;
		break;
	case 'o':
		flags[owner].disable = TRUE;
		bChangeRequested = TRUE;
		break;
	case 'f':
		flags[force].disable = TRUE;
		bChangeRequested = TRUE;
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
 * Affect: Toggle OwnerClear and ForceClear from being available
 * Default: Display current states
 * Requires: Owner auth to set OwnerClear and display current states
 */

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	int pswd_len;
	TSM_HTCM hTpm;
	TSM_HPOLICY hTpmPolicy;
	int iRc = -1;
	int i = 0;
	struct option opts[] = { {"status", no_argument, NULL, 's'},
	{"owner", no_argument, NULL, 'o'},
	{"force", no_argument, NULL, 'f'},
	{"well-known", no_argument, NULL, 'z'},
	};
	BYTE well_known[] = TSM_WELL_KNOWN_SECRET;

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "ofsz", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	//Connect to TSM and TCM
	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if (bCheck || !bChangeRequested) {
		logInfo(_("Checking current status: \n"));
		if (isWellKnown){
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
		    (hTpmPolicy,
		     pswd_len, (BYTE *)szTpmPasswd) != TSM_SUCCESS)
			goto out_close;
		do {
			TSM_BOOL bValue;
			if (tpmGetStatus(hTpm, flags[i].property, &bValue)
			    != TSM_SUCCESS)
				goto out_close;

			logMsg("%s Disabled: %s\n", _(flags[i].name),
			       logBool(mapTssBool(bValue)));

		} while (flags[++i].name);
		goto out_success;
	}

	do {
		if (flags[i].disable) {
			logDebug(_("Requested to disable: %s ability.\n"),
				 _(flags[i].name));
			if (i == owner) {
				if (isWellKnown){
					szTpmPasswd = (char *)well_known;
					pswd_len = sizeof(well_known);
				} else {
					szTpmPasswd = GETPASSWD(_("Enter owner password: "),
								&pswd_len, FALSE);
					if (!szTpmPasswd) {
						logMsg(_("Failed to get password\n"));
						goto out_close;
					}
				}
				if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
					goto out_close;

				if (policySetSecret
				    (hTpmPolicy,
				     pswd_len,
				     (BYTE *)szTpmPasswd) != TSM_SUCCESS)
					goto out_close;
			}

			if (tpmSetStatus(hTpm, flags[i].property, 0)
			    != TSM_SUCCESS)
				goto out_close;
			logInfo(_("Disabling %s successful.\n"),
				_(flags[i].name));
		}
	}
	while (flags[++i].name);
      out_success:
	logSuccess(argv[0]);
	iRc = 0;

      out_close:
	contextClose(hContext);
      out:
	if (szTpmPasswd && !isWellKnown)
		shredPasswd(szTpmPasswd);
	return iRc;
}
