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

static void help(const char* aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-y, --owner-well-known", _("Set the owner secret to all zeros (32 bytes of zeros)."));
	logCmdOption("-z, --srk-well-known", _("Set the SRK secret to all zeros (32 bytes of zeros)."));
}

static BOOL ownerWellKnown = FALSE;
static BOOL srkWellKnown = FALSE;
TSM_HCONTEXT hContext = 0;

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 'y':
		ownerWellKnown = TRUE;
		break;
	case 'z':
		srkWellKnown = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}

static inline TSM_RESULT tpmTakeOwnership(TSM_HTCM a_hTpm, TSM_HKEY a_hSrk)
{

	TSM_RESULT result =
	    Tspi_TCM_TakeOwnership(a_hTpm, a_hSrk, NULL_HKEY);
	tspiResult("Tspi_TCM_TakeOwnership", result);

	return result;
}

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	char *szSrkPasswd = NULL;
	int tpm_len, srk_len;
	TSM_HTCM hTpm;
	TSM_HKEY hSrk;
	TSM_FLAG fSrkAttrs;
	TSM_HPOLICY hTpmPolicy, hSrkPolicy;
	int iRc = -1;
	BYTE well_known_secret[] = TSM_WELL_KNOWN_SECRET;
	struct option opts[] = {
	{"owner-well-known", no_argument, NULL, 'y'},
	{"srk-well-known", no_argument, NULL, 'z'},
	};

	initIntlSys();

	if (genericOptHandler
	    (argc, argv, "yz", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (!ownerWellKnown) {
		// Prompt for owner password
		szTpmPasswd = GETPASSWD(_("Enter owner password: "), &tpm_len, TRUE);
		if (!szTpmPasswd)
			goto out;
	}

	if (!srkWellKnown) {
		// Prompt for srk password
		szSrkPasswd = GETPASSWD(_("Enter SRK password: "), &srk_len, TRUE);
		if (!szSrkPasswd)
			goto out;
	}

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if (policyGet(hTpm, &hTpmPolicy) != TSM_SUCCESS)
		goto out_close;

	if (ownerWellKnown) {
		tpm_len = TCPA_SM3_256_HASH_LEN;
		if (policySetSecret(hTpmPolicy, tpm_len, well_known_secret) != TSM_SUCCESS)
			goto out_obj_close;
	} else {
		if (policySetSecret(hTpmPolicy, tpm_len, (BYTE *)szTpmPasswd) != TSM_SUCCESS)
			goto out_close;
	}

	fSrkAttrs = TSM_KEY_TSP_SRK | TSM_KEY_AUTHORIZATION;

	if (contextCreateObject
	    (hContext, TSM_OBJECT_TYPE_KEY, fSrkAttrs,
	     &hSrk) != TSM_SUCCESS)
		goto out_close;

	if (policyGet(hSrk, &hSrkPolicy) != TSM_SUCCESS)
		goto out_obj_close;

	if (srkWellKnown) {
		srk_len = TCPA_SM3_256_HASH_LEN;
		if (policySetSecret(hSrkPolicy, srk_len, well_known_secret) != TSM_SUCCESS)
			goto out_obj_close;
	} else {
		if (policySetSecret(hSrkPolicy, srk_len, (BYTE *)szSrkPasswd) != TSM_SUCCESS)
			goto out_obj_close;
	}

	if (tpmTakeOwnership(hTpm, hSrk) != TSM_SUCCESS)
		goto out_obj_close;

	iRc = 0;
	logSuccess(argv[0]);

	out_obj_close:
		contextCloseObject(hContext, hSrk);

	out_close:
		contextClose(hContext);

	out:
		if (szTpmPasswd)
			shredPasswd(szTpmPasswd);

		if (szSrkPasswd)
			shredPasswd(szSrkPasswd);

	return iRc;
}
