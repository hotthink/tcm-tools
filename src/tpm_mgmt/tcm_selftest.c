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
#include <getopt.h>
#include <stdlib.h>		//for def. exit
#include "tcm_tspi.h"


//Controlled by input options
static int resultFlag = FALSE;
TSM_HCONTEXT hContext = 0;

TSM_RESULT selfTestFull(TSM_HTCM a_hTpm)
{
	TSM_RESULT result = Tspi_TCM_SelfTestFull(a_hTpm);
	tspiResult("Tspi_TCM_SelfTestFull", result);

	return result;
}

TSM_RESULT selfTestResult(TSM_HTCM a_hTpm,
			  UINT32 * a_uiResultLen, BYTE ** a_pResult)
{

	TSM_RESULT result = Tspi_TCM_GetTestResult(a_hTpm, a_uiResultLen,
						   a_pResult);
	tspiResult("Tspi_TCM_GetTestResult", result);

	return result;
}

int cmdSelfTest(const char *a_szCmd)
{
	TSM_HTCM hTpm;
	UINT32 uiResultLen;
	BYTE *pResult;
	int iRc = -1;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if ((!resultFlag) && (selfTestFull(hTpm) != TSM_SUCCESS))
		goto out_close;

	if (selfTestResult(hTpm, &uiResultLen, &pResult) != TSM_SUCCESS)
		goto out_close;
	logMsg(_("  TCM Test Results: "));
	logHex(uiResultLen, pResult);

	iRc = 0;
	logSuccess(a_szCmd);

      out_close:
	contextClose(hContext);

      out:
	return iRc;
}

void selftestUsage(const char *a_szCmd)
{
	logCmdHelp(a_szCmd);
	logCmdOption("-r, --results", _("Report results of last test without retesting."));
}

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 'r':
		logDebug(_("Results only\n"));
		resultFlag = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}


int main(int argc, char *argv[])
{
	int rc;
	struct option opts[] = {
		{"results", no_argument, NULL, 'r'},
	};

        initIntlSys();

	rc = genericOptHandler(argc, argv, "r", opts,
			       sizeof(opts) / sizeof(struct option), parse,
			       selftestUsage);
	if (rc)
		exit(0);

	rc = cmdSelfTest(argv[0]);

	return rc;
}
