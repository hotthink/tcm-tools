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

TSM_HCONTEXT hContext = 0;

#ifdef TSM_LIB_IS_12
#include <limits.h>

//Controled by input options
static char in_filename[PATH_MAX] = "", out_filename[PATH_MAX] = "";
static BOOL isRevocable = FALSE;
static BOOL needGenerateSecret = FALSE;
static BOOL inFileSet = FALSE;
static BOOL outFileSet = FALSE;

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logCmdOption("-r, --revocable",
		     _("Creates a revocable EK instead of the default non-revocable one. Requires [-g -o] or [-i]"));
	logCmdOption("-i, --infile FILE",
		     _("Filename containing the secret data used to revoke the EK."));
	logCmdOption("-g, --generate-secret",
		     _("Generates a 32 Bytes secret that is used to revoke the EK. Requires [-o]"));
	logCmdOption("-o, --outfile FILE",
		     _("Filename to write the secret data generated to revoke the EK."));

}

static int parse(const int aOpt, const char *aArg)
{
	switch (aOpt){
	case 'r':
		isRevocable = TRUE;
		break;
	case 'g':
		needGenerateSecret = TRUE;
		break;
	case 'i':
		inFileSet = TRUE;
		if (aArg){
			strncpy(in_filename, aArg, PATH_MAX);
		}
		break;
	case 'o':
		outFileSet = TRUE;
		if (aArg){
			strncpy(out_filename, aArg, PATH_MAX);
		}
		break;
	default:
		return -1;
	}
	return 0;

}

static TSM_RESULT
tpmCreateRevEk(TSM_HTCM a_hTpm, TSM_HKEY a_hKey,
	    TSM_VALIDATION * a_pValData, UINT32 *revDataSz, BYTE **revData)
{
	TSM_RESULT result = Tspi_TCM_CreateRevocableEndorsementKey(a_hTpm, a_hKey,
	a_pValData, revDataSz, revData);
	tspiResult("Tspi_TCM_CreateRevocableEndorsementKey", result);
	return result;
}

static int readData(UINT32 bytesToRead, BYTE **buffer)
{
	FILE *infile = NULL;
	size_t iBytes;
	int rc = 0;
	BYTE eofile;

	__memset(*buffer, 0x00, bytesToRead);
	infile = fopen(in_filename, "r");
	if ( !infile ){
		logError(_("Unable to open input file: %s\n"),
				in_filename);
		return -1;
	}

	//Read the data
	iBytes = fread( *buffer, 1, bytesToRead, infile );
	if ( iBytes < bytesToRead ) {
		logError(_("Error: the secret data file %s contains less than %d bytes. Aborting ...\n"),
				in_filename, bytesToRead);
		rc = -1;
	} else if ( (iBytes = fread( &eofile, 1, 1, infile )) ) {
		//Test if there's more than 32 bytes
		if ( !feof( infile))
			logMsg(_("WARNING: Using only the first %d bytes of file %s for secret data\n"),
					bytesToRead, in_filename);
	} else {
		logDebug(_("Read %d bytes of secret data from file %s.\n"),
			 bytesToRead, in_filename);
	}

	fclose( infile);
	return rc;
}

static int writeData(UINT32 bytesToWrite, BYTE *buffer)
{
	FILE *outfile = NULL;
	size_t iBytes;
	int rc = 0;

	logDebug(_("bytesToWrite: %d\n"), bytesToWrite);
	outfile = fopen(out_filename, "w");
	if ( !outfile ) {
		logError(_("Unable to open output file: %s\n"), out_filename);
		return -1;
	}

	//Write data in buffer
	iBytes = fwrite( buffer, 1, bytesToWrite, outfile);
	if ( iBytes != bytesToWrite ) {
		logError(_("Error: Unable to write %d bytes on the file %s.\n"),
				 bytesToWrite, out_filename);
		rc = -1;
	}

	logDebug(_("%zd bytes written on file %s.\n"), iBytes, out_filename);
	fclose( outfile );
	return rc;

}
#endif

static TSM_RESULT
tpmCreateEk(TSM_HTCM a_hTpm, TSM_HKEY a_hKey,
	    TSM_VALIDATION * a_pValData)
{

	TSM_RESULT result = Tspi_TCM_CreateEndorsementKey(a_hTpm, a_hKey,
			 a_pValData);
	tspiResult("Tspi_TCM_CreateEndorsementKey", result);
	return result;
}

int main(int argc, char **argv)
{
	TSM_RESULT tResult;
	TSM_HTCM hTpm;
	TSM_HKEY hEk;
	TSM_FLAG fEkAttrs;
	int iRc = -1;

#ifdef TSM_LIB_IS_12
	struct option opts[] = {{"revocable", no_argument, NULL, 'r'},
	{"generate-secret", no_argument, NULL, 'g'},
	{"infile", required_argument, NULL, 'i'},
	{"outfile", required_argument, NULL, 'o'},
	};
	UINT32 revDataSz;
	BYTE revokeData[TCM_SM3BASED_NONCE_LEN];
	BYTE *pRevData;
#endif

	initIntlSys();

#ifdef TSM_LIB_IS_12
	if (genericOptHandler(argc, argv, "rgi:o:", opts, sizeof(opts) / sizeof(struct option),
			      parse, help) != 0)
		goto out;

	//Check commands for command hierarchy
	if (isRevocable) {
		if (needGenerateSecret) {
			if (!outFileSet) {
				logError(_("Please specify an output file\n"));
				goto out;
			}
			if (inFileSet) {
				logError(_("The option -i, --infile is not valid with -g\n"));
				goto out;
			}
		} else if (!inFileSet) {
			logError(_("Please specify -i, --infile or -g, --generate-secret\n"));
			goto out;
		} else if (outFileSet) {
			logError(_("The option -o, --outfile is not valid with -i, --infile"));
			goto out;
		}
	}
	logDebug("Input file name: %s\n", in_filename);
	logDebug("Output file name: %s\n", out_filename);

	if (inFileSet) {
		pRevData = revokeData;
		revDataSz = sizeof(revokeData);
		if (readData(revDataSz, &pRevData))
			goto out;
	} else if (outFileSet) {
		FILE *outfile = fopen(out_filename, "w");
		if (!outfile) {
			iRc = -1;
			logError(_("Unable to open output file: %s\n"), out_filename);
			goto out;
		}
		fclose(outfile);

		//TCM should generate the revoke data
		revDataSz = 0;
		pRevData = NULL;
	}
#else
	if (genericOptHandler(argc, argv, NULL, NULL, 0, NULL, NULL) != 0){
		logError(_("See man pages for details.\n"));
		goto out;
	}
#endif

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	//Initialize EK attributes here
	fEkAttrs = TSM_KEY_SIZE_2048 | TSM_KEY_TYPE_LEGACY;
	if (contextCreateObject(hContext, TSM_OBJECT_TYPE_KEY, fEkAttrs, &hEk) != TSM_SUCCESS)
		goto out_close;

#ifdef TSM_LIB_IS_12
	if (isRevocable){
		tResult = tpmCreateRevEk(hTpm, hEk, NULL, &revDataSz, &pRevData);
		if (tResult != TSM_SUCCESS)
			goto out_close;
		//Writes the generated secret into the output file
		if (outFileSet) {
			if (writeData(revDataSz, pRevData)) {
				logError(_("Creating revocable EK succeeded, but writing the EK "
					   "revoke authorization to disk failed.\nPrinting the "
					   "revoke authorization instead:\n"));
				logHex(revDataSz, pRevData);
				logError(_("You should record this data, as its the authorization "
					   "you'll need to revoke your EK!\n"));
				goto out_close;
			}
		}
	} else
#endif
		tResult = tpmCreateEk(hTpm, hEk, NULL);
	if (tResult != TSM_SUCCESS)
		goto out_close;

	iRc = 0;
	logSuccess(argv[0]);

      out_close:
	contextClose(hContext);

      out:
	return iRc;
}
