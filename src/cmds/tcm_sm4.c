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
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "tcm_seal.h"
#include "tcm_tspi.h"
#include "tcm_utils.h"

static char in_filename[PATH_MAX] = "",out_filename[PATH_MAX] = "";
static char IV[256] = "0000000000000000";
static BOOL passUnicode = FALSE;
static BOOL isWellKnown = FALSE;
static BOOL ENC_DEC = TRUE;
TSM_HCONTEXT hContext = 0;
TSM_HTCM hTpm;

#define DATA_DEFAULT_SIZE 1024

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logCmdOption("-i, --infile FILE",
		     _
		     ("ENC/DEC Filename to read . Default is STDIN."));
	logCmdOption("-o, --outfile FILE",
		     _
		     ("ENC/DEC Filename to write . Default is STDOUT."));
	logCmdOption("-v, --sm4 iv 16B",
		     _
		     ("SM4 CBC IV is 16B.  Default is 0000000000000000."));
	logCmdOption("-e, --sm4 enc ",_("SM4 CBC ENC .  Default value."));
	logCmdOption("-d, --sm4 dec ",_("SM4 CBC DEC ."));
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
	case 'o':
		if (aArg) {
			strncpy(out_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'v':
		if (aArg && strlen(aArg) == 16) {
			strncpy(IV, aArg, 16);
			rc = 0;
		}
		break;
	case 'e':
		ENC_DEC = TRUE;
		rc = 0;
		break;
	case 'd':
		ENC_DEC = FALSE;
		rc = 0;
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

static int writeKeyAndEnc(char *keyblob,UINT32 keylen,char *encdata,UINT32 encLen)
{
	//char *reallocdata = NULL;UINT32 realloclen = 0;
	//char line[1024] = {0};UINT32 linelen = 0;
	BIO *boutdata = NULL, *bout64=NULL;
	int r = -1;

	if ((bout64 = BIO_new(BIO_f_base64())) == NULL) {
		goto out;
	}

	if ((boutdata = BIO_new(BIO_s_file())) == NULL) {
		goto out;
	}

	if (strlen(out_filename) == 0)
		BIO_set_fp(boutdata, stdout, BIO_NOCLOSE);
	else if (BIO_write_filename(boutdata, out_filename) <= 0) {
		logError(_("Unable to open output file: %s\n"),out_filename);
		goto out;
	}

	BIO_puts(boutdata, TCMSEAL_HDR_STRING);

	{
		BIO_puts(boutdata, TCMSEAL_TSM_STRING);

		boutdata = BIO_push(bout64, boutdata);
		BIO_write(boutdata, keyblob, keylen);
		if (BIO_flush(boutdata) != 1) {
			logError(_("Unable to flush KEY output file: %s\n"),out_filename);
			goto out;
		}
		boutdata = BIO_pop(bout64);
	}

	{
		BIO_puts(boutdata, TCMSEAL_ENC_STRING);

		boutdata = BIO_push(bout64, boutdata);
		BIO_write(boutdata, encdata, encLen);
		if (BIO_flush(boutdata) != 1) {
			logError(_("Unable to flush ENC output file: %s\n"),out_filename);
			goto out;
		}
		boutdata = BIO_pop(bout64);
	}

	BIO_puts( boutdata, TCMSEAL_FTR_STRING);

	r = 0;
out:
	if (boutdata)
		BIO_free(boutdata);
	if (bout64)
		BIO_free(bout64);
	return r;
}

static int loadKeyAndEnc(char **keyblob,UINT32 *keylen,char **enctodata,UINT32 *encLen)
{
	char *reallocdata = NULL;UINT32 realloclen = 0;
	char line[1024] = {0};UINT32 linelen = 0;
	BIO *bindata = NULL, *bin64=NULL, *binmem = NULL;
	struct stat stats;
	int r = -1;

	if ((r= stat(in_filename, &stats))) {
		logError(_("%s is not exit.\n"),in_filename);
		goto out;
	}	

	r = -1;
	if((bindata = BIO_new_file(in_filename, "r")) == NULL ) {
		goto out;
	}

	BIO_gets(bindata, line, sizeof(line));
	if (strncmp(line, TCMSEAL_HDR_STRING, strlen(TCMSEAL_HDR_STRING)) != 0) {
		goto out;
	}		

	BIO_gets(bindata, line, sizeof(line));
	if (strncmp(line, TCMSEAL_TSM_STRING, strlen(TCMSEAL_TSM_STRING)) != 0) {
		goto out;
	}

	if ((binmem = BIO_new(BIO_s_mem())) == NULL) {
		goto out;
	}
	BIO_set_mem_eof_return(binmem, 0);

	{
		r = -1;
		while ((linelen = BIO_gets(bindata, line, sizeof(line))) > 0) {
			if (strncmp(line, TCMSEAL_ENC_STRING,strlen(TCMSEAL_ENC_STRING)) == 0)
				break;

			if (BIO_write(binmem, line, linelen) <= 0) {
				goto out;
			}
		}

		if (strncmp(line, TCMSEAL_ENC_STRING, strlen(TCMSEAL_ENC_STRING)) != 0 ) {
			goto out;
		}

		if ((bin64 = BIO_new(BIO_f_base64())) == NULL) {
			goto out;
		}

		binmem = BIO_push(bin64, binmem);
		while ((linelen = BIO_read(binmem, line, sizeof(line))) > 0) {
			if ((*keylen + linelen) > realloclen) {
				realloclen += DATA_DEFAULT_SIZE;
				reallocdata = realloc( *keyblob, realloclen);
				if ( reallocdata == NULL ) {
					goto out;
				}
				*keyblob = reallocdata;
			}
			memcpy(*keyblob + *keylen, line, linelen);
			*keylen += linelen;
		}
		binmem = BIO_pop(bin64);
		BIO_free(bin64);
		bin64 = NULL;
		realloclen = 0;
		reallocdata = NULL;
		r = BIO_reset(binmem);
		if (r != 1) {
			goto out;
		}
	}

	{
		r = -1;
		while ((linelen = BIO_gets(bindata, line, sizeof(line))) > 0) {
			if (strncmp(line, TCMSEAL_FTR_STRING,strlen(TCMSEAL_FTR_STRING)) == 0)
				break;

			if (BIO_write(binmem, line, linelen) <= 0) {
				goto out;
			}
		}
		if (strncmp(line, TCMSEAL_FTR_STRING, strlen(TCMSEAL_FTR_STRING)) != 0 ) {
			goto out;
		}

		if ((bin64 = BIO_new(BIO_f_base64())) == NULL) {
			goto out;
		}

		binmem = BIO_push( bin64, binmem );
		while ((linelen = BIO_read(binmem, line, sizeof(line))) > 0) {
			if ((*encLen + linelen) > realloclen) {
				realloclen += DATA_DEFAULT_SIZE;
				reallocdata = realloc( *enctodata, realloclen);
				if ( reallocdata == NULL ) {
					goto out;
				}
				*enctodata = reallocdata;
			}
			memcpy(*enctodata + *encLen, line, linelen);
			*encLen += linelen;
		}
		binmem = BIO_pop(bin64);
		BIO_free(bin64);
		bin64 = NULL;
		realloclen = 0;
		reallocdata = NULL;
		r = BIO_reset(binmem);
		if (r != 1) {
			goto out;
		}
	}

	r = 0;

out:
	if(bindata)
		BIO_free(bindata);
	if(bin64)
		BIO_free(bin64);
	if (binmem) {
		BIO_set_close(binmem, BIO_CLOSE);
		BIO_free(binmem);
	}
	return r;
}

static int decrypt(void)
{
	int r = -1, i = 0;
	TSM_HKEY hSrk, hKey;
	TSM_HPOLICY hPolicy, hSrkPolicy;
	char *keyblob = NULL;UINT32 keylen = 0;
	char *enctodata = NULL;UINT32 encLen = 0;
	char *data = NULL;UINT32 datalen = 0;
	char *passwd = NULL; UINT32 pswd_len = 0;
	char wellKnown[TCPA_SM3_256_HASH_LEN] = TSM_WELL_KNOWN_SECRET;
	FILE *outfp;

	if((r = loadKeyAndEnc(&keyblob, &keylen, &enctodata, &encLen)) < 0)
		goto out_close;

	r = -1;
	if (keyLoadKeyByUUID(hContext, TSM_PS_TYPE_SYSTEM, SRK_UUID, &hSrk)
	    != TSM_SUCCESS)
		goto out_close;

	if (policyGet(hSrk, &hSrkPolicy) != TSM_SUCCESS)
		goto out_close;

	if (!isWellKnown) {
		passwd = _GETPASSWD(_("Enter SRK password: "), (int *)&pswd_len, FALSE,
				    passUnicode);
		if (!passwd) {
			logError(_("Failed to get SRK password\n"));
			goto out_close;
		}
	} else {
		passwd = (char *)wellKnown;
		pswd_len = sizeof(wellKnown);
	}

	if (policySetSecret(hSrkPolicy, (UINT32)pswd_len, (BYTE *)passwd) != TSM_SUCCESS)
		goto out_close;

	if (!isWellKnown)
		shredPasswd(passwd);
	passwd = NULL;

	if (keyLoadKeybyBlob(hContext, hSrk, keylen, (BYTE*)keyblob, &hKey) != TSM_SUCCESS)
		goto out_close;

	if (contextCreateObject
	    (hContext, TSM_OBJECT_TYPE_POLICY, TSM_POLICY_USAGE,
	     &hPolicy) != TSM_SUCCESS)
		goto out_close;

	if (policySetSecret(hPolicy, strlen(TCMSEAL_SECRET), (BYTE *)TCMSEAL_SECRET)
	    != TSM_SUCCESS)
		goto out_close;

	if (policyAssign(hPolicy, hKey) != TSM_SUCCESS)
		goto out_close;

	if(sm4Decrypt(hTpm, hKey, (BYTE*)IV, encLen, (BYTE*)enctodata, &datalen, (BYTE**)&data) != TSM_SUCCESS){
		logError(_("Unable to Decrypt input file by SM4: %s\n"),in_filename);
		goto out_close;
	}

	{
		if (strlen(out_filename) == 0) {
			for (i=0; i < datalen; i++)
				printf("%c", data[i]);
			goto out_close;
		} else if ((outfp = fopen(out_filename, "w")) == NULL) {
				logError(_("Unable to open output file %s.\n"),out_filename);
				goto out_close;
		}

		if (fwrite(data, datalen, 1, outfp) != 1) {
			logError(_("Unable to write output file %s.\n"),out_filename);
			goto out_close;
		}
		fclose(outfp);
		outfp = NULL;
	}

	r = 0;
out_close:
	if (keyblob)
		free(keyblob);
	if (enctodata)
		free(enctodata);
	if (outfp)
		free(outfp);
	if (!isWellKnown && passwd != NULL)
		shredPasswd(passwd);
	return r;
}

static int encrypt(void)
{
	int r = -1;
	TSM_HKEY hSrk, hKey;
	TSM_HPOLICY hPolicy, hSrkPolicy;
	char *reallocdata = NULL;UINT32 realloclen = 0;
	char line[1024] = {0};UINT32 linelen = 0;
	char *data = NULL;UINT32 datalen = 0;
	char *keyblob = NULL;UINT32 keylen = 0;
	char *encdata = NULL;UINT32 enclen = 0;
	BIO *bin = NULL;
	char *passwd = NULL; UINT32 pswd_len = 0;
	char wellKnown[TCPA_SM3_256_HASH_LEN] = TSM_WELL_KNOWN_SECRET;
	TSM_FLAG keyFlags = TSM_KEY_TYPE_SM4 | TSM_KEY_SIZE_2048 | 
			TSM_KEY_VOLATILE | TSM_KEY_AUTHORIZATION | TSM_KEY_NOT_MIGRATABLE;

	if (keyLoadKeyByUUID(hContext, TSM_PS_TYPE_SYSTEM, SRK_UUID, &hSrk)
	    != TSM_SUCCESS)
		goto out_close;

	if (policyGet(hSrk, &hSrkPolicy) != TSM_SUCCESS)
		goto out_close;

	if (!isWellKnown) {
		passwd = _GETPASSWD(_("Enter SRK password: "), (int *)&pswd_len, FALSE,
				    passUnicode);
		if (!passwd) {
			logError(_("Failed to get SRK password\n"));
			goto out_close;
		}
	} else {
		passwd = (char *)wellKnown;
		pswd_len = sizeof(wellKnown);
	}

	if (policySetSecret(hSrkPolicy, (UINT32)pswd_len, (BYTE *)passwd) != TSM_SUCCESS)
		goto out_close;

	if (!isWellKnown)
		shredPasswd(passwd);
	passwd = NULL;

	if (contextCreateObject
	    (hContext, TSM_OBJECT_TYPE_KEY, keyFlags,
	     &hKey) != TSM_SUCCESS)
		goto out_close;

	if (contextCreateObject
	    (hContext, TSM_OBJECT_TYPE_POLICY, TSM_POLICY_USAGE,
	     &hPolicy) != TSM_SUCCESS)
		goto out_close;

	if (policySetSecret(hPolicy, strlen(TCMSEAL_SECRET), (BYTE *)TCMSEAL_SECRET)
	    != TSM_SUCCESS)
		goto out_close;

	if (policyAssign(hPolicy, hKey) != TSM_SUCCESS)
		goto out_close;

	if (keyCreateKey(hKey, hSrk, NULL_HKEY) != TSM_SUCCESS)
		goto out_close;

	if (keyLoadKey(hKey, hSrk) != TSM_SUCCESS)
		goto out_close;

	{
		if ((bin = BIO_new(BIO_s_file())) == NULL) {
			goto out_close;
		}

		if (strlen(in_filename) == 0) 
			BIO_set_fp(bin, stdin, BIO_NOCLOSE);
		else if (!BIO_read_filename(bin, in_filename)) {
			logError(_("Unable to open input file: %s\n"),in_filename);
			goto out_close;
		}

		while ((linelen = BIO_read(bin, line, sizeof(line))) > 0) {
			if ((datalen + linelen) > realloclen) {
				realloclen += DATA_DEFAULT_SIZE;
				reallocdata = realloc(data, realloclen);
				if (reallocdata == NULL) {
					logError(_("Unable to realloc\n"));
					goto out_close;
				}
				data = reallocdata;
			}
			memcpy(data + datalen, line, linelen);
			datalen += linelen;
		}
	}

	if(sm4Encrypt(hTpm, hKey, (BYTE*)IV, datalen, (BYTE*)data, &enclen, (BYTE**)&encdata) != TSM_SUCCESS){
		logError(_("Unable to Encrypt input file by SM4: %s\n"),in_filename);
		goto out_close;
	}

	if (getAttribData
	    (hKey, TSM_TSPATTRIB_KEY_BLOB, TSM_TSPATTRIB_KEYBLOB_BLOB,
	     &keylen, (BYTE**)&keyblob) != TSM_SUCCESS)
		goto out_close;

	r = writeKeyAndEnc(keyblob, keylen, encdata, enclen);

out_close:
	if (bin)
		BIO_free(bin);
	if (data)
		free(data);
	if (!isWellKnown && passwd != NULL)
		shredPasswd(passwd);
	return r;
}

int main(int argc, char **argv)
{
	int r = -1;
	struct option opts[] =
	{ 
	   {"infile", required_argument, NULL, 'i'},
	   {"outfile", required_argument, NULL, 'o'},
	   {"IV", no_argument, NULL, 'v'},
	   {"Encrypt", no_argument, NULL, 'e'},
	   {"Decrypt", no_argument, NULL, 'd'},	   
	   {"unicode", no_argument, NULL, 'u'},
	   {"well-known", no_argument, NULL, 'z'}
	};

	initIntlSys();

	if (genericOptHandler(argc, argv, "i:o:v:eduz", opts, sizeof(opts) / sizeof(struct option), parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSM_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSM_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSM_SUCCESS)
		goto out_close;

	if(ENC_DEC)
		r = encrypt();
	else
		r = decrypt();

	logSuccess(argv[0]);
out_close:
	contextClose(hContext);
out:
	return r;
}
