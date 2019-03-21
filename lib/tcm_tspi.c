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

TSM_UUID SRK_UUID = TSM_UUID_SRK;
extern TSM_HCONTEXT hContext;

const char *mapUnknown = "Unknown";

const char *usageSigning = "Signing";
const char *usageStorage = "Storage";
const char *usageIdentity = "Identity";
const char *usageAuthChange = "AuthChange";
const char *usageBind = "Bind";
const char *usageLegacy = "Legacy";

const int flagMax = 7;
const char *flagMap[] = {
	"!VOLATILE, !MIGRATABLE, !REDIRECTION",
	"!VOLATILE, !MIGRATABLE,  REDIRECTION",
	"!VOLATILE,  MIGRATABLE, !REDIRECTION",
	"!VOLATILE,  MIGRATABLE,  REDIRECTION",
	" VOLATILE, !MIGRATABLE, !REDIRECTION",
	" VOLATILE, !MIGRATABLE,  REDIRECTION",
	" VOLATILE,  MIGRATABLE, !REDIRECTION",
	" VOLATILE,  MIGRATABLE,  REDIRECTION",
};

const char *authUsageNever = "Never";
const char *authUsageAlways = "Always";

const char *algRsa = "RSA";
const char *algDes = "DES";
const char *alg3Des = "3DES";
const char *algSha = "SHA";
const char *algHmac = "HMAC";
const char *algAes = "AES";

const char *encNone = "None";
const char *encRsaPkcs15 = "RSAESPKCSv15";
const char *encRsaOaepSha1Mgf1 = "RSAESOAEP_SHA1_MGF1";

const char *sigNone = "None";
const char *sigRsaPkcs15Sha1 = "RSASSAPKCS1v15_SHA1";
const char *sigRsaPkcs15Der = "RSASSAPKCS1v15_DER";


const char *displayKeyUsageMap(UINT32 a_uiData)
{

	switch (a_uiData) {
	case TSM_KEYUSAGE_SIGN:
		return usageSigning;

	case TSM_KEYUSAGE_STORAGE:
		return usageStorage;

	case TSM_KEYUSAGE_IDENTITY:
		return usageIdentity;

	case TSM_KEYUSAGE_AUTHCHANGE:
		return usageAuthChange;

	case TSM_KEYUSAGE_BIND:
		return usageBind;

	case TSM_KEYUSAGE_LEGACY:
		return usageLegacy;
	}

	return mapUnknown;
}

const char *displayKeyFlagsMap(UINT32 a_uiFlags)
{

	int iPos = a_uiFlags & flagMax;

	return flagMap[iPos];
}

const char *displayAuthUsageMap(UINT32 a_uiData)
{

	switch (a_uiData) {
	case TCM_AUTH_NEVER:
		return authUsageNever;

	case TCM_AUTH_ALWAYS:
		return authUsageAlways;
	}

	return mapUnknown;
}

const char *displayAlgorithmMap(UINT32 a_uiData)
{

	switch (a_uiData) {
	case TSM_ALG_RSA:
		return algRsa;

	case TSM_ALG_DES:
		return algDes;

	case TSM_ALG_3DES:
		return alg3Des;

	case TSM_ALG_SHA:
		return algSha;

	case TSM_ALG_HMAC:
		return algHmac;

	case TSM_ALG_AES:
		return algAes;
	}

	return mapUnknown;
}

const char *displayEncSchemeMap(UINT32 a_uiData)
{

	switch (a_uiData) {
	case TSM_ES_NONE:
		return encNone;

	case TSM_ES_RSAESPKCSV15:
		return encRsaPkcs15;

	case TSM_ES_RSAESOAEP_SHA1_MGF1:
		return encRsaOaepSha1Mgf1;
	}

	return mapUnknown;
}

const char *displaySigSchemeMap(UINT32 a_uiData)
{

	switch (a_uiData) {
	case TSM_SS_NONE:
		return sigNone;

	case TSM_SS_RSASSAPKCS1V15_SHA1:
		return sigRsaPkcs15Sha1;

	case TSM_SS_RSASSAPKCS1V15_DER:
		return sigRsaPkcs15Der;
	}

	return mapUnknown;
}

TSM_RESULT displayKey(TSM_HKEY a_hKey)
{

	TSM_RESULT result;
	UINT32 uiAttr, uiAttrSize;
	BYTE *pAttr;
	UINT32 uiAlg;

	result =
	    getAttribData(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			  TSM_TSPATTRIB_KEYINFO_VERSION, &uiAttrSize,
			  &pAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Version:   "));
	logHex(uiAttrSize, pAttr);

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_USAGE, &uiAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Usage:     0x%04x (%s)\n"), uiAttr, displayKeyUsageMap(uiAttr));

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_KEYFLAGS, &uiAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Flags:     0x%08x (%s)\n"), uiAttr, displayKeyFlagsMap(uiAttr));

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_AUTHUSAGE, &uiAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  AuthUsage: 0x%02x (%s)\n"), uiAttr, displayAuthUsageMap(uiAttr));

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_ALGORITHM, &uiAlg);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Algorithm:         0x%08x (%s)\n"), uiAlg, displayAlgorithmMap(uiAlg));

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_ENCSCHEME, &uiAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Encryption Scheme: 0x%08x (%s)\n"), uiAttr, displayEncSchemeMap(uiAttr));

	result =
	    getAttribUint32(a_hKey, TSM_TSPATTRIB_KEY_INFO,
			    TSM_TSPATTRIB_KEYINFO_SIGSCHEME, &uiAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Signature Scheme:  0x%08x (%s)\n"), uiAttr, displaySigSchemeMap(uiAttr));

	if (uiAlg == TSM_ALG_RSA) {
		result =
		    getAttribUint32(a_hKey, TSM_TSPATTRIB_RSAKEY_INFO,
				    TSM_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
				    &uiAttr);
		if (result != TSM_SUCCESS)
			return result;
		logMsg(_("  Key Size:          %d bits\n"), uiAttr);
	}

	result =
	    getAttribData(a_hKey, TSM_TSPATTRIB_RSAKEY_INFO,
			  TSM_TSPATTRIB_KEYINFO_RSA_MODULUS, &uiAttrSize,
			  &pAttr);
	if (result != TSM_SUCCESS)
		return result;
	logMsg(_("  Public Key:"));
	logHex(uiAttrSize, pAttr);

	return result;
}

/*
 * Not always reliable as this depends on the TSM system.data being intact
 */
BOOL isTpmOwned(TSM_HCONTEXT hContext)
{

	TSM_HKEY hSrk;
	BOOL iRc = FALSE;

	if (keyGetKeyByUUID(hContext, TSM_PS_TYPE_SYSTEM, SRK_UUID, &hSrk)
	    != TSM_SUCCESS)
		goto out;

	iRc = TRUE;

      out:
	return iRc;
}

void tspiDebug(const char *a_szName, TSM_RESULT a_iResult)
{

	logDebug(_("%s success\n"), a_szName);
}

void tspiError(const char *a_szName, TSM_RESULT a_iResult)
{

	logError(_("%s failed: 0x%08x - layer=%s, code=%04x (%d), %s\n"),
		 a_szName, a_iResult, Trspi_Error_Layer(a_iResult),
		 Trspi_Error_Code(a_iResult),
		 Trspi_Error_Code(a_iResult),
		 Trspi_Error_String(a_iResult));
}

void tspiResult(const char *a_szName, TSM_RESULT a_tResult)
{

	if (a_tResult == TSM_SUCCESS)
		tspiDebug(a_szName, a_tResult);
	else
		tspiError(a_szName, a_tResult);
}

BOOL mapTssBool(TSM_BOOL a_bValue)
{
	BOOL bRc;

	bRc = a_bValue ? TRUE : FALSE;

	return bRc;
}

TSM_RESULT contextCreate(TSM_HCONTEXT * a_hContext)
{
	TSM_RESULT result = Tspi_Context_Create(a_hContext);
	tspiResult("Tspi_Context_Create", result);

	return result;
}

TSM_RESULT contextClose(TSM_HCONTEXT a_hContext)
{

	TSM_RESULT result = Tspi_Context_FreeMemory(a_hContext, NULL);
	tspiResult("Tspi_Context_FreeMemory", result);

	result = Tspi_Context_Close(a_hContext);
	tspiResult("Tspi_Context_Close", result);

	return result;
}

TSM_RESULT contextConnect(TSM_HCONTEXT a_hContext)
{

	TSM_RESULT result = Tspi_Context_Connect(a_hContext, NULL);
	tspiResult("Tspi_Context_Connect", result);

	return result;
}


TSM_RESULT
contextCreateObject(TSM_HCONTEXT a_hContext,
		    TSM_FLAG a_fType,
		    TSM_FLAG a_fAttrs, TSM_HOBJECT * a_hObject)
{
	TSM_RESULT result =
	    Tspi_Context_CreateObject(a_hContext, a_fType, a_fAttrs,
				      a_hObject);
	tspiResult("Tspi_Context_CreateObject", result);

	return result;
}

TSM_RESULT
contextCloseObject(TSM_HCONTEXT a_hContext, TSM_HOBJECT a_hObject)
{
	TSM_RESULT result =
	    Tspi_Context_CloseObject(a_hContext, a_hObject);
	tspiResult("Tspi_Context_CloseObject", result);

	return result;
}

TSM_RESULT contextGetTpm(TSM_HCONTEXT a_hContext, TSM_HTCM * a_hTpm)
{

	TSM_RESULT result = Tspi_Context_GetTpmObject(a_hContext, a_hTpm);
	tspiResult("Tspi_Context_GetTpmObject", result);

	return result;
}


TSM_RESULT policyGet(TSM_HOBJECT a_hObject, TSM_HPOLICY * a_hPolicy)
{
	TSM_RESULT result =
	    Tspi_GetPolicyObject(a_hObject, TSM_POLICY_USAGE, a_hPolicy);
	tspiResult("Tspi_GetPolicyObject", result);

	return result;
}

TSM_RESULT policyAssign(TSM_HPOLICY a_hPolicy, TSM_HOBJECT a_hObject)
{
	TSM_RESULT result =
	    Tspi_Policy_AssignToObject(a_hPolicy, a_hObject);
	tspiResult("Tspi_Policy_AssignToObject", result);

	return result;
}

TSM_RESULT
policySetSecret(TSM_HPOLICY a_hPolicy,
		UINT32 a_uiSecretLen, BYTE * a_chSecret)
{
	TSM_RESULT result;
	BYTE wellKnown[] = TSM_WELL_KNOWN_SECRET;

	//If secret is TSM_WELL_KNOWN_SECRET, change secret mode to TSM_SECRET_MODE_SM3
	if (a_chSecret &&
	    a_uiSecretLen == sizeof(wellKnown) &&
	    !memcmp(a_chSecret, (BYTE *)wellKnown, sizeof(wellKnown)))
		result =
			Tspi_Policy_SetSecret(a_hPolicy, TSM_SECRET_MODE_SM3,
					a_uiSecretLen, a_chSecret);
	else
		result =
			Tspi_Policy_SetSecret(a_hPolicy, TSM_SECRET_MODE_PLAIN,
					a_uiSecretLen, a_chSecret);
	tspiResult("Tspi_Policy_SetSecret", result);

	return result;
}

TSM_RESULT policyFlushSecret(TSM_HPOLICY a_hPolicy)
{
	TSM_RESULT result = Tspi_Policy_FlushSecret(a_hPolicy);
	tspiResult("Tspi_Policy_FlushSecret", result);

	return result;
}

TSM_RESULT
tpmGetPubEk(TSM_HTCM a_hTpm,
	    TSM_BOOL a_fOwner,
	    TSM_VALIDATION * a_pValData, TSM_HKEY * a_phEPubKey)
{

	TSM_RESULT result = Tspi_TCM_GetPubEndorsementKey(a_hTpm, a_fOwner,
							  a_pValData,
							  a_phEPubKey);
	tspiResult("Tspi_TCM_GetPubEndorsementKey", result);

	return result;
}

TSM_RESULT
tpmSetStatus(TSM_HTCM a_hTpm, TSM_FLAG a_fStatus, TSM_BOOL a_bValue)
{

	TSM_RESULT result =
	    Tspi_TCM_SetStatus(a_hTpm, a_fStatus, a_bValue);
	tspiResult("Tspi_TCM_SetStatus", result);

	return result;
}

TSM_RESULT
tpmGetStatus(TSM_HTCM a_hTpm, TSM_FLAG a_fStatus, TSM_BOOL * a_bValue)
{

	TSM_RESULT result =
	    Tspi_TCM_GetStatus(a_hTpm, a_fStatus, a_bValue);
	tspiResult("Tspi_TCM_GetStatus", result);

	return result;
}

TSM_RESULT tpmGetRandom(TSM_HTCM a_hTpm, UINT32 a_length, BYTE ** a_data)
{

	TSM_RESULT result = Tspi_TCM_GetRandom(a_hTpm, a_length, a_data);
	tspiResult("Tspi_TCM_GetRandom", result);

	return result;
}


TSM_RESULT keyLoadKey(TSM_HKEY a_hKey, TSM_HKEY a_hWrapKey)
{

	TSM_RESULT result = Tspi_Key_LoadKey(a_hKey, a_hWrapKey);
	tspiResult("Tspi_Key_LoadKey", result);

	return result;
}

TSM_RESULT keyLoadKeybyBlob(TSM_HCONTEXT a_hContext,TSM_HKEY a_hKey, UINT32 keylen, BYTE * keyblob, TSM_HKEY* phWrapKey)
{

	TSM_RESULT result = Tspi_Context_LoadKeyByBlob(a_hContext, a_hKey, keylen, keyblob, phWrapKey);
	tspiResult("Tspi_Context_LoadKeyByBlob", result);

	return result;
}

TSM_RESULT
keyLoadKeyByUUID(TSM_HCONTEXT a_hContext,
		 TSM_FLAG a_fStoreType,
		 TSM_UUID a_uKeyId, TSM_HKEY * a_hKey)
{
	TSM_RESULT result =
	    Tspi_Context_LoadKeyByUUID(a_hContext, a_fStoreType, a_uKeyId,
				       a_hKey);
	tspiResult("Tspi_Context_LoadKeyByUUID", result);

	return result;
}

TSM_RESULT
keyGetPubKey(TSM_HKEY a_hKey, UINT32 * a_uiKeyLen, BYTE ** a_pKey)
{

	TSM_RESULT result = Tspi_Key_GetPubKey(a_hKey, a_uiKeyLen, a_pKey);
	tspiResult("Tspi_Key_GetPubKey", result);

	return result;
}

TSM_RESULT
keyGetKeyByUUID(TSM_HCONTEXT a_hContext,
		TSM_FLAG a_fStoreType,
		TSM_UUID a_uKeyId, TSM_HKEY * a_hKey)
{

	TSM_RESULT result =
	    Tspi_Context_GetKeyByUUID(a_hContext, a_fStoreType, a_uKeyId,
				      a_hKey);
	tspiResult("Tspi_Context_GetKeyByUUID", result);

	return result;
}

TSM_RESULT
getAttribData(TSM_HOBJECT a_hObject,
	      TSM_FLAG a_fAttr,
	      TSM_FLAG a_fSubAttr, UINT32 * a_uiSize, BYTE ** a_pData)
{

	TSM_RESULT result =
	    Tspi_GetAttribData(a_hObject, a_fAttr, a_fSubAttr, a_uiSize,
			       a_pData);
	tspiResult("Tspi_GetAttribData", result);

	return result;
}

TSM_RESULT
getAttribUint32(TSM_HOBJECT a_hObject,
		TSM_FLAG a_fAttr, TSM_FLAG a_fSubAttr, UINT32 * a_uiData)
{

	TSM_RESULT result =
	    Tspi_GetAttribUint32(a_hObject, a_fAttr, a_fSubAttr, a_uiData);
	tspiResult("Tspi_GetAttribUint32", result);

	return result;
}

TSM_RESULT
getCapability(TSM_HTCM a_hTpm,
	      TSM_FLAG a_fCapArea,
	      UINT32 a_uiSubCapLen,
	      BYTE * a_pSubCap, UINT32 * a_uiResultLen, BYTE ** a_pResult)
{
	TSM_RESULT result =
	    Tspi_TCM_GetCapability(a_hTpm, a_fCapArea, a_uiSubCapLen,
				   a_pSubCap, a_uiResultLen, a_pResult);
	tspiResult("Tspi_TCM_GetCapability", result);

	return result;
}

TSM_RESULT 
keyCreateKey(TSM_HKEY a_hKey, TSM_HKEY a_hWrapKey,
		TSM_HPCRS a_hPcrs)
{
	TSM_RESULT result = Tspi_Key_CreateKey(a_hKey, a_hWrapKey, a_hPcrs);
	tspiResult("Tspi_Key_CreateKey", result);

	return result;
}

TSM_RESULT dataSeal(TSM_HENCDATA a_hEncdata, TSM_HKEY a_hKey,
			UINT32 a_len, BYTE * a_data,
			TSM_HPCRS a_hPcrs)
{

	TSM_RESULT result =
		Tspi_Data_Seal(a_hEncdata, a_hKey, a_len, a_data, a_hPcrs);
	tspiResult("Tspi_Data_Seal", result);

	return result;
}

TSM_RESULT
tpmPcrRead(TSM_HTCM a_hTpm, UINT32 a_Idx,
		UINT32 *a_PcrSize, BYTE **a_PcrValue)
{
	TSM_RESULT result =
		Tspi_TCM_PcrRead(a_hTpm, a_Idx, a_PcrSize, a_PcrValue);
	tspiResult("Tspi_TCM_PcrRead", result);

	return result;
}

TSM_RESULT
pcrcompositeSetPcrValue(TSM_HPCRS a_hPcrs, UINT32 a_Idx,
			UINT32 a_PcrSize, BYTE *a_PcrValue)
{
	TSM_RESULT result =
		Tspi_PcrComposite_SetPcrValue(a_hPcrs, a_Idx, a_PcrSize, a_PcrValue);
	tspiResult("Tspi_PcrComposite_SetPcrValue", result);

	return result;
}

#ifdef TSM_LIB_IS_12
/*
 * These getPasswd functions will wrap calls to the other functions and check to see if the TSM
 * library's context tells us to remove the NULL terminating chars from the end of the password
 * when unicode is on.
 */
char *
getPasswd12(const char *a_pszPrompt, int* a_iLen, BOOL a_bConfirm)
{
	return _getPasswd12( a_pszPrompt, a_iLen, a_bConfirm, useUnicode);
}

char *_getPasswd12(const char *a_pszPrompt, int* a_iLen, BOOL a_bConfirm, BOOL a_bUseUnicode)
{
	UINT32 status;
	char *passwd;

	passwd = _getPasswd(a_pszPrompt, a_iLen, a_bConfirm, a_bUseUnicode);

	if (passwd && a_bUseUnicode) {
		/* If we're running against a 1.2 TSM, it will include the null terminating
		 * characters based on the TSM_TSPATTRIB_SECRET_HASH_MODE attribute of the
		 * context. If this is set to TSM_TSPATTRIB_HASH_MODE_NOT_NULL, we need to
		 * trim the two zeros off the end of the unicode string returned by
		 * Trspi_Native_To_UNICODE. */
		if (getAttribUint32(hContext, TSM_TSPATTRIB_SECRET_HASH_MODE,
				    TSM_TSPATTRIB_SECRET_HASH_MODE_POPUP, &status))
			goto out;

		if (status == TSM_TSPATTRIB_HASH_MODE_NOT_NULL)
			*a_iLen -= sizeof(TSM_UNICODE);
	}
out:
	return passwd;
}

TSM_RESULT
unloadVersionInfo(UINT64 *offset, BYTE *blob, TCM_CAP_VERSION_INFO *v)
{
	TSM_RESULT result = Trspi_UnloadBlob_CAP_VERSION_INFO(offset, blob, v);
	tspiResult("Trspi_UnloadBlob_CAP_VERSION_INFO", result);
	return result;
}

TSM_RESULT
pcrcompositeSetPcrLocality(TSM_HPCRS a_hPcrs, UINT32 localityValue)
{
	TSM_RESULT result =
		Tspi_PcrComposite_SetPcrLocality(a_hPcrs, localityValue);
	tspiResult("Tspi_PcrComposite_SetPcrLocality", result);

	return result;
}

TSM_RESULT
NVDefineSpace(TSM_HNVSTORE hNVStore, TSM_HPCRS hReadPcrComposite ,
              TSM_HPCRS hWritePcrComposite)
{
	TSM_RESULT result =
	        Tspi_NV_DefineSpace(hNVStore, hReadPcrComposite,
	                            hWritePcrComposite);

	tspiResult("Tspi_NV_DefineSpace", result);

	return result;
}

TSM_RESULT
NVReleaseSpace(TSM_HNVSTORE hNVStore)
{
	TSM_RESULT result =
	        Tspi_NV_ReleaseSpace(hNVStore);

	tspiResult("Tspi_NV_ReleaseSpace", result);

	return result;
}

TSM_RESULT
NVWriteValue(TSM_HNVSTORE hNVStore, UINT32 offset,
             UINT32 ulDataLength, BYTE *rgbDataToWrite)
{
	TSM_RESULT result =
	        Tspi_NV_WriteValue(hNVStore, offset,
	                           ulDataLength, rgbDataToWrite);

	tspiResult("Tspi_NV_WriteValue", result);

	return result;
}

TSM_RESULT
NVReadValue(TSM_HNVSTORE hNVStore, UINT32 offset,
            UINT32 *ulDataLength, BYTE **rgbDataRead)
{
	TSM_RESULT result =
	        Tspi_NV_ReadValue(hNVStore, offset,
	                          ulDataLength, rgbDataRead);

	tspiResult("Tspi_NV_ReadValue", result);

	return result;
}

TSM_RESULT
unloadNVDataPublic(UINT64 *offset, BYTE *blob, UINT32 blob_len, TCM_NV_DATA_PUBLIC *v)
{
	UINT64 off = *offset;
	TSM_RESULT result;
	result = Trspi_UnloadBlob_NV_DATA_PUBLIC(&off, blob, NULL);
	if (result == TSM_SUCCESS) {
		if (off > blob_len)
			return TSM_E_BAD_PARAMETER;
		result = Trspi_UnloadBlob_NV_DATA_PUBLIC(offset, blob, v);
	}
	tspiResult("Trspi_UnloadBlob_NV_DATA_PUBLIC", result);
	return result;
}

TSM_RESULT
sm3Start(TSM_HTCM a_hTpm, UINT32 * pUpdateLength)
{

	TSM_RESULT result =
	    Tspi_TCM_SM3Start(a_hTpm, pUpdateLength);
	tspiResult("Tspi_TCM_SM3Start", result);

	return result;
}

TSM_RESULT
sm3Update(TSM_HTCM a_hTpm, UINT32 dlen,	BYTE * datain)
{

	TSM_RESULT result =
	    Tspi_TCM_SM3Update(a_hTpm, dlen, datain);
	tspiResult("Tspi_TCM_SM3Update", result);

	return result;
}

TSM_RESULT
sm3Complete(TSM_HTCM a_hTpm, UINT32 dlen, BYTE * datain, BYTE * outDigest)
{

	TSM_RESULT result =
	    Tspi_TCM_SM3Complete(a_hTpm, dlen, datain, outDigest);
	tspiResult("Tspi_TCM_SM3Complete", result);

	return result;
}

TSM_RESULT
sm4Encrypt(TSM_HTCM a_hTpm, TSM_HKEY hKey, BYTE* IV,
	UINT32  dlen, BYTE* datain, UINT32* enclen, BYTE ** encdata)
{

	TSM_RESULT result =
	    Tspi_TCM_SMS4Encrypt(a_hTpm, hKey, IV, dlen, datain, enclen, encdata);
	tspiResult("Tspi_TCM_SMS4Encrypt", result);

	return result;
}

TSM_RESULT
sm4Decrypt(TSM_HTCM a_hTpm, TSM_HKEY hKey, BYTE* IV, 
	UINT32  enclen, BYTE* encdata, UINT32* dlen, BYTE ** dataout)
{

	TSM_RESULT result =
	    Tspi_TCM_SMS4Decrypt(a_hTpm, hKey, IV, enclen, encdata, dlen, dataout);
	tspiResult("Tspi_TCM_SMS4Decrypt", result);

	return result;
}


#endif
