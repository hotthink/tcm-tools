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

#ifndef __TCM_TSPI_H
#define __TCM_TSPI_H

#include <stdlib.h>
#include <tcms/tsm.h>
#include <tcms/tcms.h>
#include <tcm_utils.h>

extern TSM_UUID SRK_UUID;

#define NULL_HOBJECT 0
#define NULL_HKEY NULL_HOBJECT
#define NULL_HPCRS NULL_HOBJECT

//Display functions
const char *displayKeyUsageMap(UINT32 a_uiData);

const char *displayKeyFlagsMap(UINT32 a_uiFlags);

const char *displayAuthUsageMap(UINT32 a_uiData);

const char *displayAlgorithmMap(UINT32 a_uiData);

const char *displayEncSchemeMap(UINT32 a_uiData);

const char *displaySigSchemeMap(UINT32 a_uiData);

TSM_RESULT displayKey(TSM_HKEY a_hKey);

//Generic query functions
BOOL isTpmOwned(TSM_HCONTEXT hContext);

//TSPI logging functions
void tspiDebug(const char *a_szName, TSM_RESULT a_iResult);
void tspiError(const char *a_szName, TSM_RESULT a_iResult);
void tspiResult(const char *a_szName, TSM_RESULT a_tResult);

// Map a TSM_BOOL into a BOOL
BOOL mapTssBool(TSM_BOOL a_bValue);

//TSPI generic setup/teardown functions
TSM_RESULT contextCreate(TSM_HCONTEXT * a_hContext);
TSM_RESULT contextClose(TSM_HCONTEXT a_hContext);
TSM_RESULT contextConnect(TSM_HCONTEXT a_hContext);
TSM_RESULT contextCreateObject(TSM_HCONTEXT a_hContext,
			       TSM_FLAG a_fType,
			       TSM_FLAG a_fAttrs, TSM_HOBJECT * a_hObject);
TSM_RESULT contextCloseObject(TSM_HCONTEXT a_hContext,
			      TSM_HOBJECT a_hObject);
TSM_RESULT contextGetTpm(TSM_HCONTEXT a_hContext, TSM_HTCM * a_hTpm);
TSM_RESULT policyGet(TSM_HOBJECT a_hObject, TSM_HPOLICY * a_hPolicy);
TSM_RESULT policyAssign(TSM_HPOLICY a_hPolicy, TSM_HOBJECT a_hObject);
TSM_RESULT policySetSecret(TSM_HPOLICY a_hPolicy,
			   UINT32 a_uiSecretLen, BYTE * a_chSecret);

TSM_RESULT policyFlushSecret(TSM_HPOLICY a_hPolicy);

//Common TSPI functions
TSM_RESULT tpmGetPubEk(TSM_HTCM a_hTpm, TSM_BOOL a_fOwner,
                       TSM_VALIDATION * a_pValData, TSM_HKEY * a_phEPubKey);
TSM_RESULT tpmGetRandom(TSM_HTCM a_hTpm, UINT32 a_length, BYTE ** a_data);
TSM_RESULT tpmSetStatus(TSM_HTCM a_hTpm,
			TSM_FLAG a_fStatus, TSM_BOOL a_bValue);
TSM_RESULT tpmGetStatus(TSM_HTCM a_hTpm,
			TSM_FLAG a_fStatus, TSM_BOOL * a_bValue);
TSM_RESULT getCapability(TSM_HTCM a_hTpm,
			 TSM_FLAG a_fCapArea,
			 UINT32 a_uiSubCapLen,
			 BYTE * a_pSubCap,
			 UINT32 * a_uiResultLen, BYTE ** a_pResult);
TSM_RESULT getAttribData(TSM_HOBJECT a_hObject,
			 TSM_FLAG a_fAttr,
			 TSM_FLAG a_fSubAttr,
			 UINT32 * a_uiSize, BYTE ** a_pData);
TSM_RESULT getAttribUint32(TSM_HOBJECT a_hObject,
			   TSM_FLAG a_fAttr,
			   TSM_FLAG a_fSubAttr, UINT32 * a_uiData);

//TSPI key functions
TSM_RESULT keyLoadKey(TSM_HKEY a_hKey, TSM_HKEY a_hWrapKey);
TSM_RESULT keyLoadKeyByUUID(TSM_HCONTEXT a_hContext,
			    TSM_FLAG a_fStoreType,
			    TSM_UUID a_uKeyId, TSM_HKEY * a_hKey);
TSM_RESULT keyLoadKeybyBlob(TSM_HCONTEXT a_hContext,TSM_HKEY a_hKey, 
				UINT32 keylen, BYTE * keyblob, TSM_HKEY* phWrapKey);
TSM_RESULT keyGetPubKey(TSM_HKEY a_hKey,
			UINT32 * a_uiKeyLen, BYTE ** a_pKey);
TSM_RESULT keyGetKeyByUUID(TSM_HCONTEXT a_hContext,
			   TSM_FLAG a_fStoreType,
			   TSM_UUID a_uKeyId, TSM_HKEY * a_hKey);

TSM_RESULT keyCreateKey(TSM_HKEY a_hKey, TSM_HKEY a_hWrapKey,
			TSM_HPCRS a_hPcrs);
TSM_RESULT dataSeal(TSM_HENCDATA a_hEncdata, TSM_HKEY a_hKey,
			UINT32 a_len, BYTE * a_data,
			TSM_HPCRS a_hPcrs);
TSM_RESULT tpmPcrRead(TSM_HTCM a_hTpm, UINT32 a_Idx,
			UINT32 *a_PcrSize, BYTE **a_PcrValue);
TSM_RESULT pcrcompositeSetPcrValue(TSM_HPCRS a_hPcrs, UINT32 a_Idx,
					UINT32 a_PcrSize, BYTE *a_PcrValue);
#ifdef TSM_LIB_IS_12
TSM_RESULT unloadVersionInfo(UINT64 *offset, BYTE *blob, TCM_CAP_VERSION_INFO *v);
TSM_RESULT pcrcompositeSetPcrLocality(TSM_HPCRS a_hPcrs, UINT32 localityValue);

TSM_RESULT NVDefineSpace(TSM_HNVSTORE hNVStore,
                         TSM_HPCRS hReadPcrComposite,
                         TSM_HPCRS hWritePcrComposite);

TSM_RESULT NVReleaseSpace(TSM_HNVSTORE hNVStore);

TSM_RESULT NVWriteValue(TSM_HNVSTORE hNVStore, UINT32 offset,
                        UINT32 ulDataLength, BYTE *rgbDataToWrite);

TSM_RESULT NVReadValue(TSM_HNVSTORE hNVStore, UINT32 offset,
                       UINT32 *ulDataLength, BYTE **rgbDataRead);

TSM_RESULT unloadNVDataPublic(UINT64 *offset, BYTE *blob, UINT32 bloblen,
                              TCM_NV_DATA_PUBLIC *v);
#endif

TSM_RESULT sm3Start(TSM_HTCM a_hTpm, UINT32 * pUpdateLength);
TSM_RESULT sm3Update(TSM_HTCM a_hTpm, UINT32 dlen,	BYTE * datain);
TSM_RESULT sm3Complete(TSM_HTCM a_hTpm, UINT32 dlen, BYTE * datain, BYTE * outDigest);

TSM_RESULT
sm4Encrypt(TSM_HTCM a_hTpm, TSM_HKEY hKey, BYTE* IV,
	UINT32  dlen, BYTE* datain, UINT32* enclen, BYTE ** encdata);

TSM_RESULT
sm4Decrypt(TSM_HTCM a_hTpm, TSM_HKEY hKey, BYTE* IV, 
	UINT32  enclen, BYTE* encdata, UINT32* dlen, BYTE ** dataout);

#endif
