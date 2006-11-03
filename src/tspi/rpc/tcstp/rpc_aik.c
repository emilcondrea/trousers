
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"


TSS_RESULT
TCSP_MakeIdentity_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_ENCAUTH identityAuth,	/* in */
				 TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
				 UINT32 idKeyInfoSize,	/* in */
				 BYTE * idKeyInfo,	/* in */
				 TPM_AUTH * pSrkAuth,	/* in, out */
				 TPM_AUTH * pOwnerAuth,	/* in, out */
				 UINT32 * idKeySize,	/* out */
				 BYTE ** idKey,	/* out */
				 UINT32 * pcIdentityBindingSize,	/* out */
				 BYTE ** prgbIdentityBinding,	/* out */
				 UINT32 * pcEndorsementCredentialSize,	/* out */
				 BYTE ** prgbEndorsementCredential,	/* out */
				 UINT32 * pcPlatformCredentialSize,	/* out */
				 BYTE ** prgbPlatformCredential,	/* out */
				 UINT32 * pcConformanceCredentialSize,	/* out */
				 BYTE ** prgbConformanceCredential	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_MAKEIDENTITY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 1, &identityAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &IDLabel_PrivCAHash, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &idKeyInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, idKeyInfo, idKeyInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	i = 5;
	if (pSrkAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, pSrkAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	i = 0;
	if (result == TSS_SUCCESS) {
		i = 0;
		if (pSrkAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, pSrkAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, idKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*idKey = (BYTE *) malloc(*idKeySize);
		if (*idKey == NULL) {
			LogError("malloc of %u bytes failed.", *idKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *idKey, *idKeySize, hdr)) {
			free(*idKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcIdentityBindingSize, 0, hdr)) {
			free(*idKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbIdentityBinding = (BYTE *) malloc(*pcIdentityBindingSize);
		if (*prgbIdentityBinding == NULL) {
			LogError("malloc of %u bytes failed.", *pcIdentityBindingSize);
			free(*idKey);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbIdentityBinding, *pcIdentityBindingSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcEndorsementCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbEndorsementCredential = (BYTE *) malloc(*pcEndorsementCredentialSize);
		if (*prgbEndorsementCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcEndorsementCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbEndorsementCredential, *pcEndorsementCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcPlatformCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbPlatformCredential = (BYTE *) malloc(*pcPlatformCredentialSize);
		if (*prgbPlatformCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcPlatformCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbPlatformCredential, *pcPlatformCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcConformanceCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbConformanceCredential = (BYTE *) malloc(*pcConformanceCredentialSize);
		if (*prgbConformanceCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcConformanceCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbConformanceCredential, *pcConformanceCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			free(*prgbConformanceCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ActivateTPMIdentity_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE idKey,	/* in */
					UINT32 blobSize,	/* in */
					BYTE * blob,	/* in */
					TPM_AUTH * idKeyAuth,	/* in, out */
					TPM_AUTH * ownerAuth,	/* in, out */
					UINT32 * SymmetricKeySize,	/* out */
					BYTE ** SymmetricKey	/* out */
    ) {
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	int i = 0;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ACTIVATETPMIDENTITY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &idKey, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &blobSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, i++, blob, blobSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (idKeyAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, idKeyAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	if (setData(TCSD_PACKET_TYPE_AUTH, i++, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (hdr->result == TSS_SUCCESS) {
		i = 0;
		if (idKeyAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, idKeyAuth, 0, hdr))
				result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, i++, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, SymmetricKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*SymmetricKey = malloc(*SymmetricKeySize);
		if (*SymmetricKey == NULL) {
			LogError("malloc of %u bytes failed.", *SymmetricKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *SymmetricKey, *SymmetricKeySize, hdr)) {
			free(*SymmetricKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}
done:
	free(hdr);
	return result;
}