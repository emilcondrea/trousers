
/*
 *
 * trousers - An open source TCG Software Stack
 * Deep Quote
 * Author: Emil Condrea <emilcondrea@gmail.com>
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netdb.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcs_utils.h"
#include "rpc_tcstp_tcs.h"

TSS_RESULT
tcs_wrap_DeepQuote(struct tcsd_thread_data *data)
{
	/* Data to be forwarded to the next level */
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	TCPA_NONCE antiReplay;
	UINT32 pcrDataSizeIn;
	BYTE *pcrDataIn;
	UINT32 phPcrDataSizeIn;
	BYTE *phPcrDataIn;

	UINT32 flags;
	TPM_AUTH privAuth;  /* in/out */ 
	TPM_AUTH *pPrivAuth;

	UINT32 sigSize;
	BYTE *sig;
	TSS_RESULT result;

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if ((result = ctx_verify_context(hContext)))
		goto done;

	LogDebugFn("thread %ld context %x", THREAD_ID, hContext);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &pcrDataSizeIn, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	pcrDataIn = (BYTE *)calloc(1, pcrDataSizeIn);
	if (pcrDataIn == NULL) {
		LogError("malloc of %u bytes failed.", pcrDataSizeIn);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, pcrDataIn, pcrDataSizeIn, &data->comm)) {
		free(pcrDataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &phPcrDataSizeIn, 0, &data->comm)){
		free(pcrDataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	phPcrDataIn = (BYTE *)calloc(1, phPcrDataSizeIn);
	if (phPcrDataIn == NULL) {
		free(pcrDataIn);
		LogError("malloc of %u bytes failed.", phPcrDataSizeIn);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 6, phPcrDataIn, phPcrDataSizeIn, &data->comm)) {
		free(pcrDataIn);
		free(phPcrDataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_UINT32,7,&flags, 0, &data->comm)) {
		free(pcrDataIn);
		free(phPcrDataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	result = getData(TCSD_PACKET_TYPE_AUTH, 8, &privAuth, 0, &data->comm);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE){
		LogError("Could not obtain auth from getData()");
		pPrivAuth = NULL;
	}
	else if (result) {
		free(pcrDataIn);
		free(phPcrDataIn);
		return result;
	} else{
		LogError("assigning auth");
		pPrivAuth = &privAuth;
	}

	MUTEX_LOCK(tcsp_lock);

	result = TCSP_DeepQuote_Internal(hContext, hKey, antiReplay, pcrDataSizeIn, pcrDataIn,
				     phPcrDataSizeIn, phPcrDataIn,flags,pPrivAuth,&sigSize, &sig);

	MUTEX_UNLOCK(tcsp_lock);
	free(pcrDataIn);
	free(phPcrDataIn);
	if (result == TSS_SUCCESS) {
		i = 0;
		initData(&data->comm,3); 
		if (pPrivAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pPrivAuth, 0, &data->comm)) {
				free(sig);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &sigSize, 0, &data->comm)) {
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, sig, sigSize, &data->comm)) {
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(sig);
	} 
	else
done:		initData(&data->comm, 0);

	data->comm.hdr.u.result = result;
	return TSS_SUCCESS;
}
