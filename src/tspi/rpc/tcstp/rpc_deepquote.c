
/*
 *
 * trousers - An open source TCG Software Stack
 * Deep Quote
 * Author: Emil Condrea <emilcondrea@gmail.com>
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"

TSS_RESULT
RPC_DeepQuote_TP(struct host_table_entry *hte,
	      TCS_KEY_HANDLE keyHandle,	/* in */
	      TCPA_NONCE *antiReplay,	/* in */
	      UINT32 pcrDataSizeIn,	/* in */
	      BYTE * pcrDataIn,	/* in */
	      UINT32 phPcrDataSizeIn,	/* in */
	      BYTE * phPcrDataIn,	/* in */
	      UINT32 flags, /* in */
	      TPM_AUTH * privAuth,	/* in, out */
	      UINT32 * sigSize,	/* out */
	      BYTE ** sig)	/* out */
{
	TSS_RESULT result;
	int i;

	initData(&hte->comm, 9);

	hte->comm.hdr.u.ordinal = TCSD_DEEP_QUOTE;
	LogDebugFn("TCS Context: 0x%x", hte->tcsContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hte->tcsContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 2, antiReplay, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &pcrDataSizeIn, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, pcrDataIn, pcrDataSizeIn, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &phPcrDataSizeIn, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, phPcrDataIn, phPcrDataSizeIn, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 7, &flags, 0, &hte->comm))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	if (privAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 8, privAuth, 0, &hte->comm))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	/* Takes and sets the output data */
	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, &hte->comm)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, i++, sigSize, 0, &hte->comm)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*sig = (BYTE *) malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *sig, *sigSize, &hte->comm)) {
			free(*sig);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	return result;
}