
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

TSS_RESULT
TCSP_DeepQuote_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		    TCS_KEY_HANDLE keyHandle,	/* in */
		    TCPA_NONCE antiReplay,	/* in */
		    UINT32 pcrDataSizeIn,	/* in */
		    BYTE * pcrDataIn,	/* in */
			UINT32 phPcrDataSizeIn,	/* in */
		    BYTE * phPcrDataIn,	/* in */
		    UINT32 flags, /* in */
		    TPM_AUTH * privAuth,	/* in, out */
		    UINT32 * sigSize,	/* out */
		    BYTE ** sig)	/* out */
{
	UINT64 offset = 0;
	UINT32 paramSize;
	TSS_RESULT result;
	UINT32 keySlot;

	/* Command packet to be sent to the TPM */
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	if ((result = tpm_rqu_build( TPM_ORD_DeepQuote, &offset, txBlob, keySlot, antiReplay.nonce,
				    pcrDataSizeIn, pcrDataIn,phPcrDataSizeIn, phPcrDataIn, &flags, privAuth)))
		goto done;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		result = tpm_rsp_parse(TPM_ORD_DeepQuote, txBlob, paramSize,
				       sigSize, sig, privAuth);
	}

done:
	auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}