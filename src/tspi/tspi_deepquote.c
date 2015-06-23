
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
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

static TSS_RESULT fresh_read_pcrs(TSS_HCONTEXT*,TPM_PCR_SELECTION*,UINT32*,BYTE**);
static TSS_RESULT create_vtpmstructhash(TSS_HPCRS,TPM_NONCE*,TPM_DIGEST*);
static TSS_RESULT create_quotestructhash(TCPA_VERSION*,TPM_DIGEST*,TPM_NONCE*,TPM_DIGEST*,BYTE*,UINT64*);
static TSS_RESULT unpack_outparams(UINT32,BYTE*,UINT32,BYTE**,UINT32*,BYTE**,UINT32 *,TPM_PCRVALUE**,UINT32 *);
static void printf_buf(BYTE*,UINT32);

TSS_RESULT
Tspi_TPM_DeepQuote(TSS_HTPM        hTPM,            // in
        TSS_HKEY        hIdentKey,       // in
        UINT32          flags,     // in
        TSS_HPCRS       hPcrComposite,   // in
        TSS_HPCRS       phPcrComposite,   // in
        TPM_STORE_PUBKEY* vtpm_group_pubkey, // in
        TSS_VALIDATION* pValidationData) // in, out
{
    TPM_RESULT result = TSS_SUCCESS;
    TSS_HCONTEXT tspContext;
    TPM_AUTH privAuth;
    UINT64 offset;
    TPM_DIGEST digest,vtpm_digest;
    TPM_NONCE ptpm_extrnaldata;
    TPM_DIGEST ptpm_pcrshash;
    TPM_DIGEST qinfo_digest;
    TSS_BOOL usesAuth;
    TCS_KEY_HANDLE tcsKeyHandle;
    TSS_HPOLICY hPolicy;
    TPM_NONCE antiReplay;
    BYTE quoteinfo[1024];
    UINT64 quoteinfo_sz;
    BYTE pcrData[128];
    UINT32 pcrDataSize;
    BYTE phPcrData[128];
    UINT32 phPcrDataSize;
    UINT32 outParamsSize = 0;
    BYTE *outParams = NULL;
    Trspi_HashCtx hashCtx;
    BYTE pcr_comp_buf[1024];
    BYTE* sig = NULL;
    UINT32 sig_size;
    UINT32 i;
    TPM_PCR_COMPOSITE pcr_comp,vpcr_comp;
    
    TPM_PCR_SELECTION vtpm_pcr_sel,ptpm_pcr_sel;
    
    UINT32 vtpm_pcrread1_sz = 0;
    BYTE* vtpm_pcrread1 = NULL;

    UINT32 vtpm_pcrread2_sz = 0;
    BYTE* vtpm_pcrread2 = NULL;

    BYTE* recv_ptpm_extrahashesbuf;
    UINT32 recv_ptpm_extrahashesbuf_sz;

    TPM_PCRVALUE* recv_ptpm_pcrs = NULL;
    TPM_PCRVALUE* vtpm_pcrs = NULL;
    UINT32 vtpm_pcrs_sel_sz;
    UINT32 recv_ptpm_pcrs_sz;

    TCPA_VERSION quote_version = {1, 1, 0, 0};
    BYTE select[] = { 0, 0, 0 };

    /* Takes the context that this TPM handle is on */
    if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
        goto done;
    /* Test if the phPcrComposite is valid */
    if ((phPcrComposite) && !obj_is_pcrs(phPcrComposite)){
        result = TSPERR(TSS_E_INVALID_HANDLE);
        goto done;
    }
    /* Test if the hPcrComposite is valid */
    if ((hPcrComposite) && !obj_is_pcrs(hPcrComposite)){
        result = TSPERR(TSS_E_INVALID_HANDLE);
        goto done;
    }
    /*  get the identKey Policy */
    if ((result = obj_rsakey_get_policy(hIdentKey, TSS_POLICY_USAGE, &hPolicy, &usesAuth)))
        goto done;
    if (!usesAuth){
        result = TSPERR(TSS_E_BAD_PARAMETER);
        goto done;
    }
    /*  get the Identity TCS keyHandle */
    if ((result = obj_rsakey_get_tcs_handle(hIdentKey, &tcsKeyHandle)))
        goto done;
    /* Sets the validation data - if NULL, TSS provides it's own random value. If
     * not NULL, takes the validation external data and sets the antiReplay data
     * with this */
    if (pValidationData == NULL){
        LogDebug("Internal Verify:");
        if ((result = get_local_random(tspContext, FALSE, sizeof(TPM_NONCE),
                           (BYTE **)antiReplay.nonce)))
            goto done;
    } 
    else{
        LogDebug("External Verify:");
        if (pValidationData->ulExternalDataLength < sizeof(antiReplay.nonce)){
            result = TSPERR(TSS_E_BAD_PARAMETER);
            goto done;
        }

        memcpy(antiReplay.nonce, pValidationData->rgbExternalData,
                sizeof(antiReplay.nonce));
    }
    
    /* Create the TPM_PCR_SELECTION object for virtual sel*/
    pcrDataSize = 0;
    if (hPcrComposite){
        /* Load the PCR Selection Object into the pcrData */
        if ((result = obj_pcrs_get_selection(hPcrComposite, &pcrDataSize, pcrData)))
            goto done;
        offset = 0;
        Trspi_UnloadBlob_PCR_SELECTION(&offset,pcrData,&vtpm_pcr_sel);
        if(vtpm_pcr_sel.sizeOfSelect==0){
            result = TSPERR(TSS_E_NO_PCRS_SET);
            goto done;
        }
        if((result = obj_pcrs_set_locality(hPcrComposite,1)))
            goto done;
    }
    else{
        offset = 0;
        // marshall an empty valid selection
        vtpm_pcr_sel.sizeOfSelect = sizeof(select);
        vtpm_pcr_sel.pcrSelect = select;
        Trspi_LoadBlob_PCR_SELECTION(&offset,pcrData,&vtpm_pcr_sel);
        pcrDataSize = offset;
    }

    /* Create the TPM_PCR_SELECTION object for physical sel*/
    phPcrDataSize = 0;
    if (phPcrComposite){
        /* Load the PCR Selection Object into the phPcrData */
        if ((result = obj_pcrs_get_selection(phPcrComposite, &phPcrDataSize, phPcrData)))
            goto done;
        offset = 0;
        Trspi_UnloadBlob_PCR_SELECTION(&offset,phPcrData,&ptpm_pcr_sel);
        if(ptpm_pcr_sel.sizeOfSelect==0){
            result = TSPERR(TSS_E_NO_PCRS_SET);
            goto done;
        }
        if((result = obj_pcrs_set_locality(phPcrComposite,0)))
            goto done;
    }
    else{
        offset = 0;
        // marshall an empty valid selection
        ptpm_pcr_sel.sizeOfSelect = sizeof(select);
        ptpm_pcr_sel.pcrSelect = select;
        Trspi_LoadBlob_PCR_SELECTION(&offset,phPcrData,&ptpm_pcr_sel);
        phPcrDataSize = offset;
    }
    /* Perform OIAP auth */
    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DeepQuote);
    result |= Trspi_HashUpdate(&hashCtx, TPM_SHA1_160_HASH_LEN, antiReplay.nonce);
    result |= Trspi_HashUpdate(&hashCtx, pcrDataSize, pcrData);
    result |= Trspi_HashUpdate(&hashCtx, phPcrDataSize, phPcrData);
    result |= Trspi_Hash_UINT32(&hashCtx,flags);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
        goto done;
    if ((result = secret_PerformAuth_OIAP(hIdentKey, TPM_ORD_DeepQuote, hPolicy, FALSE,
                          &digest, &privAuth)))
        goto done;
    
    /*Unload vTPM PCR selection*/
    offset = 0;
    /*Read vTPM PCRS before DeepQuote*/
    if(hPcrComposite){
        result = fresh_read_pcrs(&tspContext,&vtpm_pcr_sel,&vtpm_pcrread1_sz,&vtpm_pcrread1);
        if(result)
            goto done;
    }

    /* Send to TCS */
    if ((result = TCS_API(tspContext)->DeepQuote(tspContext, tcsKeyHandle, &antiReplay,
                          pcrDataSize, pcrData, phPcrDataSize, phPcrData, flags, &privAuth,
                          &outParamsSize, &outParams)))
        goto free_vtpm_pcrread1;

    /*Reread vTPM PCRS before DeepQuote*/
    if(hPcrComposite){
        result = fresh_read_pcrs(&tspContext,&vtpm_pcr_sel,&vtpm_pcrread2_sz,&vtpm_pcrread2);
        if(result)
            goto free_vtpm_pcrread1;
    }

#ifdef TSS_DEBUG
    LogDebug("Got TCS Response:");
    LogDebug("      outParamsSize: %u",outParamsSize);
    LogDebug("      outParams:");
    LogDebugData(outParamsSize,outParams);
#endif

    /*In order to be sure that the PCRs were not modified by other
      application while performing the DeepQuote the PCR values
      read before must match the values read after*/
    if(hPcrComposite && vtpm_pcrread2_sz != vtpm_pcrread1_sz){
        result = TSS_E_V_INCONSISTENT_PCRS;
        goto free_vtpm_pcrread2;
    }
    if(hPcrComposite && vtpm_pcrread2_sz !=0 
        && memcmp(vtpm_pcrread2,vtpm_pcrread1,vtpm_pcrread1_sz)!=0){
        LogError("vtpm_pcrread2!=vtpm_pcrread1, try again");
        LogDebug("vtpm_pcrread1:");
        LogDebugData(vtpm_pcrread1_sz,vtpm_pcrread1);
        LogDebug("vtpm_pcrread2:");
        LogDebugData(vtpm_pcrread2_sz,vtpm_pcrread2);
        result = TSS_E_V_INCONSISTENT_PCRS;
        goto free_vtpm_pcrread2;
    }
   
    /*Validate auth session*/
    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, result);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DeepQuote);
    result |= Trspi_HashUpdate(&hashCtx, outParamsSize, outParams);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) 
        goto free_vtpm_pcrread2;
    if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth))) 
         goto free_vtpm_pcrread2;

    result = unpack_outparams(flags, outParams,outParamsSize,&sig,&sig_size,
                &recv_ptpm_extrahashesbuf,&recv_ptpm_extrahashesbuf_sz,
                &recv_ptpm_pcrs,&recv_ptpm_pcrs_sz);
    if(result)
        goto free_vtpm_pcrread2;

    if(phPcrComposite){
        /*Create TPM_PCR_COMPOSITE for physical PCRs*/
        __tspi_memset(&pcr_comp, 0, sizeof(pcr_comp)); 
        pcr_comp.select = ptpm_pcr_sel;
        pcr_comp.valueSize = recv_ptpm_pcrs_sz;
        pcr_comp.pcrValue = recv_ptpm_pcrs;

        /*Set TSS_HPCRS values from TPM_PCR_COMPOSITE*/
        if ((result = obj_pcrs_set_values(phPcrComposite, &pcr_comp))) 
             goto free_sig;
    }
    
    if(hPcrComposite){
        /* Convert raw buffer PCR values to TPM_PCRVALUE*/
        vtpm_pcrs = (TPM_PCRVALUE*)malloc(vtpm_pcrread1_sz);
        if(!vtpm_pcrs){
            LogError("Could not allocate memory for vtpm_pcrs: %d",vtpm_pcrread1_sz);
            result = TSPERR(TSS_E_OUTOFMEMORY);
            goto free_sig;
        }
        vtpm_pcrs_sel_sz = vtpm_pcrread1_sz / sizeof(TPM_PCRVALUE);
        for(i=0;i<vtpm_pcrs_sel_sz;i++)
            memcpy(vtpm_pcrs[i].digest,vtpm_pcrread1+i*sizeof(TPM_PCRVALUE),sizeof(TPM_PCRVALUE));

        /*Create TPM_PCR_COMPOSITE for virtual PCRs*/
        __tspi_memset(&vpcr_comp, 0, sizeof(vpcr_comp)); 
        vpcr_comp.select = vtpm_pcr_sel;
        vpcr_comp.valueSize = vtpm_pcrread1_sz;
        vpcr_comp.pcrValue = vtpm_pcrs;

        /*Set TSS_HPCRS values from TPM_PCR_COMPOSITE*/
        if ((result = obj_pcrs_set_values(hPcrComposite, &vpcr_comp))) 
            goto free_vtpm_pcrs_pcrval;
    }
    
    /*Create hash on quote info struct*/
    result = create_vtpmstructhash(hPcrComposite,&antiReplay,&vtpm_digest);
    if(result){
        LogError("create_vtpmstructhash failed");
        goto free_vtpm_pcrs_pcrval;
    }

#ifdef TSS_DEBUG
    LogDebug("create_vtpmstructhash created hash:");
    for (i=0; i < sizeof(TPM_DIGEST); i++)
        printf("%02x", ((uint8_t*)vtpm_digest.digest)[i]);
    printf("\n");
#endif
    /* Compute externalData the same way it is computed in vTPM manager*/
    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_HashUpdate(&hashCtx, sizeof(UINT32), (BYTE*)&flags);
    result |= Trspi_HashUpdate(&hashCtx, sizeof(TPM_DIGEST), vtpm_digest.digest);
    result |= Trspi_HashUpdate(&hashCtx, recv_ptpm_extrahashesbuf_sz, recv_ptpm_extrahashesbuf);
    result |= Trspi_HashFinal(&hashCtx, ptpm_extrnaldata.nonce);
    if(result)
        goto free_vtpm_pcrs_pcrval;

    LogDebug("resulted ptpm_extrnaldata.nonce:");
    printf_buf((BYTE*)ptpm_extrnaldata.nonce,sizeof(TPM_NONCE));

    offset = 0;
    if(phPcrComposite){
        Trspi_LoadBlob_PCR_COMPOSITE(&offset,pcr_comp_buf,&pcr_comp);
        Trspi_Hash(TSS_HASH_SHA1, offset, pcr_comp_buf, ptpm_pcrshash.digest);
    }
    else{
        memset(ptpm_pcrshash.digest,0,sizeof(TPM_DIGEST));
    }
    
    LogDebug("recv_ptpm_pcrs, sz:%d",recv_ptpm_pcrs_sz);
    printf_buf((BYTE*)recv_ptpm_pcrs,recv_ptpm_pcrs_sz);

    /*Create hash on TPM_QUOTE_INFO struct used by pTPM*/
    result = create_quotestructhash(&quote_version,&ptpm_pcrshash,&ptpm_extrnaldata,
                &qinfo_digest,quoteinfo,&quoteinfo_sz);
    if(result)
        goto free_vtpm_pcrs_pcrval;

    LogDebug("SIGNATURE HASH:");
    printf_buf((BYTE*)qinfo_digest.digest,sizeof(TPM_DIGEST));
    if(pValidationData == NULL){
        /*The hash on TPM_QUOTE_INFO was signed with vtpm group aik so
          it needs to be verified using the same key*/
        if ((result = Trspi_Verify(TSS_HASH_SHA1, qinfo_digest.digest, sizeof(TPM_DIGEST),
                    vtpm_group_pubkey->key,vtpm_group_pubkey->keyLength,
                    sig,sig_size))){
            LogError("Verify signature FAILED!");
            goto free_vtpm_pcrs_pcrval;
        }
        else{
            LogDebug("Verify signature SUCCESS");
        }
    }
    else{
        pValidationData->rgbValidationData = calloc_tspi(tspContext, sig_size);
        if (pValidationData->rgbValidationData == NULL){
            LogError("malloc of %u bytes failed.", sig_size);
            result = TSPERR(TSS_E_OUTOFMEMORY);
            goto free_vtpm_pcrs_pcrval;
        }
        pValidationData->ulValidationDataLength = sig_size;
        memcpy(pValidationData->rgbValidationData, sig, sig_size);
        
        pValidationData->rgbData = calloc_tspi(tspContext, quoteinfo_sz);
        if (pValidationData->rgbData == NULL){
            LogError("malloc of %" PRIu64 " bytes failed.", quoteinfo_sz);
            free_tspi(tspContext, pValidationData->rgbValidationData);
            pValidationData->rgbValidationData = NULL;
            pValidationData->ulValidationDataLength = 0;
            
            result = TSPERR(TSS_E_OUTOFMEMORY);
            goto free_vtpm_pcrs_pcrval;
        }
        pValidationData->ulDataLength = (UINT32)quoteinfo_sz;
        memcpy(pValidationData->rgbData, quoteinfo, quoteinfo_sz);
    }

free_vtpm_pcrs_pcrval:
    free(vtpm_pcrs);
free_sig:
    free(sig);
    free(recv_ptpm_extrahashesbuf);
    free(recv_ptpm_pcrs);
free_vtpm_pcrread2:
    free(vtpm_pcrread2);
free_vtpm_pcrread1:
    free(vtpm_pcrread1);
free_out_params:
    free(outParams);
done:
    return result;
}

static TSS_RESULT fresh_read_pcrs(
                TSS_HCONTEXT* tspContext, // in
                TPM_PCR_SELECTION* pcrSelection, // in
                UINT32* pcrSize, // out
                BYTE** pcr_values) // out
 {
    TSS_RESULT result = 0;
    TCPA_PCRVALUE outDigest;
    int i,j;
    *pcr_values = NULL;
    //get num pcrs selected
    for (i = 0, j = 0; i < pcrSelection->sizeOfSelect * 8; i++){
        /* is PCR number i selected ? */
        if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) 
            j++;
    }
    if(j==0)
        goto done;

    *pcrSize = j * sizeof(BYTE)* sizeof(TPM_PCRVALUE);
    if(*pcrSize %sizeof(TPM_PCRVALUE) != 0){
        result = TSPERR(TSS_E_FAIL);
        goto done;
    }
    *pcr_values = (BYTE*)malloc(*pcrSize);
    if(*pcr_values == NULL){
        result = TSPERR(TSS_E_OUTOFMEMORY);
        goto done;
    }

    for (i = 0, j = 0; i < pcrSelection->sizeOfSelect * 8; i++){
        /* is PCR number i selected ? */
        if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))){
            if ((result = TCS_API(*tspContext)->PcrRead(*tspContext, i, &outDigest)))
                goto fail;
            memcpy((*pcr_values +j*sizeof(TPM_PCRVALUE)), &outDigest.digest, sizeof(TPM_PCRVALUE));
            j++;
        }
    }
    goto done;
fail:
    free(*pcr_values);
    *pcr_values = NULL;
done:
    return result;
 }

static void printf_buf(BYTE* buf,UINT32 size)
{
    UINT32 i;
#ifdef TSS_DEBUG
    for(i=0;i<size;i++){
        printf("%02x", ((uint8_t*)buf)[i]);
    }
    printf("\n");
#endif
}
 static TSS_RESULT create_vtpmstructhash(
                TSS_HPCRS       hPcrComposite,
                TPM_NONCE* antiReplay, // int
                TPM_DIGEST* out_hash) // out
 {
    TPM_RESULT result = 0;
    UINT64 offset =0;
    Trspi_HashCtx hashCtx;
    BYTE* pcrInfo = NULL;
    UINT32 pcrInfoSize;
    TPM_PCR_INFO_SHORT infoshort;
    BYTE select[] = { 0, 0, 0 };
    static BYTE dquot_hdr[] = {
        0, 0, 0, 0, 'D', 'Q', 'U', 'T'
    };
    if(hPcrComposite){
        obj_pcrs_create_info_short(hPcrComposite,&pcrInfoSize,&pcrInfo);
    }
    else{
        /* Create an empty valid pcr structure*/
        infoshort.pcrSelection.sizeOfSelect = sizeof(select);
        infoshort.pcrSelection.pcrSelect = select;
        infoshort.localityAtRelease = 1;
        memset(infoshort.digestAtRelease.digest,0,sizeof(TPM_DIGEST));
        Trspi_LoadBlob_PCR_INFO_SHORT(&offset,NULL,&infoshort);
        pcrInfo = malloc(offset);
        offset = 0;
        Trspi_LoadBlob_PCR_INFO_SHORT(&offset,pcrInfo,&infoshort);
        pcrInfoSize = offset;
    }

    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_HashUpdate(&hashCtx, 8, dquot_hdr);
    result |= Trspi_HashUpdate(&hashCtx, sizeof(TPM_NONCE), antiReplay->nonce);
    result |= Trspi_HashUpdate(&hashCtx, pcrInfoSize, pcrInfo);
    if ((result |= Trspi_HashFinal(&hashCtx, out_hash->digest)))
        goto finish;
finish:
    free(pcrInfo);
    return result;
 }

 static TSS_RESULT create_quotestructhash(
                TCPA_VERSION* version, // in
                TPM_DIGEST* pcr_hash, // in
                TPM_NONCE* antiReplay, // int
                TPM_DIGEST* qinfhash, //out
                BYTE* quoteinfo, //out
                UINT64* quoteinfo_sz) // out
 {
    TPM_RESULT result = 0;
    UINT64 offset;
    
    /* generate Quote_info struct */
    /* 1. add version */
    offset = 0;
    Trspi_LoadBlob_TCPA_VERSION(&offset, quoteinfo, *version);
    /* 2. add "QUOT" */
    quoteinfo[offset++] = 'Q';
    quoteinfo[offset++] = 'U';
    quoteinfo[offset++] = 'O';
    quoteinfo[offset++] = 'T';
    /* 3. Composite Hash */
    Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
               pcr_hash->digest);
    /* 4. AntiReplay Nonce */
    Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
               antiReplay->nonce);
    Trspi_Hash(TSS_HASH_SHA1, offset, quoteinfo, qinfhash->digest);
    *quoteinfo_sz = offset;

    return result;
 }

static TSS_RESULT unpack_outparams(
        UINT32 flags, // in
        BYTE* params, // in
        UINT32 param_sz, // in
        BYTE** sig, // out
        UINT32 *sig_size, // out
        BYTE** ext_hashes, // out
        UINT32 *ext_hashesbuf_sz,  // out
        TPM_PCRVALUE** pcr_vals, // out
        UINT32 *pcr_bufsize) // out
{
    UINT64 offset = 0;
    UINT32 i,array_len;
    TSS_RESULT result = 0;;
    *sig_size = 256;
    *pcr_bufsize = 0;
    *sig = (BYTE*)malloc(sizeof(BYTE)*256);
    if(*sig == NULL){
        LogError("Could not allocate memory for result signature");
        result = TSPERR(TSS_E_OUTOFMEMORY);
        goto finish;
    }
    
    Trspi_UnloadBlob(&offset,*sig_size,params,*sig);
    array_len=0;
    while(flags!=0){
        if((flags&0x01)!=0)
            array_len++;
        flags>>=1;
    }
    *ext_hashesbuf_sz = array_len * sizeof(TPM_DIGEST);
    if( *ext_hashesbuf_sz > (param_sz - *sig_size)){
        LogError("Invalid ext_hashesbuf_sz size: %d",*ext_hashesbuf_sz);
        result = TSPERR(TSS_E_FAIL);
        goto free_sig;
    }
    if(array_len>0){
        *ext_hashes = (BYTE*)malloc(*ext_hashesbuf_sz);
        if(*ext_hashes == NULL){
            LogError("Could not allocate memory for ext_hashes");
            result = TSPERR(TSS_E_OUTOFMEMORY);
            goto free_sig;
        }
        for(i=0;i<array_len;i++)
            Trspi_UnloadBlob(&offset,sizeof(TPM_DIGEST),params,*ext_hashes + i*sizeof(TPM_DIGEST));
    }
    *pcr_bufsize = param_sz - *sig_size - *ext_hashesbuf_sz;
    if(*pcr_bufsize%sizeof(TPM_PCRVALUE) != 0){
        LogError("Invalid PCR values provided: pcr_bufsize:%d",*pcr_bufsize);
        result = TSPERR(TSS_E_FAIL);
        goto free_ext_hash;
    }
    if(*pcr_bufsize == 0)
        goto finish;
    array_len = *pcr_bufsize / sizeof(TPM_PCRVALUE);
    *pcr_vals = (TPM_PCRVALUE*)malloc(*pcr_bufsize);
    if(*pcr_vals == NULL){
        LogError("Could not allocate memory for pcr_vals");
        result = TSPERR(TSS_E_OUTOFMEMORY);
        goto free_ext_hash;
    }
    for(i=0;i<array_len;i++)
        Trspi_UnloadBlob(&offset,sizeof(TPM_PCRVALUE),params,(*pcr_vals)[i].digest);
    
    goto finish;

    free(*pcr_vals);
    *pcr_vals = NULL;
free_ext_hash:
    free(*ext_hashes);
free_sig:
    *ext_hashes = NULL;
    free(*sig);
    *sig = NULL;
finish:
    return result;
}
