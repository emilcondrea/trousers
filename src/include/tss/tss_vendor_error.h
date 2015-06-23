/*++

TSS vendor error return codes 
 
--*/

#ifndef __TSS_VENDOR_ERROR_H__
#define __TSS_VENDOR_ERROR_H__

#include <tss/tss_error_basics.h>
#define TSS_E_VENDOR_BASE TSS_VENDOR_OFFSET

//
// MessageId: TSS_E_V_INCONSISTENT_PCRS
//
// MessageText:
//
// The Deep Quote command must retried because PCR values were different
// before and after execution
//
#define TSS_E_V_INCONSISTENT_PCRS    (UINT32)(TSS_E_VENDOR_BASE + 0x001L)

#endif