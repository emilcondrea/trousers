
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */

#ifndef _TCSD_WRAP_H_
#define _TCSD_WRAP_H_

#include "tcs_tsp.h"

enum TCSP_PACKET_TYPE {
	TCSD_PACKET_TYPE_BYTE,
	TCSD_PACKET_TYPE_BOOL,
	TCSD_PACKET_TYPE_UINT16,
	TCSD_PACKET_TYPE_UINT32,
	TCSD_PACKET_TYPE_PBYTE,
	TCSD_PACKET_TYPE_KEY,
	TCSD_PACKET_TYPE_NONCE,
	TCSD_PACKET_TYPE_AUTH,
	TCSD_PACKET_TYPE_DIGEST,
	TCSD_PACKET_TYPE_UUID,
	TCSD_PACKET_TYPE_ENCAUTH,
	TCSD_PACKET_TYPE_VERSION,
	/*2004-05-12 Seiji Munetoh added */
	TCSD_PACKET_TYPE_KM_KEYINFO,
	TCSD_PACKET_TYPE_KM_KEYINFO2,
	TCSD_PACKET_TYPE_LOADKEY_INFO,
	TCSD_PACKET_TYPE_PCR_EVENT,
	TCSD_PACKET_TYPE_COUNTER_VALUE,
	TCSD_PACKET_TYPE_UINT64,
	TCSD_PACKET_TYPE_SECRET
};

enum TCSD_ORD {
	TCSD_ORD_ERROR = 0,
	/* 4.5 TCS Contest Manager */
	TCSD_ORD_OPENCONTEXT = 1,
	TCSD_ORD_CLOSECONTEXT = 2,
	TCSD_ORD_FREEMEMORY = 3,
	TCSD_ORD_TCSGETCAPABILITY = 4, /*  Tcsi_GatCapability */
	/* 4.6 TCS Key Credential Manager */
	TCSD_ORD_REGISTERKEY = 5,
	TCSD_ORD_UNREGISTERKEY = 6,
	TCSD_ORD_ENUMREGISTEREDKEYS = 7,
	TCSD_ORD_GETREGISTEREDKEY = 8,
	TCSD_ORD_GETREGISTEREDKEYBLOB = 9,
	TCSD_ORD_GETREGISTEREDKEYBYPUBLICINFO = 10,
	TCSD_ORD_LOADKEYBYBLOB = 11,
	TCSD_ORD_LOADKEYBYUUID = 12,
	TCSD_ORD_EVICTKEY = 13,
	TCSD_ORD_CREATEWRAPKEY = 14,
	TCSD_ORD_GETPUBKEY = 15,
	TCSD_ORD_MAKEIDENTITY = 16,
	/* 4.7 TCS Event Manager */
	TCSD_ORD_LOGPCREVENT = 17,
	TCSD_ORD_GETPCREVENT = 18,
	TCSD_ORD_GETPCREVENTBYPCR = 19,
	TCSD_ORD_GETPCREVENTLOG = 20,
	/* 4.8 TCS Audit Manager */
	/* 4.9 TCS TPM Parametor Block Generator  */
	TCSD_ORD_SETOWNERINSTALL = 21,
	TCSD_ORD_TAKEOWNERSHIP = 22,
	TCSD_ORD_OIAP = 23,
	TCSD_ORD_OSAP = 24,
	TCSD_ORD_CHANGEAUTH = 25,
	TCSD_ORD_CHANGEAUTHOWNER = 26,
	TCSD_ORD_CHANGEAUTHASYMSTART = 27,
	TCSD_ORD_CHANGEAUTHASYMFINISH = 28,
	TCSD_ORD_TERMINATEHANDLE = 29,
	TCSD_ORD_ACTIVATETPMIDENTITY = 30,

	TCSD_ORD_EXTEND = 31,
	TCSD_ORD_PCRREAD= 32,
	TCSD_ORD_QUOTE = 33,
	TCSD_ORD_DIRWRITEAUTH = 34,
	TCSD_ORD_DIRREAD = 35,
	TCSD_ORD_SEAL = 36,
	TCSD_ORD_UNSEAL = 37,
	TCSD_ORD_UNBIND = 38,
	TCSD_ORD_CREATEMIGRATIONBLOB = 39,
	TCSD_ORD_CONVERTMIGRATIONBLOB = 40,
	TCSD_ORD_AUTHORIZEMIGRATIONKEY = 41,

	TCSD_ORD_CERTIFYKEY = 42,
	TCSD_ORD_SIGN = 43,
	TCSD_ORD_GETRANDOM =44,
	TCSD_ORD_STIRRANDOM =45,
	TCSD_ORD_GETCAPABILITY =46,  /*  Tcsip_GatCapability */
	TCSD_ORD_GETCAPABILITYSIGNED = 47,
	TCSD_ORD_GETCAPABILITYOWNER = 48,

	TCSD_ORD_CREATEENDORSEMENTKEYPAIR = 49,
	TCSD_ORD_READPUBEK = 50,
	TCSD_ORD_DISABLEPUBEKREAD = 51,
	TCSD_ORD_OWNERREADPUBEK =52,

	TCSD_ORD_SELFTESTFULL = 53,
	TCSD_ORD_CERTIFYSELFTEST = 54,
	TCSD_ORD_CONTINUESELFTEST = 55,
	TCSD_ORD_GETTESTRESULT = 56,
	TCSD_ORD_OWNERSETDISABLE = 57,
	TCSD_ORD_OWNERCLEAR = 58,
	TCSD_ORD_DISABLEOWNERCLEAR = 59,
	TCSD_ORD_FORCECLEAR = 60,
	TCSD_ORD_DISABLEFORCECLEAR = 61,
	TCSD_ORD_PHYSICALDISABLE = 62,
	TCSD_ORD_PHYSICALENABLE = 63,
	TCSD_ORD_PHYSICALSETDEACTIVATED = 64,
	TCSD_ORD_SETTEMPDEACTIVATED = 65,
	TCSD_ORD_PHYSICALPRESENCE = 66,
	TCSD_ORD_FIELDUPGRADE = 67,
	TCSD_ORD_SETRIDIRECTION = 68,

	TCSD_ORD_CREATEMAINTENANCEARCHIVE = 69,
	TCSD_ORD_LOADMAINTENANCEARCHIVE = 70,
	TCSD_ORD_KILLMAINTENANCEFEATURE = 71,
	TCSD_ORD_LOADMANUFACTURERMAINTENANCEPUB = 72,
	TCSD_ORD_READMANUFACTURERMAINTENANCEPUB = 73,
	/* DAA */
	TCSD_ORD_DAAJOIN = 74,
        TCSD_ORD_DAASIGN = 75,
	TCSD_ORD_SETCAPABILITY = 76,
	TCSD_ORD_RESETLOCKVALUE = 77,

	TCSD_ORD_PCRRESET = 78,
	TCSD_ORD_READCOUNTER = 79,
	TCSD_ORD_CREATECOUNTER = 80,
	TCSD_ORD_INCREMENTCOUNTER = 81,
	TCSD_ORD_RELEASECOUNTER = 82,
	TCSD_ORD_RELEASECOUNTEROWNER = 83,
	TCSD_ORD_READCURRENTTICKS = 84,
	TCSD_ORD_TICKSTAMPBLOB = 85,
	TCSD_ORD_GETCREDENTIAL = 86,
	/* NV */
	TCSD_ORD_NVDEFINEORRELEASESPACE = 87,
	TCSD_ORD_NVWRITEVALUE = 88,
	TCSD_ORD_NVWRITEVALUEAUTH = 89,
	TCSD_ORD_NVREADVALUE = 90,
	TCSD_ORD_NVREADVALUEAUTH = 91,

	TCSD_ORD_ESTABLISHTRANSPORT = 92,
	TCSD_ORD_EXECUTETRANSPORT = 93,
	TCSD_ORD_RELEASETRANSPORTSIGNED = 94,
	/* Audit */
	TCSD_ORD_SETORDINALAUDITSTATUS = 95,
	TCSD_ORD_GETAUDITDIGEST = 96,
	TCSD_ORD_GETAUDITDIGESTSIGNED = 97,
	TCSD_ORD_SEALX = 98,

	TCSD_ORD_SETOPERATORAUTH = 99,
	TCSD_ORD_OWNERREADINTERNALPUB = 100,
	TCSD_ORD_ENUMREGISTEREDKEYS2 = 101,
	TCSD_ORD_SETTEMPDEACTIVATED2 = 102,

	/* Delegation */
	TCSD_ORD_DELEGATE_MANAGE = 103,
	TCSD_ORD_DELEGATE_CREATEKEYDELEGATION = 104,
	TCSD_ORD_DELEGATE_CREATEOWNERDELEGATION = 105,
	TCSD_ORD_DELEGATE_LOADOWNERDELEGATION = 106,
	TCSD_ORD_DELEGATE_READTABLE = 107,
	TCSD_ORD_DELEGATE_UPDATEVERIFICATIONCOUNT = 108,
	TCSD_ORD_DELEGATE_VERIFYDELEGATION = 109,

	TCSD_ORD_CREATEREVOCABLEENDORSEMENTKEYPAIR = 110,
	TCSD_ORD_REVOKEENDORSEMENTKEYPAIR = 111,

	TCSD_ORD_MAKEIDENTITY2 = 112,
	TCSD_ORD_QUOTE2 = 113,

	/* CMK */
	TCSD_ORD_CMK_SETRESTRICTIONS = 114,
	TCSD_ORD_CMK_APPROVEMA = 115,
	TCSD_ORD_CMK_CREATEKEY = 116,
	TCSD_ORD_CMK_CREATETICKET = 117,
	TCSD_ORD_CMK_CREATEBLOB = 118,
	TCSD_ORD_CMK_CONVERTMIGRATION = 119,

	TCSD_ORD_FLUSHSPECIFIC = 120,
	TCSD_ORD_KEYCONTROLOWNER = 121,
	TCSD_ORD_DSAP = 122,
	TCSD_DEEP_QUOTE = 123,

	/* Last */
	TCSD_LAST_ORD = 124
};
#define TCSD_MAX_NUM_ORDS TCSD_LAST_ORD

#include "tcsd.h"

#endif
