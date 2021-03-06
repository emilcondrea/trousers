/*
 * TPM Ordinal definitions extracted from the TPM 1.2 specification, rev 85.
 */

#ifndef __TPM_ORDINAL_H__
#define __TPM_ORDINAL_H__

#define TPM_PROTECTED_COMMAND                     ((UINT32)(0x00000000))
#define TPM_UNPROTECTED_COMMAND                   ((UINT32)(0x80000000))
#define TPM_CONNECTION_COMMAND                    ((UINT32)(0x40000000))
#define TPM_VENDOR_COMMAND                        ((UINT32)(0x20000000))

#define TPM_MAIN                                  ((UINT16)(0x0000))
#define TPM_PC                                    ((UINT16)(0x0001))
#define TPM_PDA                                   ((UINT16)(0x0002))
#define TPM_CELL_PHONE                            ((UINT16)(0x0003))
#define TPM_SERVER                                ((UINT16)(0x0004))

#define TPM_PROTECTED_ORDINAL              (TPM_MAIN | TPM_PROTECTED_COMMAND)
#define TPM_UNPROTECTED_ORDINAL            (TPM_MAIN | TPM_UNPROTECTED_COMMAND)
#define TPM_CONNECTION_ORDINAL             (TPM_MAIN | TPM_CONNECTION_COMMAND)


#define TPM_ORD_OIAP                              ((UINT32)0x0000000A)
#define TPM_ORD_OSAP                              ((UINT32)0x0000000B)
#define TPM_ORD_ChangeAuth                        ((UINT32)0x0000000C)
#define TPM_ORD_TakeOwnership                     ((UINT32)0x0000000D)
#define TPM_ORD_ChangeAuthAsymStart               ((UINT32)0x0000000E)
#define TPM_ORD_ChangeAuthAsymFinish              ((UINT32)0x0000000F)
#define TPM_ORD_ChangeAuthOwner                   ((UINT32)0x00000010)
#define TPM_ORD_DSAP                              ((UINT32)0x00000011)
#define TPM_ORD_CMK_CreateTicket                  ((UINT32)0x00000012)
#define TPM_ORD_CMK_CreateKey                     ((UINT32)0x00000013)
#define TPM_ORD_Extend                            ((UINT32)0x00000014)
#define TPM_ORD_PcrRead                           ((UINT32)0x00000015)
#define TPM_ORD_Quote                             ((UINT32)0x00000016)
#define TPM_ORD_Seal                              ((UINT32)0x00000017)
#define TPM_ORD_Unseal                            ((UINT32)0x00000018)
#define TPM_ORD_DirWriteAuth                      ((UINT32)0x00000019)
#define TPM_ORD_DirRead                           ((UINT32)0x0000001A)
#define TPM_ORD_CMK_CreateBlob                    ((UINT32)0x0000001B)
#define TPM_ORD_CMK_SetRestrictions               ((UINT32)0x0000001C)
#define TPM_ORD_CMK_ApproveMA                     ((UINT32)0x0000001D)
#define TPM_ORD_UnBind                            ((UINT32)0x0000001E)
#define TPM_ORD_CreateWrapKey                     ((UINT32)0x0000001F)
#define TPM_ORD_LoadKey                           ((UINT32)0x00000020)
#define TPM_ORD_GetPubKey                         ((UINT32)0x00000021)
#define TPM_ORD_EvictKey                          ((UINT32)0x00000022)
#define TPM_ORD_KeyControlOwner                   ((UINT32)0x00000023)
#define TPM_ORD_CMK_ConvertMigration              ((UINT32)0x00000024)
#define TPM_ORD_MigrateKey                        ((UINT32)0x00000025)
#define TPM_ORD_CreateMigrationBlob               ((UINT32)0x00000028)
#define TPM_ORD_DAA_Join                          ((UINT32)0x00000029)
#define TPM_ORD_ConvertMigrationBlob              ((UINT32)0x0000002A)
#define TPM_ORD_AuthorizeMigrationKey             ((UINT32)0x0000002B)
#define TPM_ORD_CreateMaintenanceArchive          ((UINT32)0x0000002C)
#define TPM_ORD_LoadMaintenanceArchive            ((UINT32)0x0000002D)
#define TPM_ORD_KillMaintenanceFeature            ((UINT32)0x0000002E)
#define TPM_ORD_LoadManuMaintPub                  ((UINT32)0x0000002F)
#define TPM_ORD_ReadManuMaintPub                  ((UINT32)0x00000030)
#define TPM_ORD_DAA_Sign                          ((UINT32)0x00000031)
#define TPM_ORD_CertifyKey                        ((UINT32)0x00000032)
#define TPM_ORD_CertifyKey2                       ((UINT32)0x00000033)
#define TPM_ORD_Sign                              ((UINT32)0x0000003C)
#define TPM_ORD_Sealx                             ((UINT32)0x0000003D)
#define TPM_ORD_Quote2                            ((UINT32)0x0000003E)
#define TPM_ORD_SetCapability                     ((UINT32)0x0000003F)
#define TPM_ORD_ResetLockValue                    ((UINT32)0x00000040)
#define TPM_ORD_LoadKey2                          ((UINT32)0x00000041)
#define TPM_ORD_GetRandom                         ((UINT32)0x00000046)
#define TPM_ORD_StirRandom                        ((UINT32)0x00000047)
#define TPM_ORD_SelfTestFull                      ((UINT32)0x00000050)
#define TPM_ORD_CertifySelfTest                   ((UINT32)0x00000052)
#define TPM_ORD_ContinueSelfTest                  ((UINT32)0x00000053)
#define TPM_ORD_GetTestResult                     ((UINT32)0x00000054)
#define TPM_ORD_Reset                             ((UINT32)0x0000005A)
#define TPM_ORD_OwnerClear                        ((UINT32)0x0000005B)
#define TPM_ORD_DisableOwnerClear                 ((UINT32)0x0000005C)
#define TPM_ORD_ForceClear                        ((UINT32)0x0000005D)
#define TPM_ORD_DisableForceClear                 ((UINT32)0x0000005E)
#define TPM_ORD_GetCapabilitySigned               ((UINT32)0x00000064)
#define TPM_ORD_GetCapability                     ((UINT32)0x00000065)
#define TPM_ORD_GetCapabilityOwner                ((UINT32)0x00000066)
#define TPM_ORD_OwnerSetDisable                   ((UINT32)0x0000006E)
#define TPM_ORD_PhysicalEnable                    ((UINT32)0x0000006F)
#define TPM_ORD_PhysicalDisable                   ((UINT32)0x00000070)
#define TPM_ORD_SetOwnerInstall                   ((UINT32)0x00000071)
#define TPM_ORD_PhysicalSetDeactivated            ((UINT32)0x00000072)
#define TPM_ORD_SetTempDeactivated                ((UINT32)0x00000073)
#define TPM_ORD_SetOperatorAuth                   ((UINT32)0x00000074)
#define TPM_ORD_SetOwnerPointer                   ((UINT32)0x00000075)
#define TPM_ORD_CreateEndorsementKeyPair          ((UINT32)0x00000078)
#define TPM_ORD_MakeIdentity                      ((UINT32)0x00000079)
#define TPM_ORD_ActivateIdentity                  ((UINT32)0x0000007A)
#define TPM_ORD_ReadPubek                         ((UINT32)0x0000007C)
#define TPM_ORD_OwnerReadPubek                    ((UINT32)0x0000007D)
#define TPM_ORD_DisablePubekRead                  ((UINT32)0x0000007E)
#define TPM_ORD_CreateRevocableEK                 ((UINT32)0x0000007F)
#define TPM_ORD_RevokeTrust                       ((UINT32)0x00000080)
#define TPM_ORD_OwnerReadInternalPub              ((UINT32)0x00000081)
#define TPM_ORD_GetAuditEvent                     ((UINT32)0x00000082)
#define TPM_ORD_GetAuditEventSigned               ((UINT32)0x00000083)
#define TPM_ORD_GetAuditDigest                    ((UINT32)0x00000085)
#define TPM_ORD_GetAuditDigestSigned              ((UINT32)0x00000086)
#define TPM_ORD_GetOrdinalAuditStatus             ((UINT32)0x0000008C)
#define TPM_ORD_SetOrdinalAuditStatus             ((UINT32)0x0000008D)
#define TPM_ORD_Terminate_Handle                  ((UINT32)0x00000096)
#define TPM_ORD_Init                              ((UINT32)0x00000097)
#define TPM_ORD_SaveState                         ((UINT32)0x00000098)
#define TPM_ORD_Startup                           ((UINT32)0x00000099)
#define TPM_ORD_SetRedirection                    ((UINT32)0x0000009A)
#define TPM_ORD_SHA1Start                         ((UINT32)0x000000A0)
#define TPM_ORD_SHA1Update                        ((UINT32)0x000000A1)
#define TPM_ORD_SHA1Complete                      ((UINT32)0x000000A2)
#define TPM_ORD_SHA1CompleteExtend                ((UINT32)0x000000A3)
#define TPM_ORD_FieldUpgrade                      ((UINT32)0x000000AA)
#define TPM_ORD_SaveKeyContext                    ((UINT32)0x000000B4)
#define TPM_ORD_LoadKeyContext                    ((UINT32)0x000000B5)
#define TPM_ORD_SaveAuthContext                   ((UINT32)0x000000B6)
#define TPM_ORD_LoadAuthContext                   ((UINT32)0x000000B7)
#define TPM_ORD_SaveContext                       ((UINT32)0x000000B8)
#define TPM_ORD_LoadContext                       ((UINT32)0x000000B9)
#define TPM_ORD_FlushSpecific                     ((UINT32)0x000000BA)
#define TPM_ORD_PCR_Reset                         ((UINT32)0x000000C8)
#define TPM_ORD_NV_DefineSpace                    ((UINT32)0x000000CC)
#define TPM_ORD_NV_WriteValue                     ((UINT32)0x000000CD)
#define TPM_ORD_NV_WriteValueAuth                 ((UINT32)0x000000CE)
#define TPM_ORD_NV_ReadValue                      ((UINT32)0x000000CF)
#define TPM_ORD_NV_ReadValueAuth                  ((UINT32)0x000000D0)
#define TPM_ORD_Delegate_UpdateVerification       ((UINT32)0x000000D1)
#define TPM_ORD_Delegate_Manage                   ((UINT32)0x000000D2)
#define TPM_ORD_Delegate_CreateKeyDelegation      ((UINT32)0x000000D4)
#define TPM_ORD_Delegate_CreateOwnerDelegation    ((UINT32)0x000000D5)
#define TPM_ORD_Delegate_VerifyDelegation         ((UINT32)0x000000D6)
#define TPM_ORD_Delegate_LoadOwnerDelegation      ((UINT32)0x000000D8)
#define TPM_ORD_Delegate_ReadTable                ((UINT32)0x000000DB)
#define TPM_ORD_CreateCounter                     ((UINT32)0x000000DC)
#define TPM_ORD_IncrementCounter                  ((UINT32)0x000000DD)
#define TPM_ORD_ReadCounter                       ((UINT32)0x000000DE)
#define TPM_ORD_ReleaseCounter                    ((UINT32)0x000000DF)
#define TPM_ORD_ReleaseCounterOwner               ((UINT32)0x000000E0)
#define TPM_ORD_EstablishTransport                ((UINT32)0x000000E6)
#define TPM_ORD_ExecuteTransport                  ((UINT32)0x000000E7)
#define TPM_ORD_ReleaseTransportSigned            ((UINT32)0x000000E8)
#define TPM_ORD_GetTicks                          ((UINT32)0x000000F1)
#define TPM_ORD_TickStampBlob                     ((UINT32)0x000000F2)

#define TSC_ORD_PhysicalPresence                  ((UINT32)0x4000000A)
#define TSC_ORD_ResetEstablishmentBit             ((UINT32)0x4000000B)

#define TPM_ORD_DeepQuote                         (TPM_ORD_Quote|TPM_VENDOR_COMMAND)

#endif // __TPM_ORDINAL_H__
