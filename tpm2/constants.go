package tpm2

import (
	"fmt"
	"hash"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

// 6.3
const (
	TPMAlgRSA          TPMAlgID = 0x0001
	TPMAlgTDES         TPMAlgID = 0x0003
	TPMAlgSHA          TPMAlgID = 0x0004
	TPMAlgSHA1                  = TPMAlgSHA
	TPMAlgHMAC         TPMAlgID = 0x0005
	TPMAlgAES          TPMAlgID = 0x0006
	TPMAlgMGF1         TPMAlgID = 0x0007
	TPMAlgKeyedHash    TPMAlgID = 0x0008
	TPMAlgXOR          TPMAlgID = 0x000A
	TPMAlgSHA256       TPMAlgID = 0x000B
	TPMAlgSHA384       TPMAlgID = 0x000C
	TPMAlgSHA512       TPMAlgID = 0x000D
	TPMAlgNull         TPMAlgID = 0x0010
	TPMAlgSM3256       TPMAlgID = 0x0012
	TPMAlgSM4          TPMAlgID = 0x0013
	TPMAlgRSASSA       TPMAlgID = 0x0014
	TPMAlgRSAES        TPMAlgID = 0x0015
	TPMAlgRSAPSS       TPMAlgID = 0x0016
	TPMAlgOAEP         TPMAlgID = 0x0017
	TPMAlgECDSA        TPMAlgID = 0x0018
	TPMAlgECDH         TPMAlgID = 0x0019
	TPMAlgECDAA        TPMAlgID = 0x001A
	TPMAlgSM2          TPMAlgID = 0x001B
	TPMAlgECSchnorr    TPMAlgID = 0x001C
	TPMAlgECMQV        TPMAlgID = 0x001D
	TPMAlgKDF1SP80056A TPMAlgID = 0x0020
	TPMAlgKDF2         TPMAlgID = 0x0021
	TPMAlgKDF1SP800108 TPMAlgID = 0x0022
	TPMAlgECC          TPMAlgID = 0x0023
	TPMAlgSymCipher    TPMAlgID = 0x0025
	TPMAlgCamellia     TPMAlgID = 0x0026
	TPMAlgSHA3256      TPMAlgID = 0x0027
	TPMAlgSHA3384      TPMAlgID = 0x0028
	TPMAlgSHA3512      TPMAlgID = 0x0029
	TPMAlgCTR          TPMAlgID = 0x0040
	TPMAlgOFB          TPMAlgID = 0x0041
	TPMAlgCBC          TPMAlgID = 0x0042
	TPMAlgCFB          TPMAlgID = 0x0043
	TPMAlgECB          TPMAlgID = 0x0044
)

// Enumerate the algorithms in TPMIAlgHash so that we can define functions on them.
func (a TPMIAlgHash) Hash() hash.Hash {
	switch TPMAlgID(a) {
	case TPMAlgSHA1:
		return sha1.New()
	case TPMAlgSHA256:
		return sha256.New()
	case TPMAlgSHA384:
		return sha512.New384()
	case TPMAlgSHA512:
		return sha512.New()
	}
	panic(fmt.Sprintf("unsupported hash algorithm: %v", a))
}

// 6.4
const (
	TPMECCNone     TPMECCCurve = 0x0000
	TPMECCNistP192 TPMECCCurve = 0x0001
	TPMECCNistP224 TPMECCCurve = 0x0002
	TPMECCNistP256 TPMECCCurve = 0x0003
	TPMECCNistP384 TPMECCCurve = 0x0004
	TPMECCNistP521 TPMECCCurve = 0x0005
	TPMECCBNP256   TPMECCCurve = 0x0010
	TPMECCBNP638   TPMECCCurve = 0x0011
	TPMECCSM2P256  TPMECCCurve = 0x0020
)

// 6.5.2
const (
	TPMCCNVUndefineSpaceSpecial     TPMCC = 0x0000011F
	TPMCCEvictControl               TPMCC = 0x00000120
	TPMCCHierarchyControl           TPMCC = 0x00000121
	TPMCCNVUndefineSpace            TPMCC = 0x00000122
	TPMCCChangeEPS                  TPMCC = 0x00000124
	TPMCCChangePPS                  TPMCC = 0x00000125
	TPMCCClear                      TPMCC = 0x00000126
	TPMCCClearControl               TPMCC = 0x00000127
	TPMCCClockSet                   TPMCC = 0x00000128
	TPMCCHierarchyChanegAuth        TPMCC = 0x00000129
	TPMCCNVDefineSpace              TPMCC = 0x0000012A
	TPMCCPCRAllocate                TPMCC = 0x0000012B
	TPMCCPCRSetAuthPolicy           TPMCC = 0x0000012C
	TPMCCPPCommands                 TPMCC = 0x0000012D
	TPMCCSetPrimaryPolicy           TPMCC = 0x0000012E
	TPMCCFieldUpgradeStart          TPMCC = 0x0000012F
	TPMCCClockRateAdjust            TPMCC = 0x00000130
	TPMCCCreatePrimary              TPMCC = 0x00000131
	TPMCCNVGlobalWriteLock          TPMCC = 0x00000132
	TPMCCGetCommandAuditDigest      TPMCC = 0x00000133
	TPMCCNVIncrement                TPMCC = 0x00000134
	TPMCCNVSetBits                  TPMCC = 0x00000135
	TPMCCNVExtend                   TPMCC = 0x00000136
	TPMCCNVWrite                    TPMCC = 0x00000137
	TPMCCNVWriteLock                TPMCC = 0x00000138
	TPMCCDictionaryAttackLockReset  TPMCC = 0x00000139
	TPMCCDictionaryAttackParameters TPMCC = 0x0000013A
	TPMCCNVChangeAuth               TPMCC = 0x0000013B
	TPMCCPCREvent                   TPMCC = 0x0000013C
	TPMCCPCRReset                   TPMCC = 0x0000013D
	TPMCCSequenceComplete           TPMCC = 0x0000013E
	TPMCCSetAlgorithmSet            TPMCC = 0x0000013F
	TPMCCSetCommandCodeAuditStatus  TPMCC = 0x00000140
	TPMCCFieldUpgradeData           TPMCC = 0x00000141
	TPMCCIncrementalSelfTest        TPMCC = 0x00000142
	TPMCCSelfTest                   TPMCC = 0x00000143
	TPMCCStartup                    TPMCC = 0x00000144
	TPMCCShutdown                   TPMCC = 0x00000145
	TPMCCStirRandom                 TPMCC = 0x00000146
	TPMCCActivateCredential         TPMCC = 0x00000147
	TPMCCCertify                    TPMCC = 0x00000148
	TPMCCPolicyNV                   TPMCC = 0x00000149
	TPMCCCertifyCreation            TPMCC = 0x0000014A
	TPMCCDuplicate                  TPMCC = 0x0000014B
	TPMCCGetTime                    TPMCC = 0x0000014C
	TPMCCGetSessionAuditDigest      TPMCC = 0x0000014D
	TPMCCNVRead                     TPMCC = 0x0000014E
	TPMCCNVReadLock                 TPMCC = 0x0000014F
	TPMCCObjectChangeAuth           TPMCC = 0x00000150
	TPMCCPolicySecret               TPMCC = 0x00000151
	TPMCCRewrap                     TPMCC = 0x00000152
	TPMCCCreate                     TPMCC = 0x00000153
	TPMCCECDHZGen                   TPMCC = 0x00000154
	TPMCCHMAC                       TPMCC = 0x00000155
	TPMCCMAC                        TPMCC = TPMCCHMAC
	TPMCCImport                     TPMCC = 0x00000156
	TPMCCLoad                       TPMCC = 0x00000157
	TPMCCQuote                      TPMCC = 0x00000158
	TPMCCRSADecrypt                 TPMCC = 0x00000159
	TPMCCHMACStart                  TPMCC = 0x0000015B
	TPMCCMACStart                         = TPMCCHMACStart
	TPMCCSequenceUpdate             TPMCC = 0x0000015C
	TPMCCSign                       TPMCC = 0x0000015D
	TPMCCUnseal                     TPMCC = 0x0000015E
	TPMCCPolicySigned               TPMCC = 0x00000160
	TPMCCContextLoad                TPMCC = 0x00000161
	TPMCCContextSave                TPMCC = 0x00000162
	TPMCCECDHKeyGen                 TPMCC = 0x00000163
	TPMCCEncryptDecrypt             TPMCC = 0x00000164
	TPMCCFlushContext               TPMCC = 0x00000165
	TPMCCLoadExternal               TPMCC = 0x00000167
	TPMCCMakeCredential             TPMCC = 0x00000168
	TPMCCNVReadPublic               TPMCC = 0x00000169
	TPMCCPolicyAuthorize            TPMCC = 0x0000016A
	TPMCCPolicyAuthValue            TPMCC = 0x0000016B
	TPMCCPolicyCommandCode          TPMCC = 0x0000016C
	TPMCCPolicyCounterTimer         TPMCC = 0x0000016D
	TPMCCPolicyCpHash               TPMCC = 0x0000016E
	TPMCCPolicyLocality             TPMCC = 0x0000016F
	TPMCCPolicyNameHash             TPMCC = 0x00000170
	TPMCCPolicyOR                   TPMCC = 0x00000171
	TPMCCPolicyTicket               TPMCC = 0x00000172
	TPMCCReadPublic                 TPMCC = 0x00000173
	TPMCCRSAEncrypt                 TPMCC = 0x00000174
	TPMCCStartAuthSession           TPMCC = 0x00000176
	TPMCCVerifySignature            TPMCC = 0x00000177
	TPMCCECCParameters              TPMCC = 0x00000178
	TPMCCFirmwareRead               TPMCC = 0x00000179
	TPMCCGetCapability              TPMCC = 0x0000017A
	TPMCCGetRandom                  TPMCC = 0x0000017B
	TPMCCGetTestResult              TPMCC = 0x0000017C
	TPMCCHash                       TPMCC = 0x0000017D
	TPMCCPCRRead                    TPMCC = 0x0000017E
	TPMCCPolicyPCR                  TPMCC = 0x0000017F
	TPMCCPolicyRestart              TPMCC = 0x00000180
	TPMCCReadClock                  TPMCC = 0x00000181
	TPMCCPCRExtend                  TPMCC = 0x00000182
	TPMCCPCRSetAuthValue            TPMCC = 0x00000183
	TPMCCNVCertify                  TPMCC = 0x00000184
	TPMCCEventSequenceComplete      TPMCC = 0x00000185
	TPMCCHashSequenceStart          TPMCC = 0x00000186
	TPMCCPolicyPhysicalPresence     TPMCC = 0x00000187
	TPMCCPolicyDuplicationSelect    TPMCC = 0x00000188
	TPMCCPolicyGetDigest            TPMCC = 0x00000189
	TPMCCTestParams                 TPMCC = 0x0000018A
	TPMCCCommit                     TPMCC = 0x0000018B
	TPMCCPolicyPassword             TPMCC = 0x0000018C
	TPMCCZGen2Phase                 TPMCC = 0x0000018D
	TPMCCECEphemeral                TPMCC = 0x0000018E
	TPMCCPolicyNvWritten            TPMCC = 0x0000018F
	TPMCCPolicyTemplate             TPMCC = 0x00000190
	TPMCCCreateLoaded               TPMCC = 0x00000191
	TPMCCPolicyAuthorizeNV          TPMCC = 0x00000192
	TPMCCEncryptDecrypt2            TPMCC = 0x00000193
	TPMCCACGetCapability            TPMCC = 0x00000194
	TPMCCACSend                     TPMCC = 0x00000195
	TPMCCPolicyACSendSelect         TPMCC = 0x00000196
	TPMCCCertifyX509                TPMCC = 0x00000197
	TPMCCACTSetTimeout              TPMCC = 0x00000198
)

// 6.9
const (
	TPMSTRspCommand         TPMST = 0x00C4
	TPMSTNull               TPMST = 0x8000
	TPMSTNoSessions         TPMST = 0x8001
	TPMSTSessions           TPMST = 0x8002
	TPMSTAttestNV           TPMST = 0x8014
	TPMSTAttestCommandAudit TPMST = 0x8015
	TPMSTAttestSessionAudit TPMST = 0x8016
	TPMSTAttestCertify      TPMST = 0x8017
	TPMSTAttestQuote        TPMST = 0x8018
	TPMSTAttestTime         TPMST = 0x8019
	TPMSTAttestCreation     TPMST = 0x801A
	TPMSTAttestNVDigest     TPMST = 0x801C
	TPMSTCreation           TPMST = 0x8021
	TPMSTVerified           TPMST = 0x8022
	TPMSTAuthSecret         TPMST = 0x8023
	TPMSTHashCheck          TPMST = 0x8024
	TPMSTAuthSigned         TPMST = 0x8025
	TPMSTFuManifest         TPMST = 0x8029
)

// 6.11
const (
	TPMSEHMAC TPMSE = 0x00
	TPMSEPolicy TPMSE = 0x01
	TPMXETrial TPMSE = 0x03
)

// 7.4
const (
	TPMRHOwner       TPMHandle = 0x40000001
	TPMRHNull        TPMHandle = 0x40000007
	TPMRSPW          TPMHandle = 0x40000009
	TPMRHLockout     TPMHandle = 0x4000000A
	TPMRHEndorsement TPMHandle = 0x4000000B
	TPMRHPlatform    TPMHandle = 0x4000000C
	TPMRHPlatformNV  TPMHandle = 0x4000000D
)
