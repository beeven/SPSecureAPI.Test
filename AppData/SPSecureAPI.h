
// 调用任何对卡的操作之前必须调用该函数，完成操作后请立刻关闭卡
unsigned int SpcInitEnvEx();

// 完成操作后，调用此函数关闭加密设备
unsigned int SpcClearEnv();

// 验证口令，调用该函数之前必须先打开卡
unsigned int SpcVerifyPIN (uint8_t* szPIN, unsigned int nPINLen);

// 修改卡口令，调用此函数前必须打开卡
unsigned int SpcChangePIN (uint8_t* szOldPIN, unsigned int  nOldPINLen, uint8_t* szNewPIN, unsigned int nNewPINLen);

// 从卡内取随机数，调用此函数前必须打开卡
unsigned int SpcGetRandom (uint8_t* szRandom, unsigned int nRandomLen);

// 取读卡器中卡的状态
unsigned int SpcGetCardState(unsigned int  nType, unsigned int  nIndex, unsigned int  *nState);

unsigned int  SpcGetCardID(uint8_t* szCardID, unsigned int* nCardIDLen);

unsigned int  SpcGetCertNo(uint8_t* szCertNo, unsigned int* nCertNoLen);

unsigned int  SpcGetUName(uint8_t* szUserName, unsigned int* nUserNameLen);

unsigned int  SpcGetEntID(uint8_t* szEntID, unsigned int* nEntIDLen);

unsigned int  SpcGetEntName(uint8_t* szEntName, unsigned int* nEntNameLen);

unsigned int  SpcGetEntMode(uint8_t* szEntMode, unsigned int* nEntModeLen);

unsigned int  SpcGetCardUserInfo(char* szInfo, unsigned int* nInfoLen);

unsigned int  SpcGetSignCert(uint8_t *szCert,  unsigned int* nCertLen);

unsigned int  SpcGetEnvCert(uint8_t *szEnvCert,  unsigned int* nEnvCertLen);

unsigned int  SpcGetCardAttachInfo(uint8_t *szAttachInfo, unsigned int *nAttachInfoLen);


unsigned int  SpcSignData(uint8_t* szInData, unsigned int nInDataLen,	 uint8_t* szSignData, unsigned int* nSignDataLen);

unsigned int  SpcSignDataNoHash(uint8_t* szInData, unsigned int nInDataLen, uint8_t* szSignData, unsigned int* nSignDataLen);

unsigned int  SpcVerifySignData(uint8_t* szCert, unsigned int nCertLen, uint8_t* szInData, unsigned int nInDataLen, uint8_t* szSignData, unsigned int nSignDataLen);

unsigned int  SpcVerifySignDataNoHash(uint8_t* szCert, unsigned int nCertLen, uint8_t* szInData, unsigned int nInDataLen, uint8_t* szSignData, unsigned int nSignDataLen);

unsigned int  SpcVerifySignWithPubKey(uint8_t *szPubKey, unsigned int nPubKeyLen, uint8_t *szInData, unsigned int nInDataLen, uint8_t * szSignData, unsigned int nSignDataLen);

unsigned int  SpcVerifySignNohashWithPubKey(uint8_t *szPubKey, unsigned int nPubKeyLen, uint8_t * szInData , unsigned int nInDataLen,  uint8_t * szSignData, unsigned int nSignDataLen);

unsigned int  SpcEncodePEM(uint8_t* szInData, unsigned int nInDataLen, uint8_t* szOutData, unsigned int* nOutDataLen);

unsigned int  SpcDecodePEM(uint8_t* szInData, unsigned int nInDataLen, uint8_t* szOutData, unsigned int* nOutDataLen);

unsigned int  SpcSHA1Digest(uint8_t* szInfo, unsigned int nInfoLen, uint8_t* szSha1, unsigned int* nSha1Len);

unsigned int  SpcVerifyCert(uint8_t *szRootCert, unsigned int nRootCertLen, uint8_t *szCert, unsigned int nCertLen, uint8_t* szTime);

unsigned int  SpcGetValidTimeFromCert(uint8_t *szCert, unsigned int nCertLen, char* szStartTime, char* szEndTime);

unsigned int  SpcGetCertInfo(uint8_t *szCert, unsigned int nCertLen, unsigned int nIndex, uint8_t *szOut, unsigned int *nOutLen);

unsigned int  SpcGetCertPubKey(uint8_t *szCert,  unsigned int nCertLen, uint8_t *szPubKey, unsigned int *nPubKeyLen);

unsigned int  SpcSealEnvelope(uint8_t *szCert, unsigned int nCertLen, uint8_t *szInData, unsigned int nInLen, uint8_t *szOutData, unsigned int* nOutLen);

unsigned int  SpcOpenEnvelope(uint8_t *szInData, unsigned int nInLen,    uint8_t *szOutData, unsigned int *nOutLen);

unsigned int  SpcSymEncrypt(unsigned int nFlag, uint8_t* szInData, unsigned int nInDataLen, uint8_t* szOutData, unsigned int* nOutDataLen,  uint8_t* szKey);

unsigned int  SpcSymDecrypt(unsigned int nFlag, uint8_t* szInData, unsigned int nInDataLen, uint8_t* szOutData, unsigned int* nOutDataLen, uint8_t* szKey);

unsigned int  SpcRSAEncrypt(uint8_t* szCert, unsigned int nCertLen, uint8_t* szInData, unsigned int nInDataLen, uint8_t* szOutData, unsigned int* nOutDataLen);

unsigned int  SpcRSADecrypt(uint8_t* szInData, unsigned int nInDataLen,  uint8_t* szOutData,  unsigned int* nOutDataLen);

unsigned int  SpcGetModuleVer(char* szVersion);

char*  SpcGetErrMsg(unsigned int errCode);

unsigned int  SpcGetRaType(unsigned int *nType);