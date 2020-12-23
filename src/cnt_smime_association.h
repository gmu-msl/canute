/*
   Copyright (c) <2014> Verisign, Inc.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights 
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
   copies of the Software, and to permit persons to whom the Software is furnished 
   to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all 
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
   PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
   OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef _CNT_SMIME_ASSOCIATION_H
#define _CNT_SMIME_ASSOCIATION_H

#include <string>

#include "cnt_association.h"
#ifdef _CNT_NO_SMIME
class CntSmimeCert
{
  public:
    CntSmimeCert(){};
    virtual ~CntSmimeCert(){};
};
#else
#include "cnt_smime_cert.h"
#endif
#include "cnt_defs.h"

class CntSmimeAssociation : public CntAssociation
{
  // Member Variables
  private:
    CntUsage_e m_eUsage;
    CntSelector_e m_eSelector;
    CntMatching_e m_eMatching;
    CntBytesVector_t m_oHash;
    CntSmimeCert m_oCert;

  // Methods
  public:
    CntSmimeAssociation();
    CntSmimeAssociation(const CntSmimeAssociation &p_oRHS);
    virtual ~CntSmimeAssociation();

    bool init(CntUsage_e p_eUsage,
              CntSelector_e p_eSelector,
              CntMatching_e p_eMatching,
              uint8_t *p_pCertAssocData,
              size_t p_uDataLen,
              CntX509Encoding_e p_eEncoding = CNT_X509_DER);
    bool initFromFile(CntUsage_e p_eUsage,
                      CntSelector_e p_eSelector,
                      CntMatching_e p_eMatching,
                      std::string &p_sFile);


    bool isFullCert();
    bool isFingerprintCert();
    bool isTA();
    bool isPKIX();
    bool isEE();

    CntUsage_e getUsage();
    CntSelector_e getSelector();
    CntMatching_e getMatching();
    bool getHash(CntBytesVector_t &p_oOutput);
    bool getHash(std::string &p_sOutput);

    virtual bool toWire(CntBytesVector_t &p_oOutput);
    virtual bool fromWire(uint8_t *p_pBuffer, size_t p_uLen);

    virtual bool toText(std::string &p_sOutput);
    virtual bool fromText(std::string &p_sTxt);

    CntSmimeCert &getCert();
    void setCert(CntSmimeCert &p_oCert);

    virtual bool verify(CntBytesVector_t &p_oBytes);
    virtual bool encrypt(CntBytesVector_t &p_oBytes,
                         CntBytesVector_t &p_oEncryptedBytes);
    virtual bool encrypt(CntBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted);
    virtual bool encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted);
    virtual bool decrypt(CntBytesVector_t &p_oEncryptedBytes,
                         CntBytesVector_t &p_oBytes);
    virtual bool decrypt(std::string &p_sEncrypted,
                         CntBytesVector_t &p_oBytes);
    virtual bool sign(CntBytesVector_t &p_oBytes,
                      CntBytesVector_t &p_oSignature);
    virtual bool sign(CntBytesVector_t &p_oBytes,
                      std::string &p_sSignature);

    virtual CntAssociation &operator=(const CntSmimeAssociation &p_oRHS);

    virtual bool clear();
};

#endif
