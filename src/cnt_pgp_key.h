/*
   Copyright (c) <2015> Verisign, Inc.

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


#ifndef _CNT_PGP_KEY_H
#define _CNT_PGP_KEY_H

#include <gpgme.h>

#include <string>

#include "cnt_defs.h"

class CntPgpKey
{
  // Member Variables
  private:
    bool m_bInit;
    char *m_pPubKeyBuf;
    size_t m_uPubKeyBufLen;
    gpgme_ctx_t m_pGpgmeCtx;
    gpgme_key_t m_pPubKey;
    std::string m_sID;
    std::string m_sHomeDir;
    std::string m_sKeyFingerprint;
    CntBytesVector_t m_oPubKey;

  // Methods
  public:
    CntPgpKey();
    virtual ~CntPgpKey();

    bool init(CntBytesVector_t &p_oBytes, const char *p_szHomeDir = NULL);
    bool init(CntBytesVector_t &p_oBytes, std::string &p_sHomeDir);
    bool initLocal(std::string &p_sID, const char *p_szHomeDir = NULL);
    bool initLocal(std::string &p_sID, std::string &p_sHomeDir);
    bool init(uint8_t *p_pBytes, size_t p_uBytesLen);
    bool calcCertAssocData(CntSelector_e p_eSelector,
                  CntMatching_e p_eMatching,
                  CntBytesVector_t &p_oHash);
    bool calcCertAssocData(CntSelector_e p_eSelector,
                  CntMatching_e p_eMatching,
                  std::string &p_sHash);
    bool clear();

    uint8_t *getPrivateKey();
    size_t getPrivateKeyLen();

    uint8_t *getBytes();
    size_t getBytesLen();

    bool verify(CntBytesVector_t &p_oBytes);
    bool encrypt(CntBytesVector_t &p_oBytes,
                 CntBytesVector_t &p_oEncryptedBytes);
    bool encrypt(CntBytesVector_t &p_oBytes,
                 std::string &p_sEncrypted);
    bool encrypt(std::string &p_oClear,
                 std::string &p_sEncrypted);
    bool decrypt(CntBytesVector_t &p_oEncryptedBytes,
                 CntBytesVector_t &p_oBytes);
    bool decrypt(std::string &p_sEncrypted,
                 CntBytesVector_t &p_oBytes);
    bool sign(CntBytesVector_t &p_oBytes,
              CntBytesVector_t &p_oSignature);
    bool sign(CntBytesVector_t &p_oBytes,
              std::string &p_sSignature);

    virtual CntPgpKey &operator=(CntPgpKey const &p_oRHS);

  protected:
    bool primeGpgme();
};

#endif
