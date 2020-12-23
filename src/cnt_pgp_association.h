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


#ifndef _CNT_PGP_ASSOCIATION_H
#define _CNT_PGP_ASSOCIATION_H

#include <string>

#include "cnt_association.h"
#ifdef _CNT_NO_PGP
class CntPgpKey
{
  public: 
    CntPgpKey(){};
    virtual ~CntPgpKey(){};
};
#else
#include "cnt_pgp_key.h"
#endif
#include "cnt_defs.h"

class CntPgpAssociation : public CntAssociation
{
  // Member Variables
  private:
    CntPgpKey m_oKey;

  // Methods
  public:
    CntPgpAssociation();
    CntPgpAssociation(const CntPgpAssociation &p_oRHS);
    virtual ~CntPgpAssociation();

    bool init(CntPgpKey &p_oKey);
    bool initLocal(std::string &p_sID, const char *p_szHomeDir = NULL);


    virtual bool toWire(CntBytesVector_t &p_oOutput);
    virtual bool fromWire(uint8_t *p_pBuffer, size_t p_uLen);

    virtual bool toText(std::string &p_sOutput);
    virtual bool fromText(std::string &p_sTxt);

    CntPgpKey &getKey();
    void setKey(CntPgpKey &p_oKey);

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

    virtual CntAssociation &operator=(const CntPgpAssociation &p_oRHS);

    virtual bool clear();
};

#endif
