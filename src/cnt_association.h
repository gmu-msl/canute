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


#ifndef _CNT_ASSOCIATION_H
#define _CNT_ASSOCIATION_H

#include <string>

#include "cnt_defs.h"

class CntAssociation
{
  // Member Variables
  private:

  protected:
    bool m_bInit;

  // Methods
  public:
    CntAssociation() : m_bInit(false) {};
    CntAssociation(const CntAssociation &p_oRHS)  : m_bInit(false) {*this = p_oRHS;};
    virtual ~CntAssociation() {};

    bool isInitialized() {return m_bInit;};

    virtual bool toWire(CntBytesVector_t &p_oOutput) = 0;
    virtual bool fromWire(uint8_t *p_pBuffer, size_t p_uLen) = 0;

    virtual bool toText(std::string &p_sOutput) = 0;
    virtual bool fromText(std::string &p_sTxt) = 0;

    virtual bool verify(CntBytesVector_t &p_oBytes) = 0;
    virtual bool encrypt(CntBytesVector_t &p_oBytes,
                         CntBytesVector_t &p_oEncryptedBytes) = 0;
    virtual bool encrypt(CntBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted) = 0;
    virtual bool encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted) = 0;
    virtual bool decrypt(CntBytesVector_t &p_oEncryptedBytes,
                         CntBytesVector_t &p_oBytes) = 0;
    virtual bool decrypt(std::string &p_sEncrypted,
                         CntBytesVector_t &p_oBytes) = 0;
    virtual bool sign(CntBytesVector_t &p_oBytes,
                      CntBytesVector_t &p_oSignature) = 0;
    virtual bool sign(CntBytesVector_t &p_oBytes,
                      std::string &p_sSignature) = 0;


    virtual CntAssociation &operator=(const CntAssociation &p_oRHS) {m_bInit = p_oRHS.m_bInit; return *this;};

  protected:
    bool init() {m_bInit = true; return m_bInit;};
    virtual bool clear() = 0;
};

#endif
