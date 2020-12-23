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


#include "cnt_pgp_association.h"
#include "cnt_defs.h"

using namespace std;

CntPgpAssociation::CntPgpAssociation()
  : CntAssociation()
{

}

CntPgpAssociation::CntPgpAssociation(const CntPgpAssociation &p_oRHS)
  : CntAssociation()
{
  (*this) = p_oRHS;
}

CntPgpAssociation::~CntPgpAssociation()
{
  clear();
}

bool CntPgpAssociation::init(CntPgpKey &p_oKey)
{
  return isInitialized();
}

bool CntPgpAssociation::initLocal(std::string &p_sID, const char *p_szHomeDir /*= NULL*/)
{
  return isInitialized();
}

bool CntPgpAssociation::toWire(CntBytesVector_t &p_oOutput)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  return bRet;
}

CntPgpKey &CntPgpAssociation::getKey()
{
  return m_oKey;
}

void CntPgpAssociation::setKey(CntPgpKey &p_oKey)
{
  m_oKey = p_oKey;
}

bool CntPgpAssociation::verify(CntBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         CntBytesVector_t &p_oEncryptedBytes)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::decrypt(CntBytesVector_t &p_oEncryptedBytes,
                         CntBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::decrypt(std::string &p_sEncrypted,
                         CntBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::sign(CntBytesVector_t &p_oBytes,
                      CntBytesVector_t &p_oSignature)
{
  bool bRet = false;

  return bRet;
}

bool CntPgpAssociation::sign(CntBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  bool bRet = false;

  return bRet;
}

CntAssociation &CntPgpAssociation::operator=(const CntPgpAssociation &p_oRHS)
{
  CntAssociation::operator=(p_oRHS);

  return *this;
}

bool CntPgpAssociation::clear()
{

  return false;
}

