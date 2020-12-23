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


#include <stdio.h>
#include <inttypes.h>

#include "cnt_smime_association.h"
#include "cnt_defs.h"

using namespace std;

CntSmimeAssociation::CntSmimeAssociation()
  : m_eUsage(USG_PRE_INIT),
    m_eSelector(SEL_PRE_INIT),
    m_eMatching(MAT_PRE_INIT)
{

}

CntSmimeAssociation::CntSmimeAssociation(const CntSmimeAssociation &p_oRHS)
  : m_eUsage(USG_PRE_INIT),
    m_eSelector(SEL_PRE_INIT),
    m_eMatching(MAT_PRE_INIT)
{
  (*this) = p_oRHS;
}

CntSmimeAssociation::~CntSmimeAssociation()
{
  clear();
}

bool CntSmimeAssociation::init(CntUsage_e p_eUsage,
              CntSelector_e p_eSelector,
              CntMatching_e p_eMatching,
              uint8_t *p_pCertAssocData,
              size_t p_uDataLen,
              CntX509Encoding_e p_eEncoding /*= CNT_X509_DER*/)
{
  return isInitialized();
}

bool CntSmimeAssociation::initFromFile(CntUsage_e p_eUsage,
                                       CntSelector_e p_eSelector,
                                       CntMatching_e p_eMatching,
                                       std::string &p_sFile)
{
  return isInitialized();
}

bool CntSmimeAssociation::isFullCert()
{
  return (SEL_FULL == m_eSelector && MAT_FULL == m_eMatching);
}

bool CntSmimeAssociation::isFingerprintCert()
{
  return MAT_FULL != m_eMatching;
}

bool CntSmimeAssociation::isTA()
{
  return USG_PKIX_TA == m_eUsage || USG_DANE_TA == m_eUsage;
}

bool CntSmimeAssociation::isPKIX()
{
  return USG_PKIX_TA == m_eUsage || USG_PKIX_EE == m_eUsage;
}

bool CntSmimeAssociation::isEE()
{
  return USG_PKIX_EE== m_eUsage || USG_DANE_EE == m_eUsage;
}

CntUsage_e CntSmimeAssociation::getUsage()
{
  return m_eUsage;
}

CntSelector_e CntSmimeAssociation::getSelector()
{
  return m_eSelector;
}

CntMatching_e CntSmimeAssociation::getMatching()
{
  return m_eMatching;
}

bool CntSmimeAssociation::getHash(CntBytesVector_t &p_oOutput)
{

  return true;;
}

bool CntSmimeAssociation::getHash(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool CntSmimeAssociation::toWire(CntBytesVector_t &p_oOutput)
{
  bool bRet = false;

  return bRet;
}

bool CntSmimeAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  return bRet;
}

bool CntSmimeAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool CntSmimeAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  return bRet;
}

CntSmimeCert &CntSmimeAssociation::getCert()
{
  return m_oCert;
}

void CntSmimeAssociation::setCert(CntSmimeCert &p_oCert)
{
  m_oCert = p_oCert;
}

bool CntSmimeAssociation::verify(CntBytesVector_t &p_oBytes)
{
  return false;
}

bool CntSmimeAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         CntBytesVector_t &p_oEncryptedBytes)
{
  return false;
}

bool CntSmimeAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  return false;
}

bool CntSmimeAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  return false;
}

bool CntSmimeAssociation::decrypt(CntBytesVector_t &p_oEncryptedBytes,
                         CntBytesVector_t &p_oBytes)
{
  return false;
}

bool CntSmimeAssociation::decrypt(std::string &p_sEncrypted,
                         CntBytesVector_t &p_oBytes)
{
  return false;
}

bool CntSmimeAssociation::sign(CntBytesVector_t &p_oBytes,
                      CntBytesVector_t &p_oSignature)
{
  return false;
}

bool CntSmimeAssociation::sign(CntBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  return false;
}

CntAssociation &CntSmimeAssociation::operator=(const CntSmimeAssociation &p_oRHS)
{
  CntAssociation::operator=(p_oRHS);
  m_eUsage = p_oRHS.m_eUsage;
  m_eSelector = p_oRHS.m_eSelector;
  m_eMatching = p_oRHS.m_eMatching;
  m_oHash = p_oRHS.m_oHash;

  return *this;
}

bool CntSmimeAssociation::clear()
{
  m_bInit = false;
  m_eUsage = USG_PRE_INIT;
  m_eSelector = SEL_PRE_INIT;
  m_eMatching = MAT_PRE_INIT;

  return true;
}

