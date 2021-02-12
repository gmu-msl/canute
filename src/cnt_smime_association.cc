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

#include <sstream>
#include <iomanip>

#include <errno.h>
#include <cstring>
#include <arpa/inet.h>

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
  if (isInitialized())
  {
    clear();
  }

  m_eUsage = p_eUsage;
  m_eSelector = p_eSelector;
  m_eMatching = p_eMatching;

  if (NULL == p_pCertAssocData)
  {
    cnt_log("Unable to init with NULL data\n");
  }
  else if (0 == p_uDataLen)
  {
    cnt_log("Unable to init with 0-len data\n");
  }
  else if (MAT_FULL == m_eMatching)
  {
    if (m_oCert.init(p_pCertAssocData, p_uDataLen, p_eEncoding))
    {
      CntAssociation::init();
    }
  }
  else
  {
    m_oHash.clear();
    m_oHash.insert(m_oHash.begin(),
                   (const char *) p_pCertAssocData, 
                   (const char *) p_pCertAssocData + p_uDataLen);
    CntAssociation::init();
  }

  return isInitialized();
}

bool CntSmimeAssociation::initFromPipe(CntUsage_e p_eUsage,
                                       CntSelector_e p_eSelector,
                                       CntMatching_e p_eMatching)
{
  if (isInitialized())
  {
    clear();
  }

  m_eUsage = p_eUsage;
  m_eSelector = p_eSelector;
  m_eMatching = p_eMatching;

  if (m_oCert.initFromPipe())
  {
    CntAssociation::init();
  }

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
  bool bRet = false;

  if (!isInitialized())
  {
    cnt_log("Association is not initialized.\n");
  }
  else if (MAT_FULL != m_eMatching)
  {
    bRet = m_oCert.calcCertAssocData(m_eSelector, m_eMatching, p_oOutput);
  }
  else
  {
    p_oOutput = m_oHash;
    bRet = true;
  }

  return true;;
}

bool CntSmimeAssociation::initFromFile(CntUsage_e p_eUsage,
                                       CntSelector_e p_eSelector,
                                       CntMatching_e p_eMatching,
                                       std::string &p_sFile)
{
  if (isInitialized())
  {
    clear();
  }

  m_eUsage = p_eUsage;
  m_eSelector = p_eSelector;
  m_eMatching = p_eMatching;

  if (m_oCert.initFromFile(p_sFile))
  {
    CntAssociation::init();
  }

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
  bool bRet = false;

  if (!isInitialized())
  {
    cnt_log("Association is not initialized.\n");
  }
  else if (MAT_FULL != m_eMatching)
  {
    bRet = m_oCert.calcCertAssocData(m_eSelector, m_eMatching, p_oOutput);
  }
  else
  {
    p_oOutput = m_oHash;
    bRet = true;
  }

  return true;;
}

bool CntSmimeAssociation::getHash(std::string &p_sOutput)
{
  bool bRet = false;

  CntBytesVector_t oBytes;
  bRet = getHash(oBytes);
  if (bRet)
  {
    ostringstream oSS;
    size_t uLen = oBytes.size();
    char szOct[4] = {0, 0, 0, 0};
    for (size_t u = 0; u < uLen; u++)
    {
      memset(szOct, 0, 4);
      sprintf(szOct, " %02x", oBytes[u]);
      oSS << szOct;
    }
    p_sOutput = oSS.str();
  }

  return bRet;
}

bool CntSmimeAssociation::toWire(CntBytesVector_t &p_oOutput)
{
  bool bRet = false;

  p_oOutput.clear();
  CntSmimeaRR_t tRR;
  tRR.m_uUsage = m_eUsage;
  tRR.m_uSelector = m_eSelector;
  tRR.m_uMatching = m_eMatching;
  p_oOutput.insert(p_oOutput.end(), (uint8_t *) &tRR, (uint8_t *) &tRR + sizeof(tRR));

  CntBytesVector_t oHash;
  if (MAT_FULL == m_eMatching)
  {
    if (!m_oCert.calcCertAssocData(m_eSelector, m_eMatching, oHash))
    {
      cnt_log("Unable to calc values of cert.\n");
    }
    else
    {
      p_oOutput.insert(p_oOutput.end(), oHash.begin(), oHash.end());
      bRet = true;
    }
  }
  else if (!getHash(oHash))
  {
    cnt_log("Unable to get hash.");
  }
  else
  {
    p_oOutput.insert(p_oOutput.end(), oHash.begin(), oHash.end());

    bRet = true;
  }

  return bRet;
}

bool CntSmimeAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  if (NULL == p_pBuffer)
  {
    cnt_log("NULL buffer specified.\n");
  }
  else if (0 == p_uLen)
  {
    cnt_log("0 length buffer specified.\n");
  }
  // Check to see tht this buffer can have the bare min to be
  // a valid SMIMEA RR (usage + sel + match + acc + data)
  else if (p_uLen < CNT_SMIMEA_MIN_LEN)
  {
    cnt_log("Buffer is too small to contain a SMIMEA RR %lu < %d\n", p_uLen, CNT_SMIMEA_MIN_LEN);
  }
  else if (p_uLen > CNT_SMIMEA_MAX_LEN)
  {
    cnt_log("Buffer is greater than %lu > %u.\n", p_uLen, CNT_SMIMEA_MAX_LEN);
  }
  else
  {
    CntSmimeaRR_t tRR;
    memset(&tRR, 0, sizeof(tRR));
    memcpy(&tRR, p_pBuffer, sizeof(tRR));

    // The rest is cert of hash data
    // char *pCert = &(p_pBuffer[iIdx + uLen]);
    uint8_t *pCert = &(p_pBuffer[sizeof(tRR)]);
    bRet = init((CntUsage_e) tRR.m_uUsage,
                (CntSelector_e) tRR.m_uSelector,
                (CntMatching_e) tRR.m_uMatching,
                pCert,
                p_uLen - (sizeof(tRR)));
  }

  return bRet;
}

bool CntSmimeAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  CntBytesVector_t oBytes;
  bRet = toWire(oBytes);
  if (bRet)
  {
    ostringstream oSS;
    size_t uLen = oBytes.size();
    oSS << "\\# " << uLen << " (";
    char szOct[4] = {0, 0, 0, 0};
    for (size_t u = 0; u < uLen; u++)
    {
      memset(szOct, 0, 4);
      sprintf(szOct, " %02x", oBytes[u]);
      oSS << szOct;
    }
    oSS << " )";

    p_sOutput = oSS.str();
  }

  return bRet;
}

bool CntSmimeAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  size_t uLen = p_sTxt.size();

  if (uLen < CNT_SMIMEA_MIN_TXT_LEN)
  {
    cnt_log("SMIMEA length %lu is too short (< %d)\n", uLen, CNT_SMIMEA_MIN_TXT_LEN);
  }
  else
  {
    stringstream oSS(p_sTxt);
    vector< string > oTokens;
    string sTok;
    while (std::getline(oSS, sTok, ' '))
    {
      if (!sTok.empty() 
          && sTok != "("
          && sTok != ")")
      {
        oTokens.push_back(sTok);
      }
    }

    sTok = oTokens.front();
    if (sTok != "\\#")
    {
      cnt_log("First token is '%s', not '\\#'\n", sTok.c_str());
    }
    else
    {
      int iLen = 0;
      vector< string >::iterator tIter = oTokens.erase(oTokens.begin());
      if (oTokens.end() == tIter)
      {
        cnt_log("Not enough tokens in input string '%s'\n", p_sTxt.c_str());
      }
      else if (0 == (iLen = (int) strtol((*tIter).c_str(), NULL, 10))
               && 0 != errno)
      {
        cnt_log("Unable to convert length '%s' into int: %s\n", (*tIter).c_str(), strerror(errno));
      }
      else
      {
        stringstream oSS2;
        for (tIter = oTokens.erase(tIter);
             oTokens.end() != tIter;
             tIter++)
        {
          oSS2 << *tIter;
        }
        string sBytes = oSS2.str();

        if (iLen != sBytes.size()/2)
        {
          cnt_log("The length field (%d) does not match the number of hex-encoded octets %d in '%s'\n",
                  iLen,
                  (int) sBytes.size()/2,
                  sBytes.c_str());
        }
        else
        {
          CntBytesVector_t oBytes;
          const char *szBytes = sBytes.c_str();
          char szOctet[3] = {0, 0, 0};
          for (int i = 0; i < iLen*2; i++)
          {
            szOctet[0] = szBytes[i++];
            szOctet[1] = szBytes[i];
            uint8_t c = (uint8_t) strtol(szOctet, NULL, 16);
            oBytes.push_back(c);
          }

          bRet = fromWire(oBytes.data(), oBytes.size());
        }
      }
    }
  }

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
  return getCert().verify(p_oBytes);
}

bool CntSmimeAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         CntBytesVector_t &p_oEncryptedBytes)
{
  return getCert().encrypt(p_oBytes, p_oEncryptedBytes);
}

bool CntSmimeAssociation::encrypt(CntBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  return getCert().encrypt(p_oBytes, p_sEncrypted);
}

bool CntSmimeAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  return getCert().encrypt(p_oClear, p_sEncrypted);
}

bool CntSmimeAssociation::decrypt(CntBytesVector_t &p_oEncryptedBytes,
                         CntBytesVector_t &p_oBytes)
{
  return getCert().decrypt(p_oEncryptedBytes, p_oBytes);
}

bool CntSmimeAssociation::decrypt(std::string &p_sEncrypted,
                         CntBytesVector_t &p_oBytes)
{
  return getCert().decrypt(p_sEncrypted, p_oBytes);
}

bool CntSmimeAssociation::sign(CntBytesVector_t &p_oBytes,
                      CntBytesVector_t &p_oSignature)
{
  return getCert().sign(p_oBytes, p_oSignature);
}

bool CntSmimeAssociation::sign(CntBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  return getCert().sign(p_oBytes, p_sSignature);
}

CntAssociation &CntSmimeAssociation::operator=(const CntSmimeAssociation &p_oRHS)
{
  CntAssociation::operator=(p_oRHS);
  m_eUsage = p_oRHS.m_eUsage;
  m_eSelector = p_oRHS.m_eSelector;
  m_eMatching = p_oRHS.m_eMatching;
  m_oCert = p_oRHS.m_oCert;
  m_oHash = p_oRHS.m_oHash;

  return *this;
}

bool CntSmimeAssociation::clear()
{
  m_bInit = false;
  m_eUsage = USG_PRE_INIT;
  m_eSelector = SEL_PRE_INIT;
  m_eMatching = MAT_PRE_INIT;
  m_oCert.clear();
  m_oHash.clear();

  return true;
}

