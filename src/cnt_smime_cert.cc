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

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <fstream>
#include <sstream>
#include <iostream>

#include <cstring>

#include "cnt_smime_cert.h"


using namespace std;

CntSmimeCert::CntSmimeCert()
  : m_bInit(false),
    m_pCertBuf(NULL),
    m_pPrivKeyBuf(NULL),
    m_uCertBufLen(0),
    m_uPrivKeyBufLen(0),
    m_eEncoding(CNT_ENC_PRE_INIT),
    m_pCert(NULL),
    m_pPubKey(NULL),
    m_pPrivKey(NULL),
    m_pStore(NULL)
{

}

CntSmimeCert::CntSmimeCert(const CntSmimeCert &p_oRHS)
  : m_bInit(false),
    m_pCertBuf(NULL),
    m_pPrivKeyBuf(NULL),
    m_uCertBufLen(0),
    m_uPrivKeyBufLen(0),
    m_eEncoding(CNT_ENC_PRE_INIT),
    m_pCert(NULL),
    m_pPubKey(NULL),
    m_pPrivKey(NULL),
    m_pStore(NULL)
{
  (*this) = p_oRHS;
}

CntSmimeCert::~CntSmimeCert()
{
  clear();
}

bool CntSmimeCert::init(CntBytesVector_t &p_oBytes, CntX509Encoding_e p_eEncoding /*= CNT_X509_PEM*/)
{
  clear();
  
  BIO *pCrypto = NULL;
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  char pErrBuff[1024];
  memset(pErrBuff, 0, 1024);

  if (0 == p_oBytes.size())
  {
    cnt_log("Unable to init with empty buffer.\n");
  }
  else
  {
    m_eEncoding = p_eEncoding;
    m_uCertBufLen = p_oBytes.size();
    m_pCertBuf = new uint8_t[m_uCertBufLen];
    memset(m_pCertBuf, 0, m_uCertBufLen);
    memcpy(m_pCertBuf, p_oBytes.data(), m_uCertBufLen);

    pCrypto = BIO_new_mem_buf((void *) p_oBytes.data(), p_oBytes.size());
    if (NULL == pCrypto)
    {
      cnt_log("Unable to load cyrpto bytes: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else if (CNT_X509_PEM == p_eEncoding
             && NULL == (m_pCert = PEM_read_bio_X509(pCrypto, NULL, 0, NULL)))
    {
      cnt_log("Unable to read PEM X509 out of BIO: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else if (CNT_X509_DER == p_eEncoding
             && NULL == (m_pCert = d2i_X509_bio(pCrypto, NULL)))
    {
      cnt_log("Unable to read DER encoded X509 out of BIO: %s\n", 
               ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else if (1 != BIO_reset(pCrypto))
    {
      cnt_log("Unable to reset BIO pointer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else if (NULL == (m_pPubKey = X509_PUBKEY_get(X509_get_X509_PUBKEY(m_pCert))))
    {
      cnt_log("Unable to create public key from cert: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else
    {
      // m_uCertBufLen = iErr;

      if (NULL == (m_pPrivKey = PEM_read_bio_PrivateKey(pCrypto, NULL, 0, NULL)))
      {
        cnt_log("Unable to create private key from BIO: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        m_pPrivKey = NULL;
      }

      m_bInit = true;
    }
  }
  if (pCrypto)
  {
    BIO_free(pCrypto);
  }

  return m_bInit;
}

bool CntSmimeCert::initFromPipe()
{
  // read whole PEM cert into memory piped from stdin (it's not _that_ big, right?)
  std::string s((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  // convert to byte vector to pass to init.
  CntBytesVector_t oBytes(s.begin(),s.end());

  return init(oBytes);
}

bool CntSmimeCert::initFromFile(std::string &p_sFile)
{
  ifstream oIF(p_sFile.c_str(), std::ios::binary);
  CntBytesVector_t oBytes((std::istreambuf_iterator<char>(oIF)),
                         std::istreambuf_iterator<char>());

  return init(oBytes);
}

bool CntSmimeCert::init(uint8_t *p_pBytes, 
                        size_t p_uBytesLen, 
                        CntX509Encoding_e p_eEncoding /*= CNT_X509_PEM*/)
{
  bool bRet = false;

  if (NULL == p_pBytes)
  {
    cnt_log("Unable to init with NULL bytes.\n");
  }
  else if (0 == p_uBytesLen)
  {
    cnt_log("Unable to init with 0 bytes.\n");
  }
  else
  {
    CntBytesVector_t oVec(p_pBytes, p_pBytes + p_uBytesLen);

    bRet = init(oVec, p_eEncoding);
  }

  return bRet;
}

bool CntSmimeCert::calcCertAssocData(CntSelector_e p_eSelector,
                            CntMatching_e p_eMatching,
                            CntBytesVector_t &p_oHash)
{
  bool bRet = false;

  if (!m_bInit)
  {
    cnt_log("Unable to calculate hash over uninitialized certifiate.\n");
  }
  else
  {
    unsigned char *pBuff = NULL;
    unsigned char *pBuffPtr = NULL;
    int iLen = 0;
    char pErrBuff[1024];
    memset(pErrBuff, 0, 1024);
    p_oHash.clear();

    if (SEL_FULL == p_eSelector)
    {
      // call i2d_X509 (?)
      iLen = i2d_X509(m_pCert, NULL);
      if (iLen <= 0)
      {
        cnt_log("Unable to query X.509 cert's length: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
      }
      else
      {
        pBuff = (unsigned char *) OPENSSL_malloc(iLen);
        pBuffPtr = pBuff;
        if (NULL == pBuff)
        {
          cnt_log("Unable to allocate buffer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
          iLen = 0;
        }
        else if (0 >= (iLen = i2d_X509(m_pCert, &pBuffPtr)))
        {
          cnt_log("Unable to parse X.509 cert (2nd time?): %s\n", ERR_error_string(ERR_get_error(),
                pErrBuff));
        }
      }
    }
    else if (SEL_SPKI == p_eSelector)
    {
      iLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(m_pCert), NULL);
      if (iLen <= 0)
      {
        cnt_log("Unable to get SPKI from cert: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
      }
      else
      {
        pBuff = (unsigned char *) OPENSSL_malloc(iLen);
        pBuffPtr = pBuff;
        if (NULL == pBuff)
        {
          cnt_log("Unable to allocate buffer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
          iLen = 0;
        }
        else if (0 >= (iLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(m_pCert), &pBuffPtr)))
        {
          cnt_log("Unable to parse X.509 cert into SPKI (2nd time?): %s\n", ERR_error_string(ERR_get_error(),
                pErrBuff));
        }
      }
    }
    else
    {
      cnt_log("Selector %d is not recognized.\n", (int) p_eSelector);
    }

    if (iLen > 0)
    {
      if (MAT_FULL == p_eMatching)
      {
        p_oHash.insert(p_oHash.begin(), pBuff, pBuff + iLen);
        bRet = true;
      }
      else if (MAT_SHA256 == p_eMatching)
      {
        unsigned char pHash[SHA256_DIGEST_LENGTH];
        memset(pHash, 0, SHA256_DIGEST_LENGTH);
        SHA256_CTX oCtx;
        if (!SHA256_Init(&oCtx))
        {
          cnt_log("Unable to init SHA256 context: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else if (!SHA256_Update(&oCtx, pBuff, iLen))
        {
          cnt_log("Unable to update hash: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else if (!SHA256_Final(pHash, &oCtx))
        {
          cnt_log("Unable to finalize hash: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else
        {
          p_oHash.insert(p_oHash.begin(), pHash, pHash + SHA256_DIGEST_LENGTH);
          bRet = true;
        }
      }
      else if (MAT_SHA512 == p_eMatching)
      {
        unsigned char pHash[SHA512_DIGEST_LENGTH];
        memset(pHash, 0, SHA512_DIGEST_LENGTH);
        SHA512_CTX oCtx;
        if (!SHA512_Init(&oCtx))
        {
          cnt_log("Unable to init SHA256 context: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else if (!SHA512_Update(&oCtx, pBuff, iLen))
        {
          cnt_log("Unable to update hash: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else if (!SHA512_Final(pHash, &oCtx))
        {
          cnt_log("Unable to finalize hash: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
        }
        else
        {
          p_oHash.insert(p_oHash.begin(), pHash, pHash + SHA512_DIGEST_LENGTH);
          bRet = true;
        }
      }
      else
      {
        cnt_log("Matching %d is not recognized.\n", p_eMatching);
      }
    }

    if (NULL != pBuff)
    {
      OPENSSL_free(pBuff);
    }
  }

  return bRet;
}

bool CntSmimeCert::calcCertAssocData(CntSelector_e p_eSelector,
                            CntMatching_e p_eMatching,
                            std::string &p_sHash)
{
  CntBytesVector_t oBytes;
  bool bRet = calcCertAssocData(p_eSelector, p_eMatching, oBytes);

  if (bRet)
  {
    ostringstream oSS;
    size_t uLen = oBytes.size();
    char szOct[4] = {0, 0, 0, 0};
    for (size_t u = 0; u < uLen; u++)
    {
      memset(szOct, 0, 4);
      sprintf(szOct, "%02x", oBytes[u]);
      oSS << szOct;
    }
    p_sHash = oSS.str();
  }

  return bRet;
}

bool CntSmimeCert::clear()
{
  m_bInit = false;

  if (NULL != m_pCertBuf)
  {
    delete[] m_pCertBuf;
    m_pCertBuf = NULL;
  }

  if (NULL != m_pPrivKeyBuf)
  {
    delete[] m_pPrivKeyBuf;
    m_pPrivKeyBuf = NULL;
  }

  if (NULL != m_pCert)
  {
    X509_free(m_pCert);
    m_pCert = NULL;
  }

  if (NULL != m_pPubKey)
  {
    EVP_PKEY_free(m_pPubKey);
    m_pPubKey = NULL;
  }

  if (NULL != m_pPrivKey)
  {
    EVP_PKEY_free(m_pPrivKey);
    m_pPrivKey = NULL;
  }

  if (NULL != m_pStore)
  {
    X509_STORE_free(m_pStore);
    m_pStore = NULL;
  }

  return true;
}

uint8_t *CntSmimeCert::getPrivateKey()
{
  return m_pPrivKeyBuf;
}

size_t CntSmimeCert::getPrivateKeyLen()
{
  return m_uPrivKeyBufLen;
}

uint8_t *CntSmimeCert::getBytes()
{
  return m_pCertBuf;
}

size_t CntSmimeCert::getBytesLen()
{
  return m_uCertBufLen;
}

bool CntSmimeCert::verify(CntBytesVector_t &p_oBytes)
{
  bool bRet = false;

  BIO *pIn = NULL;
  BIO *pContent = NULL;
  CMS_ContentInfo *pCMS = NULL;
  STACK_OF(X509) *pRecipStack = NULL;
  char pErrBuff[1024];
  memset(pErrBuff, 0, 1024);
  X509 *pCert = NULL;

  if (!m_bInit)
  {
    cnt_log("Unable to verify before cert object is initialized.\n");
  }
  else if (NULL == (pCert = X509_dup(m_pCert)))
  {
    cnt_log("Unable to dup member X.509 cert: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  // Create a recipient stack and add recipient cert to it.
  else if (NULL == (pRecipStack = sk_X509_new_null()))
  {
    cnt_log("Unable to create recip stack: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (!sk_X509_push(pRecipStack, pCert))
  {
    cnt_log("Unable to add certificate to recipient stack: %s\n", ERR_error_string(ERR_get_error(),
          pErrBuff));
  }
  else if (NULL == (pIn = BIO_new_mem_buf((void *) p_oBytes.data(), p_oBytes.size())))
  {
    cnt_log("Unable to create new memory buffer for email body: %s\n", ERR_error_string(ERR_get_error(),
          pErrBuff)); 
  }
  else if (NULL == (pCMS = SMIME_read_CMS(pIn, &pContent)))
  {
    cnt_log("Unable to create CMS and BIO content buffer: %s\n", ERR_error_string(ERR_get_error(),
          pErrBuff));
  }
  else
  {
    // Everything is setup.  A failure here is a cypto validation failure (not code).
    bRet = (1 == CMS_verify(pCMS, pRecipStack, NULL, pContent, NULL, CMS_NOINTERN|CMS_NO_SIGNER_CERT_VERIFY));
    if (!bRet)
    {
      cnt_log("Unable to verify content buffer: %s\n", ERR_error_string(ERR_get_error(),
            pErrBuff));
    }
  }

  if (NULL != pIn)
  {
    BIO_free(pIn);
  }
  if (NULL != pCMS)
  {
    CMS_ContentInfo_free(pCMS);
  }
  if (NULL != pRecipStack)
  {
    sk_X509_pop_free(pRecipStack, X509_free);
  }

  return bRet;
}

bool CntSmimeCert::encrypt(CntBytesVector_t &p_oBytes,
                 CntBytesVector_t &p_oEncryptedBytes)
{
  bool bRet = false;

  int iFlags = 0;
  BIO *pIn = NULL;
  BIO *pOut = BIO_new(BIO_s_mem());
  PKCS7 *pP7 = NULL;
  STACK_OF(X509) *pRecipStack = NULL;
  char pErrBuff[1024];
  memset(pErrBuff, 0, 1024);
  X509 *pCert = NULL;

  // Create a recipient stack and add recipient cert to it.
  pRecipStack = sk_X509_new_null();
  if (NULL == pRecipStack)
  {
    cnt_log("Unable to create recip stack: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (NULL == (pCert = X509_dup(m_pCert)))
  {
    cnt_log("Unable to dup member X.509 cert: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (!sk_X509_push(pRecipStack, pCert))
  {
    cnt_log("Unable to add certificate to recipient stack: %s\n", ERR_error_string(ERR_get_error(),
          pErrBuff));
  }
  else if (NULL == (pIn = BIO_new_mem_buf((void *) p_oBytes.data(), p_oBytes.size())))
  {
    cnt_log("Unable to load clear-text into new buffer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (NULL == (pP7 = PKCS7_encrypt(pRecipStack, pIn, EVP_des_ede3_cbc(), iFlags)))
  {
    cnt_log("Unable to encrypt with PKCS7 call: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (!SMIME_write_PKCS7(pOut, pP7, pIn, iFlags))
  {
    cnt_log("Unable to format cipher text into SMIME: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else
  {
    char *pSmimeTxt = NULL;
    int iLen = BIO_get_mem_data(pOut, &pSmimeTxt);
    p_oEncryptedBytes.assign(pSmimeTxt, pSmimeTxt + iLen);

    bRet = true;
  }

  if (NULL != pP7)
  {
    PKCS7_free(pP7);
  }
  if (NULL != pRecipStack)
  {
    sk_X509_pop_free(pRecipStack, X509_free);
  }
  if (NULL != pIn)
  {
    BIO_free(pIn);
  }
  if (NULL != pOut)
  {
    BIO_free(pOut);
  }

  return bRet;
}

bool CntSmimeCert::encrypt(CntBytesVector_t &p_oBytes,
                 std::string &p_sEncrypted)
{
  CntBytesVector_t oEncBytes;
  bool bRet = encrypt(p_oBytes, oEncBytes);
  p_sEncrypted.assign((char *) oEncBytes.data(), oEncBytes.size());
#ifdef CNT_DEBUG
  if (bRet)
  {
    cnt_log("Took in clear-text: %s\n", (char *) p_oBytes.data());
    cnt_log("Converted to S/MIME buffer:\n%s\n", p_sEncrypted.c_str());
  }
#endif

  return bRet;
}

bool CntSmimeCert::encrypt(std::string &p_sClear,
                           std::string &p_sEncrypted)
{
  CntBytesVector_t oClearBytes(p_sClear.c_str(), p_sClear.c_str() + p_sClear.size());
  CntBytesVector_t oEncBytes;
cnt_log("Took %lu clear bytes in, and moved them to %lu clear bytes\n", p_sClear.size(), oClearBytes.size());
  bool bRet = encrypt(oClearBytes, oEncBytes);
  if (bRet)
  {
    p_sEncrypted.assign((char *) oEncBytes.data(), oEncBytes.size());
#ifdef CNT_DEBUG
    cnt_log("Took in clear-text: %s\n", (char *) p_sClear.c_str());
    cnt_log("Converted to S/MIME buffer:\n%s\n", p_sEncrypted.c_str());
#endif
  }

  return bRet;
}

bool CntSmimeCert::decrypt(CntBytesVector_t &p_oEncryptedBytes,
                 CntBytesVector_t &p_oBytes)
{
  bool bRet = false;

  if (NULL == m_pPrivKey)
  {
    cnt_log("Unable to decrypt without private key.\n");
  }
  else
  {
    char pErrBuff[1024];
        memset(pErrBuff, 0, 1024);

    CMS_ContentInfo *pCMS = NULL;
    BIO *pOut = BIO_new(BIO_s_mem());
    char *pOutTxt = NULL;
    int iLen = 0;
    BIO *pIn = BIO_new_mem_buf(p_oEncryptedBytes.data(), p_oEncryptedBytes.size());
    if (NULL == pIn)
    {
      cnt_log("Unable to load encrypted data into BIO buffer: %s\n", ERR_error_string(ERR_get_error(),
            pErrBuff));
    }
    else if (NULL == (pCMS = SMIME_read_CMS(pIn, NULL)))
    {
      cnt_log("Unable to read data from BIO buffer to S/MIME: %s\n", ERR_error_string(ERR_get_error(),
            pErrBuff));
    }
    else if (!CMS_decrypt(pCMS, m_pPrivKey, NULL, NULL, pOut, 0))
    {
      cnt_log("Unable to decrypt: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
    }
    else if (0 >= (iLen = BIO_get_mem_data(pOut, &pOutTxt)))
    {
      cnt_log("Unable to get pointer to clear-text result: %s\n", ERR_error_string(ERR_get_error(),
            pErrBuff));
    }
    else
    {
      p_oBytes.assign(pOutTxt, pOutTxt + iLen);

      bRet = true;
    }

    if (NULL != pCMS)
    {
      CMS_ContentInfo_free(pCMS);
    }
    if (NULL != pIn)
    {
      BIO_free(pIn);
    }
    if (NULL != pOut)
    {
      BIO_free(pOut);
    }
  }

  return bRet;
}

bool CntSmimeCert::decrypt(std::string &p_sEncrypted,
                 CntBytesVector_t &p_oBytes)
{
  CntBytesVector_t oEncBytes(p_sEncrypted.c_str(), p_sEncrypted.c_str() + p_sEncrypted.size());
  bool bRet = decrypt(oEncBytes, p_oBytes);
#ifdef CNT_DEBUG
  if (bRet)
  {
    cnt_log("Took in cipher-text: %s\n", p_sEncrypted.c_str());
    cnt_log("Converted to %s", (char *) p_oBytes.data());
  }
#endif

  return bRet;
}

bool CntSmimeCert::sign(CntBytesVector_t &p_oBytes,
              CntBytesVector_t &p_oSignature)
{
  bool bRet = false;

  BIO *pIn = NULL;
  BIO *pOut = BIO_new(BIO_s_mem());
  CMS_ContentInfo *pCMS = NULL;
  char pErrBuff[1024];
      memset(pErrBuff, 0, 1024);

  if (!m_bInit)
  {
    cnt_log("Unable to sign before initialization.\n");
  }
  else if (NULL == m_pPrivKey)
  {
    cnt_log("Unable to sign without a private key.\n");
  }
  else if (NULL == m_pCert)
  {
    cnt_log("Member cert is NULL.\n");
  }
  else if (NULL == pOut)
  {
    cnt_log("Unable to allocate output buffer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (NULL == (pIn = BIO_new_mem_buf((void *) p_oBytes.data(), p_oBytes.size())))
  {
    cnt_log("Unable to read input bytes into buffer: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (NULL == (pCMS = CMS_sign(NULL, NULL, NULL, pIn, CMS_STREAM|CMS_DETACHED)))
  {
    cnt_log("Unable to create detached signature: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else if (NULL == CMS_add1_signer(pCMS, m_pCert, m_pPrivKey, NULL, 0))
  {
    cnt_log("Unable to add signer: '%s' SSLeay version: '%s'\n", 
            ERR_error_string(ERR_get_error(), pErrBuff),
            SSLeay_version(SSLEAY_VERSION|SSLEAY_DIR));
  }
  else if (!SMIME_write_CMS(pOut, pCMS, pIn, CMS_STREAM|CMS_DETACHED))
  {
    cnt_log("Unable to create S/MIME signature: %s\n", ERR_error_string(ERR_get_error(), pErrBuff));
  }
  else
  {
    char *pSmimeTxt = NULL;
    int iLen = BIO_get_mem_data(pOut, &pSmimeTxt);
    p_oSignature.assign(pSmimeTxt, pSmimeTxt + iLen);

    bRet = true;
  }

  if (NULL != pIn)
  {
    BIO_free(pIn);
  }
  if (NULL != pOut)
  {
    BIO_free(pOut);
  }
  if (NULL != pCMS)
  {
    CMS_ContentInfo_free(pCMS);
  }

  return bRet;
}

bool CntSmimeCert::sign(CntBytesVector_t &p_oBytes,
              std::string &p_sSignature)
{
  CntBytesVector_t oSig;
  bool bRet = sign(p_oBytes, oSig);
  p_sSignature.assign((char *) oSig.data(), oSig.size());

  return bRet;
}

/*
CntSmimeCert &CntSmimeCert::operator2=(CntSmimeCert const &p_oRHS)
{
  clear();
  m_bInit = p_oRHS.m_bInit;

  if (m_bInit)
  {
    m_uCertBufLen = p_oRHS.m_uCertBufLen;
    m_uPrivKeyBufLen = p_oRHS.m_uPrivKeyBufLen;

    if (m_uCertBufLen > 0)
    {
      m_pCertBuf = new uint8_t[m_uCertBufLen];
      memset(m_pCertBuf, 0, m_uCertBufLen);
      memcpy(m_pCertBuf, p_oRHS.m_pCertBuf, m_uCertBufLen);
    }

    if (m_uPrivKeyBufLen > 0)
    {
      m_pPrivKeyBuf = new uint8_t[m_uPrivKeyBufLen];
      memset(m_pPrivKeyBuf, 0, m_uPrivKeyBufLen);
      memcpy(m_pPrivKeyBuf, p_oRHS.m_pPrivKeyBuf, m_uPrivKeyBufLen);
    }
    char pErrBuff[1024];
        memset(pErrBuff, 0, 1024);

    if (NULL != p_oRHS.m_pCert)
    {
      m_pCert = X509_dup(p_oRHS.m_pCert);
      if (NULL == m_pCert)
      {
        cnt_log("Unable to copy X.509 cert using X509_dup(): %s\n", ERR_error_string(ERR_get_error(),
              pErrBuff));
      }
    }

    if (NULL != p_oRHS.m_pPubKey)
    {
      m_pPubKey = p_oRHS.m_pPubKey;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      CRYPTO_add(&m_pPubKey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
      EVP_PKEY_up_ref((EVP_PKEY *) &m_pPubKey);
#endif
    }

    if (NULL != p_oRHS.m_pPrivKey && m_uPrivKeyBufLen > 0)
    {
      m_pPrivKey = p_oRHS.m_pPrivKey;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      CRYPTO_add(&m_pPrivKey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
      EVP_PKEY_up_ref((EVP_PKEY *) &m_pPrivKey);
#endif
    }
  }

  return *this;
}
*/

CntSmimeCert &CntSmimeCert::operator=(CntSmimeCert const &p_oRHS)
{
  clear();
  m_bInit = p_oRHS.m_bInit;

  if (m_bInit)
  {
    init(p_oRHS.m_pCertBuf, p_oRHS.m_uCertBufLen, p_oRHS.m_eEncoding);
  }
}
