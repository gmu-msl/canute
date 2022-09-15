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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "cnt_tbird.h"
#include "cnt_id_cache.h"
#include "cnt_id.h"
#include "cnt_net.h"
#include "cnt_smime_association.h"
#include "cnt_smime_cert.h"
#include "cnt_defs.h"

using namespace std;

extern "C" {

int init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile)
{
  return cnt_init(p_szEmailAddr, p_szCertFilePath, p_szLogFile);
}

const char* hash_sha224(const char *p_szKey)
{
  return NULL;
}

int cnt_init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile)
{
  int iRet = 0;

  try
  {
    if (NULL != p_szLogFile && 0 < strlen(p_szLogFile))
    {
      dup(fileno(stderr));
      freopen(p_szLogFile,"w",stderr);
      dup2(fileno(stderr), fileno(stdout));
    }

    CntIdCache &oCache = CntIdCache::getInstance();
    CntID oID;
    CntSmimeAssociation oAssoc;

    if (NULL == p_szEmailAddr)
    {
      cnt_log("Unable to load ID with NULL email address.\n");
    }
    else if (NULL == p_szCertFilePath)
    {
      cnt_log("Unable to load NULL file.\n");
    }
    else
    {
      string sEmail = p_szEmailAddr;
      string sFile = p_szCertFilePath;
      if (!oID.init(sEmail))
      {
        cnt_log("Unable to initialized ID with email '%s'\n", sEmail.c_str());
      }
      else if (!oAssoc.initFromFile(USG_DANE_EE, SEL_FULL, MAT_FULL, sFile))
      {
        cnt_log("Unable to init cert, for encryption, from file '%s'\n", sFile.c_str());
      }
      else if (!oID.addAssociation(oAssoc))
      {
        cnt_log("Unable to add encryption association for file '%s'\n", sFile.c_str());
      }
      else if (!oAssoc.initFromFile(USG_DANE_EE, SEL_FULL, MAT_FULL, sFile))
      {
        cnt_log("Unable to init cert, for signing, from file '%s'\n", sFile.c_str());
      }
      else if (!oID.addAssociation(oAssoc))
      {
        cnt_log("Unable to add signing association for file '%s'\n", sFile.c_str());
      }
      else if (!oCache.addID(oID, 0))
      {
        cnt_log("Unable to add ID to cache.\n");
      }
      else
      {
cnt_log("ADDED ID, '%s'\n", sEmail.c_str());
        iRet = 1;
      }
    }
  }
  catch (...)
  {
    cnt_log("Caught exception.\n");
    iRet = 0;
  }

  return iRet;
}

// returns 1 == OK, 0 == ERR per CMS_verify
int cnt_encrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      cnt_log("Unable to encrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      cnt_log("Unable to encrypt NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      CntID oID;
      CntIdCache &oIdCache = CntIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, oID))
      {
        bFound = true;
      }
      else
      {
        uint32_t uTTL = 0;
        CntNet oNet;
        if (!oID.init(sEmail))
        {
          cnt_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          cnt_log("Unable to initialize network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, uTTL))
        {
          cnt_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          oIdCache.addID(oID, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numSmimeAssociations())
        {
          cnt_log("Unable to encrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          // This is where we could choose a specific SMIMEA RR if we have a preference.
          // For now, we will just find the first one that fits our needs.
          CntSmimeAssociation *pAssoc = *(oID.beginSmimeAssociations());
          CntSmimeCert &oCert = pAssoc->getCert();

          if (!oCert.encrypt(sBody, sRet))
          {
            cnt_log("Unable to encrypt.\n");
            sRet = "";
          }
          else
          {
            iRet = 1;
          }
        }
      }
    }
  }
  catch(...)
  {
    cnt_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int cnt_decrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      cnt_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      cnt_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      CntID oID;
      CntIdCache &oIdCache = CntIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, oID))
      {
        cnt_log("Unable to find ID for '%s'\n", sEmail.c_str());
      }
      else
      {
        if (0 >= oID.numSmimeAssociations())
        {
          cnt_log("Unable to decrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          for (CntSmimeAssocKIter_t tIter = oID.beginSmimeAssociations();
               oID.endSmimeAssociations() != tIter;
               tIter++)
          {
            CntSmimeAssociation *pAssoc = *tIter;
            CntSmimeCert &oCert = pAssoc->getCert();
            CntBytesVector_t oOut;

            if (oCert.decrypt(sBody, oOut))
            {
              sRet.assign((char *) oOut.data(), oOut.size());
              iRet = 1;
              break;
            }
          }
        }
      }
    }
  }
  catch(...)
  {
    cnt_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int cnt_sign(const char *p_szEmail,   const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      cnt_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      cnt_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      CntID oID;
      CntSmimeCert oCert;
      CntBytesVector_t oBytes(sBody.begin(), sBody.end());
      CntIdCache &oIdCache = CntIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, oID))
      {
        cnt_log("Unable to lookup ID for email '%s'\n", sEmail.c_str());
      }
      else if (oID.numSmimeAssociations() < 1)
      {
        cnt_log("Unable to sign with no associations in ID '%s'\n", sEmail.c_str());
      }
      else
      {
        // This is where we could choose a specific SMIMEA RR if we have a preference.
        // For now, we will just find the first one that fits our needs.
        CntSmimeAssociation *pAssoc = *(oID.beginSmimeAssociations());
        CntSmimeCert &oCert = pAssoc->getCert();

        if (!oCert.sign(oBytes, sRet))
        {
          cnt_log("Unable to sign with ID '%s'\n", sEmail.c_str());
          sRet = "";
        }
        else
        {
          iRet = 1;
        }
      }
    }
  }
  catch(...)
  {
    cnt_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int cnt_verify(const char *p_szEmail, const char *p_pBuf)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  bool bVerified = false;

  try
  {
    if (NULL == p_szEmail)
    {
      cnt_log("Unable to verify email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      cnt_log("Unable to verify NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      CntID oID;
      CntIdCache &oIdCache = CntIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, oID))
      {
        bFound = true;
      }
      else
      {
        cnt_log("Cache did not have entry for email '%s', fetching over DNS\n", sEmail.c_str());
        uint32_t uTTL = 0;
        CntNet oNet;
        if (!oID.init(sEmail))
        {
          cnt_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          cnt_log("Unable to init network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, uTTL))
        {
          cnt_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          cnt_log("Fetched SMIMEA for ID '%s', adding to cache with TTL %lu...\n", 
                  sEmail.c_str(), 
                  (unsigned long) uTTL);
          oIdCache.addID(oID, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numSmimeAssociations())
        {
          cnt_log("Unable to verify message to '%s' because no signing associations found.\n", sEmail.c_str());
        }
        else
        {
          CntBytesVector_t oBytes(sBody.begin(), sBody.end());
          for (CntSmimeAssocKIter_t tIter = oID.beginSmimeAssociations();
               oID.endSmimeAssociations() != tIter;
               tIter++)
          {
            CntSmimeAssociation *pAssoc = *tIter;
            CntSmimeCert &oCert = pAssoc->getCert();
            CntBytesVector_t oOut;

            if (oCert.verify(oBytes))
            {
              bVerified = true;
              break;
            }
          }
        }
      }
    }
  }
  catch(...)
  {
    cnt_log("Unable to encrypt, caught exception.\n");
  }

  return (int) bVerified;
}

int cnt_lookup(const char *p_szEmail, int p_iEnc)
{
  int iRet = 0;

  try
  {
    if (NULL == p_szEmail)
    {
      cnt_log("Unable to encrypt email to NULL inbox.\n");
    }
    else
    {
      string sEmail = p_szEmail;

      CntID oID;
      CntIdCache &oIdCache = CntIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, oID))
      {
        bFound = true;
      }
      else
      {
        cnt_log("Cache did not have entry for email '%s', fetching over DNS\n", sEmail.c_str());

        uint32_t uTTL = 0;
        CntNet oNet;
        if (!oID.init(sEmail))
        {
          cnt_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          cnt_log("Unable to initialize network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, uTTL))
        {
          cnt_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          cnt_log("Fetched SMIMEA for ID '%s', adding to cache with TTL %lu...\n", 
                   sEmail.c_str(), 
                   (unsigned long) uTTL);
          oIdCache.addID(oID, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numSmimeAssociations())
        {
          cnt_log("Lookup to '%s' failed, because no associations found.\n", sEmail.c_str());
        }
        else
        {
          iRet = 1;
        }
      }
    }
  }
  catch(...)
  {
    cnt_log("Unable to lookup ID, caught exception.\n");
  }

  return iRet;
}


}
