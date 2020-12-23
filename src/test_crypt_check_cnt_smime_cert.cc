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
#include <cstring>

#ifndef _CNT_DEBUG
#define _CNT_DEBUG
#endif


#include "cnt_smime_cert.h"

using namespace std;

void _usage()
{
  printf("test_crypt_check_cnt_smime_cert [ <private smime cert file (./smime.key)> ] | -h\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sCertFile = "./smime.key";

  if (argc > 1)
  {
    if (0 == strncmp(argv[1], "-h", 2))
    {
      _usage();
      iRet = 0;
    }
    else
    {
      sCertFile = argv[1];
    }
  }

  if (0 != iRet)
  {
    string sClearText = "This is a \n test...";
    CntBytesVector_t oBytes(sClearText.begin(), sClearText.end());
    CntBytesVector_t oBytes2(sClearText.begin(), sClearText.end());
    string sSigText;
    CntBytesVector_t oSigBytes;
    string sCipherText;
    CntBytesVector_t oCipherBytes;
    CntBytesVector_t oClearBytes;
    CntBytesVector_t oHash;
    string sHash;

    CntSmimeCert oCert;

    fprintf(stdout, "Loading cert from file...\n");
    if (!oCert.initFromFile(sCertFile))
    {
      // fprintf(stderr, "Unable to initialize with file '%s'\n", sCertFile.c_str());
      cnt_log("Unable to initialize with file '%s'\n", sCertFile.c_str());
    }
    else
    {
      fprintf(stdout, "Success, signing test string '%s'...\n", sClearText.c_str());
      if (!oCert.sign(oBytes, sSigText))
      {
        fprintf(stderr, "Unable to sign text '%s'\n", sClearText.c_str());
      }
      else
      {
        CntBytesVector_t oSigTestBytes(sSigText.begin(), sSigText.end());

        fprintf(stdout, "Success, verifying signature '%s'...\n", sSigText.c_str());
        if (!oCert.verify(oSigTestBytes))
        {
          fprintf(stderr, "Unable to verify signature: '%s'\n", sSigText.c_str());
        }
        else
        {
          fprintf(stdout, "Success, encrypting test string '%s'...\n", sClearText.c_str());
          if (!oCert.encrypt(oBytes, sCipherText))
          {
            fprintf(stderr, "Unable to encrypt clear text '%s'\n", sClearText.c_str());
          }
          else
          {
            fprintf(stdout, "Success, decrypting '%s'...\n", sCipherText.c_str());
            if (!oCert.decrypt(sCipherText, oClearBytes))
            {
              fprintf(stderr, "Unable to decrypt cipher text: '%s'\n", sCipherText.c_str());
            }
            else
            {
              fprintf(stdout, "Success\n");
              bool bOK = true;

              oCert.clear();
              iRet = (bOK) ? 0 : 1;
            }
          }
        }
      }
    }
  }

  if (0 == iRet)
  {
    printf(">>>SUCCESS<<<\n");
  }
  else
  {
    printf(">>>FAIL<<<\n");
  }

  return iRet;
}
