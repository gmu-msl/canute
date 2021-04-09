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
#include <errno.h>
#include <string.h>

#include <iostream>
#include <string>

#include "cnt_id.h"
#include "cnt_smime_association.h"

#ifndef NOERROR
#define NOERROR 0
#endif

using namespace std;

void _usage()
{
    fprintf(stdout, "smimea-gen [ <email address> <usage number> <selector number> <matching number> [cert file in PEM format] ] | -h\n");
}

bool _menu(string &p_sEmail, int &p_iUsage, int &p_iSel, int &p_iMat, string &p_sAccess, string &p_sFile)
{
  bool bRet = false;

  char szOption[128] = {0};
  int iOption = -1;

  memset(szOption, 0, 128);

  try
  {
    fprintf(stdout, "Enter email address > ");
    p_sEmail.clear();
    getline(std::cin, p_sEmail);

    fprintf(stdout, "Choose the Usage from the following values:\n");
    fprintf(stdout, "\t0: CA constraint (PKIX-TA)\n");
    fprintf(stdout, "\t1: Service certificate constraint (PKIX-EE)\n");
    fprintf(stdout, "\t2: Trust anchor assertion  (DANE-TA)\n");
    fprintf(stdout, "\t3: Domain-issued certificate (DANE-EE)\n");
    fprintf(stdout, "\t4: Reject\n");
    fprintf(stdout, "> ");

    errno = NOERROR;

    if (NULL == fgets(szOption, 127, stdin))
    {
      fprintf(stderr, "Unable to read option: %s\n", strerror(errno));
      throw 1;
    }
    else if (0 == (iOption = (int) strtol(szOption, NULL, 10)) && NOERROR != errno)
    {
      fprintf(stderr, "Unable to convert '%s' to int: %s\n", szOption, strerror(errno));
      throw 1;
    }
    else
    {
      p_iUsage = iOption;
    }

    errno = NOERROR;
    memset(szOption, 0, 128);
    fprintf(stdout, "Choose the Selector from the following values:\n");
    fprintf(stdout, "\t0: Full certificate (Cert)\n");
    fprintf(stdout, "\t1: SubjectPublicKeyInfo (SPKI)\n");
    fprintf(stdout, "> ");
    if (NULL == fgets(szOption, 127, stdin))
    {
      fprintf(stderr, "Unable to read option: %s\n", strerror(errno));
      throw 2;
    }
    else if (0 == (iOption = (int) strtol(szOption, NULL, 10)) && NOERROR != errno)
    {
      fprintf(stderr, "Unable to convert '%s' to int: %s\n", szOption, strerror(errno));
      throw 2;
    }
    else
    {
      p_iSel = iOption;
    }

    errno = NOERROR;
  memset(szOption, 0, 128);
    fprintf(stdout, "Choose the Matching from the following values:\n");
    fprintf(stdout, "\t0: No hash used (Full)\n");
    fprintf(stdout, "\t1: 256 bit hash by SHA2 (SHA-256)\n");
    fprintf(stdout, "\t1: 512 bit hash by SHA2 (SHA-512)\n");
    fprintf(stdout, "> ");

    if (NULL == fgets(szOption, 127, stdin))
    {
      fprintf(stderr, "Unable to read option: %s\n", strerror(errno));
      throw 3;
    }
    else if (0 == (iOption = (int) strtol(szOption, NULL, 10)) && NOERROR != errno)
    {
      fprintf(stderr, "Unable to convert '%s' to int: %s\n", szOption, strerror(errno));
      throw 3;
    }
    else
    {
      p_iMat = iOption;
    }

    // Get the access field.
    
    fprintf(stdout, "Enter the location of the certificate file (in PEM format)\n> ");
    p_sAccess.clear();
    getline(std::cin, p_sFile);

    bRet = true;
  }
  catch (int p_iExp)
  {
    switch (p_iExp)
    {
    case 1:
      fprintf(stderr, "Error parsing Usage.\n");
      break;
    case 2:
      fprintf(stderr, "Error parsing selector.\n");
      break;
    case 3:
      fprintf(stderr, "Error parsing matching.\n");
      break;
    default:
      fprintf(stderr, "Unknown int error %d\n", p_iExp);
      break;
    }
  }
  catch (...)
  {
    fprintf(stderr, "Caught unknown exception...\n");
  }

  return bRet;
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  int iUsage = -1;
  int iSelector = -1;
  int iMatching = -1;
  string sEmail;
  string sAccess;
  string sCertFile;

  if (2 == argc)
  {
    if (0 != strncmp(argv[1], "-h", 2))
    {
      fprintf(stderr, "Unknown option. . .\n");
    }
    _usage();
    iRet = 0;
  }
  else if ( argc > 6 )
  {
    _usage();
  }
  else
  {
    bool bOK = false;
    bool pipeMode = false;
    if (5 == argc) {
      pipeMode = true;
    }
    if (1 == argc)
    {
      bOK = _menu(sEmail, iUsage, iSelector, iMatching, sAccess, sCertFile);
    }
    else
    {
      sEmail = argv[1];
      errno = NOERROR;
      if (0 == (iUsage = (int) strtol(argv[2], NULL, 10))
          && NOERROR != errno)
      {
        fprintf(stderr, "Unable to convert usage '%s' to integer: %s\n", argv[2], strerror(errno));
      }
      else if (0 == (iSelector = (int) strtol(argv[3], NULL, 10))
               && NOERROR != errno)
      {
        fprintf(stderr, "Unable to convert selector '%s' to integer: %s\n", argv[3], strerror(errno));
      }
      else if (0 == (iMatching = (int) strtol(argv[4], NULL, 10))
               && NOERROR != errno)
      {
        fprintf(stderr, "Unable to convert matching '%s' to integer: %s\n", argv[4], strerror(errno));
      }
      else
      {
        if (!pipeMode) {
          sCertFile = argv[5];
        }

        bOK = true;
      }
    }

    if (bOK)
    {
      CntID oID;
      CntSmimeAssociation oAssoc;
      string sTxt;

      bool failed = false;

      if (!oID.init(sEmail))
      {
        failed = true;
        fprintf(stderr, "Unable to init ID.\n");
      } 
      if (!failed && pipeMode && !oAssoc.initFromPipe((CntUsage_e) iUsage,
                                    (CntSelector_e) iSelector,
                                    (CntMatching_e) iMatching))
      {
        failed = true;
        fprintf(stderr, "Unable to init association from pipe.\n");
      }
      if (!failed && !pipeMode && oAssoc.initFromFile((CntUsage_e) iUsage,
                                      (CntSelector_e) iSelector,
                                      (CntMatching_e) iMatching,
                                      sCertFile))
      {
        failed = true;
        fprintf(stderr, "Unable to init association.\n");
      }
      else if (!failed && !oAssoc.toText(sTxt))
      {
        failed = true;
        fprintf(stderr, "Unable to get text of association.\n");
      }
      if (!failed)
      {
        // fprintf(stdout, "%s IN TYPE%d %s;\n", oID.getSmimeName().c_str(), CNT_SMIMEA_RR_TYPE, sTxt.c_str());
        fprintf(stdout, "%s IN SMIMEA %s;\n", oID.getSmimeName().c_str(), sTxt.c_str());
        iRet = 0;
      }
    }
  }

  return iRet;
}
