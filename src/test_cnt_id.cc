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

#include <fstream>

#include <cstring>

#ifndef _CNT_DEBUG
#define _CNT_DEBUG
#endif

#include "cnt_id.h"
#include "cnt_smime_association.h"
#include "cnt_pgp_association.h"

using namespace std;

void _usage()
{
  printf("test_cnt_id [ <email addr (user@example.com)> ] | -h\n");
}

const char *g_szPEM = "-----BEGIN CERTIFICATE-----\n\
MIID8DCCAtigAwIBAgIGAuJnwc8eMA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQG\n\
EwJVUzERMA8GA1UECAwIVmlyZ2luaWExDzANBgNVBAcMBlJlc3RvbjEXMBUGA1UE\n\
CgwOVmVyaXNpZ24sIEluYy4xEzARBgNVBAMMCkpvaG4gU21pdGgxHzAdBgkqhkiG\n\
9w0BCQEWEHVzZXJAZXhhbXBsZS5jb20wHhcNMTUwMzE3MTkwNjI4WhcNMjAwMzE1\n\
MTkwNjI4WjCBgDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMQ8wDQYD\n\
VQQHDAZSZXN0b24xFzAVBgNVBAoMDlZlcmlzaWduLCBJbmMuMRMwEQYDVQQDDApK\n\
b2huIFNtaXRoMR8wHQYJKoZIhvcNAQkBFhB1c2VyQGV4YW1wbGUuY29tMIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAg+X19fh35e/ttBfommJnDSKKYT\n\
OvjkmBjctJuQqkhFKT3D90TfpsBMEZi2CCRuxpZOVPcNymkRYLKnLErikTDNcODt\n\
R3eaAbk6CFSueFyB/ZnlCGiIMEoXHn3B4ZZ8Ju4OmlJHfjVu6UIQBS6oXalThmiq\n\
0Nr+pemBvYis06XIdQUz+V8ZuFpeOglsXT9rZn7GGWkP3x/609OvL/EFWzWVivqp\n\
5clUIPSa+dF+39ZfYEAWgj7uzcjfq2N9YVh454P4xqPGDsFAO1yFv69tFc9kedVM\n\
iBBFlnT5Lu5/oLnlghfuiSxL095wItkxMNnJ1KyQ92Sz0bHmk1PBxanoUwIDAQAB\n\
o24wbDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\n\
BQcDAgYIKwYBBQUHAwQwHQYDVR0OBBYEFAyhO3lm37B6EdJ3hRjvq5qCcI6uMBEG\n\
CWCGSAGG+EIBAQQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAQEAn8jAXqRDrr4Rlz2h\n\
lz8mzKcn16uR0TKrYVvXan3nwcAB7/lLh/9+koLRLA4CQWxIeDKRu0y/EkwGsoBv\n\
a62qVjKDhWjnjeHpphU45CHca0JdyN76lsJExw5DKGCw1xEUWgz2wS9ocBEGFH9M\n\
lTkbsCXUxAz6nFsPynzbCJkzIOi8SlZKjcKQi9RdP+9H5Gj295IlMEim1KoWG1jk\n\
rQrDcHoYwqbokih/LMlIVDggL9BW4qD9jCvNjVNtnPIV1bCwFUSBjkVtPPbkZ+PL\n\
CdtJb/4rE5Xolff9/XBEff1F9DGkXmNy3XA6NTRtf8EryVqwzVpx8us8UCnvGSfg\n\
JJWbAg==\n\
-----END CERTIFICATE-----\n";

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sEmailAddr = "user@example.com";

  if (argc > 1)
  {
    if (0 == strncmp("-h", argv[1], 2))
    {
      _usage();
      iRet = 0;
    }
    else
    {
      sEmailAddr = argv[1];
    }
  }

  if (1 == iRet)
  {
    CntID oID;

    fprintf(stdout, "Setting email to '%s'\n", sEmailAddr.c_str());
    if (!oID.init(sEmailAddr))
    {
      cnt_log("Unable to initialize object.\n");
    }
    else if (sEmailAddr != oID.getEmail())
    {
      cnt_log("Input email and output email are not equal: '%s' != '%s'\n", 
              sEmailAddr.c_str(),
              oID.getEmail().c_str());
    }
    else
    {
      fprintf(stdout, "Inbox component is: '%s'\n", oID.getInbox().c_str());
      fprintf(stdout, "Domain component is '%s'\n", oID.getDomain().c_str());
      fprintf(stdout, "S/MIME domain name is '%s'\n", oID.getSmimeName().c_str());

      fprintf(stdout, "Adding associations...\n");

      CntSmimeAssociation oAssoc;

      CntBytesVector_t oCert;
      oCert.insert(oCert.begin(), g_szPEM, g_szPEM + strlen(g_szPEM));


      if (oID.addAssociation(oAssoc))
      {
        cnt_log("Was ABLE to add UNINITIALIZED association.\n");
      }
      else if (!oAssoc.init(USG_DANE_EE, SEL_FULL, MAT_FULL, (unsigned char *) g_szPEM, strlen(g_szPEM), CNT_X509_PEM))
      {
        cnt_log("Unable to init association with PEM string.\n");
      }
      else if (!oID.addAssociation(oAssoc))
      {
        cnt_log("Unable to add association.\n");
      }
      else if (1 != oID.numSmimeAssociations())
      {
        cnt_log("Got the wrong number of associations (should have been 1, but got %lu)\n",
                oID.numSmimeAssociations());
      }
      else
      {
        CntSmimeAssociation oAssoc;

        if (!oAssoc.init(USG_DANE_EE, SEL_FULL, MAT_FULL, (unsigned char *) g_szPEM, strlen(g_szPEM), CNT_X509_PEM))
        {
          cnt_log("Unable to RE-init association for signing, with PEM string.\n");
        }
        else if (!oID.addAssociation(oAssoc))
        {
          cnt_log("Unable to re-add new assoc.\n");
        }
        else if (2 != oID.numSmimeAssociations())
        {
          cnt_log("Got the wrong number of associations (should have been 2, but got %lu)\n", 
                  oID.numSmimeAssociations());
        }
        else
        {
          CntPgpAssociation oAssoc3;

          if (!oAssoc3.initLocal(sEmailAddr))
          {
            cnt_log("Unable to init CntPgpAssociation with '%s'. Perhaps not a PGP key in the local key ring?\n", sEmailAddr.c_str());
          }
          else if (!oID.addAssociation(oAssoc3))
          {
            cnt_log("Unable to add PGP association.\n");
          }
          else if (1 != oID.numPgpAssociations())
          {
            cnt_log("Got back the wrong number of PGP associations (should have been 1, but got %lu)\n", oID.numPgpAssociations());
          }
          else
          {
            fprintf(stdout, "PGP domain name is '%s'\n", oID.getPgpName().c_str());

            oAssoc.clear();
            oAssoc3.clear();
            iRet = 0;
          }
        }
      }
    }
  }

  if (0 == iRet)
  {
    fprintf(stdout, ">>>SUCCESS<<<\n");
  }
  else
  {
    fprintf(stdout, ">>>FAIL<<<\n");
  }

  return iRet;
}
