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
#include <string.h>

extern "C" {
#include <getdns/getdns.h>
}

#include "cnt_net.h"
#include "cnt_id.h"
#include "cnt_defs.h"
#include "cnt_smime_association.h"

using namespace std;

CntNetGetDNS::CntNetGetDNS()
  : m_bInit(false),
    m_pGetDNS(NULL)
{

}

CntNetGetDNS::~CntNetGetDNS()
{
  if (NULL != m_pGetDNS)
  {
    getdns_context_destroy(m_pGetDNS);
  }
}

bool CntNetGetDNS::init(const char *p_szRootTaFile /*= NULL*/)
{
  if (m_bInit && NULL != m_pGetDNS)
  {
    getdns_context_destroy(m_pGetDNS);
    m_pGetDNS = NULL;
  }

  m_bInit = false;

  getdns_return_t tRet = getdns_context_create(&m_pGetDNS, 1);
  if (GETDNS_RETURN_GOOD != tRet)
  {
    cnt_log("Unable to init getDNS: %d\n", tRet);
  }
  else
  {
    m_bInit = true;
  }

  return m_bInit;
}

bool CntNetGetDNS::init(std::string &p_sRootTaFile)
{
  return init(p_sRootTaFile.c_str());
}

bool CntNetGetDNS::lookupSmimeID(CntID &p_oID, uint32_t &p_uTTL)
{
  bool bRet = false;

  string sDomain = p_oID.getSmimeName();
  getdns_dict *pDict = getdns_dict_create();
  getdns_dict *pFullResponse = NULL;
  getdns_return_t tRet = GETDNS_RETURN_GOOD;
  uint32_t uError = 0;

cnt_log("Fetching '%s'\n", p_oID.getSignName().c_str());

  if (NULL == pDict)
  {
    cnt_log("Unable to allocate getdns dictionary.\n");
  }
  else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_set_int(pDict, 
                                                             "add_warning_for_bad_dns", 
                                                             GETDNS_EXTENSION_TRUE)))
  {
    cnt_log("Unable to set dictionary value for 'add_warning_for_bad_dns' %d\n", tRet);
  }
  else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_set_int(pDict,
                                                             "dnssec_return_status",
                                                             GETDNS_EXTENSION_TRUE)))
  {
    cnt_log("Unable to set dictionary value for 'dnssec_return_status': %d\n", tRet);
  }
  else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_set_int(pDict,
                                                             "dnssec_return_only_secure",
                                                             GETDNS_EXTENSION_TRUE)))
  {
    cnt_log("Unable to set dictionary value for 'dnssec_return_only_secure': %d\n", tRet);
  }
  // Now we can actually make the query...
  else
  {
// getdns_context_set_dns_transport(m_pGetDNS, GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP);
// getdns_context_set_dns_transport(m_pGetDNS, GETDNS_TRANSPORT_TCP_ONLY);
// getdns_context_set_dns_transport(m_pGetDNS, GETDNS_TRANSPORT_UDP_ONLY);
    size_t uNumAnswers = 0;
    struct getdns_list *pReplyList = NULL;

    tRet = getdns_general_sync(m_pGetDNS,
                               sDomain.c_str(),
                               CNT_SMIMEA_RR_TYPE,
                               pDict,
                               &pFullResponse);
    if (GETDNS_RETURN_BAD_DOMAIN_NAME == tRet)
    {
      cnt_log("Bad domain name: '%s'\n", sDomain.c_str());
    }
    else if (NULL == pFullResponse)
    {
      cnt_log("NULL reponse returned with code: %d for domain '%s'\n", tRet, sDomain.c_str());
    }
    else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_int(pFullResponse,
                                                               (char *) "status",
                                                               &uError)))
    {
      cnt_log("Unable to look through response dictionary for 'status': %d\n", tRet);
    }
    else if (GETDNS_RESPSTATUS_GOOD != uError)
    {
      cnt_log("Search had no results: %u\n", uError);
    }
    else if (GETDNS_RETURN_NO_SUCH_DICT_NAME == (tRet = getdns_dict_get_list(pFullResponse,
                                                                             (char *) "replies_tree",
                                                                             &pReplyList)))
    {
      cnt_log("Unable to get replies tree from reponse.\n");
    }
    else if (GETDNS_RETURN_NO_SUCH_DICT_NAME == (tRet = getdns_list_get_length(pReplyList, &uNumAnswers)))
    {
      cnt_log("Unable to find number of answers from replies_tree.\n");
    }
    // Now we can look over the reponse(s)...
    else
    {
      for (size_t u = 0; !bRet && u < uNumAnswers; u++)
      {
        size_t uNumRRs = 0;
        struct getdns_dict *pResp = NULL;
        struct getdns_list *pAns = NULL;

        // First get the dict from the new list
        if (GETDNS_RETURN_GOOD != (tRet = getdns_list_get_dict(pReplyList, 
                                                               u, 
                                                               &pResp)))
        {
          cnt_log("Unable to get embedded reponse at index %lu: %d\n", u, tRet);
          break;
        }
        else if (NULL == pResp)
        {
          cnt_log("Got a NULL back from successful getdns_list_get_dict() call. . .\n");
          break;
        }
        // Now get a new list from the new dict...
        else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_list(pResp,
                                                                    (char *) "answer", 
                                                                    &pAns)))
        {
          cnt_log("Unable to get answer from internal resp list: %d\n", tRet);
          break;
        }
        else if (NULL == pAns)
        {
          cnt_log("Got a NULL back from successful getdns_dict_get_list() call. . .\n");
          break;
        }
        else if (GETDNS_RETURN_GOOD != (tRet = getdns_list_get_length(pAns, &uNumRRs)))
        {
          cnt_log("Unable to get number of RRs in response: %d\n", tRet);
          break;
        }
        else if (uNumRRs > 1000)
        {
          cnt_log("Failed sanity check: got %lu RRs in response\n", uNumRRs);
          break;
        }
        // Loop over RRs...
        else
        {
          for (size_t uRR = 0; uRR < uNumRRs; uRR++)
          {
            uint32_t uType = 0;
            struct getdns_dict *pRR = NULL;
            struct getdns_dict *pRData = NULL;
            struct getdns_bindata *pBinData = NULL;

            if (GETDNS_RETURN_GOOD != (tRet = getdns_list_get_dict(pAns,
                                                                   uRR,
                                                                   &pRR)))
            {
              cnt_log("Unable to get RR %lu from answer section: %d\n", uRR, tRet);
              break;
            }
            else if (NULL == pRR)
            {
              cnt_log("Got NULL back from successful call to getdns_list_get_dict()\n");
              break;
            }
            else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_dict(pRR,
                                                                        (char *) "rdata",
                                                                        &pRData)))
            {
              cnt_log("Unable to get RData from RR: %d\n", tRet);
              break;
            }
            else if (NULL == pRData)
            {
              cnt_log("Got NULL back from successful call to getdns_dict_get_dict()...\n");
              break;
            }
            else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_int(pRR,
                                                                       (char *) "type",
                                                                       &uType)))
            {
              cnt_log("Unable to get RR type: %d\n", tRet);
              break;
            }
            else if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_int(pRR,
                                                                       (char *) "ttl",
                                                                       &p_uTTL)))
            {
              cnt_log("Unable to get RR TTL: %d\n", tRet);
              break;
            }
            // If this is (one of) our target(s)...
            else if (CNT_SMIMEA_RR_TYPE == uType)
            {
              CntSmimeAssociation oAssoc;
              if (GETDNS_RETURN_GOOD != (tRet = getdns_dict_get_bindata(pRData,
                                                                        (char *) "rdata_raw",
                                                                        &pBinData)))
              {
                if (GETDNS_RETURN_NO_SUCH_DICT_NAME == tRet)
                {
                  cnt_log("Unable to find raw data in SMIMEA RR...\n");
                }
                else
                {
                  cnt_log("Unable to get raw data from RR: %d\n", tRet);
                }
                break;
              }
              else if (!oAssoc.fromWire(pBinData->data, pBinData->size))
              {
                cnt_log("Unable to parse SMIMEA RR from wire format.\n");
                break;
              }
              // Success
              else
              {
                bRet = p_oID.addAssociation(oAssoc);
              }
            }
          }
        }
      }
    }
  }

  if (NULL != pDict)
  {
    getdns_dict_destroy(pDict);
  }
  if (NULL != pFullResponse)
  {
    getdns_dict_destroy(pFullResponse);
  }

  return bRet;
}


