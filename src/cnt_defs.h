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

#ifndef _CNT_DEFS_H
#define _CNT_DEFS_H

#include <string>
#include <list>
#include <map>
#include <vector>

#include <inttypes.h>
#include <stdint.h>

class CntSmimeAssociation;
class CntPgpAssociation;
class CntID;
class CntSmimeCert;

#ifdef _CNT_DEBUG
#define cnt_log(X, ...) fprintf(stderr, "%s [%d] " X, __FILE__, __LINE__, ##__VA_ARGS__); fflush(stderr);
#else
#define cnt_log(X, ...) ;
#endif

#define CNT_SMIMEA_MIN_LEN 1 + 1 + 1 + 0 + 0
#define CNT_SMIMEA_MAX_LEN 10000000
#define CNT_SMIMEA_MIN_TXT_LEN 2 + 1 + 1

#define CNT_OPENPGPKEY_MAX_LEN 10000000

#define CNT_SMIMEA_RR_TYPE 53
#define CNT_OPENPGPKEY_RR_TYPE 61

#define CNT_SHA256_TRUNCATION_LIMIT 28

typedef std::list< CntSmimeAssociation * > CntSmimeAssocList_t;
typedef CntSmimeAssocList_t::iterator CntSmimeAssocIter_t;
typedef CntSmimeAssocList_t::const_iterator CntSmimeAssocKIter_t;

typedef std::list< CntPgpAssociation * > CntPgpAssocList_t;
typedef CntPgpAssocList_t::iterator CntPgpAssocIter_t;
typedef CntPgpAssocList_t::const_iterator CntPgpAssocKIter_t;

typedef std::list< CntSmimeCert * > CntSmimeCertList_t;
typedef CntSmimeCertList_t::iterator CntSmimeCertIter_t;
typedef CntSmimeCertList_t::const_iterator CntSmimeCertKIter_t;

#define LDAP_SECURE_PORT 636
#define LDAP_PREFIX "ldap://"
#define LDAP_SECURE_PREFIX "ldaps://"
#define LDAP_REG_STRING "ldap"
#define LDAP_SECURE_STRING "ldaps"
#define LDAP_USER_CERT_NAME "userCertificate"
#define LDAP_USER_SMIME_CERT_NAME "userSMIMECertificate"


typedef struct
{
  time_t m_tExpiration;
  CntID *m_pID;
} CntIdTtl_t;

typedef struct __attribute__ ((__packed__))
{
  uint8_t m_uUsage;
  uint8_t m_uSelector;
  uint8_t m_uMatching;
  char m_pCertAssociationData[0];
} CntSmimeaRR_t;

typedef std::map< std::string, CntIdTtl_t > CntIdMap_t;
typedef CntIdMap_t::iterator CntIdMapIter_t;

// typedef std::vector< unsigned char > CntBytesVector_t;
// typedef std::vector< char > CntBytesVector_t;
typedef std::vector< uint8_t > CntBytesVector_t;
typedef CntBytesVector_t::iterator CntBytesIter_t;

typedef enum
{
  USG_PRE_INIT = -1,
  USG_PKIX_TA,
  USG_PKIX_EE,
  USG_DANE_TA,
  USG_DANE_EE,
  USG_PRIV
} CntUsage_e;

typedef enum
{
  SEL_PRE_INIT = -1,
  SEL_FULL,
  SEL_SPKI,
  SEL_PRIV
} CntSelector_e;

typedef enum
{
  MAT_PRE_INIT = -1,
  MAT_FULL,
  MAT_SHA256,
  MAT_SHA512,
  MAT_PRIV
} CntMatching_e;

typedef enum
{
  CNT_X509_PEM = 0,
  CNT_X509_DER
} CntX509Encoding_e;


#endif
