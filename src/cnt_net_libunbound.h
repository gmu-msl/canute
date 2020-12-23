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
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef _CNT_NET_LIBUNBOUND_H
#define _CNT_NET_LIBUNBOUND_H

#include <unbound.h>

#include "cnt_net_engine.h"
#include "cnt_defs.h"

#define CNT_LIBUNBOUND_TA_FILE "/usr/local/etc/unbound/root.key"
#define CNT_LIBUNBOUND_LIN_TA_FILE "/var/lib/unbound/root.key"

class CntNetLibunbound : public CntNetEngine
{
  // Member Variables
  private:
    struct ub_ctx* m_pCtx;

  // Methods
  public:
    CntNetLibunbound();
    virtual ~CntNetLibunbound();

    virtual bool init(const char *p_szRootTaFile = NULL);
    virtual bool init(std::string &p_sRootTaFile);

    virtual bool lookupSmimeID(CntID &p_oID,
                          uint32_t &p_uTTL);

};

#endif
