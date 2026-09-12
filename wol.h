/* 

BSD 3-Clause License

Copyright (c) 2026, John Howie (john@howieconsultinginc.com)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

** File: wol.h
**
** Author: John Howie (john@howieconsultinginc.com)
**
** Description
**
**      This header file contains the function prototypes and miscelaneous
** definitions used by the library functions and calling routines
**
** Modifications
**
** 2026-05-31 John Howie        Original.
**
*/

# ifndef __WOL_H__
# define __WOL_H__

/*
** Some definitions we use
*/

# define ETHERS_FILE            "/etc/ethers"
# define UDPBROADCAST_PORT      9               // discard/udp

/*
** Function Prototypes
*/

bool wakeup_macaddrorhost (const char *broadcastaddr, const char *macaddressorhostname, const char *ethersfile, unsigned short udpport);
const struct ether_addr *lookuphostinethersfile (const char *hostname, const char *ethersfile);
bool wakeup_etheraddr (const char *broadcastaddr, const struct ether_addr *etheraddr, unsigned short udpport);

# endif // __WOL_H__