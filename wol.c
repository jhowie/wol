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

** File: wol.c
**
** Author: John Howie (john@howieconsultinginc.com)
**
** Description
**
**      This file contains the implementation of the library wol. It is used
** to wake a system from sleep by broadcasting a magic packet containing the
** MAC or ethernet address. The remote system can be specified as a MAC address
** or hostname, or an ethernet address structure
**
** Modifications
**
** 2026-05-31 John Howie        Original.
**
*/

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdbool.h>
# include <errno.h>
# include <netinet/if_ether.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>

# include "wol.h"

/* bool wakeup_macaddrorhost (const char *broadcastaddr, const char *macaddressorhostname, const char *ethersfile, unsigned short udpport)
**
** This function takes a MAC address or hostname, and attempts to resolve it to
** an ethernet address, which is passed to wakeup_etheraddr () to actually wake
** up the host by sending a magic packet. If it cannot resolve the MAC address
** or hostname, it returns false, otherwise it returns the result of the
** function wakeup_etheraddr ().
*/

bool wakeup_macaddrorhost (const char *broadcastaddr, const char *macaddressorhostname, const char *ethersfile, unsigned short udpport)
{
        const struct ether_addr	*etheraddr;

        // Assume the first argument is a MAC address in XX:XX:XX:XX:XX:XX
        // address format, and convert it to an ether_addr structure

        if ((etheraddr = ether_aton (macaddressorhostname)) != (struct ether_addr *) 0) {
                // We were able to convert the string to an ethernet address,
                // so call the function to wake up the remote host

                return wakeup_etheraddr (broadcastaddr, etheraddr, udpport);
        }

        // The first argument is not a MAC address (or was not formatted
        // correctly). Assume it is a hostname, and try to look that up instead

        if ((etheraddr = lookuphostinethersfile (macaddressorhostname, ethersfile)) != (struct ether_addr *) 0) {
                // The argument was a hostname (or alias we resolved to a
                // hostname), and we found an ethernet address for it. Call the
                // function to wake up the remote host

                return wakeup_etheraddr (broadcastaddr, etheraddr, udpport);
        }

        // If we got here, the first argument was not a (valid) MAC address or
        // it was an alias or hostname that did not resolve to an ethernet
        // address. All we can do is return false

        return false;
}

/* struct ether_addr *lookuphostinethersfile (const char *hostname, const char *ethersfile)
**
** This routine is used to retrieve an ethernet address from an ethers file
** (either the system ethers file, or one supplied by the user).
*/

const struct ether_addr *lookuphostinethersfile (const char *hostname, const char *ethersfile)
{
	struct hostent *hostdetails;
	char *lookuphostname;
	FILE *ethersfilefp;
	char *linebuf = NULL;
	size_t linebuflen = 0;
	ssize_t linelen;
	char *etherhostname;
	static struct ether_addr hostetheraddr;
	char *displayhostetheraddr;

	// Lookup the hostname. We do this in case the user did not provide
	// a FQDN. We need the FQDN to lookup the ethers(5) format file

	hostdetails = gethostbyname (hostname);
	if (hostdetails == (struct hostent *) 0) {
		// We could not find the host in our lookup. We will just use
		// the user-supplied hostname in its place, based on the
		// assumption that the user knows best and specified a host
		// in the ethers(5) format file

		lookuphostname = (char *) hostname;
	}
	else {
		// Use the FQDN in the results of our host lookup (it might be
		// the same as what the user provided, if they did not provide
		// an alias or provide a hostname to which a search domain was
		// appended in the lookup)

		lookuphostname = hostdetails -> h_name;
	}

	// Open the ethers file (either the system file or the path to one
	// provided by the user)

	if ((ethersfilefp = fopen (ethersfile, "r")) == 0) {
		// We were unable to open the ethers file

		return (struct ether_addr *) 0;
	}

	// Loop through the ethers file reading a line at a time

	while ((linelen = getline (&linebuf, &linebuflen, ethersfilefp)) > 0) {
		// Try to convert the line just read into an ethernet address
		// and a hostname. We allocate memory for the hostname before
		// we proceed

		etherhostname = malloc (linelen);
		if (! ether_line(linebuf, &hostetheraddr, etherhostname)) {
			// We got a valid line from the ethers file, with a
			// hostname and ether address. Check to see if we got a
			// match for the hostname

			if (! strcmp (lookuphostname, etherhostname)) {
				// We found a match for the hostname we were
				// looking for. Close the file and return the
				// ether address

				(void) fclose (ethersfilefp);
				return &hostetheraddr;
			}
		}

		// Free up the hostname

		free (etherhostname);
	}

	// We did not find the host in the ethers file, close the file and
	// return a null ether_addr pointer

	(void) fclose (ethersfilefp);
	return (struct ether_addr *) 0;
}

/* bool wakeup_etheraddr (const char *broadcastaddr, const struct ether_addr *etheraddr, unsigned short udpport)
**
** This function is called to broadcast the Wakeup On LAN (WOL) "magic" packet
** to the locsal subnet
*/

bool wakeup_etheraddr (const char *broadcastaddr, const struct ether_addr *etheraddr, unsigned short udpport)
{
        unsigned char   	magicpacket [1024];
        int            		etheraddrcount, udp_broadcastsocket, socketoptions, broadcastresult, onesbcast = 1;
	struct sockaddr_in	broadcastaddr_in;

        // Create the "magic" packet we will broadcast to wake up the remote
        // system. We start by initializing the entire magic packet to 0x00 and
        // then the first six bytes to 0xFF 

        (void) memset (magicpacket, (int) 0x00, sizeof (magicpacket));
        (void) memset (magicpacket, (int) 0xFF, 6);

        // Now, copy over the MAC address sixteen times to the "magic" packet

	for (etheraddrcount = 0; etheraddrcount < 16; etheraddrcount ++)
		memcpy (&(magicpacket [(etheraddrcount * ETHER_ADDR_LEN) + ETHER_ADDR_LEN]), etheraddr -> octet, ETHER_ADDR_LEN);

        // Now, open the UDP socket and configure it for broadcasts

        if ((udp_broadcastsocket = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                // An error occurred, and we could not open a socket endpoint,
                // and all we can do is return FALSE

                return false;
        }

        // Configure the socket to allow us to send broadcast packets

        socketoptions = SO_BROADCAST;
        if (setsockopt (udp_broadcastsocket, SOL_SOCKET, SO_BROADCAST, (const void *) &socketoptions, sizeof (int)) != 0) {
                // An error occurred, and we could not configure the socket to
                // send broadcast packets. All we can do is return false

                return false;
        }

# ifdef IP_ONESBCAST
	// If the broadcast address was selected by the user, we need to set
	// the socket option IP_ONESBCAST

	if (broadcastaddr != (char *) 0) {
		// Set the IP_ONESBCAST socket option

		if (setsockopt (udp_broadcastsocket, IPPROTO_IP, IP_ONESBCAST, &onesbcast, sizeof (onesbcast)) != 0) {
			// An error occurred, and we could not set the socket
			// option

			return false;
		}
	}
# endif	// IP_ONESBCAST

	// Build the broadcast destination address and port

	memset (&broadcastaddr_in, 0, sizeof (struct sockaddr_in));
	broadcastaddr_in.sin_family = AF_INET;
	broadcastaddr_in.sin_port = udpport;
	broadcastaddr_in.sin_addr.s_addr = ((broadcastaddr != (char *) 0) ? inet_addr (broadcastaddr) : INADDR_BROADCAST);
	broadcastaddr_in.sin_len = sizeof (struct sockaddr_in);

	// Send the "magic" packet

	broadcastresult = sendto (udp_broadcastsocket, (const char *) magicpacket, ((16 * ETHER_ADDR_LEN) + 6), 0, (const struct sockaddr *) &broadcastaddr_in, sizeof (struct sockaddr));

	// Close the socket

	(void) close (udp_broadcastsocket);

	// Check the amount of data sent, and whether or not we were successful

	if (broadcastresult != ((16 * ETHER_ADDR_LEN) + ETHER_ADDR_LEN)) {
		// An error occurred and we could not send the magic packet,
		// so return false

		return false;
	}
	else {
		// We were successful, so return true

		return true;
	}

	// We should never get here!

	return false;
}