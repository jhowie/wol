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

** File: main.c
**
** Author: John Howie (john@howieconsultinginc.com)
**
** Description
**
**      This file contains the implementation of main () for the program
** vmwold. It reads the configuration of a vmware installation, to associate
** MAC addresses with virtual machines. It then listens for WOL "magic" packets
** for those ethernet addresses and then send a command to vmware to start the
** virtual machine (it does not track state of the virtual machine).
**
** Modifications
**
** 2026-06-06 John Howie        Original.
**
*/

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <errno.h>
# include <stdbool.h>
# include <stdarg.h>
# include <sys/socket.h>
# include <netinet/if_ether.h>
# include <netdb.h>

# include "../wol.h"
# include "vmprod.h"

int             main (int argc, char *argv []);
static void     DisplayHelp (void);
static bool	getudpport (const char *port, unsigned short *udpport);
void            vmwold_cleanup (void);
static void     vmwold_listener (unsigned short udpport, bool verbose);
void            vmwold_signalhandler (int signal);

// Global variables used in this module

static int      wol_listen_socket = -1;
static bool     wol_listen = true;
static bool     verbose = false;

int main (int argc, char *argv [])
{
        int             c, i;
        unsigned short	udpport = htons (UDPBROADCAST_PORT);
        char            *vmserverurl = DEFAULTRESTSERVERURL;
        char            *credentials = (char *) 0;
	int	        retval;

        // Process the command line, looking for options

        while ((c = getopt (argc, argv, "c:hp:u:v")) != -1) {
                // Check which option we got

                switch (c) {
                case 'c':
                        // The user wants to specify the credentials to use. We
                        // just use what is passed to us on the comman line
                        // with no transformation

                        credentials = optarg;
                        break;

		case 'h':
			// The user wants to see the help text

			DisplayHelp ();
			return (EXIT_SUCCESS);
			break;

                case 'p':
                        // The user wants to specify the broadcast port number
                        // to listen on. Nornally we would not care what port
                        // number is used in the broadcast address

			if (! getudpport (optarg, &udpport)) {
				// An error occurred, and we could not convert
				// the argument to a port

				fprintf (stderr, "Port %s is not valid (must be udp service or port between 0 and 65535).\n", optarg);
				exit (EXIT_FAILURE);
			}
                        break;

                case 'u':
                        // The user wants to specify the URL to send vmware
                        // REST queries to. The user needs to specify the full
                        // URL, including protocol (http or https), the server
                        // name or IP address (e.g. localhost or 127.0.0.1),
                        // and the port number if not the default for the
                        // protocol specified (e.g. 8697)

                        vmserverurl = optarg;
                        break;

                case 'v':
                        // The user wants verbose debugging

                        verbose = true;
                        break;

		default:
			// We got an unexpected option

			DisplayHelp ();
			exit (EXIT_FAILURE);
			break;
                }
        }

        // Update the argc and argv values, to remove the options we processed

        argc -= optind;
        argv += optind;

        // There should be no command line arguments, so if anything remains we
        // just display an error, the help text, and then exit

        if (argc != 0) {
                // There are extraneous arguments

                fprintf (stderr, "Error: unknown extraneous arguments\n\n");
                DisplayHelp ();
                exit (EXIT_FAILURE);
        }

        // Check if the user specified credentials
        
        if (credentials == (char *) 0) {
                // They did not, so we ask for them. We call the function
                // specific to the version of vmwold we are building, as each
                // product supports different authentication methods

                if (! vmprod_getcredentials (&credentials, verbose)) {
                        // We were unable to get the credentials. All we can do
                        // is exit (the function outputs appropriate error
                        // messages for the product)

                        exit (EXIT_FAILURE);
                }
        }

        // Now we need to initialize ourselves for the vmware product we are
        // using, to enumerate virtual machines and get their MAC addresses

        if (! vmprod_initialize (vmserverurl, credentials, verbose)) {
                // An error occurred, and we were unable to initialize vmware

                exit (EXIT_FAILURE);
        }

        // We need to set up an exit handler, to ensure everything gets cleaned
        // up on exit

        if (atexit (vmwold_cleanup) != 0) {
                // An error occurred, and we are unable to cleanup properly

                vmprod_writeerrmsg ("Unable to setup cleanup function (%s)\n", strerror (errno));
                exit (EXIT_FAILURE);
        }

        // Set up the signal handler for CTRL-C, which we use to exit the
        // program

        signal (SIGINT, vmwold_signalhandler); 

        // Now, we just call the worker function that listens for WOL "magic"
        // packets, and processes them

        vmwold_listener (udpport, verbose);
        
	// We should never, ever get here

	return -1;
}

/* static void DisplayHelp (void)
**
** This function displays help options and other information.
*/

static void DisplayHelp (void)
{
        printf ("Usage:\n\n");
        printf ("\tvmwold [-c <creds>] [-h] [-p <port>] [-u <URL>] [-v]\n");
        printf ("\n");
	printf ("This program is used to listen for Wake On LAN (WOL) \"magic\" packets broadcast\n");
	printf ("on the local subnet. When it finds one, it compares the MAC address to a list in\n");
        printf ("memory, obtained by querying the REST API of the VMware product it is built for,\n");
        printf ("and sending a start command using the same REST API.\n");
	printf ("\n");
        printf ("\t-c <creds>   Authentication credentials (see Product Specific Help)\n");
        printf ("\t-h           Displays this help text\n");
	printf ("\t-p <port>    The name of a UDP service or a number between 0 and 65,535\n");
	printf ("\t-u <URL>     The URL of the vmware REST server\n");
	printf ("\n");
	printf ("Credentials must be specified in a format compatible with the destination vmware\n");
	printf ("product. If credentials are not specified, you will be prompted for them. If\n");
        printf ("credentials are specified they may be visible to other users on the system. See\n");
        printf ("Product Specific Help, below, for more information.\n");
	printf ("\n");
	printf ("If a UDP service name or port number is not specified, the program will listen\n");
	printf ("for \"magic\" packets on discard/udp (UDP port 9).\n");
	printf ("\n");
	printf ("If the URL to the vmware REST API server is specified it should include the\n");
        printf ("protocol (http or https), the IP address or hostname, and a port number (if not\n");
        printf ("the port associated with the protocol. E.g.:\n\n");
        printf ("\t%s\n\n", DEFAULTRESTSERVERURL);
        printf ("Product Specific Help\n\n");

        // Call product-specific help

        vmprod_DisplayHelp ();
}

/* static bool getudpport (const char *port, unsigned short *udpport)
**
** This function is used to convert the command line argument to the "port"
** option to long value. The user can specify either the name of a service in
** /etc/services, or a numeric value between 0 and 65,535. On success the
** return value is between 0 and 65,535, and on failure it is -1
*/

static bool getudpport (const char *port, unsigned short *udpport)
{
	struct servent	*udp_serviceentry;
	int		udpresult = 0;
	char		*invaliddigit = (char *) 0;

	// First, assume that the argument passed to us is a UDP service name,
	// and attempt to lookup it up in the services database (/etc/services
	// or similar)

	if ((udp_serviceentry = getservbyname (port, "udp")) != (struct servent *) 0) {
		// We found an entry in the services database. Return the port
		// number associated with it

		*udpport = udp_serviceentry ->s_port;
		return true;
	}

	// We did not find a service entry, so assume that we got a number for
	// the port. Convert the value passed as an argument to a long value

	udpresult = strtol (optarg, &invaliddigit, 10);

	// Check that we were able to convert the number

	if (((udpresult == 0) && (errno != 0)) || (*invaliddigit != (char) 0) || ((udpresult < 0) || (udpresult > 65535))) {
		// We were unable to convert the argument to a port number OR
		// the port number is less than 0 or greater than 65535 (the
		// maximum UDP port number)

		return false;
	}
	else {
		// Return the port number

		*udpport = htons (udpresult);
		return true;
	}

	// We should never ever get here

	return false;
}

/* void vmwold_cleanup (void)
**
** This function is called when exit () is called, to clean up everything before
** we exit. It is a simple function, and not truly necessary, but lets be neat
*/

void vmwold_cleanup (void)
{
        // Close the listener socket we are listening on

        if (verbose)
                printf ("vmwold_cleanup: exiting gracefully...\n");

        (void) close (wol_listen_socket);       // Should really check return!
}

/* static void vmwold_listener (unsigned short udpport)
**
** This function is the main worker of the program. It listens continuously for
** broadcast UDP packets, and if they contain a WOL "magic" packet, extracts
** the ethernet address of the machine to wake up, checks it against the list
** maintained of virtual machines and their ethernet addresses, and send a
** start command if one matches
*/

static void vmwold_listener (unsigned short udpport, bool verbose)
{
        struct sockaddr_in      listeningaddress;
        unsigned char           databuffer [2048], ethernetaddr [ETHER_ADDR_LEN], magichdr [6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        char                    *ethernetstr;
        int                     retval, i, datalen;
        fd_set                  listenset;
        struct timeval          timeout;

        // Create the socket we will use to listen for broadcast messages on

        if ((wol_listen_socket = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                // An error occurred, and we could not open the socket we will
                // listen on. All we can do is write out an error and exit on a
                // failure value

                vmprod_writeerrmsg ("Error opening listening socket (%s)\n", strerror (errno));
                exit (EXIT_FAILURE);
        }

        // Build up the address (broadcast) and port we will listen on

        memset ((void *) &listeningaddress, 0, sizeof (struct sockaddr_in));
        listeningaddress.sin_family = AF_INET;
        listeningaddress.sin_addr.s_addr = INADDR_ANY;
        listeningaddress.sin_port = udpport;
        listeningaddress.sin_len = sizeof (struct sockaddr_in);

        // Configure the socket to "hear" only packets that match the address
        // we just configured, byu binding it

        if (bind (wol_listen_socket, (struct sockaddr *) &listeningaddress, sizeof (struct sockaddr_in)) != 0) {
                // An error occurred and we could not restrict the network
                // packets we get

                vmprod_writeerrmsg ("Error occurred binding address to socket (%s)\n", strerror (errno));
                exit (EXIT_FAILURE);
        }

        // Go into a loop, listening for incoming packets on the socket

        if (verbose)
                printf ("Listening for WOL \"magic\" packets on %d...\n", ntohs (udpport));

        FD_ZERO (&listenset);
        while (wol_listen) {
                // Wait for a UDP packet to arrive using the select system call

                FD_SET (wol_listen_socket, &listenset);
                timeout.tv_sec = 0;
                timeout.tv_usec = 100000;       // One tenth of a second

                if ((retval = select ((wol_listen_socket +1), &listenset, (fd_set *) 0, (fd_set *) 0, &timeout)) == -1) {
                        // An error occurred

                        if (errno != EINTR)
                                vmprod_writeerrmsg ("Error occurred in select (%s)\n", strerror (errno));
                        exit (EXIT_FAILURE);
                }

                // Check that our socket descriptor is set in the return, and
                // that this was not a timeout. If neither is true, go back
                // arround again

                if ((retval == 0) || (! FD_ISSET (wol_listen_socket, &listenset)))
                        continue;
                
                // Get data from the socket
                
                if ((datalen = recvfrom (wol_listen_socket, &databuffer, sizeof (databuffer), 0, (struct sockaddr *) 0, 0)) == -1) {
                        // An error occurred - generate an error message

                        vmprod_writeerrmsg ("Error occurred in recvfrom (%s)\n", strerror (errno));
                        exit (EXIT_FAILURE);
                }

                // Simple check - make sure we got no less than 102 bytes, as that
                // is the minimum size of a magic packet

                if (datalen < 102)
                        continue;       // Not a magic packet

                // Check the first six bytes of the packet - to see if they
                // contain the header (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)

                if (memcmp ((void *) databuffer, (void *) magichdr, 6))
                        continue;       // Not a magic packet

                // We found what appears to be a magic packet header, so get
                // the next six bytes - that is a MAC address. We then look for
                // that pattern fifteen more times to qualify this as a magic
                // packet. Note that we set the index to one (rather than 0)
                // in the loop, as there is not point in comparing the address
                // we read to itself. If we do not find the ethernet address
                // fifteen subsequent times, it is not a magic packet

                memcpy (ethernetaddr, (void *) (databuffer + 6), ETHER_ADDR_LEN);
                for (i = 1; i < 16; i ++) {
                        // Compare the ethernet address we copied to the
                        // address at the offset in the packet

                        if (memcmp (ethernetaddr, (void *) databuffer + 6 + (ETHER_ADDR_LEN * i), ETHER_ADDR_LEN))
                                continue;
                }

                // We found a magic packet! Convert the ethernet address to a
                // string we can pass to the VMware function to lookup and see
                // if it is one we care about. While the function will return a
                // boolean value indicating success or failure, we don't care
                // (we might in the future, though, such as reporting the
                // virtual machine is running properly

                ethernetstr = ether_ntoa ((const struct ether_addr *) ethernetaddr);
                if (verbose)
                        printf ("Received magic packet for %s\n", ethernetstr);

                (void) vmprod_processwol (ethernetstr, verbose);
        }

        exit (EXIT_SUCCESS);
}

/* void vmwold_signalhandler (void)
**
** This function is called when a signal we handle is caught. It is used to
** catch CTRL-C. All it does is set a global flag to false, which will cause
** the listener to stop
*/

void vmwold_signalhandler (int signal)
{
        wol_listen = false;
}