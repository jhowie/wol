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
**      This file contains the implementation of main () for the program wol.
** It processes command line options and then calls the functions in the
** library that implements the Wake On Lan (wol) functionality.
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
# include <errno.h>
# include <stdbool.h>
# include <netdb.h>

# include "wol.h"

int     main (int argc, char *argv []);
void    DisplayHelp (void);
bool	getudpport (const char *port, unsigned short *udpport);

int main (int argc, char *argv [])
{
        int     	c, i;
        unsigned short	udpport = htons (UDPBROADCAST_PORT);
        char    	*broadcastaddr = (char *) 0, *macaddressorhostname, *ethersfile = ETHERS_FILE;
	int		retval;

        // Capture the name this program was invoked as, as we might need it
        // later (a feature of this implementation is that the name of the
        // program as invoked can be treated as a hostname)

        macaddressorhostname = argv [0];

        // Process the command line, looking for options

# ifdef IP_ONESBCAST
        while ((c = getopt (argc, argv, "b:f:hp:")) != -1) {
# else
        while ((c = getopt (argc, argv, "f:hp:")) != -1) {
# endif // IP_ONESBCAST
                // Check which option we got

                switch (c) {
# ifdef IP_ONESBCAST
		case 'b':
			// The user wants to specify the interface to send the
			// broadcast packet from. This is done by specifying
			// the broadcast address of the interface

			broadcastaddr = optarg;
			break;
# endif // IP_ONESBCAST

                case 'f':
                        // The user wants to specify the filename of the ethers
                        // file used to lookup the MAC ethernet address. Check
			// it exists, and we can read it

			if (access (optarg, (F_OK | R_OK)) == -1) {
				// We could not open the specified file, so
				// display an error and exit

				fprintf (stderr, "Unable to read ethers file %s (%s)\n", optarg, strerror (errno));
				exit (EXIT_FAILURE);
			}
			else {
				// Record the name of the ethers file to use

                        	ethersfile = optarg;
			}
                        break;

		case 'h':
			// The user wants to see the help text

			DisplayHelp ();
			return (EXIT_SUCCESS);
			break;

                case 'p':
                        // The user wants to specify the broadcast port number
                        // to use

			if (! getudpport (optarg, &udpport)) {
				// An error occurred, and we could not convert
				// the argument to a port

				fprintf (stderr, "Port %s is not valid (must be udp service or port between 0 and 65535).\n", optarg);
				exit (EXIT_FAILURE);
			}
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

        // Process arguments on the command line as MAC addresses or hostname

	if (argc == 0) {
		// No arguments were provided beyond options, and we would need
		// at least one argument to process. That argument is the name
		// of the system or the MAC address we want to send the WOL
		// magic packet to. However, we captured the name the program
		// was invoked as earlier, and if not "wol", we assume it is
		// the name of the system we want to wake up. This works if the
		// program is linked to (usually by symbolic link, eg. there is
		// a link to /usr/local/bin/wol from a file named "mysystem",
		// and the program is invoked as "mysystem")

		if (! strcmp (macaddressorhostname, WOLPROGRAMNAME)) {
			// Invoke the function to wake up the system identified
			// by the name of this program

			if (! wakeup_macaddrorhost (broadcastaddr, macaddressorhostname, ethersfile, (unsigned short) udpport)) {
				// We were unable to send the WOL packet to the
				// system. Display an error message and exit

				fprintf (stderr, "Unable to send wake-up to %s\n", macaddressorhostname);
				exit (EXIT_FAILURE);
			}
			else {
				// We were successful

				exit (EXIT_SUCCESS);
			}
		}
		else {
			// The program truly is missing an argument, the name
			// of the system to wake up or its MAC address

			fprintf (stderr, "Missing system name or MAC address\n");
			exit (EXIT_FAILURE);
		}
	}
	else {
		// Process the argument(s) remaining, which we treat as a
		// hostname or MAC address. We assume success

		retval = EXIT_SUCCESS;
	        for (i = 0; i < argc; i++) {
			macaddressorhostname = argv [i];
        	        if (! wakeup_macaddrorhost (broadcastaddr, macaddressorhostname, ethersfile, (unsigned short) udpport)) {
				// An error occurred, and we were unable to
				// send the WOL packet to the destination

				fprintf (stderr, "Unable to send wake-up to %s (%s)\n", macaddressorhostname, ((errno == 0) ? "check hostname or MAC address" : strerror (errno)));
				retval = EXIT_FAILURE;
			}
        	}

		// Return the success or failure value

		exit (retval);
	}

	// We should never, ever get here

	return -1;
}

/* void DisplayHelp (void)
**
** This function displays help options and other information.
*/

void DisplayHelp (void)
{
        printf ("Usage:\n\n");
# ifdef IP_ONESBCAST
	printf ("\twol [-b <baddr>] [-f <file>] [-h] [-p <port>] [[host] ...]\n");
# else
	printf ("\twol [-f <file>] [-h] [-p <port>] [[host] ...]\n");
# endif
	printf ("\n");
	printf ("This program is used to broadcast a Wake On LAN (WOL) \"magic\" packet to the\n");
	printf ("local subnet, to wake up one or more target systems specified as arguments\n");
	printf ("\n");
# ifdef IP_ONESBCAST
	printf ("\t-b <baddr>	Use the specified broadcast address (see below)\n");
# endif	// IP_ONESBCAST
	printf ("\t-f <file>    The filename of an ethers(5) file (default is /etc/ethers)\n");
	printf ("\t-h           Displays this help text.\n");
	printf ("\t-p <port>    The name of a UDP service or a number between 0 and 65,535\n");
	printf ("\n");
# ifdef IP_ONESBCAST
	printf ("If run on a system with multiple network interfaces, the host will select an\n");
	printf ("interface to send the broadcast packet out from. This default behavior can be\n");
	printf ("overridden using the -b flag and specifying the broadcast address (baddr). The\n");
	printf ("broadcast address should be specified as the network portion of the interface\n");
	printf ("and the broadcast address, e.g. -b 172.17.255.255 or -b 192.168.3.255\n");
	printf ("\n");
# endif // IP_ONESBCAST
	printf ("The host to wake up can be specified using a MAC address or a hostname. If");
	printf ("a MAC address is specified it should be in the format XX:XX:XX:XX:XX:XX. Each\n");
	printf ("octect (XX) should be a hexadecimal value (00 - FF). If a hostname is specified\n");
	printf ("it can be a short name or alias, or a Fully Qualified Domain Name (FQDN). The\n");
	printf ("hostname is looked up to try and get a FQDN, but if one is not found the short\n");
	printf ("name or alias is looked up in the ethers(5) file regardless. More than one MAC\n");
	printf ("or hostname can be specified, and MAC addresses and hostnames may be specified\n");
	printf ("interchangeably.\n");
	printf ("\n");
	printf ("If there is a symbolic link to the program, and no MAC addresses or hostnames\n");
	printf ("are specified, the name of the symbolic link is interpreted as a hostname.\n");
}

/* bool getudpport (const char *port, unsigned short *udpport)
**
** This function is used to convert the command line argument to the "port"
** option to long value. The user can specify either the name of a service in
** /etc/services, or a numeric value between 0 and 65,535. On success the
** return value is between 0 and 65,535, and on failure it is -1
*/

bool getudpport (const char *port, unsigned short *udpport)
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