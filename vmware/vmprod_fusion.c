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

** File: vmprod_fusion.c
**
** Author: John Howie (john@howieconsultinginc.com)
**
** Description
**
**      This file contains the implementation of the vmware Fusion-specific
** functions for the daemon that listens for WOL "magic" packets and sends
** start commands to vmware. It is necessary as various vmware products have
** different REST APIs
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
# include <curl/curl.h>

# include "vmprod.h"
# include "parseJSON.h"

# define VMPROD_RESTAPI_GETVMS        "/api/vms"

CURL            *vmrestserver;  // Handle to the vmrest server
extern int      errno;

/*
** The following is a data type we use when processing data received from the
** VMware Fusion server
*/

typedef struct http_data {
        unsigned char   *data;
        size_t          length;
} HTTP_DATA, *PHTTP_DATA;

/*
** The following is a structure we use to store virtual machine MAC addresses
** and the machine identifiers, and a pointer to the list of structures
*/

typedef struct vm_addr_id {
        char                    *macaddress;
        char                    *id;
        struct vm_addr_id       *next;        
} VM_ADDR_ID, *PVM_ADDR_ID;

PVM_ADDR_ID vmaddrlist = (PVM_ADDR_ID) 0;

/*
** The following are functions local to this module
*/

size_t http_write_callback (char *ptr, size_t size, size_t nmemb, void *userdata);

/* bool vmprod_getcredentials (char **credentials, bool verbose)
**
** This function is called whenever the user invokes the program without
** specifying the credentials to be used. In VMware Fusion, the credentials
** are a simple username and password, so that is what we ask for
*/

bool vmprod_getcredentials (char **credentials, bool verbose)
{
        char    *username = (char *) 0, *password = (char *) 0, *nlptr;
        size_t  linelen, linecap;

        // Get the username

        printf ("Username: ");
        linecap = 0;
        if ((linelen = getline (&username, &linecap, stdin)) == -1) {
                // An error occurred, and we are unable to get the username so
                // write out an error and return false

                vmprod_writeerrmsg ("Unable to get Username (%s)\n", (errno == 0 ? "Unknown error" : strerror (errno)));
                return false;
        }

        // Get the password

        password = getpass ("Password: ");

        // Build the credentials used when communicating with the VMware REST
        // API server. Strip off the newline at the end of the username

        nlptr = index (username, (int) '\n');
        if (nlptr != (char *) 0) *nlptr = (char) 0;

        // Create a buffer large enough to store the username and password, and
        // the ':' and terminating NULL

        if ((*credentials = malloc (strlen (username) + strlen (password) + 2)) == (char *) 0)
        {
                // An error occurred, and we could not allocate memory for the
                // credentials we need

                free ((void *) username);
                free ((void *) password);
                vmprod_writeerrmsg ("Unable to create credentials (%s)\n", (errno == 0 ? "Unknown error" : strerror (errno)));
                return false;
        }

        // Build the credentials string

        strcpy (*credentials, username);
        strcat (*credentials, ":");
        strcat (*credentials, password);

        // We are done, return true

        return true;
}

/* bool vmprod_initialize (const char *vmserverurl, const char* credentials, bool verbose)
**
** This function is called to initialize the program. It connects to VMware
** Fusion over the REST API, obtains a list of the virtual machines on it, and
** then queries each for their network adapters and the ethernet addresses of
** each. It stores the MAC address of each ethernet adapter and the machine it
** belongs to in a list, which is consulted when we receive a magic packet
*/

bool vmprod_initialize (const char *vmserverurl, const char* credentials, bool verbose)
{
        CURLcode                curlresult;
        HTTP_DATA               vmserver_response;
        char                    *vmserverrestapiurl, *vmid, *macaddress;
        struct curl_slist       *headers = (struct curl_slist *) 0;
        long                    vmserver_responsecode;
        JSON                    vmlistarray, vminfoobject, vmidstring, vmnetworkobject, vmnicsarray, vmnicobject, vmmacstring;
        PVM_ADDR_ID             newvmaddr;
        
        if (verbose)
                printf ("vmprod_initialize: starting...\n");

        // Set up CURL to connect to the server

        vmrestserver = curl_easy_init ();
        if (! vmrestserver) {
                // An error occurred, and we cannot proceed

                vmprod_writeerrmsg ("Unable to setup connection to vmrest server\n");
                return false;
        }

        // Set the authentication options. First we specify basic
        // authentication

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the authentication
                // method to basic

                vmprod_writeerrmsg ("Unable to set option for basic authentication (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Next, we specify the credentials we will use

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_USERPWD, credentials);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the credentials

                vmprod_writeerrmsg ("Unable to set credentials for vmrest server (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Set the callback function that processes chunks of the server
        // response, as we get them

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_WRITEFUNCTION, http_write_callback);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the write callback
                // function

                vmprod_writeerrmsg ("Unable to set callback function to process HTTP response data (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Set the structure we use to hold the response data

        memset (&vmserver_response, 0, sizeof (vmserver_response));
        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_WRITEDATA, (void *) &vmserver_response);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the option that
                // is used to tell CURL what our data structure is

                vmprod_writeerrmsg ("Unable to set data option, to hold response data (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Set the URL to query the REST API for the list of virtual machines,
        // starting with allocating memory for the URL

        vmserverrestapiurl = (char *) malloc (strlen (vmserverurl) + strlen (VMPROD_RESTAPI_GETVMS) + 1);
        if (vmserverrestapiurl == (char *) 0) {
                // An error occurred allocating memory

                vmprod_writeerrmsg ("Unable to allocate memory for URL to query for VMs (%s)\n", strerror (errno));
                return false;
        }

        // Build the URL string to query for VMs

        strcpy (vmserverrestapiurl, vmserverurl);
        strcat (vmserverrestapiurl, VMPROD_RESTAPI_GETVMS);

        // Set the URL option

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_URL, vmserverrestapiurl);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the URL for the API

                vmprod_writeerrmsg ("Unable to set URL to query VMs (%s)\n", curl_easy_strerror (curlresult));
                (void) free (vmserverrestapiurl);
                return false;
        }

        // Set the header we need

        if ((headers = curl_slist_append (headers, "Accept: application/vnd.vmware.vmw.rest-v1+json")) == (struct curl_slist *) 0) {
                // An error occurred, all we can do is write out an error
                // message and return

                vmprod_writeerrmsg ("Unable to create header list (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Tell curl to add our header

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_HTTPHEADER, headers);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the header option

                vmprod_writeerrmsg ("Unable to set header (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Lastly, before actually performing the HTTP request, we tell curl to
        // make a GET request

        curlresult = curl_easy_setopt (vmrestserver, CURLOPT_HTTPGET, 1);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not set the HTTP GET option

                vmprod_writeerrmsg ("Unable to set HTTP GET option (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // We are now ready to make the request, to get the list of VMs!

        if (verbose)
                printf ("Calling REST API to query for list of virtual machines...\n");

        curlresult = curl_easy_perform (vmrestserver);
        if (curlresult != CURLE_OK) {
                // An error occurred. All we can do is write an error message
                // and return

                vmprod_writeerrmsg ("Unable to execute HTTP request (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Get the response code from the CURL request

        curlresult = curl_easy_getinfo (vmrestserver, CURLINFO_RESPONSE_CODE, &vmserver_responsecode);
        if (curlresult != CURLE_OK) {
                // An error occurred, and we could not get the response code
                // for the request we just made

                vmprod_writeerrmsg ("Unable to get response code querying VMs (%s)\n", curl_easy_strerror (curlresult));
                return false;
        }

        // Check what the response code was. We want 200, and nothing else

        if (vmserver_responsecode != 200) {
                // We did not get the code we wanted. All we can do is display
                // an error message and return false

                vmprod_writeerrmsg ("Received bad response from server (%d)\n", vmserver_responsecode);
                return false;
        }

        // Now, we have to process the response. It should be in JSON, and
        // should be an array of objects, with each object being a virtual
        // machine. We parse the JSON

        set_parse_JSON_debug (verbose);
        if ((vmlistarray = parse_JSON_from_buffer ((char *) vmserver_response.data, vmserver_response.length, false)) == (JSON) 0) {
                // An error occurred, and we could not parse the JSON

                vmprod_writeerrmsg ("Unable to parse JSON received from server (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                return false;
        }

        // Free up the data received from the server, as we no longer need it,
        // and reset the data structure (we use it again, later)

        free (vmserver_response.data);
        memset (&vmserver_response, 0, sizeof (HTTP_DATA));

        // Go through the objects in the array we should have received. Get the
        // first object representing a virtual machine (assuming that there is
        // at least one)

        vminfoobject = get_first_element_in_JSON_array (vmlistarray);
        while (vminfoobject != (JSON) 0) {
                // Process the object. We need the "id" member value

                if ((vmidstring = get_membervalue_in_JSON_object (vminfoobject, (unsigned char *) "id", true)) == (JSON) 0) {
                        // We encountered an error, getting the value
                        // associated with the member name "id"

                        vmprod_writeerrmsg ("Unable to get value for member name \"id\" (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Process the id of the machine. We use it to get the network
                // configuration of the virtual machine

                if ((vmid = (char *) get_JSON_string (vmidstring)) == (char *) 0) {
                        // We could not get the string

                        vmprod_writeerrmsg ("Unable to convert the id of the machine to a string (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                if (verbose)
                        printf ("Processing virtual machine id: %s...\n", vmid);

                // We now need to query the server for the network
                // configuration for this virtual machine, using the id we just
                // obtained from the list

                // Set the URL to query the REST API for the list NICs on the
                // virtual machine. Free up the memory we allocated earlier (we
                // could use realloc, here)

                free (vmserverrestapiurl);
                vmserverrestapiurl = (char *) malloc (strlen (vmserverurl) + strlen (VMPROD_RESTAPI_GETVMS) + 1 + strlen (vmid) + 5);
                if (vmserverrestapiurl == (char *) 0) {
                        // An error occurred allocating memory

                        vmprod_writeerrmsg ("Unable to allocate memory for URL to query for NICs (%s)\n", strerror (errno));
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Build the URL string to query for VMs

                strcpy (vmserverrestapiurl, vmserverurl);
                strcat (vmserverrestapiurl, VMPROD_RESTAPI_GETVMS);
                strcat (vmserverrestapiurl, "/");
                strcat (vmserverrestapiurl, vmid);
                strcat (vmserverrestapiurl, "/nic");

                // Set the URL option

                curlresult = curl_easy_setopt (vmrestserver, CURLOPT_URL, vmserverrestapiurl);
                if (curlresult != CURLE_OK) {
                        // An error occurred, and we could not set the URL for the API

                        vmprod_writeerrmsg ("Unable to set URL to query NICs on virtual machine (%s)\n", curl_easy_strerror (curlresult));
                        (void) free (vmserverrestapiurl);
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // We are now ready to make the request, to get the list of
                // NICs on this virtual machine

                if (verbose)
                        printf ("Calling REST API to query for NICs on virtual machine...\n");

                curlresult = curl_easy_perform (vmrestserver);
                if (curlresult != CURLE_OK) {
                        // An error occurred. All we can do is write an error message
                        // and return

                        vmprod_writeerrmsg ("Unable to execute HTTP request for NICs (%s)\n", curl_easy_strerror (curlresult));
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Get the response code from the CURL request

                curlresult = curl_easy_getinfo (vmrestserver, CURLINFO_RESPONSE_CODE, &vmserver_responsecode);
                if (curlresult != CURLE_OK) {
                        // An error occurred, and we could not get the response code
                        // for the request we just made

                        vmprod_writeerrmsg ("Unable to get response code querying for NICs (%s)\n", curl_easy_strerror (curlresult));
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Check what the response code was. We want 200, but we might
                // get a 500 for an encrypted machine

                switch (vmserver_responsecode) {
                case 200:
                        // This is what we hoped for, just break

                        break;

                case 500:
                        // The machine is encrypted, and we cannot get the NICs
                        // so just ignore it and move to the next machine

                        if (verbose)
                                printf ("Virtual machine is encrypted, skipping it...\n");

                        free (vmserver_response.data);
                        memset (&vmserver_response, 0, sizeof (HTTP_DATA));
                        vminfoobject = get_next_element_in_JSON_array (vmlistarray);
                        continue;
                        break;

                default:
                        // We did not get the code we wanted. All we can do is display
                        // an error message and return false

                        vmprod_writeerrmsg ("Received bad response from server when querying for NICs (%d)\n", vmserver_responsecode);
                        free_parsed_JSON (vmlistarray);
                        return false;
                        break;
                }

                // Parse the response, which should be an object with a member
                // that is an array of objects, one for each NIC associated
                // with the virtual machine

                if ((vmnetworkobject = parse_JSON_from_buffer ((char *) vmserver_response.data, vmserver_response.length, false)) == (JSON) 0) {
                // An error occurred, and we could not parse the JSON

                        vmprod_writeerrmsg ("Unable to parse JSON received from server (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Free up the data received from the server, as we no longer need it,
                // and reset the data structure (we use it again, later)

                free (vmserver_response.data);
                memset (&vmserver_response, 0, sizeof (HTTP_DATA));

                // Get the array of NICs in the object

                if ((vmnicsarray = get_membervalue_in_JSON_object (vmnetworkobject, (unsigned char *) "nics", true)) == (JSON) 0) {
                        // An error occured, and we could not get the array of
                        // NICs in the virtual machine

                        vmprod_writeerrmsg ("Unable to get array of NICs from network object (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                        free_parsed_JSON (vmnetworkobject);
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Get the first NIC in the array of NICs associated with the
                // virtual machine, and then process it

                vmnicobject = get_first_element_in_JSON_array (vmnicsarray);
                while (vmnicobject != (JSON) 0) {
                        // Get the MAC address fron this NIC object

                        if ((vmmacstring = get_membervalue_in_JSON_object (vmnicobject, (unsigned char *) "macAddress", true)) == (JSON) 0) {
                                // We could not get the MAC address from the
                                // NIC object. All we can do is clean up and
                                // return

                                vmprod_writeerrmsg ("Unable to get MAC address from NIC object (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                                free_parsed_JSON (vmnetworkobject);
                                free_parsed_JSON (vmlistarray);
                                return false;
                        }

                        // Now, convert the returned JSON string into a string
                        // we can work with

                        if ((macaddress = (char *) get_JSON_string (vmmacstring)) == (char *) 0) {
                                // An error occurred, and we could not get the
                                // MAC address from the JSON string

                                vmprod_writeerrmsg ("Unable to get MAC address as string from JSON string (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                                free_parsed_JSON (vmnetworkobject);
                                free_parsed_JSON (vmlistarray);
                                return false;
                        }

                        // Now, add the machine identifier and the MAC address
                        // to the list we are building. Start by allocating
                        // memory for the new virtual machine MAC address and
                        // identifier we want to add

                        if ((newvmaddr = malloc (sizeof (VM_ADDR_ID))) == (PVM_ADDR_ID) 0) {
                                // An error occured, and we could not allocate
                                // memory for the new virtual machine MAC
                                // address

                                vmprod_writeerrmsg ("Unable to allocate memory for new MAC address and machine id (%s)\n", strerror (errno));
                                free_parsed_JSON (vmnetworkobject);
                                free_parsed_JSON (vmlistarray);
                                return false;
                        }

                        // Populate the members of the structure, and insert it
                        // at the head of the list of virtual machine MAC
                        // addresses

                        if (verbose)
                                printf ("Adding MAC Address %s for Machine ID %s to list\n", macaddress, vmid);

                        newvmaddr ->id = vmid;
                        newvmaddr -> macaddress = macaddress;
                        newvmaddr -> next = vmaddrlist;
                        vmaddrlist = newvmaddr;

                        // Get the next NIC in the array of NICs associated
                        // with this virtual machine

                        vmnicobject = get_next_element_in_JSON_array (vmnicsarray);
                }

                // Free up the virtual machine networks object we got, as we
                // no longer need it

                free_parsed_JSON (vmnetworkobject);

                // Check that we do not have an error (when getting the first
                // or next element in the array of NICs)

                if (get_last_JSON_error () != JSON_OK) {
                        // An errror occured. We just clean up and return

                        vmprod_writeerrmsg ("Unable to get first / next NIC in array of NICs (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                        free_parsed_JSON (vmlistarray);
                        return false;
                }

                // Try and get the next object element in the array of virtual
                // machines

                vminfoobject = get_next_element_in_JSON_array (vmlistarray);
        }

        // We do not need the JSON any longer, so free it up

        free_parsed_JSON (vmlistarray);

        // Check that we did not encounter an error

        if (get_last_JSON_error () != JSON_OK) {
                // An error occurred - display the details and return as we
                // assume we could not get a list of virtual machines

                vmprod_writeerrmsg ("An error occurred processing the JSON array of virtual machines (%d - %s)\n", get_last_JSON_error (), get_last_JSON_error_string ());
                return false;
        }

        return true;
}

/* void vmprod_DisplayHelp (void)
**
** Display VMware product-specific help (in this case, VMware Fusion)
*/

void vmprod_DisplayHelp (void)
{
        printf ("VMware Fusion accepts a simple username and password for credentials. If\n");
        printf ("specified on the command line, they should be in the format:\n\n");
        printf ("\tusername:password\n\n");
        printf ("If you do not specify credentials on the command line, you will be prompted to\n");
        printf ("enter them interactively.\n");
}

/* void vmprod_writeerrmsg (char *fmt, ...)
**
** This function is used to write out an error message. It is specific to the
** VMware product. In the case of VMware Fusion, we just write out to the
** standard error
*/

void vmprod_writeerrmsg (char *fmt, ...)
{
        va_list ap;
        
        // Initialize the variable arguments

        va_start (ap, fmt);

        // Just pass everything to vfprintf ()

        vfprintf (stderr, fmt, ap);

        // Clean-up

        va_end (ap);
}

/* bool vmprod_processwol (char *ethernetstr, bool verbose)
**
** This function is called to process a received Wake On LAN (WOL) "magic"
** packet by the listener. It check the Ethernet address passed as a string
** against the list obtained from VMware Fusion, and if there is a match it
** sends a start command to Fusion for the associated virtual machine
*/

bool vmprod_processwol (char *ethernetstr, bool verbose)
{
        PVM_ADDR_ID     current_addr = vmaddrlist;

        // Go through the list of MAC addresses we have, looking for a match to
        // the MAC aaddress we just got

        while (current_addr != (PVM_ADDR_ID) 0) {
                // Compare the ethernet MAC address in the current address with
                // the address passed to us

                if (! strcasecmp (ethernetstr, current_addr ->macaddress)) {
                        // We found a matching MAC address in the list of
                        // addresses we have for virtual machines

                        if (verbose)
                                printf ("Found MAC address in list, belongs to machine %s\n", current_addr ->id);

                        // TODO: Write code that tells machine to power on

                        return true;
                }

                // Get the next virtual machine MAC address in the list

                current_addr = current_addr ->next;
        }

        // If we got here, there was no matching MAC address

        if (verbose)
                printf ("No matching MAC address found\n");

        return true;
}

/* size_t http_write_callback (char *ptr, size_t size, size_t nmemb, void *userdata)
**
** This function is called by the CURL library when data is received as part of
** an HTTP request to a server. It can be called many times in response to a
** request, with chunks of data. We need to process each chunk we get. We do
** that by adding each chunk to a response body.
*/

size_t http_write_callback (char *ptr, size_t size, size_t nmemb, void *userdata)
{
        size_t          additionaldatasize;
        HTTP_DATA       *response;
        unsigned char   *new_data;

        // Process the chunk of data we just got. We calculate the size of the
        // chunk, and allocate more memory for it. We add two additional bytes
        // to the memory required, so that the JSON parser library we use can
        // parse the JSON without copying it to a new buffer. Note that if this
        // callback is invoked multiple times, an extra two bytes will be added
        // every time

        additionaldatasize = size * nmemb;
        response = (HTTP_DATA *) userdata;
        new_data = (unsigned char *) realloc (response -> data, response -> length + additionaldatasize +2);
        if (new_data == (unsigned char *) 0) {
                // An error occurred, and we could not allocate memory for the
                // additional data we got. All we can do is write out an error
                // message and exit

                vmprod_writeerrmsg ("Unable to allocate memory to store received data (%s)\n", (errno == 0 ? "Unknown error" : strerror (errno)));
                exit (EXIT_FAILURE);
        }

        // Add the chunk we just received to the response data

        response -> data = new_data;
        memcpy ((void *) (response -> data + response -> length), (void *) ptr, additionaldatasize);
        response -> length += additionaldatasize;

        // Return the amount of data we processed

        return additionaldatasize;
}
