/*

  grepcidr 1.3 - Filter IP addresses matching IPv4 CIDR specification
  Copyright (C) 2004, 2005  Jem E. Berkes <jberkes@pc-tools.net>
  	www.sysdesign.ca

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/


#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#define EXIT_OK		0
#define EXIT_NOMATCH	1
#define EXIT_ERROR	2

#define TXT_VERSION	"grepcidr 1.3\nCopyright (C) 2004, 2005  Jem E. Berkes <jberkes@pc-tools.net>\n"
#define TXT_USAGE	"Usage:\n" \
			"\tgrepcidr [-V] [-c] [-v] PATTERN [FILE]\n" \
			"\tgrepcidr [-V] [-c] [-v] [-e PATTERN | -f FILE] [FILE]\n"
#define MAXFIELD	512
#define TOKEN_SEPS	"\t,\r\n"	/* so user can specify multiple patterns on command line */
#define INIT_NETWORKS	8192

/*
	Specifies a network. Whether originally in CIDR format (IP/mask)
	or a range of IPs (IP_start-IP_end), spec is converted to a range.
	The range is min to max (32-bit IPs) inclusive.
*/
struct netspec
{
	unsigned int min;
	unsigned int max;
};

/* Macro to test for valid IP address in four integers */
#define VALID_IP(IP) ((IP[0]<256) && (IP[1]<256) && (IP[2]<256) && (IP[3]<256))
/* Macro to build 32-bit IP from four integers */
#define BUILD_IP(IP) ((IP[0]<<24) | (IP[1]<<16) | (IP[2]<<8) | IP[3])


/* Global variables */
unsigned int patterns = 0;		/* total patterns in array */
unsigned int capacity = 0;		/* current capacity of array */
struct netspec* array = NULL;		/* array of patterns, network specs */

/*
	Insert new spec inside array of network spec
	Dynamically grow array buffer as needed
	The array must have already been initially allocated, with valid capacity
*/
void array_insert(struct netspec* newspec)
{
	if (patterns == capacity)
	{
		capacity *= 2;
		array = realloc(array, capacity*sizeof(struct netspec));
	}
	array[patterns++] = *newspec;
}


/*
	Convert IP address string to 32-bit integer version
	Returns 0 on failure
*/
unsigned int ip_to_uint(const char* ip)
{
	unsigned int IP[4];     /* 4 octets for IP address */
	if ((sscanf(ip, "%u.%u.%u.%u", &IP[0], &IP[1], &IP[2], &IP[3]) == 4) && VALID_IP(IP))
		return BUILD_IP(IP);
	else
		return 0;
}


/*
	Given string, fills in the struct netspec (must be allocated)
	Accept CIDR IP/mask format or IP_start-IP_end range.
	Returns true (nonzero) on success, false (zero) on failure.
*/
int net_parse(const char* line, struct netspec* spec)
{
	unsigned int IP1[4], IP2[4];
	int maskbits = 32;	/* if using CIDR IP/mask format */
	
	/* Try parsing IP/mask, CIDR format */
	if (strchr(line, '/') && (sscanf(line, "%u.%u.%u.%u/%d", &IP1[0], &IP1[1], &IP1[2], &IP1[3], &maskbits) == 5)
		&& VALID_IP(IP1) && (maskbits >= 1) && (maskbits <= 32))
	{
		spec->min = BUILD_IP(IP1) & (~((1 << (32-maskbits))-1) & 0xFFFFFFFF);
		spec->max = spec->min | (((1 << (32-maskbits))-1) & 0xFFFFFFFF);
		return 1;
	}
	/* Try parsing a range. Spaces around hyphen are optional. */
	else if (strchr(line, '-') && (sscanf(line, "%u.%u.%u.%u - %u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3],
		&IP2[0], &IP2[1], &IP2[2], &IP2[3]) == 8) && VALID_IP(IP1) && VALID_IP(IP2))
	{
		spec->min = BUILD_IP(IP1);
		spec->max = BUILD_IP(IP2);
		if (spec->max >= spec->min)
			return 1;
		else
			return 0;
	}
	/* Try simple IP address */
	else if ((sscanf(line, "%u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3]) == 4) && VALID_IP(IP1))
	{
		spec->min = BUILD_IP(IP1);
		spec->max = spec->min;
		return 1;
	}
	return 0;	/* could not parse */
}


/* Compare two netspecs, for sorting. Comparison is done on minimum of range */
int netsort(const void* a, const void* b)
{
	unsigned int c1 = ((struct netspec*)a)->min;
	unsigned int c2 = ((struct netspec*)b)->min;
	if (c1 < c2) return -1;
	if (c1 > c2) return +1;
	return 0;
}

/* Compare two netspecs, for searching. Test if key (only min) is inside range */
int netsearch(const void* a, const void* b)
{
	unsigned int key = ((struct netspec*)a)->min;
	unsigned int min = ((struct netspec*)b)->min;
	unsigned int max = ((struct netspec*)b)->max;
	if (key < min) return -1;
	if (key > max) return +1;
	return 0;
}


int main(int argc, char* argv[])
{
	static char shortopts[] = "ce:f:vV";
	FILE* inp_stream = stdin;		/* input stream, list of IPs to match */
	char* pat_filename = NULL;		/* filename containing patterns */
	char* pat_strings = NULL;		/* pattern strings on command line */
	unsigned int counting = 0;		/* when non-zero, counts matches */
	int invert = 0;				/* flag for inverted mode */
	char line[MAXFIELD];
	int foundopt;
	int anymatch = 0;			/* did anything match? for exit code */
	static regex_t preg;			/* compiled regular expression for IPs */

	if (argc == 1)
	{
		fprintf(stderr, TXT_USAGE);
		return EXIT_ERROR;
	}

	while ((foundopt = getopt(argc, argv, shortopts)) != -1)
	{
		switch (foundopt)
		{
			case 'V':
				puts(TXT_VERSION);
				return EXIT_ERROR;
				
			case 'c':
				counting = 1;
				break;
				
			case 'v':
				invert = 1;
				break;
				
			case 'e':
				pat_strings = optarg;
				break;

			case 'f':
				pat_filename = optarg;
				break;
				
			default:
				fprintf(stderr, TXT_USAGE);
				return EXIT_ERROR;
		}
	}
	
	if (!pat_filename && !pat_strings)
	{
		if (optind < argc)
			pat_strings = argv[optind++];
		else
		{
			fprintf(stderr, "Specify PATTERN or -f FILE to read patterns from\n");
			return EXIT_ERROR;
		}
	}
	
	if (optind < argc)
	{
		inp_stream = fopen(argv[optind], "r");
		if (!inp_stream)
		{
			perror(argv[optind]);
			return EXIT_ERROR;
		}		
	}
	
	/* Initial array allocation */
	capacity = INIT_NETWORKS;
	array = (struct netspec*) malloc(capacity*sizeof(struct netspec));
	
	/* Load patterns defining networks */
	if (pat_filename)
	{
		FILE* data = fopen(pat_filename, "r");
		if (data)
		{
			while (fgets(line, sizeof(line), data))
			{
				struct netspec spec;
				if ((*line != '#') && net_parse(line, &spec))
					array_insert(&spec);
			}
			fclose(data);
		}
		else
		{
			perror(pat_filename);
			return EXIT_ERROR;
		}
	}
	if (pat_strings)
	{
		char* token = strtok(pat_strings, TOKEN_SEPS);
		while (token)
		{
			struct netspec spec;
			if (net_parse(token, &spec))
				array_insert(&spec);
			token = strtok(NULL, TOKEN_SEPS);
		}
	}
	
	/* Prepare array for rapid searching */
	{
		unsigned int item;
		qsort(array, patterns, sizeof(struct netspec), netsort);
		/* cure overlaps so that ranges are disjoint and consistent */
		for (item=1; item<patterns; item++)
		{
			if (array[item].max <= array[item-1].max)
				array[item] = array[item-1];
			else if (array[item].min <= array[item-1].max)
				array[item].min = array[item-1].max + 1;	/* overflow possibility */
		}
	}
	
	/* Compile the regular expression for matching IP addresses */
	if (regcomp(&preg, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", REG_EXTENDED) != 0)
	{
		(void)fputs("regcomp() failed\n", stderr);
		return EXIT_ERROR;
	}

	/* Match IPs from input stream to network patterns */
	while (fgets(line, sizeof(line), inp_stream))
	{
		struct netspec key;
		regoff_t offset;
		regmatch_t pmatch;
		for (offset = 0; regexec(&preg, &line[offset], 1, &pmatch, 0) == 0; offset += pmatch.rm_eo)
		{
			if ((key.min=ip_to_uint(&line[offset + pmatch.rm_so])))
			{
				int match = 0;
				if (bsearch(&key, array, patterns, sizeof(struct netspec), netsearch))
					match = 1;
				if (invert ^ match)
				{
					anymatch = 1;
					if (counting)
						counting++;
					else
						printf("%s", line);
					break;
				}
			}
		}
	}
	
	/* Cleanup */
	if (inp_stream != stdin)
		fclose(inp_stream);
	if (array)
		free(array);
	regfree(&preg);

	if (counting)
		printf("%u\n", counting-1);
	if (anymatch)
		return EXIT_OK;
	else
		return EXIT_NOMATCH;
}
