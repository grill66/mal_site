#include "windivert.h"
#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define MAXBUF 1500

int PrintPacket(unsigned char * packet, int len) {
	int i = 0;
	
	for (i = 0; i < len; i++) {
		if (i == 0)				printf("%02X ",		packet[0]);
		else if ((i % 16) == 0) printf("\n%02X ",	packet[i]);
		else if ((i % 8) == 0)	printf(" %02X ",	packet[i]);
		else					printf("%02X ",		packet[i]);
	}

	printf("\n");

	return 0;
}

int MalSiteCmp (FILE * fp, const char * url){
	char			buf[512] = { 0, };
	int				urllen = 0;
	char			tempchar;

	while (1) {
		tempchar = fgetc(fp);
		if (tempchar == EOF) break;
		else if (tempchar == '\x0A') {

			fseek(fp, -urllen - 2, SEEK_CUR);
			fread(buf, 1, urllen, fp);
			
			if (buf == NULL) break;
			else {
				if (strstr(buf, url) != NULL) {
					fseek(fp, 0, SEEK_SET);
					return 1;
				}
				
			}
			
			urllen = 0;
			fseek(fp, 2, SEEK_CUR);
			memset(buf, 0, sizeof(buf));
		}
		else {
			urllen++;
		}
		
			

	}
	
	fseek(fp, 0, SEEK_SET);

	return 0;
}

int main() {

	WINDIVERT_ADDRESS	windivert_address;
	HANDLE				windivert_handle = NULL;
	unsigned char		packet[MAXBUF];
	unsigned int		packetlen;
	WINDIVERT_IPHDR *	pwindivert_iphdr;
	WINDIVERT_TCPHDR *	pwindivert_tcphdr;
	unsigned char *		phttp;
	unsigned char *		urlstartaddr;
	unsigned char *		urlendaddr;
	unsigned char		url[256] = { 0, };
	int					i = 0;
	FILE *				fp;
	
	fp = fopen("C:\\mal_site.txt", "r");

	windivert_handle = WinDivertOpen("tcp.DstPort == 80 or tcp.SrcPort == 80", 0, 0, 0);

	if (windivert_handle == INVALID_HANDLE_VALUE) {
		printf("Handle Error : %d\n", GetLastError());
		exit(1);
	}


	while (TRUE) {
		if (!WinDivertRecv(windivert_handle, packet, sizeof(packet), &windivert_address, &packetlen)) {
			printf("Recv Error\n");
			continue;
		}
		
		pwindivert_iphdr = packet;
		pwindivert_tcphdr = (char *)pwindivert_iphdr + (int)pwindivert_iphdr->HdrLength * 4;
		phttp = (char *)pwindivert_tcphdr + (int)pwindivert_tcphdr->HdrLength * 4;

		if (strstr(phttp, "HTTP/1.1") || strstr(phttp, "HTTP/1.0")) {
			if (urlstartaddr = strstr(phttp, "Host")) {
				urlstartaddr = (char *)urlstartaddr + 6;

				if (urlstartaddr) {
					urlendaddr = strstr(urlstartaddr, "\x0d\x0a");
					if (urlendaddr) {
						memset(url, 0, sizeof(url));
						memcpy(url, urlstartaddr, (int)urlendaddr - (int)urlstartaddr);
											
						//printf("%s\n", url);
						
						if (MalSiteCmp(fp, url)) {	//if TRUE, mal site detected	
							printf("[BLOCKED] url : %s\n", url);
							continue;
						}
					}
				}
			}
		}

		if (!WinDivertSend(windivert_handle, packet, packetlen, &windivert_address, NULL)) {
			printf("Send Error\n");
			continue;
		}
	}	


	return 0;
}