#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>


int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char userMessage[1500];
	u_char packet[100];
	int i = 0;
	int contador = 0;
	int seleccion = 0;
	pcap_if_t *alldevs;
	pcap_if_t *d;

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for(d= alldevs; d != NULL; d= d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	printf("Select interface: ");
	scanf("%d", &seleccion);

    for(d= alldevs; d != NULL; d= d->next)
	{
		contador++;
		if(contador == seleccion) break;
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return 0;
	}

	/* We don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);


	/* Check the validity of the command line
	if (argc != 2)
	{
		printf("usage: %s interface", argv[0]);
		return 1;
	}*/

	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,		// name of the device
							 65536,			// portion of the packet to capture. It doesn't matter in this case
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
	}

	printf("Introduce el mensaje que quieres enviar: ");
	fflush(stdin);
	gets(userMessage);

	int userLength;
	userLength = strlen(userMessage);

	if(userLength < 46) {
        for(int i = userLength; i <= 46; i++) userMessage[i] = '\0';
	}

	int messageLength;
	messageLength = 14 + userLength;
	u_char message[messageLength];

	//Destination
	message[0]=0xFF;
	message[1]=0xFF;
	message[2]=0xFF;
	message[3]=0xFF;
	message[4]=0xFF;
	message[5]=0xFF;

	//Source
	message[6]=0x44;
	message[7]=0x85;
	message[8]=0x00;
	message[9]=0xE8;
	message[10]=0x7B;
	message[11]=0xDC;

	//Ethertype
	message[12] = 0x21;
	message[13] = 0x21;

	int j = 0;
	for(int i = 14; i < messageLength; i++) {
        message[i] = userMessage[j];
        j++;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		message,				// buffer with the packet
		messageLength					// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);
	return 0;
}


