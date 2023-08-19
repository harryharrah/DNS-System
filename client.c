#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), sendto() and recvfrom() */
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#include <netinet/in.h>/* for IP Address structure*/
#include <stdint.h>
#include "DNS.h"

unsigned int generateUDPFormat(char *out, struct DNS_Header header, struct DNS_Query query);
unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader);
unsigned int extractQuery(char* beginingPointer, struct DNS_Query* dnsquery);
unsigned int extractRRs(char *beginingPointer, struct DNS_RR *dnsrr);
void InvertIP(char *argv,char *InvertIp);

int main(int argc, char *argv[])
{
	int sock; /* Socket descriptor */
	struct sockaddr_in servAddr; /* Echo server address */
	
	//query
	struct DNS_Header header;
	struct DNS_Query query;
	
	//reciever
	struct DNS_Query recvQuery = {0};
	struct DNS_Header recvHead = {0};
	struct DNS_RR recvRecord = {0}; 
	
	//MX second query
	struct DNS_Query mxQuery = {0};
	struct DNS_Header mxHead ={0} ;
	struct DNS_RR mxRecord = {0};
	
	char buffOut[DNS_LENGTH_MAX]; /* String to send to local server */
	char buffIn[DNS_LENGTH_MAX];/* Buffer for receiving local string */
	char InvertIp[DNS_LENGTH_MAX];/*Change the PTR input IP address to the format of domain name*/
	unsigned short localServPort = 53;/*Local server port*/
	char *out = buffOut;/*point to the first address of buffOut*/
	unsigned short offset = 0;/*The string length of the DNS query message stored in the buffOut*/
	unsigned short *offsetptr; 

	/*Check the input query information*/
	if (argc != 3)
	{
		printf("Usage: %s <Query type> <Query infomation>\n", argv[0]);
		exit(1);
	}else if((strcmp(argv[1],"A")!=0) && (strcmp(argv[1],"MX")!=0) && (strcmp(argv[1],"CNAME")!=0) && (strcmp(argv[1],"PTR")!=0)){
		printf("Usage: Query type should be 'A','MX','CNAME',or 'PTR'.\n");
		exit(1);
	}

	/* Create a datagram/UDP socket */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
		printf("socket() failed.\n");
		return -1;
	}
	/*Initial variables*/
	memset(&servAddr, 0, sizeof(servAddr));
	memset(buffOut, 0, DNS_LENGTH_MAX);
	memset(buffIn, 0, DNS_LENGTH_MAX);
	memset(InvertIp, 0, DNS_LENGTH_MAX);
	/* Construct the server address structure */
	servAddr.sin_family = AF_INET; /* Internet addr family */
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.2");/*Server IP address*/
	servAddr.sin_port = htons(localServPort); /* Server port */
	printf("Sending query data to local server 127.0.0.2\n");
	printf("------------------QUERY------------------\n");
	printf("The Query Domain Name is: %s\n", argv[2]);
	printf("The Query Type is: %s\n", argv[1]);
	printf("Now Start the Query Process\n");
	printf("-----------------------------------------\n");	
	
	/*Set value for struct DNS_Header*/
	header.id = htons(header.id = 1);
	header.tag = 0;
	header.queryNum = htons(header.queryNum = 1);
	header.answerNum = 0;
	header.authorNum = 0;
	header.addNum = 0;
	//printf("%hd, %hd, %hd, %hd, %hd, %hd \n",header.id,header.tag,header.queryNum,header.answerNum,header.authorNum,header.addNum);

	/*Set value for struct DNS_Query*/	
	query.name = argv[2];
	if(strcmp(argv[1],"A")==0){
		query.queryType = A_Type;
	}else if(strcmp(argv[1],"MX")==0){
		query.queryType = MX_Type;
	}else if(strcmp(argv[1],"CNAME")==0){
		query.queryType = CNAME_Type;
	}else if(strcmp(argv[1],"PTR")==0){
		query.queryType = PTR_Type;
		InvertIP(argv[2],InvertIp);
//		printf("InvertIp:%s\n",InvertIp);		
		memset(query.name, 0, 50);
		memcpy(query.name,InvertIp,strlen(InvertIp)+1);/*Change the PTR query name of IP address to domain name format*/
	}
	query.queryClass = IN;	
	//printf("%s, %hd, %hd,",query.name,query.queryType,query.queryClass);

	/*Generate DNS query format message*/
	out += generateUDPFormat(out,header,query);
	offset = out - buffOut; 
	
//	int p=0;
//	while(p<=50){
//		printf("%d: %hu\n",p,buffOut[p]);
//		p++;
//	}
	
//	printf("offset:%hd\n",offset);
	
	/*Send DNS message to local Server*/
	if ((sendto(sock, buffOut, offset, 0, (struct sockaddr *) &servAddr, sizeof(servAddr))) != offset){
		printf("sendto() sent a different number of bytes than expected.\n");
	}

	/*Recieve the response from the local Server*/
	unsigned int serAddrLen = sizeof(servAddr);
	if ((recvfrom(sock, buffIn, sizeof(buffIn), 0,(struct sockaddr *) &servAddr, &serAddrLen))< 0)
			printf("recvfrom() failed.\n");
//	printf("from %s:UDP%d : %s\n",inet_ntoa(DNSClntAddr.sin_addr),DNSClntAddr.sin_port,bufin);
//	int n=0;
//	while(n<=100){
//		printf("%d: %hu\n",n,buffIn[n]);
//		n++;
//	}
	
	printf("------------------ANSWER------------------\n");
	char *i = buffIn;/*A pointer point to the first address of buffIn*/
	
	/*Resolve the message of header part*/
	i += extractHeader(i, &recvHead);
	/*Resolve the message of query part*/
	i += 2*extractQuery(i, &recvQuery); /*The increament of i is the whole length of the query part and name+type+class length of RR part.*/
	
	/*Set the value of RR name,type and class*/ 
	recvRecord.name = recvQuery.name; 
	recvRecord.type = recvQuery.queryType;
	recvRecord.responseClass = recvQuery.queryClass;	
	
	/*Resolve the reamin message of RR part*/	
	if(recvHead.tag == 32768){
		printf("Successfully find the answer!!!\n");
		printf("Query name = %s\n",recvQuery.name); 
		i += extractRRs(i,&recvRecord);
		
		if(recvQuery.queryType == MX_Type){
			/*Resolve the addtion part of MX type of query*/
			mxRecord.type = A_Type;
			mxRecord.responseClass = 1;
			i += 4;
			i += extractRRs(i, &mxRecord);
		}
		
		if(recvQuery.queryType == A_Type){
			printf("Query Type: A\n"); 
			printf("Query Class: IN\n"); 
			printf("TTL: %d\n", recvRecord.ttl);
			printf("IP Addr: %s\n", recvRecord.responseData);
		}else if(recvQuery.queryType == MX_Type){
			printf("Query Type: MX\n"); 
			printf("Query Class: IN\n"); 
			printf("TTL: %d\n", recvRecord.ttl);
			printf("Mail Server Domain Name: %s\n", recvRecord.responseData);
			printf("Mail Server IP Address: %s\n", mxRecord.responseData);
		}else if(recvQuery.queryType == CNAME_Type){
			printf("Query Type: CNAME\n"); 
			printf("Query Class: IN\n"); 
			printf("TTL: %d\n", recvRecord.ttl);
			printf("Server alias Domain Name: %s\n", recvRecord.responseData);
		}else if(recvQuery.queryType == PTR_Type){
			printf("Query Type: PTR\n"); 
			printf("Query Class: IN\n"); 
			printf("TTL: %d\n", recvRecord.ttl);
			printf("Domain Name: %s\n", recvRecord.responseData);
		}
	}else{
		printf("Failed to find the answer!!!\n");
	}
	printf("----------------ANSWER END----------------\n");

	close(sock);
	exit(0);
}

void InvertIP(char *argv,char *InvertIp){
	int splitIp[4]={0};
	memset(InvertIp, 0, 50);
	sscanf(argv,"%d.%d.%d.%d",&splitIp[0],&splitIp[1],&splitIp[2],&splitIp[3]);/*Split the IP address into 4 int value by dot*/
//	printf("%d %d %d %d\n",splitIp[0],splitIp[1],splitIp[2],splitIp[3]);
	int i=3;
	for(i;i>=0;i--){
		char string[6];
		//splitIp[i]=splitIp[i]+'0';
		snprintf(string,5,"%d",splitIp[i]);/*Convert the int value into string format*/
		//printf("%s\n",string);
		strcat(InvertIp,string);/*add the string in the last position of InvertIp*/
		strcat(InvertIp,".");	/*add a dot in the last position of InvertIp*/	
	}
	strcat(InvertIp,"in-addr.arpa");/*add this string in the last position of InvertIp*/
//	printf("%s",InvertIp);
//	int k=0;
//	while(InvertIp[k]!='\0'){
//		printf("%d: %c\n",k,InvertIp[k]);
//		k++;
//	}
}

 unsigned int generateUDPFormat(char *out, struct DNS_Header header, struct DNS_Query query){
	char* initial = out;
//	printf("initialAddr:%p\n",&initial);
	memcpy(out, &header, sizeof(header));/*put the value of struct header into out*/
	out+=sizeof(header);/*the position of out pointer add*/
	
	/*将query name按照dot拆分，并将每一段字符串长度存储在该段字符串前面一位*/
	unsigned char count = 0;
	int i = 0;/*The index of the query name*/ 
	int tempts = 0;
	out++; /*先给out加1保证空出一位来存放拆分后第一部分域名的长度*/
	//printf("outaddr: %p\n", out);
	while(1){
		//printf("get: %c\n", query.name[i]);
		if(query.name[i] == '.'){
				memcpy(out-count-1, &count, sizeof(char));
				//printf("out:%p %d\n",out, out[i]);
				//printf("Count: %d\n", count);
				count = 0;
				out++; 
				i++;
				tempts = 1;				
		}
		else if(query.name[i] == '\0'){
			memcpy(out, &(query.name[i]), sizeof(char));
			memcpy(out-count-1, &count, sizeof(char));
			//printf("out:%p %d\n",out, out[i]);
			count = 0;
			break;/*End of the string, thus breaking the loop*/ 
		}
		else{
			memcpy(out, &(query.name[i]), sizeof(char));
			//printf("out:%p %d\n",out, out[i]);
			out++;
			i++;
			count++; 
		}
	}
	out++;
//	printf("outAddr:%p\n",&out);
	int len = out - initial; /*前面所有存储内容的长度*/
	unsigned short temp = htons(query.queryType);
	memcpy(out, &temp, sizeof(short));
	temp = htons(query.queryClass);
	out+=sizeof(short);
	memcpy(out, &temp, sizeof(short));
	out+=sizeof(short);
//	printf("len:%d\n",len);

//	int p=0;
//	while(p<=50){
//	printf("%d: %hu\n",p,initial[p]);
//	p++;
//	}
	return len+2*sizeof(short); 
}

unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader){
	dnsheader->id = ntohs(*(unsigned short*) (beginingPointer));
	//printf("%hu\n",dnsheader->id);
    dnsheader->tag = ntohs(*(unsigned short*) (beginingPointer+2));	
	//printf("%hu\n",dnsheader->tag);
	dnsheader->queryNum = ntohs(*(unsigned short*) (beginingPointer+4));
	//printf("queryName: %hu\n", dnsheader->queryNum);
	dnsheader->answerNum = ntohs(*(unsigned short*) (beginingPointer+6));
	//printf("%hu\n",dnsheader->answerNum);
	dnsheader->authorNum = ntohs(*(unsigned short*) (beginingPointer+8));
	//printf("%hu\n",dnsheader->authorNum);
	dnsheader->addNum = ntohs(*(unsigned short*) (beginingPointer+10));
	//printf("%hu\n",dnsheader->addNum);
	
	//printf("hllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll:%d\n",sizeof(*dnsheader));
	return sizeof(*dnsheader);
}

unsigned int extractQuery(char* beginingPointer, struct DNS_Query* dnsquery){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	unsigned char count = 0;
	int i = 0;

	//count = ntohs(*(unsigned char*)(beginingPointer));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*beginingPointer!='\0'){
			count = *(unsigned char*)(beginingPointer);
			//printf("count:%d\n", count);
			beginingPointer++;/*point to the first character of query name*/
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), beginingPointer, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; beginingPointer++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
		}else{
			domainName[i-1] = '\0'; //标注结束 
			beginingPointer++; 
			break;
		}
	}
//	printf("i: %d\n", i);  
//	printf("Converted name: %s\n", domainName);
	// printf("length: %d\n", i);
	dnsquery->name = (char*)malloc(i*sizeof(char));
	memcpy(dnsquery->name, domainName, i); //此时的i便为变长字符串的长度了，经过了循环遍历 
//	printf("Query name: %s\n", dnsquery->name);
	
	dnsquery->queryType = ntohs(*(unsigned short*) (beginingPointer));
	dnsquery->queryClass = ntohs(*(unsigned short*) (beginingPointer+2));
//	 printf("Query Type: %d\n", dnsquery->queryType);
//	 printf("Query Class: %d\n", dnsquery->queryClass);
	//printf("qllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll:%d\n",i+4+1);
	return i+4+1; //网络形式的域名表示和点分值差1，在这里特地补上 
}

unsigned int extractRRs(char *beginingPointer, struct DNS_RR *dnsrr){
	unsigned int ipAddr;
	
	dnsrr->ttl = ntohl(*(unsigned int*)(beginingPointer)); //这里是ntohl，32bit数字的转化 
	char str[INET_ADDRSTRLEN];
	struct in_addr addr;
	//printf("Query Answer TTL: %d\n", dnsrr->ttl);
	beginingPointer+=sizeof(dnsrr->ttl);//4
	dnsrr->data_len = ntohs(*(unsigned short*)(beginingPointer));
	//printf("Data Length: %d\n", dnsrr->data_len);
	beginingPointer+=sizeof(dnsrr->data_len);//2
	//rRecord->rdata = (char*)malloc((rRecord->data_len)*sizeof(char));
	//printf("hello\n");
	if(dnsrr->type == MX_Type){
		beginingPointer += 2; //将Preferencre的长度空出去
	}
	
	if(dnsrr->type == A_Type){
		ipAddr = *(unsigned int*)(beginingPointer);
//		printf("Query Answer TTL: %d\n", dnsrr->ttl);
		memcpy(&addr, &ipAddr, 4);
		const char *ptr = inet_ntop(AF_INET, &addr, str, sizeof(str)); //转化为十进制点分值的IP地址
//		printf("Query Answer IP: %s\n", ptr);
		dnsrr->responseData = (char*)malloc((strlen(ptr)+1)*sizeof(char));
		strcpy(dnsrr->responseData,ptr);
		return 10;//4(TTL)+2(DATA_LEN)+4(IP)
	}else if((dnsrr->type == CNAME_Type) || (dnsrr->type == PTR_Type)){
		char domainName[100];
		memset(domainName, 0, 100);
		char *d = domainName;
		//printf("d: %s\n", d);
		unsigned char count = 0;
		int i = 0; 
		//count = ntohs(*(unsigned char*)(q));
		//完成报文中数字加域名形式至点分值的转换 
		while(1){
			if(*beginingPointer!='\0'){
				count = *(unsigned char*)(beginingPointer);
				//printf("count:%d\n", count);
				beginingPointer++;
				while(count){
					//printf("i: %d\n", i);
					//printf("char1:%c\n", *q);
					memcpy(&(domainName[i]), beginingPointer, sizeof(char));
					//printf("domain name i: %c\n", domainName[i]);
					count--; beginingPointer++; i++;
				}
				domainName[i] = '.'; //加点 
				i++;
			}else{
				domainName[i-1] = '\0'; //标注结束 
				beginingPointer++; 
				break;
			}
		}
		// printf("i: %d\n", i);  
		// printf("Converted domain name: %s\n", domainName);
		// printf("length: %d\n", i);
		dnsrr->responseData = (char*)malloc(i*sizeof(char));
		memcpy(dnsrr->responseData, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
		// printf("Query name: %s\n", rRecord->rdata);
		// 	printf("The CNAME is: %s\n", rRecord->rdata);
		return 4 + 2 + dnsrr->data_len;
	}else if(dnsrr->type == MX_Type){
		//int firstlen = dnsrr.data_len - 5;
		char domainName[100];
		memset(domainName, 0, 100);
		char *d = domainName;
		//printf("d: %s\n", d);
		unsigned char count = 0;
		int i = 0; 
		//count = ntohs(*(unsigned char*)(q));
		//完成报文中数字加域名形式至点分值的转换 
		while(1){
			if(*beginingPointer!='\0'){
				count = *(unsigned char*)(beginingPointer);
//				printf("count:%d\n", count);
				beginingPointer++;
				while(count){
//					printf("i: %d\n", i);
//					printf("char1:%c\n", *beginingPointer);
					memcpy(&(domainName[i]), beginingPointer, sizeof(char));
//					printf("domain name i: %c\n", domainName[i]);
					count--; beginingPointer++; i++;
				}
				domainName[i] = '.'; //加点 
				i++;
			}else{
				domainName[i-1] = '\0'; //标注结束 
				beginingPointer++; 
				break;
			}
		}
//		printf("i: %d\n", i);  
//		printf("Converted domain name: %s\n", domainName);
//		printf("length: %d\n", i);
		//strcpy(domainName, strcat(domainName, dnsrr->name)); //由于压缩了指针，对两字符串进行拼接
		//printf("Converted domain name: %s\n", domainName);
		//int totalen = strlen(dnsrr->name) + i; //拼接后总长度
		dnsrr->responseData = (char*)malloc(i*sizeof(char));
		memcpy(dnsrr->responseData, domainName, i); 
//		printf("Query name: %s\n", dnsrr->name);
//		printf("The CNAME is: %s\n", dnsrr->responseData);
//		printf("rlllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll: %d\n",4+2+dnsrr->data_len+1);
		return 4+2+dnsrr->data_len+1;
	}	
}

