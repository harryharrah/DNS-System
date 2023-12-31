#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), sendto() and recvfrom() */
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#include <netinet/in.h>/* for IP Address structure*/
#include <stdint.h>
#include "DNS.h"

unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader);
unsigned int extractQuery(char* beginingPointer, struct DNS_Query* dnsquery);
void splitDomainName(char *domainName, char *splitName);
int isEqual(char *str1, char* str2);
char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record);
void splitForipToint(char str[], char *strings[]);
unsigned int ipToint(char ipString[]);

int main(){
	int sock,local_fd; /* Socket descriptor */
	struct sockaddr_in CnUsServerAddr; /* Echo server address */
	struct sockaddr_in LocalServerAddr;
	struct DNS_Header header;
	struct DNS_Query query;

	char buffOut[DNS_LENGTH_MAX]; /* String to send to echo server */
	char buffIn[DNS_LENGTH_MAX];
	char splitName[50];
	char nextAddr[50];
	
	int recvMsgSize; /* Size of received message */
	unsigned short localServPort = 53;
	
	
	//reciever
	struct DNS_Query recvQuery = {0};
	struct DNS_Header recvHead = {0};
	struct DNS_RR recvrRecord = {0}; 
	//responser
	struct DNS_Query resQuery = {0};
	struct DNS_Header resHead ={0} ;
	struct DNS_RR resRecord = {0}; 
	
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		printf("socket() failed.\n");
		return -1;
	}
	
	CnUsServerAddr.sin_family=AF_INET;
	CnUsServerAddr.sin_port=htons(localServPort);
	CnUsServerAddr.sin_addr.s_addr=inet_addr("127.0.0.4");
	if ((bind(sock, (struct sockaddr *) &CnUsServerAddr, sizeof(CnUsServerAddr))) < 0)
		printf("bind() failed.\n");
	
//通过调用listen将套接字设置为监听模式
	if(listen(sock,BACKLOG)==-1)
	{
		printf("listen failed");
		close(sock);
		return -1;
	}
	printf("-----------------------Listen to the localServer---------------------------\n");
	
	while(1)/* Run forever */
	{
		//服务器等待客户端连接中，游客户端连接时调用accept产生一个新的套接字
		socklen_t addr_length=sizeof(LocalServerAddr);
		if((local_fd=accept(sock,(struct sockaddr *)&LocalServerAddr,&addr_length))<0)
		{
			printf("accept failed");
			close(sock);
			return -1;
		}
		printf("----------------------Connect with localServer successfully!-------------------------\n");	
		
		char *out = buffOut+2;
		memset(buffOut, 0, DNS_LENGTH_MAX);
       	memset(buffIn, 0, DNS_LENGTH_MAX);
		//char *i = buffIn;
		recvMsgSize = 0;
		/* Block until receive message from localServer */
		if ((recvMsgSize = recv(local_fd, buffIn, sizeof(buffIn), 0)) < 0)
			printf("recv() failed.\n");
//		printf("from %s:UDP%d :\n",inet_ntoa(LocalServerAddr.sin_addr),LocalServerAddr.sin_port);
//			int p=0;
//			while(p<=50){
//			printf("%d: %hu\n",p,buffIn[p]);
//			p++;
//			}

		//解析localserver 
		char *i = buffIn+2;
		i += extractHeader(i, &recvHead);
	   	i += extractQuery(i, &recvQuery); 
		printf("query name = %s\n",recvQuery.name);
		splitDomainName(recvQuery.name, splitName);
		printf("Split name = %s\n",splitName);
		
		//Response
		resHead.id =htons(recvHead.id);
		resHead.tag =htons(0x8000);//10000.... 
		resHead.queryNum =htons(recvHead.queryNum);
		resHead.answerNum = 0; 
		resHead.authorNum = htons(1);/*因为会告知下一级服务器地址,没找到则后续更改为0*/
		resHead.addNum = 0;
		resQuery = recvQuery;
		resRecord.name=recvQuery.name;
    	resRecord.responseClass=recvQuery.queryClass;

		resRecord.type=A_Type;//A Type, which return the IP address of the TLD DNS Server 
		resRecord.ttl = (unsigned int)86400;
		resRecord.data_len = 4;
		
		//memset(resRecord.responseData, 0, 50);

		if(isEqual(splitName,"edu.cn")){
	    	strcpy(nextAddr, "127.0.0.7");
	    	char *p = nextAddr;
	    	resRecord.responseData = p;
	    	printf("hello, in edu.cn!\n");
	    	printf("resRecordData: %s\n", resRecord.responseData);
			out = generateTCPANSFormat(out,&resHead,&resQuery,&resRecord);  
		}else if(isEqual(splitName,"gov.us")){
			printf("hello, in gov.us!\n");
			strcpy(nextAddr, "127.0.0.6");
			char *p = nextAddr;
	    	resRecord.responseData=p;
	    	printf("resRecordData: %s\n", resRecord.responseData);
			out = generateTCPANSFormat(out,&resHead,&resQuery,&resRecord); 
		}else{
			printf("Sorry, I can't find the answer!\n");
			resHead.authorNum = 0;
			resHead.tag =htons(0x8003); 
			//out = buffOut; 
			out = generateTCPANSFormat(out,&resHead,&resQuery,&resRecord); 
			//查询失败 
		}
		if (sendto(local_fd,buffOut,out-buffOut+3,0, (struct sockaddr *) &LocalServerAddr,sizeof(LocalServerAddr))!=(out-buffOut+3)){
		    printf("sendto() sent a different number of bytes than expected.\n");
		    close(local_fd);
		} 
		close(local_fd);
	}	
	//printf("IP=%s, PORT=%u\n",inet_ntoa(LocalServerAddr.sin_addr),ntohs(LocalServerAddr.sin_port));	
	close(sock);
}

unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader){
	dnsheader->id = ntohs(*(unsigned short*) (beginingPointer));
//	printf("%hu\n",dnsheader->id);
    dnsheader->tag = ntohs(*(unsigned short*) (beginingPointer+2));	
//	printf("%hu\n",dnsheader->tag);
	dnsheader->queryNum = ntohs(*(unsigned short*) (beginingPointer+4));
//	printf("queryName: %hu\n", dnsheader->queryNum);
	dnsheader->answerNum = ntohs(*(unsigned short*) (beginingPointer+6));
//	printf("%hu\n",dnsheader->answerNum);
	dnsheader->authorNum = ntohs(*(unsigned short*) (beginingPointer+8));
//	printf("%hu\n",dnsheader->authorNum);
	dnsheader->addNum = ntohs(*(unsigned short*) (beginingPointer+10));
//	printf("%hu\n",dnsheader->addNum);
	
	return sizeof(*dnsheader);
}

unsigned int extractQuery(char* beginingPointer, struct DNS_Query* dnsquery){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	unsigned char count = 0;
	int i = 0;

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
	return i+4+1; //网络形式的域名表示和点分值差1，在这里特地补上 
}

void splitDomainName(char *domainName, char *splitName){
	int i = strlen(domainName)-1; //免去\0的影响 
	//printf("domainName: %s\n", domainName);
	int j = 0;
	int k = 0;
	int countdot=0;
	char invertName[100];
	char splitOneName[100];
	memset(invertName, 0, 100);
	memset(splitOneName, 0, 100);
	while(1){
		if(domainName[i]!='.'){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
		}
		else if(countdot==0){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
			countdot++;
		}
		else break;
	}
	invertName[j] = '\0';
	//printf("splitOneInvert: %s\n", invertName);
	i = strlen(invertName)-1;
	while(1){
		if(k < strlen(invertName)){
			//printf("s: %c\n", invertName[i]);
			splitName[k] = invertName[i];
			i--; k++;
		}else break;
		
	}
	splitName[k] = '\0';
	//printf("splitTwo: %s\n", splitName);
}

int isEqual(char *str1, char* str2){
    if (strlen(str1)!=strlen(str2))
     	return 0;
	int i=0;
    for (i = 0; str1[i]!='\0'; i++){
        if (str1[i]!=str2[i])
        return 0;
    }
   	return 1;
}

char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record){
		char *bufoutaddrRecord = bufout+1;
		//header->answerNum = 1;
		//header->tag =htons(header->tag=32768);
		memcpy(bufout, header, sizeof(*header));
//		printf("header de id%hu",header->id);
       
		bufout += (sizeof(*header))+1;
		unsigned char count = 0;
		int i = 0;
		int j = 1; 
		int tempts = 0;
		while(1){
//			printf("get: %c\n", query->name[i]);
			if(query->name[i] == '.'){
					memcpy(bufout-count-1, &count, sizeof(char));
//					printf("Count: %d\n", count);
					count = 0;
					bufout++; i++;
					tempts = 1;
				
			}
			else if(query->name[i] == '\0'){
				memcpy(bufout, &(query->name[i]), sizeof(char));
				memcpy(bufout-count-1, &count, sizeof(char));
				count = 0;
				break;
			}
			else{
				memcpy(bufout, &(query->name[i]), sizeof(char));
				bufout++;
				i++;
				count++; 
			}
		}
		bufout++;
		int len = bufout -bufoutaddrRecord+6; //calculate all length
//        printf("len xian zai shi ................%d",len);
		unsigned int temp = htons(query->queryType);
		memcpy(bufout, &temp, sizeof(short));
		temp = htons(query->queryClass);
		bufout+=sizeof(short);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=sizeof(short);
		
		if(header->tag==htons(0x8003)){
			record->responseData=0;
//			printf("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNO : %s",record->responseData);
			len = bufout -bufoutaddrRecord+3; //calculate all length
			char* offset = bufoutaddrRecord - 3; //Leave two bytes for packet capture
			temp = htons(len); 
			memcpy(offset, &temp, sizeof(short));
//			printf(" ANS formal format is %s\n",offset);
//		    int m=0;
//			while(m<=100){
//				printf("ANS %d: %hu\n",m,offset[m]);
//				m++;
//			}			
			return bufout;
		}		
		
        memcpy(bufout, bufoutaddrRecord+11, len-17);//-18+11
        bufout+=(len-17);
        temp=htons(record->type);
	    memcpy(bufout, &temp, sizeof(short));
        bufout+=2;
	    temp=htons(record->responseClass);
	    memcpy(bufout, &temp, sizeof(short));
	    bufout+=2;
	    unsigned int tempint = htonl(record->ttl); //杩欓噷鏄痟tonl 32浣嶆暟瀛楃殑涓绘満瀛楄妭搴忚浆鍖� 
        //printf("tttttttttttttttttttllllllllllllllllllllllll:%d",tempint);
	    memcpy(bufout, &tempint, (sizeof(int)));
        bufout+=4;
        temp=htons(record->data_len);
	    memcpy(bufout, &temp, sizeof(short));
	    bufout+=2;

    // int i=0;
        //printf("zui zhong shencha zhi response data weisha: %c\n", record->responseData[i]);
		unsigned int ipAddr = htonl(ipToint(record->responseData));
		//unsigned int ipAddr = inet_addr(record->responseData);
//        printf("ipppppppppppppppppppppppppppppaddddddddddddddddddr : %u",ipAddr);
		memcpy(bufout, &ipAddr,record->data_len); //灏嗗瓧绗︿覆杞寲涓虹綉缁滃瓧鑺傚簭鐨�4bytes鏁版嵁 
//		int p=0;
//		while(p<=50){
//			printf("ping shen mo shi 655 zhi bufout  %d is: %hd\n",p,bufout[p]);
//		    p++;
//	    }
		//printf("rrDate: %s\n", o);
		bufout+=record->data_len; //涔熷氨鏄绉诲姩4浣� 
	    //printf("i=%d\n", i);
	    //temp =  htons(49164); //杩欓噷鎸囦唬1100000000001100锛孌NS鎶ユ枃涓帇缂╂寚閽堢殑鎿嶄綔
	    //memcpy(o, &temp, sizeof(short)); 
	    //return 16+i;
        //////////////////////////////////////////////
        len = bufout -bufoutaddrRecord+3; //calculate all length
		char* offset = bufoutaddrRecord - 3; //Leave two bytes for packet capture
		temp = htons(len); 
		memcpy(offset, &temp, sizeof(short)); //Write DNS packet length in the first two bytes 
//		printf(" ANS formal format is %s\n",offset);
//        int m=0;
//		while(m<=100){
//			printf("ANS %d: %hu\n",m,offset[m]);
//			m++;
//		}
        return bufout;
}

void splitForipToint(char str[], char *strings[]) {
    strings[0] = str;
    int j = 1;
	int i = 0;
    unsigned long len = strlen(str);
    for (i = 0; i < len; i++) {
        if (str[i] == '.') {
            str[i] = '\0';
            strings[j] = str + (i + 1);
            j++;
        }
    }
}

unsigned int ipToint(char ipString[]) {
    char *strings[4];
    splitForipToint(ipString, strings);
	int i = 0;
    unsigned int ip = 0;
    for (i = 0; i < 4; i++) {
        ip += (unsigned int)((atoi(strings[i])) << 8*(3 - i));
    }
    return ip;
}


