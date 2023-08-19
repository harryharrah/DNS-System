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
int isEqual(char *str1, char* str2);
char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record, struct DNS_RR *mxrecord);
void generateDNS_RR(struct DNS_Query *recvQuery,struct DNS_RR *resRecord ,char *row);
int searchDomainName(struct DNS_Query query, char *row);
void splitForipToint(char str[], char *strings[]);
unsigned int ipToint(char ipString[]);

int main(){
	int sock,local_fd; /* Socket descriptor */
	struct sockaddr_in eduServerAddr; /* Echo server address */
	struct sockaddr_in LocalServerAddr;
	struct DNS_Header header;
	struct DNS_Query query;

	char buffOut[DNS_LENGTH_MAX]; /* String to send to echo server */
	char buffIn[DNS_LENGTH_MAX];
	char nextAddr[50];
	
	int recvMsgSize; /* Size of received message */
	
	//reciever
	struct DNS_Query recvQuery = {0};
	struct DNS_Header recvHead = {0};
	struct DNS_RR recvrRecord = {0}; 
	//responser
	struct DNS_Query resQuery = {0};
	struct DNS_Header resHead ={0} ;
	struct DNS_RR resRecord = {0}; 
	
	struct DNS_Query mxQuery = {0};
	struct DNS_Header mxHead ={0} ;
	struct DNS_RR mxRecord = {0};
	
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		printf("socket() failed.\n");
		return -1;
	}
	
	eduServerAddr.sin_family=AF_INET;
	eduServerAddr.sin_port=htons(53);
	eduServerAddr.sin_addr.s_addr=inet_addr("127.0.0.7");
	if ((bind(sock, (struct sockaddr *) &eduServerAddr, sizeof(eduServerAddr))) < 0)
		printf("bind() failed.\n");
	
//通过调用listen将套接字设置为监听模式
	if(listen(sock,BACKLOG)==-1)
	{
		printf("listen failed");
		close(sock);
		return -1;
	}
	printf("-----------------------Listen to the localServer---------------------------\n");
//服务器等待客户端连接中，游客户端连接时调用accept产生一个新的套接字
	socklen_t addr_length=sizeof(LocalServerAddr);
	
	while(1)/* Run forever */
	{
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
       	int localCheckFlag = 0;
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
		
		//Response
		printf("edu start searching.............\n");
		resHead.id =htons(recvHead.id);
		resHead.tag =htons(0x8000);//10000.... 
		resHead.queryNum =htons(recvHead.queryNum);
		resHead.answerNum = htons(1); //这里不一定是1，若没查到后续更改为0 
		resHead.authorNum = 0;
		resHead.addNum = 0;
		resQuery = recvQuery;
		char *filePath;
        filePath="eduDatabase.txt";
        FILE *fp = fopen(filePath, "r"); //读取对应文件
	    char row[DNSMAXLEN]; memset(row, 0, DNSMAXLEN); 
	    while(fgets(row, DNSMAXLEN-1, fp) != NULL){ //逐行对比 
	    //printf("in compare whileA\n");
		if(searchDomainName(recvQuery, row)){
			generateDNS_RR(&recvQuery,&resRecord,row);
            resHead.answerNum = htons(1); //找到answer，在answerNum处赋值 
		    localCheckFlag=1;   //表明查询完成，无需再进入下一节点查询 
		    break;
		    }
	    }
	    
       
        if(localCheckFlag==1&&recvQuery.queryType==MX_Type){//search A type if there is mx cache
			mxQuery.name = (char*)malloc((strlen(resRecord.responseData)+1)*sizeof(char));
			strcpy(mxQuery.name, resRecord.responseData);
			//printf("mxQueryName: %s\n", mxQuery->name);
			mxQuery.queryClass = recvQuery.queryClass;
			mxQuery.queryType = A_Type; 
            filePath="eduDatabase.txt";
        	fp = fopen(filePath, "r"); //读取对应文件
	        memset(row, 0, DNSMAXLEN); 
	        while(fgets(row, DNSMAXLEN-1, fp) != NULL){ //逐行对比 
	          //printf("in compare whileA\n");
		        if(searchDomainName(mxQuery, row)){
			        // printf("youlou\n");
                    // p=0;
			        // while(p<=50){
			        // printf("row %d is: %c\n",p,row[p]);
			        // p++;
			        // }
		        	generateDNS_RR(&mxQuery,&mxRecord,row);
					//printf("mxRRde%hu",mxRecord.responseData)
					//  p=0;
			        // while(p<=50){
			        // printf("mxRRde rd %d mxRRde%hu\n",p,mxRecord.responseData[p]);
			        // p++;
			        // }
		        	resHead.addNum = htons(1); //找到Aanswer，在add处赋值 
		        	break;
		    	}
	    	}
        }
    	if(localCheckFlag==0){
            printf("Counldn't find the answer in this Zoom!'\n");
            resHead.tag =htons(0x8003);
            resHead.answerNum = 0;
        }
        
        out = generateTCPANSFormat(out,&resHead,&resQuery,&resRecord,&mxRecord); 
		////////////////////////////////////////////////////////////////////////////////////

		if (sendto(local_fd,buffOut,out-buffOut+3,0, (struct sockaddr *) &LocalServerAddr,sizeof(LocalServerAddr))!=(out-buffOut+3)){
		    printf("sendto() sent a different number of bytes than expected.\n");
		    //close(local_fd);
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

	//count = ntohs(*(unsigned char*)(beginingPointer));
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

int reachNextInformation(char *beginPosition){
	int i=0;
	while(1){
		if(beginPosition[i]==' '||beginPosition[i]=='\n'||beginPosition[i]=='\0')
			break;
		else i++;
	}
	return i+1;
}

void generateDNS_RR(struct DNS_Query *recvQuery,struct DNS_RR *resRecord ,char *row){
//	int p=0;
//	while(p<=50){
//		printf("rrrrrrrrrrrrrrrrrrrrroooooooooooooooooowwwwwwwwwwwwwwww %d is: %c\n",p,row[p]);
//		p++;
//  }
	char* offset=row; 
	unsigned int len=0;
	//printf("in DNS\n");
	
	/*
	 *拷贝可从query里获取的信息
	 */
//	resRecord->name = (char*)malloc(strlen(recvQuery->name)*sizeof(char));
    resRecord->name=recvQuery->name;
    resRecord->responseClass=recvQuery->queryClass;
	resRecord->type=recvQuery->queryType;
	
	/*
	 *拷贝ttl 
	 */
	 len=reachNextInformation(offset);  offset+=len;//name
	 //printf("name_length: %d\n",len);

	 len=reachNextInformation(offset);//ttl字符串长度 
	// printf("ttl_char_length:%d\n",len);
	 
	 char strttl[len]; memcpy(strttl, offset, len-1); strttl[len-1]='\0'; offset += len;
	 int TTL = atoi(strttl);    //printf("TTL；%d\n",TTL); //转换后TTL 
	 resRecord->ttl=(unsigned int)TTL; 
	 //printf("ttl: %d\n",resRecord->ttl);
	 /*
	  *移动光标 
	  */
	 len=reachNextInformation(offset);  offset+=len; //type
	 //printf("offset length:%d\n",len);
	 len=reachNextInformation(offset);  offset+=len;//class
	 //printf("len length:%d\n",len);
	 /*
	  *拷贝 rdata 
	  */
	len=reachNextInformation(offset); 
	//printf("rdata: %d\n",len);
	char strData[len]; memcpy(strData,offset,len-1); strData[len-2]='\0'; 
	char*strPointer=strData;
	resRecord->responseData=(char*)malloc((len-1)*sizeof(char));
	memcpy(resRecord->responseData,strPointer,len-1);
	//printf("size: %d\n",strlen(resRecord->rdata));
//	printf("rdata: %s\n",resRecord->responseData); 
	
	/*
	 *拷贝datalength 
	 */
	if(resRecord->type == A_Type){
		resRecord->data_len = 4; //永远是4byte
	}
	else if(resRecord->type == CNAME_Type||resRecord->type == PTR_Type){
		resRecord->data_len = strlen(resRecord->responseData)+2;
	}
	else if(resRecord->type == MX_Type){
		//这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)
		resRecord->data_len = strlen(resRecord->responseData)+3;
	}
	  
	 //printf("%hu\n",len-1);
	
}

int searchDomainName(struct DNS_Query query, char *row){
    int len = strlen(query.name);
	unsigned short type = query.queryType;
	int flag = 0;
    int i=0;
    while(i<len){
//	printf("namei: %c\n",name[i]);
//	printf("rowi: %c\n",row[i]);
	if(query.name[i]!=row[i]){
        return 0;
    }
	i++;
    }
    if(row[i]!=' ') 
        return 0;
	else{ 
		i++;
		while(1){
			if(flag==2){
				break;
			}
			if(row[i]!=' '){
				i++;
			}
			else{
				i++;
				flag++;
			}
		}
		if(row[i]=='A'){
			if(type == A_Type){
				return 1;
			}
			else{
				return 0;
			}
		}
		else if(row[i]=='C'){
			if(type == CNAME_Type){
				return 1;
			}
			else{
				return 0;
			}
		}
		else if(row[i]=='M'){
			if(type == MX_Type){
				return 1;
			}
			else{
				return 0;
			}
		}
		else if(row[i]=='P'){
			if(type == PTR_Type){
				return 1;
			}
			else{
				return 0;
			}
		}
		else{
			return 0;
		}
		}
}

char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record, struct DNS_RR *mxrecord){
		char *bufoutaddrRecord = bufout+1;
		//header->answerNum = 1;
		//header->tag =htons(header->tag=32768);
		memcpy(bufout, header, sizeof(*header));

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
	    unsigned int tempint = htonl(record->ttl); //杩欓噷鏄痟tonl 32浣嶆暟瀛楃殑涓绘満瀛楄妭搴忚浆鍖?
	    memcpy(bufout, &tempint, (sizeof(int)));
        bufout+=4;
        temp=htons(record->data_len);
	    memcpy(bufout, &temp, sizeof(short));
	    bufout+=2;
        //////////////////////////////////////////////
        if(record->type == MX_Type){
		temp=htons(1);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=2;
	    }
	
	    if(record->type == A_Type){
    // int i=0;
        //printf("zui zhong shencha zhi response data weisha: %c\n", record->responseData[i]);
		unsigned int ipAddr = htonl(ipToint(record->responseData));
		//unsigned int ipAddr = inet_addr(record->responseData);
//        printf("ipppppppppppppppppppppppppppppaddddddddddddddddddr : %u",ipAddr);
		memcpy(bufout, &ipAddr,record->data_len); //灏嗗瓧绗︿覆杞?鍖栦负缃戠粶瀛楄妭搴忕??bytes鏁版嵁 
//		 int p=0;
//			    while(p<=50){
//			    printf("ping shen mo shi 655 zhi bufout  %d is: %hd\n",p,bufout[p]);
//			    p++;
//			    }
		//printf("rrDate: %s\n", o);
		bufout+=record->data_len; //涔熷氨鏄?瑕佺Щ鍔?4浣?
		//return 16;
	    }
	    else if(record->type == CNAME_Type){
		char* ini = bufout; //for initial
	    char count = 0;
	    int i = 0;
	    int j = 1; //杞?鎹㈠悗璁℃??
	    int tempts = 0;
	    bufout++; //鍏堝線鍚庣Щ鍔ㄤ竴浣?
	    while(1){
		    
		    if(record->responseData[i] == '.'){
				memcpy(bufout-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				bufout++; i++;
				tempts = 1;
				
		    }
		    else if(record->responseData[i] == '\0'){
			    memcpy(bufout, &(record->responseData[i]), sizeof(char));
			    memcpy(bufout-count-1, &count, sizeof(char));
			    count = 0;
			    break;
		    }
		    else{
			    memcpy(bufout, &(record->responseData[i]), sizeof(char));
			    bufout++;
			    i++;
			    count++; 
		    }
	    }
		//return 12 + rr->data_len + 1;
	    }
	    else if(record->type == MX_Type){ //MX鐨勬儏鍐?
		char* ini = bufout; //for initial
	    unsigned char count = 0;
	    int i = 0;
	    int j = 1; //杞?鎹㈠悗璁℃??
	    int tempts = 0;
	    bufout++; //鍏堝線鍚庣Щ鍔ㄤ竴浣?
	    while(1){
//		    printf("mx problem: %c\n", record->responseData[i]);
		    if(record->responseData[i] == '.'){
				memcpy(bufout-count-1, &count, sizeof(char));
//				("Count: %d\n", count);
				count = 0;
				bufout++; i++;
				tempts = 1;
				
		    }
		    else if(record->responseData[i] == '\0'){
			memcpy(bufout, &(record->responseData[i]), sizeof(char));
			memcpy(bufout-count-1, &count, sizeof(char));
			count = 0;
			break;
		    }
		    else{
			    memcpy(bufout, &(record->responseData[i]), sizeof(char));
			    bufout++;
			    i++;
			    count++; 
		    }
	    }
	    bufout++;
		///////////////////////////////////AAAAAAAAAAAAA
	  	

		temp=htons(mxrecord->type);
		memcpy(bufout, &temp, sizeof(short));
		//printf("rrType: %d\n", rr->type);
		bufout+=2;

		temp=htons(mxrecord->responseClass);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=2;

		tempts=htonl(mxrecord->ttl); //杩欓噷鏄痟tonl 32浣嶆暟瀛楃殑涓绘満瀛楄妭搴忚浆鍖?
		//printf("ttlconvert: %d\n", temp32);
		memcpy(bufout, &tempts, (2*sizeof(short)));
		bufout+=4;

		temp=htons(mxrecord->data_len);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=2;

	
	
		unsigned int  ipAddr = htonl(ipToint(mxrecord->responseData));
		memcpy(bufout, &ipAddr, mxrecord->data_len); //灏嗗瓧绗︿覆杞?鍖栦负缃戠粶瀛楄妭搴忕??bytes鏁版嵁 
		//printf("rrDate: %d\n", ipAddr);
		bufout+=mxrecord->data_len; //涔熷氨鏄?瑕佺Щ鍔?4浣?
		////////////////////////////////////
        }
		else if(record->type == PTR_Type){
		char* ini = bufout; //for initial
	    char count = 0;
	    int i = 0;
	    int j = 1; //杞?鎹㈠悗璁℃??
	    int tempts = 0;
	    bufout++; //鍏堝線鍚庣Щ鍔ㄤ竴浣?
	    while(1){
		    
		    if(record->responseData[i] == '.'){
				memcpy(bufout-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				bufout++; i++;
				tempts = 1;
				
		    }
		    else if(record->responseData[i] == '\0'){
			    memcpy(bufout, &(record->responseData[i]), sizeof(char));
			    memcpy(bufout-count-1, &count, sizeof(char));
			    count = 0;
			    break;
		    }
		    else{
			    memcpy(bufout, &(record->responseData[i]), sizeof(char));
			    bufout++;
			    i++;
			    count++; 
		    }
	    }
		}
        len = bufout -bufoutaddrRecord+4; //calculate all length
		char* offset = bufoutaddrRecord - 3; //Leave two bytes for packet capture
		temp = htons(len); 
		memcpy(offset, &temp, sizeof(short)); //Write DNS packet length in the first two bytes 
//		printf(" ANS formal format is %s\n",offset);
//         int p=0;
//			while(p<=100){
//			printf("ANS %d: %hu\n",p,offset[p]);
//			p++;
//			}
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


