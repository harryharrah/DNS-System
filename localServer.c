#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdint.h>
#include<sys/time.h>
#include<time.h>
 

#include "DNS.h"
#define ECHOMAX 255 /* Longest string to echo */
#define STRING_NUMBER 1/*number of string*/
unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader);
unsigned int extractQuery(char* beginingPointer, struct DNS_Query* dnsquery);
char* generateTCPASKFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query );
char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record, struct DNS_RR *mxrecord);
void generateDNS_RR(struct DNS_Query *recvQuery,struct DNS_RR *resRecord ,char *row);
int searchDomainName(struct DNS_Query query, char *row);
void splitForipToint(char str[], char *strings[]);
unsigned int ipToint(char ipString[]);
unsigned int extractRRs(char *beginingPointer, struct DNS_RR *dnsrr);
 int isequal(char *str1, char* str2);
 unsigned int getAnsLength(char a, char b);
 int coppy(char* des,char*src);
 void recordInCache(char* bufin);
 void int2string(unsigned int b, char *c);
 int reverse(char *a,int len);
int main()
{
	struct timeval tv;
    struct timezone tz;   
    struct tm *t;
	int sock,i; /* Socket */
	struct sockaddr_in LocalServAddr; /* Local address */
	struct sockaddr_in DNSClntAddr; /* Client address */
	unsigned int cliAddrLen; /* Length of client address */
	char DNSBuffer[DNS_LENGTH_MAX]; /* Buffer for echo string */
	//unsigned short echoServPort; /* Server port */
	int recvMsgSize; /* Size of received message */
	unsigned char queryInfo[127];
	unsigned char* convertQueryInfo;
	//reciever
	struct DNS_Query recvQuery = {0};
	struct DNS_Header recvHead = {0};
	struct DNS_RR recvRecord = {0};  
	//responser
	struct DNS_Query resQuery = {0};
	struct DNS_Header resHead ={0} ;
	struct DNS_RR resRecord = {0};
    ////MX second query
	struct DNS_Query mxQuery = {0};
	struct DNS_Header mxHead ={0} ;
	struct DNS_RR mxRecord = {0};
	char bufin[DNS_LENGTH_MAX];
	char bufout[DNS_LENGTH_MAX];
	memset(bufin, 0, DNS_LENGTH_MAX);
	memset(bufout, 0, DNS_LENGTH_MAX);
    int localCheckFlag=0; 
	/* Create socket for sending/receiving datagrams */
	if ((sock = socket(PF_INET, SOCK_DGRAM,0)) < 0)
		printf("socket() failed.\n");

	/* Construct local address structure */
	memset(&LocalServAddr, 0, sizeof(LocalServAddr));
	LocalServAddr.sin_family = AF_INET;
	LocalServAddr.sin_addr.s_addr = inet_addr("127.0.0.2");
	LocalServAddr.sin_port =htons(53);
	/* Bind to the local address */
	if ((bind(sock, (struct sockaddr *) &LocalServAddr, sizeof(LocalServAddr))) < 0)
		printf("bind() failed.\n");
	while(1)/* Run forever */
	{
		//memset(bufOut, 0, DNS_LENGTH_MAX);
       	memset(bufin, 0, DNS_LENGTH_MAX);
        memset(bufout, 0, DNS_LENGTH_MAX);
        localCheckFlag = 0;
		//char *i = bufin;
		recvMsgSize = 0;
		/* Set the size of the in-out parameter */
		cliAddrLen = sizeof(DNSClntAddr);
		/* Block until receive message from a client */
		if ((recvMsgSize = recvfrom(sock, bufin, sizeof(bufin), 0,(struct sockaddr *) &DNSClntAddr, &cliAddrLen)) < 0)
			printf("recvfrom() failed.\n");
			// int p=0;
			// while(p<=50){
			// printf("%d: %hu\n",p,bufin[p]);
			// p++;
			// }
		printf("\n127.0.0.1 : ");
		gettimeofday(&tv, &tz);
    	t = localtime(&tv.tv_sec);
    	printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
		printf(" ---> 127.0.0.2 : ");
		gettimeofday(&tv, &tz);
    	t = localtime(&tv.tv_sec);
    	printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
		char *i = bufin;
		i += extractHeader(i, &recvHead);
		// printf("i-bufin = %hu\n",i-bufin);
		// printf("head1:%hu\n",recvHead.id);
        // printf("head2:%hu\n",recvHead.tag);
        // printf("head3:%hu\n",recvHead.queryNum);
        // printf("head4:%hu\n",recvHead.answerNum);
        // printf("head5:%hu\n",recvHead.authorNum);
        // printf("head6:%hu\n",recvHead.addNum);
	   	i += extractQuery(i, &recvQuery); 
		// printf("head id = %hu",recvHead.id);
		// printf("query name = %s\n",recvQuery.name);
        char* o = bufout;
//		/* Send received datagram back to the client */
//		if ((sendto(sock, DNSBuffer, recvMsgSize, 0,(struct sockaddr *) &DNSClntAddr, sizeof(DNSClntAddr))) != recvMsgSize)
//			printf("sendto() sent a different number of bytes than expected.\n");
        //绝赞本地查询
        // printf("start searching.............\n");
		resHead.id =htons(recvHead.id);
		resHead.tag =htons(0x8000);
		resHead.queryNum =htons(recvHead.queryNum);
		resHead.answerNum = htons(1);
		resHead.authorNum = 0;
		resHead.addNum = 0;
		resQuery = recvQuery;
		char *filePath;
        filePath="localCache.txt";
        FILE *fp = fopen(filePath, "r"); //Read the corresponding file
	    char row[DNSMAXLEN]; memset(row, 0, DNSMAXLEN); 
	    while(fgets(row, DNSMAXLEN-1, fp) != NULL){ //Line by line comparison 
	    //printf("in compare whileA\n");
		if(searchDomainName(recvQuery, row)){
			generateDNS_RR(&recvQuery,&resRecord,row);
            resHead.answerNum = htons(1); //Find the answer and assign a value at answerNum 
		    localCheckFlag=1;   //Indicates that the query is complete and there is no need to move on to the next node 
		    break;
		    }
	    }
	    
       
        if(localCheckFlag==1&&recvQuery.queryType==MX_Type){//search A type if there is mx cache
			mxQuery.name = (char*)malloc((strlen(resRecord.responseData)+1)*sizeof(char));
			strcpy(mxQuery.name, resRecord.responseData);
			//printf("mxQueryName: %s\n", mxQuery->name);
			mxQuery.queryClass = recvQuery.queryClass;
			mxQuery.queryType = A_Type; 
            filePath="localCache.txt";
        	fp = fopen(filePath, "r"); //Read the corresponding file
	        memset(row, 0, DNSMAXLEN); 
	        while(fgets(row, DNSMAXLEN-1, fp) != NULL){ //Line by line comparison 
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
		        	resHead.addNum = htons(1); //Find Aanswer and assign the value at add 
		        	break;
		    	}
	    	}
        }
       

	    
         if(localCheckFlag==0){
         	
            // printf("ben di mou a\n");
            int socketToRoot=0;
		    socketToRoot=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		    if(socketToRoot<0)
		    {
		    	perror("Root socket failed");
		    	return -1;
		    }
		    // printf("Root Socket Created!\n");
		    
		    struct sockaddr_in socketToRootaddr={0};
		    socketToRootaddr.sin_family=AF_INET;
		    socketToRootaddr.sin_port=htons(53);
		    socketToRootaddr.sin_addr.s_addr=inet_addr("127.0.0.3");
		    
		    struct sockaddr_in MyAddr={0};
		    MyAddr.sin_family = AF_INET;
			MyAddr.sin_addr.s_addr = inet_addr("127.0.0.2");

		    struct sockaddr_in nextHop={0};
		    nextHop.sin_family = AF_INET;
			nextHop.sin_port=htons(53);
			nextHop.sin_addr.s_addr = 0;
			
			/* Bind to the local address */
			if ((bind(socketToRoot, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		    // printf("Root bind() successful.\n");
		    
		    int socketToRootFlag=0;
		    int addrlen=0;
		    
		    socketToRootFlag=connect(socketToRoot,(struct sockaddr *)&socketToRootaddr,sizeof(socketToRootaddr));
		    if(socketToRootFlag<0)
	    	{
		    	perror("connect failed");
		    	close(socketToRoot);
	    		return -1;
	    	}
	    	// printf("Connected with Root server successfully!\n");
	    	memset(bufout, 0, DNS_LENGTH_MAX);
	    	//bufout = bufin;
	       char* begining = o-3;
           o = generateTCPASKFormat(o,&recvHead,&recvQuery);
        //    printf("lennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn: %d",o-begining);
		   char askToServer[DNS_LENGTH_MAX];
		   char* asktoServer = askToServer;
		   int askToServerLen = o-begining+2;
		   memset(asktoServer,0,DNS_LENGTH_MAX);
		   memcpy(asktoServer,begining,askToServerLen);
	    	if(send(socketToRoot, begining, o-begining+2, 0)<0){
        	  perror("send");
        	
            return 2;
          }else{ 
        	// printf("Send Query to Root\n");
			printf(" ---> 127.0.0.3 : ");
			gettimeofday(&tv, &tz);
    		t = localtime(&tv.tv_sec);
    		printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			}
			////////here is listen to root response 
			recvMsgSize = 0;
  			/* Block until receive message from localServer */
			memset(bufin,0,DNS_LENGTH_MAX);
  			if ((recvMsgSize = recv(socketToRoot, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
				//////////////add a shutdown 
				}
			printf(" ---> 127.0.0.2 : ");
			gettimeofday(&tv, &tz);
    		t = localtime(&tv.tv_sec);
    		printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				close(socketToRoot);
				//  p=0;
		    	//  while(p<=100){
		    	//  printf("respnse Fron RRRRRRRRRRROOOOOOOOOOOOOOTTTTTTTTTTTTt %d is: %hu\n",p,bufin[p+2]);
		    	//  p++;
		    	//  }
				 i = bufin+2;
				// printf("00000000000000%p\n",i);
				 i += extractHeader(i, &recvHead);
				//printf("after header%p\n",i);
	   			 i += 2*extractQuery(i, &recvQuery); 
				 //printf("222222222222222%p",i);
				//  printf("atfer query%hu\n",recvQuery.queryClass);
				//  printf("%s",recvQuery.name);
				//  printf("%hu",recvQuery.queryType);
				 recvRecord.name=recvQuery.name;
				 recvRecord.type = A_Type;
				 recvRecord.responseClass = recvQuery.queryClass;
				 

				//  p=0;
		    	//  while(p<=100){
		    	//  printf("eeeeeeeeeexxxxxxxxxtttttttttract from RRRRRRRRRRRooot %d is: %hu\n",p,recvRecord.responseData[p]);
		    	//  p++;
		    	//  }
				char * ii = bufin+2;
				 if(recvHead.tag==0x8003){//root find nothing 
					if(sendto(sock,ii,getAnsLength(bufin[0],bufin[1])-2,0,(struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(getAnsLength(bufin[0],bufin[1])-2)){
					printf("sendto() sent a different number of bytes than expected.\n");
					}
					printf(" ---> 127.0.0.1 : ");
					gettimeofday(&tv, &tz);
    				t = localtime(&tv.tv_sec);
    				printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);

				 }
				 else{//go to root finded des
				 while(recvHead.tag!=0x8003){
					i += extractRRs(i,&recvRecord);
				 	// printf("111111111111111%hu",recvRecord.type);
				 	// printf("22222222222222222%s",recvRecord.name);
					// p=0;
		    	    //     while(p<=50){
		    	    //     printf("next hooooooooooooooooooooooooooooooop is  %d is: %hu\n",p,recvRecord.responseData[p]);
		    	    //     p++;
		    	    //     }
					// printf("xext hhhhooooooooppppppppp%s",recvRecord.responseData);
					if(isequal(recvRecord.responseData,"127.0.0.4")){
					nextHop.sin_addr.s_addr = inet_addr("127.0.0.4");
					//gggggggggggggggggggggggggggggggggggo to next hop
					int socketToNext=0;
		       		socketToNext=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		    		if(socketToNext<0)
		   			 {
		    			perror(" cn us Next socket failed");
		    			return -1;
		   			 }
		    			// printf("cn us Next Socket Created!\n");
/* Bind to the local address */
			if ((bind(socketToNext, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		   		//  printf("cn us Next bind() successful.\n");
		    
		   		 int socketToNextFlag=0;
		    	int addrlen=0;
		    
		    	socketToNextFlag=connect(socketToNext,(struct sockaddr *)&nextHop,sizeof(nextHop));
		   		 if(socketToNextFlag<0)
	    			{
		    			perror("connect failed");
		    			close(socketToNext);
	    				return -1;
	    			}
	    		// printf("Connected with Root server successfully!\n");
	    		memset(bufout, 0, DNS_LENGTH_MAX);
	    		//bufout = bufin;
          	 	// printf("lennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn: %d",o-begining);
	    		if(send(socketToNext, asktoServer, askToServerLen, 0)<0){
        		  perror("send");
        	
          		  return 2;
          		}else{ 
        		// printf("Send Query to Next\n");
				printf(" ---> 127.0.0.4 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
        		}
			////////here is listen to root response 
			    recvMsgSize = 0;
  			/* Block until receive message from localServer */
			    memset(bufin,0,DNS_LENGTH_MAX);
  			 if ((recvMsgSize = recv(socketToNext, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
				//////////////add a shutdown 
				}
				printf(" ---> 127.0.0.2 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				close(socketToNext);
				 i = bufin+2;
				 i += extractHeader(i, &recvHead);
	   			 i += 2*extractQuery(i, &recvQuery); 
				recvRecord.name=recvQuery.name;
				 recvRecord.type = A_Type;
				 recvRecord.responseClass = recvQuery.queryClass;
				 i += extractRRs(i,&recvRecord);
				 close(socketToNext);
				 socketToNext = 0;
				 socketToNextFlag = 0;
				  socketToNext=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		    	if(socketToNext<0)
		    	{
		    	perror("To next socket failed");
		    	return -1;
		    	}
		    	// printf("Next Socket Created!\n");
				 if(isequal(recvRecord.responseData,"127.0.0.6")){
					nextHop.sin_addr.s_addr = inet_addr("127.0.0.6");
				if ((bind(socketToNext, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		   		//  printf("06 Next bind() successful.\n");
		    
		   		 int socketToNextFlag=0;
		    	int addrlen=0;
		    
		    	socketToNextFlag=connect(socketToNext,(struct sockaddr *)&nextHop,sizeof(nextHop));
		   		 if(socketToNextFlag<0)
	    			{
		    			perror("connect failed");
		    			close(socketToNext);
	    				return -1;
	    			}
	    		// printf("Connected with Root server successfully!\n");
	    		memset(bufout, 0, DNS_LENGTH_MAX);
	    		//bufout = bufin;
          	 	//printf("lennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn: %d",o-begining);
	    		if(send(socketToNext, asktoServer, askToServerLen, 0)<0){
        		  perror("send");
        	
          		  return 2;
          		}else{ 
        		// printf("Send Query to Next\n");
				printf(" ---> 127.0.0.6 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
        		}
			////////here is listen to root response 
			    recvMsgSize = 0;
  			/* Block until receive message from localServer */
			    memset(bufin,0,DNS_LENGTH_MAX);
  			 if ((recvMsgSize = recv(socketToNext, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
				//////////////add a shutdown 
				}
				printf(" ---> 127.0.0.2 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				i = bufin+2;
				close(socketToNext);
				//  i += extractHeader(i, &recvHead);
	   			//  i += 2*extractQuery(i, &recvQuery); 
				// recvRecord.name=recvQuery.name;
				//  recvRecord.type = recvQuery.queryType;
				//  recvRecord.responseClass = recvQuery.queryClass;
				//  i += extractRRs(i,&recvRecord);
			if(sendto(sock,i,getAnsLength(bufin[0],bufin[1])-2,0,(struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(getAnsLength(bufin[0],bufin[1])-2)){
			printf("sendto() sent a different number of bytes than expected.\n");
			}
			printf(" ---> 127.0.0.1 : ");
			recordInCache(i);
			gettimeofday(&tv, &tz);
    		t = localtime(&tv.tv_sec);
    		printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
					}
				else{
					nextHop.sin_addr.s_addr = inet_addr("127.0.0.7");
					if ((bind(socketToNext, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		   		// printf("07 Next bind() successful.\n");
		    
		   		 int socketToNextFlag=0;
		    	int addrlen=0;
		    
		    	socketToNextFlag=connect(socketToNext,(struct sockaddr *)&nextHop,sizeof(nextHop));
		   		 if(socketToNextFlag<0)
	    			{
		    			perror("connect failed");
		    			close(socketToNext);
	    				return -1;
	    			}
	    		//printf("Connected with Root server successfully!\n");
	    		memset(bufout, 0, DNS_LENGTH_MAX);
	    		//bufout = bufin;
          	 	//printf("lennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn: %d",o-begining);
	    		if(send(socketToNext, asktoServer, askToServerLen, 0)<0){
        		  perror("send");
        	
          		  return 2;
          		}else{ 
        		// printf("Send Query to Next\n");
				printf(" ---> 127.0.0.7 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
        		}
			////////here is listen to root response 
			    recvMsgSize = 0;
  			/* Block until receive message from localServer */
			    memset(bufin,0,DNS_LENGTH_MAX);
  			 if ((recvMsgSize = recv(socketToNext, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
				//////////////add a shutdown 
				}
				printf(" ---> 127.0.0.2 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				i = bufin+2;
				close(socketToNext);
				//  i += extractHeader(i, &recvHead);
	   			//  i += 2*extractQuery(i, &recvQuery); 
				// recvRecord.name=recvQuery.name;
				//  recvRecord.type = recvQuery.queryType;
				//  recvRecord.responseClass = recvQuery.queryClass;
				//  i += extractRRs(i,&recvRecord);
			if(sendto(sock,i,getAnsLength(bufin[0],bufin[1])-2,0,(struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(getAnsLength(bufin[0],bufin[1])-2)){
			printf("sendto() sent a different number of bytes than expected.\n");
			}
			printf(" ---> 127.0.0.1 : ");
			
			recordInCache(i);
			gettimeofday(&tv, &tz);
    		t = localtime(&tv.tv_sec);
    		printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
					}

				
					//ggggggggggggggggggggggggggggggggggggo to next hop
					break;
				 }
				 else if(isequal(recvRecord.responseData,"127.0.0.5")){
					memset(bufout,0,DNS_LENGTH_MAX);
					memcpy(bufout,bufin,DNS_LENGTH_MAX);
					// p=0;
		    	    //     while(p<=100){
		    	    //     printf("aaaaaaaaafffffffffftttttttttttter hoooooooop %d is: %hu\n",p,bufout[p]);
		    	    //     p++;
		    	    //     }
						//////qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
					int socketToNext=0;
		       		socketToNext=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		    		if(socketToNext<0)
		   			 {
		    			perror("Next socket failed");
		    			return -1;
		   			 }
		    			//printf("Next Socket Created!\n");
/* Bind to the local address */
			if ((bind(socketToNext, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		   		// printf("0.5 Next bind() successful.\n");
		    
		   		 int socketToNextFlag=0;
		    	int addrlen=0;
		    	nextHop.sin_addr.s_addr = inet_addr("127.0.0.5");
				nextHop.sin_family = AF_INET;
			    nextHop.sin_port=htons(53);
		    	socketToNextFlag=connect(socketToNext,(struct sockaddr *)&nextHop,sizeof(nextHop));
		   		 if(socketToNextFlag<0)
	    			{
		    			perror("connect failed");
		    			close(socketToNext);
	    				return -1;
	    			}
	    		//printf("Connected with comorg server successfully!\n");
	    		//memset(bufout, 0, DNS_LENGTH_MAX);
	    		//bufout = bufin;
				//printf("o-begining iiiiiiiiiiiiiiiiiissssssssssssssssssss%d",o-begining+2);
	    		if(send(socketToNext,asktoServer, askToServerLen, 0)<0){
        		  perror("send");
        	
          		  return 2;
          		}else{ 
        		// printf("Send Query to Next\n");
				printf(" ---> 127.0.0.5 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
        		}
			////////here is listen to root response 
			    recvMsgSize = 0;
  			/* Block until receive message from localServer */
			    memset(bufin,0,DNS_LENGTH_MAX);
				//   p=0;
		   		//  while(p<=100){
		     	// 	printf("bufin  isssssssssssssssssss %d is: %hu\n",p,bufin[p]);
		  		//  p++;
		    	//	}
  			 if ((recvMsgSize = recv(socketToNext, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
						//////qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
					break;

				 }
				 printf(" ---> 127.0.0.2 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				 i = bufin+2;
		         if(sendto(sock,i,getAnsLength(bufin[0],bufin[1])-2,0,(struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(getAnsLength(bufin[0],bufin[1])-2)){
			    printf("sendto() sent a different number of bytes than expected.\n");
		         }
				 printf(" ---> 127.0.0.1 : ");
				 
				recordInCache(i);
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				 //close(socketToNext);
				 close(socketToNext);
				 break;
				 }
				else if(isequal(recvRecord.responseData,"127.0.0.8")){
										memset(bufout,0,DNS_LENGTH_MAX);
					memcpy(bufout,bufin,DNS_LENGTH_MAX);
					// p=0;
		    	    //     while(p<=100){
		    	    //     printf("aaaaaaaaafffffffffftttttttttttter hoooooooop %d is: %hu\n",p,bufout[p]);
		    	    //     p++;
		    	    //     }
						//////qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
					int socketToNext=0;
		       		socketToNext=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		    		if(socketToNext<0)
		   			 {
		    			perror("Next socket failed");
		    			return -1;
		   			 }
		    			//printf("Next Socket Created!\n");
/* Bind to the local address */
			if ((bind(socketToNext, (struct sockaddr *) &MyAddr, sizeof(MyAddr))) < 0)
				printf("bind() failed.\n");
		   		 //printf("0.8 Next bind() successful.\n");
		    
		   		 int socketToNextFlag=0;
		    	int addrlen=0;
		    	nextHop.sin_addr.s_addr = inet_addr("127.0.0.8");
				nextHop.sin_family = AF_INET;
			    nextHop.sin_port=htons(53);
				//printf("why connection fail %d\n",nextHop.sin_addr.s_addr);
				//printf("why connection fail %hu\n",nextHop.sin_family);
				//printf("why connection fail %hu\n",nextHop.sin_port);
		    	socketToNextFlag=connect(socketToNext,(struct sockaddr *)&nextHop,sizeof(nextHop));
		   		 if(socketToNextFlag<0)
	    			{
		    			perror("connect failed");
		    			close(socketToNext);
	    				return -1;
	    			}
	    		//printf("Connected with comorg server successfully!\n");
	    		//memset(bufout, 0, DNS_LENGTH_MAX);
	    		//bufout = bufin;
				//printf("o-begining iiiiiiiiiiiiiiiiiissssssssssssssssssss%d",o-begining+2);
	    		if(send(socketToNext,asktoServer, askToServerLen, 0)<0){
        		  perror("send");
        	
          		  return 2;
          		}else{ 
        		// printf("Send Query to Next\n");
				printf(" ---> 127.0.0.8 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
        		}
			////////here is listen to root response 
			    recvMsgSize = 0;
  			/* Block until receive message from localServer */
			    memset(bufin,0,DNS_LENGTH_MAX);
				//   p=0;
		   		//  while(p<=100){
		     	// 	printf("bufin  isssssssssssssssssss %d is: %hu\n",p,bufin[p]);
		  		//  p++;
		    	// 	}
  			 if ((recvMsgSize = recv(socketToNext, bufin, sizeof(bufin), 0)) < 0){
   				printf("recv() failed.\n");
						//////qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
					break;

				 }
				 printf(" ---> 127.0.0.2 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				 i = bufin+2;
		         if(sendto(sock,i,getAnsLength(bufin[0],bufin[1])-2,0,(struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(getAnsLength(bufin[0],bufin[1])-2)){
			    printf("sendto() sent a different number of bytes than expected.\n");
		         }
				 printf(" ---> 127.0.0.1 : ");
				 
				recordInCache(i);
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
				 //close(socketToNext);
				 close(socketToNext);
				 break;
				}
				break;
				 }}}
				 ///////////////////////////////
        	//close(socketToRoot);
	
            else{
              memset(bufout, 0, DNS_LENGTH_MAX);
              o = generateTCPANSFormat(o,&resHead,&recvQuery,&resRecord,&mxRecord);
            //   printf("RR:ttl%d",resRecord.ttl);
            //   printf("RR:type%hu",resRecord.type);
            //    p=0;
		    // 	        while(p<=50){
		    // 	        printf("rr name %d is: %c\n",p,resRecord.name[p]);
		    // 	        p++;
		    // 	        }
                if (sendto(sock,bufout,o-bufout+2,0, (struct sockaddr *) &DNSClntAddr,sizeof(DNSClntAddr))!=(o-bufout+2)){
		            printf("sendto() sent a different number of bytes than expected.\n");
					
	            }
				printf(" ---> 127.0.0.1 : ");
				gettimeofday(&tv, &tz);
    			t = localtime(&tv.tv_sec);
    			printf("%d-%d-%d %d:%d:%d.%ld\n", 1900+t->tm_year, 1+t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec);
			
			
            
         }
	
}
 	close(sock);
	 exit(0);
}
unsigned int extractHeader(char* beginingPointer, struct DNS_Header* dnsheader){
		dnsheader->id = ntohs(*(unsigned short*) (beginingPointer));
		//printf("ex1%hu\n",dnsheader->id);
	    dnsheader->tag = ntohs(*(unsigned short*) (beginingPointer+2));
		//printf("ex2%hu\n",dnsheader->tag);
		dnsheader->queryNum = ntohs(*(unsigned short*) (beginingPointer+4));
		//printf("ex3%hu\n", dnsheader->queryNum);
		dnsheader->answerNum = ntohs(*(unsigned short*) (beginingPointer+6));
		//printf("ex4%hu\n",dnsheader->answerNum);
		dnsheader->authorNum = ntohs(*(unsigned short*) (beginingPointer+8));
		//printf("ex5%hu\n",dnsheader->authorNum);
		dnsheader->addNum = ntohs(*(unsigned short*) (beginingPointer+10));
		//printf("ex6%hu\n",dnsheader->addNum);
	
		//printf("hlennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn%d\n",sizeof(*dnsheader));
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
		//Complete the conversion from numeric plus domain name form to point score value in the message 
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
				domainName[i] = '.'; //Adding Points 
				i++;
			}
			else{
				domainName[i-1] = '\0'; //End of marker 
				beginingPointer++; 
				break;
			}
		}
		//  printf("i: %d\n", i);  
		//  printf("Converted domain name: %s\n", domainName);
		// printf("length: %d\n", i);
		dnsquery->name = (char*)malloc(i*sizeof(char));
		memcpy(dnsquery->name, domainName, i); //At this point, i is the length of the variable length string, after a loop traversal 
		//printf("Query name: %s\n", dnsquery->name);
	
		dnsquery->queryType = ntohs(*(unsigned short*) (beginingPointer));
		dnsquery->queryClass = ntohs(*(unsigned short*) (beginingPointer+2));
		// printf("Query Type: %d\n", dnsquery->queryType);
		// printf("Query Class: %d\n", dnsquery->queryClass);
		// printf("qlennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn%d\n",i+4+1);
		return i+4+1;  
		}
	char* generateTCPASKFormat(char *bufout, struct DNS_Header *header, struct DNS_Query *query ){
		char *bufoutaddrRecord = bufout;
		memcpy(bufout, header, sizeof(*header));
       
		bufout += sizeof(*header);
		unsigned char count = 0;
		int i = 0;
		int j = 1; 
		int tempts = 0;
		while(1){
			//printf("get: %c\n", query->name[i]);
			if(query->name[i] == '.'){
					memcpy(bufout-count-1, &count, sizeof(char));
					//printf("Count: %d\n", count);
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
		int len = bufout -bufoutaddrRecord+7; //calculate all length
        
		unsigned short temp = htons(query->queryType);
		memcpy(bufout, &temp, sizeof(short));
		temp = htons(query->queryClass);
		bufout+=sizeof(short);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=sizeof(short);
		//printf("dns format is %s\n",bufoutaddrRecord);
		char* offset = bufoutaddrRecord - 3; //Leave two bytes for packet capture
		temp = htons(len); 
		memcpy(offset, &temp, sizeof(short)); //Write DNS packet length in the first two bytes 
		//printf("formal format is %s\n",offset);
        // int p=0;
			//while(p<=50){
			//printf("after query%d: %hu\n",p,offset[p]);
			//p++;
			//}
        return bufout;
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
// 	int p=0;
// 	while(p<=50){
// 		printf("rrrrrrrrrrrrrrrrrrrrroooooooooooooooooowwwwwwwwwwwwwwww %d is: %c\n",p,row[p]);
// 		p++;
//   }
	char* offset=row; 
	unsigned int len=0;
	//printf("in DNS\n");
	
	
//	resRecord->name = (char*)malloc(strlen(recvQuery->name)*sizeof(char));
    resRecord->name=recvQuery->name;
    resRecord->responseClass=recvQuery->queryClass;
	resRecord->type=recvQuery->queryType;
	
	
	 len=reachNextInformation(offset);  offset+=len;//name
	 //printf("name_length: %d\n",len);

	 len=reachNextInformation(offset);//ttl string length 
	// printf("ttl_char_length:%d\n",len);
	 
	 char strttl[len]; memcpy(strttl, offset, len-1); strttl[len-1]='\0'; offset += len;
	 int TTL = atoi(strttl);    //printf("TTL；%d\n",TTL); //TTL after conversion 
	 resRecord->ttl=(unsigned int)TTL; 
	 //printf("ttl: %d\n",resRecord->ttl);
	
	 len=reachNextInformation(offset);  offset+=len; //type
	 //printf("offset length:%d\n",len);
	 len=reachNextInformation(offset);  offset+=len;//class
	 //printf("len length:%d\n",len);
	 
	len=reachNextInformation(offset); 
	//printf("rdata: %d\n",len);
	char strData[len]; memcpy(strData,offset,len-1); strData[len-2]='\0'; 
	char*strPointer=strData;
	resRecord->responseData=(char*)malloc((len-1)*sizeof(char));
	memcpy(resRecord->responseData,strPointer,len-1);
	//printf("size: %d\n",strlen(resRecord->rdata));
	//printf("rdata: %s\n",resRecord->responseData); 
	
	
	if(resRecord->type == A_Type){
		resRecord->data_len = 4; //Always 4byte
	}
	else if(resRecord->type == CNAME_Type||resRecord->type == PTR_Type){
		resRecord->data_len = strlen(resRecord->responseData)+2;
	}
	else if(resRecord->type == MX_Type){
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
//////////////////////////////////////////////////////////////////////////////////////////
char* generateTCPANSFormat(char* bufout, struct DNS_Header* header, struct DNS_Query *query ,struct DNS_RR *record, struct DNS_RR *mxrecord){
		char *bufoutaddrRecord = bufout+1;
		//header->answerNum = 1;
		//header->tag =htons(header->tag=32768);
		memcpy(bufout, header, sizeof(*header));
		// printf("header de id%hu",header->id);
		// printf("header de tag%hu",header->tag);
		// printf("header de ansnum%hu",header->answerNum);
		// printf("header de querynum%hu",header->queryNum);
		// printf("header de auth%hu",header->authorNum);
       
		bufout += (sizeof(*header))+1;
		unsigned char count = 0;
		int i = 0;
		int j = 1; 
		int tempts = 0;
		while(1){
			//printf("get: %c\n", query->name[i]);
			if(query->name[i] == '.'){
					memcpy(bufout-count-1, &count, sizeof(char));
					//printf("Count: %d\n", count);
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
       // printf("len xian zai shi ................%d",len);
		unsigned int temp = htons(query->queryType);
		memcpy(bufout, &temp, sizeof(short));
		temp = htons(query->queryClass);
		bufout+=sizeof(short);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=sizeof(short);
        memcpy(bufout, bufoutaddrRecord+11, len-17);//-18+11
        bufout+=(len-17);
        temp=htons(record->type);
	    memcpy(bufout, &temp, sizeof(short));
        bufout+=2;
	    temp=htons(record->responseClass);
	    memcpy(bufout, &temp, sizeof(short));
	    bufout+=2;
	    unsigned int tempint = htonl(record->ttl); //Here is the host byte order conversion for htonl 32-bit numbers 
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
        //printf("ipppppppppppppppppppppppppppppaddddddddddddddddddr : %u",ipAddr);
		memcpy(bufout, &ipAddr,record->data_len); //Convert string to 4bytes of data in network byte order 
		//  int p=0;
		// 	    while(p<=50){
		// 	    printf("ping shen mo shi 655 zhi bufout  %d is: %hd\n",p,bufout[p]);
		// 	    p++;
		// 	    }
		//printf("rrDate: %s\n", o);
		bufout+=record->data_len; 
	    }
	    else if(record->type == CNAME_Type){
		char* ini = bufout; //for initial
	    char count = 0;
	    int i = 0;
	    int j = 1; //Count after conversion 
	    int tempts = 0;
	    bufout++; //Move back one place first 
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
	    else if(record->type == MX_Type){ //The case of MX
		char* ini = bufout; //for initial
	    unsigned char count = 0;
	    int i = 0;
	    int j = 1; //Count after conversion 
	    int tempts = 0;
	    bufout++; //Move back one place first 
	    while(1){
		   //printf("mx problem: %c\n", record->responseData[i]);
		    if(record->responseData[i] == '.'){
				memcpy(bufout-count-1, &count, sizeof(char));
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

		tempts=htonl(mxrecord->ttl); //Here is the host byte order conversion for htonl 32-bit numbers 
		//printf("ttlconvert: %d\n", temp32);
		memcpy(bufout, &tempts, (2*sizeof(short)));
		bufout+=4;

		temp=htons(mxrecord->data_len);
		memcpy(bufout, &temp, sizeof(short));
		bufout+=2;

	
	
		unsigned int  ipAddr = htonl(ipToint(mxrecord->responseData));
		memcpy(bufout, &ipAddr, mxrecord->data_len); //Convert string to 4bytes of data in network byte order 
		//printf("rrDate: %d\n", ipAddr);
		bufout+=mxrecord->data_len; //That is, to move 4 bits 
		////////////////////////////////////
        }
		else if(record->type == PTR_Type){
		char* ini = bufout; //for initial
	    char count = 0;
	    int i = 0;
	    int j = 1; //Count after conversion 
	    int tempts = 0;
	    bufout++; //Move back one place first 
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
		// printf(" ANS formal format is %s\n",offset);
        //  int p=0;
		// 	while(p<=100){
		// 	printf("ANS %d: %hu\n",p,offset[p]);
		// 	p++;
		// 	}
        return bufout;
}
//     ///////////////////////////////////////////////////////////////////////////////////////////////////////////
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
unsigned int extractRRs(char *beginingPointer, struct DNS_RR *dnsrr){
	unsigned int ipAddr;
	
	dnsrr->ttl = ntohl(*(unsigned int*)(beginingPointer)); 
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
		beginingPointer += 2; //
	}
	
	if(dnsrr->type == A_Type){
		ipAddr = *(unsigned int*)(beginingPointer);
		//printf("Query Answer TTL: %d\n", dnsrr->ttl);
		memcpy(&addr, &ipAddr, 4);
		const char *ptr = inet_ntop(AF_INET, &addr, str, sizeof(str)); 
		//printf("Query Answer IP: %s\n", ptr);
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
				domainName[i] = '.'; //źÓľă 
				i++;
			}else{
				domainName[i-1] = '\0'; //ąę×˘˝áĘř 
				beginingPointer++; 
				break;
			}
		}
		// printf("i: %d\n", i);  
		// printf("Converted domain name: %s\n", domainName);
		// printf("length: %d\n", i);
		dnsrr->responseData = (char*)malloc(i*sizeof(char));
		memcpy(dnsrr->responseData, domainName, i); //´ËĘąľÄiąăÎŞ×Şťťşóąäł¤×Öˇű´ŽľÄł¤śČÁËŁŹž­šýÁËŃ­ťˇąéŔú 
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
		while(1){
			if(*beginingPointer!='\0'){
				count = *(unsigned char*)(beginingPointer);
				//printf("count:%d\n", count);
				beginingPointer++;
				while(count){
					//printf("i: %d\n", i);
					//printf("char1:%c\n", *beginingPointer);
					memcpy(&(domainName[i]), beginingPointer, sizeof(char));
					//printf("domain name i: %c\n", domainName[i]);
					count--; beginingPointer++; i++;
				}
				domainName[i] = '.'; //źÓľă 
				i++;
			}else{
				domainName[i-1] = '\0'; //ąę×˘˝áĘř 
				beginingPointer++; 
				break;
			}
		}
		//printf("i: %d\n", i);  
		//printf("Converted domain name: %s\n", domainName);
		//printf("length: %d\n", i);
		//printf("Converted domain name: %s\n", domainName);
		//int totalen = strlen(dnsrr->name) + i; //Ć´˝Óşó×Üł¤śČ
		dnsrr->responseData = (char*)malloc(i*sizeof(char));
		memcpy(dnsrr->responseData, domainName, i); 
		//printf("Query name: %s\n", dnsrr->name);
		//printf("The CNAME is: %s\n", dnsrr->responseData);
		//printf("rlllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll: %d\n",4+2+dnsrr->data_len+1);
		return 4+2+dnsrr->data_len+1;
	}	
}
 int isequal(char *str1, char* str2)
{
     int i=0;
    for (i = 0; str1[i]!='\0'&&str2[i]!='\0'; i++){
        if (str1[i]!=str2[i])
        return 0;
     }
   return 1;
  }
unsigned int getAnsLength(char a, char b){
	return (unsigned int)(a*256+b);
}
int copy(char* des,char*src){
	int i=0;
	for(i=0;i<strlen(src);i++){
		*(des+i)=*(src+i);
	}
	return i;
}
void recordInCache(char* bufin){
	struct DNS_Query recvQuery = {0};
	struct DNS_Header recvHead = {0};
	struct DNS_RR recvRecord = {0};  
	struct DNS_RR mxRecord = {0};
	char *i = bufin;
	
	i += extractHeader(i, &recvHead);
	if(recvHead.tag!=0x8000){
		return;
	}
	i += 2*extractQuery(i, &recvQuery); //The whole length of query and name+type+class length of Answer.
	
	recvRecord.name = recvQuery.name; 
	recvRecord.type = recvQuery.queryType;
	recvRecord.responseClass = recvQuery.queryClass;	
	
	//i+=(4+strlen(recvRecord.name)+1);	
	
		i += extractRRs(i,&recvRecord);
		//printf("%s\n",recvRecord.name);
		//printf("%hu\n",recvRecord.type);
		//printf("%hu\n",recvRecord.responseClass);
		//printf("%d\n",recvRecord.ttl);
		//printf("%s\n",recvRecord.responseData);
		
		if(recvQuery.queryType == MX_Type){
			//mxRecord.name = (char*)malloc((strlen(recvRecord->rdata)+1)*sizeof(char));
			//strcpy(mxRecord.name, recvRecord.responseData);
			mxRecord.type = A_Type;
			mxRecord.responseClass = 1;
			i += 4;
			i += extractRRs(i, &mxRecord);
		}
		//printf("Successfully find the answer!!!\n");
		//printf("Query name = %s\n",recvQuery.name); 
		//printf("hai mei bao o-4\n");
		char temp[DNSMAXLEN];
		//printf("hai mei bao o-3\n");
		 char * tem = temp;
		//printf("hai mei bao o-2\n");
		memset(tem,0,DNSMAXLEN);
		//printf("hai mei bao o-1\n");
		temp[0] = '\0';
		int tempFlag=0;
		char ttlbuffer[100];
		char * ttlb = ttlbuffer;
		memset(ttlb,0,100);
		if(recvQuery.queryType == A_Type){
// 		printf("hai mei bao o0\n");
			tem+=coppy(tem,recvQuery.name);
			//printf("%s\n",temp);
			//printf("hai mei bao o1\n");
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			int2string(recvRecord.ttl,ttlb);
			tem+=coppy(tem,ttlbuffer);
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			tem+=coppy(tem,"IN\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,"A\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,recvRecord.responseData);
			tem+=coppy(tem,"\r\n\0");
			//printf("%s\n",temp);
		}else if(recvQuery.queryType == MX_Type){
			tem+=coppy(tem,recvQuery.name);
			//printf("%s\n",temp);
			//printf("hai mei bao o1\n");
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			int2string(recvRecord.ttl,ttlb);
			tem+=coppy(tem,ttlbuffer);
			memset(ttlbuffer,0,100);
			tem+=coppy(tem," \0");
			//printf("%s\n",temp)
			tem+=coppy(tem,"IN\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,"MX\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,recvRecord.responseData);
			tem+=coppy(tem,"\r\n\0");
			tem+=coppy(tem,recvRecord.responseData);
			//printf("%s\n",temp);
			//printf("hai mei bao o1\n");
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			int2string(recvRecord.ttl,ttlb);
			tem+=coppy(tem,ttlbuffer);
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			tem+=coppy(tem,"IN\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,"A\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,mxRecord.responseData);
			tem+=coppy(tem,"\r\n\0");
		}else if(recvQuery.queryType == CNAME_Type){
			tem+=coppy(tem,recvQuery.name);
			//printf("%s\n",temp);
			//printf("hai mei bao o1\n");
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			int2string(recvRecord.ttl,ttlb);
			tem+=coppy(tem,ttlbuffer);
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			tem+=coppy(tem,"IN\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,"CNAME\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,recvRecord.responseData);
			tem+=coppy(tem,"\r\n\0");
			//printf("%s\n",temp);
		}else if(recvQuery.queryType == PTR_Type){
			tem+=coppy(tem,recvQuery.name);
			//printf("%s\n",temp);
			//printf("hai mei bao o1\n");
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			int2string(recvRecord.ttl,ttlb);
			tem+=coppy(tem,ttlbuffer);
			tem+=coppy(tem," \0");
			//printf("%s\n",temp);
			tem+=coppy(tem,"IN\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,"PTR\0");
			tem+=coppy(tem," \0");
			tem+=coppy(tem,recvRecord.responseData);
			tem+=coppy(tem,"\r\n\0");
			//printf("%s\n",temp);
		}
 FILE *outfile;
 outfile = fopen("localCache.txt","a+");
 if(outfile==NULL)
 {
  printf("Can't open the file!\n");
 }
 fprintf(outfile,"%s",temp);
 
 fclose(outfile);
}
int coppy(char* des,char*src){
	int i=0;
	for(i=0;i<strlen(src);i++){
		*(des+i)=*(src+i);
	}
	return i;
}
int reverse(char *a,int len)
{ int i = 0;
  int t;
  int j;

  for(i=0;i<len/2;i++)
  { t = a[i];
    a[i] = a[len-1-i];
    a[len-1-i] = t; 
  }
}
//int to string function
void int2string(unsigned int b, char *c)
{
int z = (int)b;
 char d[100];
 char temp[2]={0};//Need to store data temporarily during the conversion process 
 int i;
 while(z>=10)
 {   
	char a = z%10 + '0';//Converting remainders to characters
  temp[0] = a;//The remaining converted characters are temporarily stored in the temp array
  z = z/10;//The remainder is the value of the lowest digit and converted into characters, you need to divide by 10 to put the value of the tens digit on the lowest digit
  strcat(c,temp);//Append the temporarily stored temp to c
 }
 	char a = z%10 + '0';
  temp[0] = a;
  z = z/10;
  strcat(c,temp);
 reverse(c,strlen(c));//Invert the array after all conversions are complete 
}	
