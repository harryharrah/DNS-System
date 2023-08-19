#ifndef DNS_H_
#define DNS_H_
#define DNSMAXLEN 526
#define QR 32768
#define NAME_TO_ADDR 0
#define ADDR_TO_NAME 2048
#define SERV_STAT 4096
#define AA 1024
#define TC 512
#define RD 256
#define RA 128
#define SUCCESS 0
#define FORMAT_ERR 1
#define SERV_ERR 2
#define NOT_EXIST 3
#define FORMAT_NOT_SUPPORT 4
#define POLICY 5

#define A_Type 1
#define CNAME_Type 5
#define MX_Type 15
#define PTR_Type 12
 
#define IN 1
#define DNS_LENGTH_MAX 1000
#define BACKLOG 10 

//struct of the header part of DNS 
struct DNS_Header{
	unsigned short id;
	unsigned short tag;
	unsigned short queryNum;
	unsigned short answerNum;
	unsigned short authorNum;
	unsigned short addNum;
};

//struct of the query part of DNS  
struct DNS_Query{
	unsigned char* name;
	unsigned short queryType;
	unsigned short queryClass;
};

//struct of the response region of DNS  
struct DNS_RR{
	unsigned char *name;
	unsigned short type;
	unsigned short responseClass;
	unsigned int ttl;
	unsigned short data_len;
	unsigned char *responseData;
};

#endif
