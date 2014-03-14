#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <csignal>
#include<time.h>
#include<pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
using namespace std;
int epoch=2;
static int flow=0;
static int flow_tcp=0;
static int flow_udp=0;
int tuple_mode=2;
bool tuple_flag=false;
bool verbose_flag=false;
bool file_flag=false;
struct pcap_stat stat;
static int count_udp=0,count_icmp=0,count_default=0,count_tcp=0;
int previous_length=0;
bool entry=false;
pthread_mutex_t lock;
struct timeval ts1;
bool first_entry=true;
bool packet_end=false;
bool onetime=true;
static int count=0;
 long initial_time=0;
long initial_utime=0;
//static u_short ip_Id;
static unsigned long packet_length=0;
char writefile[100];
FILE *fp=NULL;

struct two_tuple
{
char src[32];
char dest[32];
int ip_p;

struct two_tuple *next;
};


struct five_tuple
{
string src;
string dest;
int ip_p;
int sport;
int dport;

struct five_tuple *next;
};

struct two_tuple *current1=NULL;
struct two_tuple *head1=NULL;

struct five_tuple *current2=NULL;
struct five_tuple *head2=NULL;



void getPort_udp(const u_char * Buffer, int &sport,int &dport)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer );
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  );
     
     
//    sprintf(sport,"%d", ntohs(udph->source));

 //   sprintf(dport,"%d",ntohs(udph->dest));

	sport=ntohs(udph->source);
	dport=ntohs(udph->dest);

    //cout<<"\n**sport\t"<<sport<<"\t"<<dport;

}


void getPort_tcp(const u_char * Buffer, int &sport,int &dport)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer ); 
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen );


    sport=ntohs(tcph->source);
    dport=ntohs(tcph->dest);
//	cout<<"\n**sport\t"<<sport<<"\t"<<dport;

}


void searchOrInsert_two(struct two_tuple *current,char* src,char *dest,int ip_p)
{
struct two_tuple *prev;
while(current!=NULL)
	{
	if((current->src != NULL) &&(current->dest != NULL))
	{
	if((strcmp(current->src,src)!=0)||(strcmp(current->dest,dest)!=0)||(current->ip_p!=ip_p))
		{
		prev=current;
		current=current->next;
		}
	else
		{
		//Already flow is noted for same pair of IP's
		//current->flow++;
		break;
		}
	}
	}

//Not found so far in the list
if(current== NULL)
	{
	struct two_tuple *temp=new two_tuple;
	temp->next=NULL;
	strcpy(temp->src,src);
	strcpy(temp->dest,dest);
	temp->ip_p=ip_p;
 	if(temp->ip_p == IPPROTO_TCP)
               flow_tcp++;
        else if(temp->ip_p == IPPROTO_UDP)
               flow_udp++;

	flow++;	
	prev->next=temp;
			
	}
}

void searchOrInsert_five(struct five_tuple *current,string src,string dest,int ip_p,int sport,int dport)
{
struct five_tuple *prev;
if((sport !=0)&&(dport!=0))
{
while(current!=NULL)
        {
        if((current->src.compare(src)!=0)||(current->dest.compare(dest)!=0)||(current->ip_p!=ip_p)||(current->sport!=sport)||(current->dport!=dport))
                {
                prev=current;
                current=current->next;
                }
        else
                {
                //Already flow is noted for same pair of IP's
                //current->flow++;
                break;
                }
        }

}
else
{
while(current!=NULL)
        {
        if((current->src.compare(src)!=0)||(current->dest.compare(dest)!=0)||(current->ip_p!=ip_p))
                {
                prev=current;
                current=current->next;
                }
        else
                {
                //Already flow is noted for same pair of IP's
                //current->flow++;
                break;
                }
        }

}
//Not found so far in the list
if(current== NULL)
        {
        struct five_tuple *temp=new five_tuple;
        temp->next=NULL;
        temp->src=src;
        temp->dest=dest;
        temp->ip_p=ip_p;
	temp->sport=sport;
	temp->dport=dport;
        if(temp->ip_p == IPPROTO_TCP)
               flow_tcp++;
        else if(temp->ip_p == IPPROTO_UDP)
               flow_udp++;

	flow++;

        prev->next=temp;

        }
}


void deleteList1(struct two_tuple *current)
{
if(current != NULL)
{
struct two_tuple *temp=current->next;
while(temp != NULL)
	{
	delete(current);
	current=temp;
	temp=current->next;
	}
delete(current);
head1=NULL;
}

head1=NULL;
current=NULL;

}

void deleteList2(struct five_tuple *current)
{
if(current != NULL)
{
struct five_tuple *temp=current->next;
while(temp != NULL)
        {
        delete(current);
        current=temp;
        temp=current->next;
        }
delete(current);
head2=NULL;
}
}
	
void print_screen()
{
if(initial_time != 0)
  {
    if(tuple_flag ==true)
      {
	if(verbose_flag == false)
	{
		printf("\n%ld.%06ld\t%d\t%ld\t%d",initial_time, initial_utime,count,(packet_length),flow);
	}
	else
	{
		printf("\n%ld.%06ld\t%d\t%ld\t%d\t%d\t%d\t%d\t%d\t%d\t%d",initial_time, initial_utime,count,(packet_length),flow,count_tcp,count_udp,count_icmp,count_default,flow_tcp,flow_udp);
	}
      }
    else
	{
	 if(verbose_flag == false)
        {
                printf("\n%ld.%06ld\t%d\t%ld",initial_time, initial_utime,count,(packet_length));
        }
        else
        {
                printf("\n%ld.%06ld\t%d\t%ld\t%d\t%d\t%d\t%d",initial_time, initial_utime,count,(packet_length),count_tcp,count_udp,count_icmp,count_default);
        }

        }
   }
}
void print_file()
{
if(initial_time != 0)
 {
FILE *fp=fopen (writefile,"a+");
    if(tuple_flag==true)
     {
	if(verbose_flag == false)
	{
		fprintf(fp,"\n%ld.%06ld\t%d\t%ld\t%d",initial_time, initial_utime,count,(packet_length),flow);
	}
	else
	{
		fprintf(fp,"\n%ld.%06ld\t%d\t%ld\t%d\t%d\t%d\t%d\t%d\t%d\t%d",initial_time, initial_utime,count,(packet_length),flow,count_tcp,count_udp,count_icmp,count_default,flow_tcp,flow_udp);
	}
      }
     else
      {
if(verbose_flag == false)
        {
                fprintf(fp,"\n%ld.%06ld\t%d\t%ld",initial_time, initial_utime,count,(packet_length));
        }
        else
        {
                fprintf(fp,"\n%ld.%06ld\t%d\t%ld\t%d\t%d\t%d\t%d",initial_time,initial_utime,count,(packet_length),count_tcp,count_udp,count_icmp,count_default);
        }
	
      }
fclose(fp);
}
}
void dump_packet(const unsigned char *packet, struct timeval ts,
		unsigned int capture_len,unsigned long packet_len)
{
	//static u_short ip_Id;
	//static int count=0;
	struct ip *ip;
	if(onetime == true)
	{
		initial_time=ts.tv_sec;
		initial_utime=ts.tv_usec;
	}
	onetime=false;

	packet += sizeof(struct ether_header);


	ip = (struct ip*) packet;
	int IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */
	if(IP_header_length >=20)
	{
	//static unsigned long packet_length=0;

	//int len     = ntohs(ip->ip_len);
//cout<<"\n"<<ip->ip_src.sin_port;
	int sport=0;
	int dport=0;

	 if(ip->ip_p == IPPROTO_TCP)
                  getPort_tcp(packet , sport,dport);
         else if(ip->ip_p == IPPROTO_UDP)
                  getPort_udp(packet,sport,dport);

	if(((ip->ip_v == 4)))
	{

		
		if((initial_time+epoch > ts.tv_sec)||((initial_time+epoch == ts.tv_sec)&&(ts.tv_usec <= initial_utime)))
		{

		if(tuple_mode ==2)
		{
			if(head1 == NULL)
				{
				head1=new struct two_tuple;
				current1=head1;
				if(ip->ip_p == IPPROTO_TCP)
					flow_tcp=1;
				else if(ip->ip_p == IPPROTO_UDP)
					flow_udp=1;
				flow=1;
				strcpy(current1->src,inet_ntoa(ip->ip_src));
				strcpy(current1->dest,inet_ntoa(ip->ip_dst));
				current1->ip_p=ip->ip_p;
				current1->next=NULL;
				//current1->src=ip->ip_src;
				//current1->dest=ip_dest;
				}
			else
				{
	char src_l[32];
	char dest_l[32];
	memset(src_l,0,32);
	memset(dest_l,0,32);
	strcpy(src_l,inet_ntoa(ip->ip_src));
	strcpy(dest_l,inet_ntoa(ip->ip_dst));
	current1=head1;
	
	if(current1 != NULL)
	searchOrInsert_two(current1,src_l,dest_l,ip->ip_p);
				}
		}
		else if(tuple_mode == 5)
		{

		if(head2 == NULL)
                                {
                                head2=new struct five_tuple;
                                current2=head2;
                                if(ip->ip_p == IPPROTO_TCP)
                                        flow_tcp=1;
                                else if(ip->ip_p == IPPROTO_UDP)
                                        flow_udp=1;
				flow=1;

                                current2->src=inet_ntoa(ip->ip_src);
                                current2->dest=inet_ntoa(ip->ip_dst);
                                current2->ip_p=ip->ip_p;
				current2->sport=sport;
				current2->dport=dport;
				current2->next=NULL;
                                //current1->src=ip->ip_src;
                                //current1->dest=ip_dest;
                                }
                        else
                                {
        searchOrInsert_five(current2,inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst),ip->ip_p,sport,dport);
                                }


		}				

			
			//cout<<"Packet received ";
			if((count==0)&&(!first_entry))
			{
				count=2;
			}
			else
			{
				++count;
			}
			if(ip->ip_p == IPPROTO_TCP)
			{
				++count_tcp;
			}

			else if (ip->ip_p == IPPROTO_UDP)
			{
				++count_udp;
			}
			else if (ip->ip_p == IPPROTO_ICMP)
			{
				++count_icmp;
			}
			else 
			{
				++count_default;
			}


			packet_length=packet_length+packet_len;
			if(entry == true)
				packet_length=packet_length+previous_length;
			entry=false;
			//packet_length=packet_length+(ntohs(capture_len));
			first_entry=false;

		}
		else
		{

			if(file_flag == false)
				print_screen();
			else
				print_file();

			packet_end=true;
			while((initial_time+epoch <= ts.tv_sec))
			{
				if(packet_end==false)
				{

					if(file_flag == false)
						print_screen();
					else
						print_file();

				}
				if(packet_end == true)
					packet_length=0;
				initial_time=initial_time+epoch;
				//packet_length=packet_len;
				previous_length=packet_len;
				entry=true;
				count=0;
				count_udp=0;
				count_icmp=0;
				count_default=0;
				count_tcp=0;
			
				packet_end=false;
				flow_tcp=0;
				flow_udp=0;
				flow=0;

				//deleteList(head1);	


				if((initial_time+epoch == ts.tv_sec)&&(ts.tv_usec > initial_utime))
				{
					if(file_flag == false)
						print_screen();
					else
						print_file();

					initial_time=initial_time+epoch;
					break;
				}
			}
			if(ip->ip_p == IPPROTO_TCP)
                        {
                           ++count_tcp;
                        }

                        else if (ip->ip_p == IPPROTO_UDP)
                        {
                          ++count_udp;
                        }
                        else if (ip->ip_p == IPPROTO_ICMP)
                        {
                           ++count_icmp;
                        }
			else
			{
			  ++count_default;
			}
                       if(tuple_mode ==2)
			{ 
			deleteList1(head1);
			if(head1 == NULL)
                                {
                                head1=new struct two_tuple;
                                current1=head1;
				 if(ip->ip_p == IPPROTO_TCP)
                                        flow_tcp=1;
                                else if(ip->ip_p == IPPROTO_UDP)
                                        flow_udp=1;
				flow=1;

                                strcpy(current1->src,inet_ntoa(ip->ip_src));
                                strcpy(current1->dest,inet_ntoa(ip->ip_dst));
				current1->ip_p=ip->ip_p;
                                }
			}
			else if(tuple_mode ==5)
                        {
                        deleteList2(head2);
                        if(head2 == NULL)
                                {
                                head2=new struct five_tuple;
                                current2=head2;
                                 if(ip->ip_p == IPPROTO_TCP)
                                        flow_tcp=1;
                                else if(ip->ip_p == IPPROTO_UDP)
                                        flow_udp=1;
				flow=1;
                                current2->src=inet_ntoa(ip->ip_src);
                                current2->dest=inet_ntoa(ip->ip_dst);
                                current2->ip_p=ip->ip_p;
				current2->sport=sport;
				current2->dport=dport;
                                }
                        }



		}
	}

}
}

void dump_live_packet(const unsigned char *packet, struct timeval ts,
		unsigned int capture_len,unsigned long packet_len)
{
	//static int count=0;
	struct ip *ip;
	//struct UDP_hdr *udp;
	//unsigned int IP_header_length;
	if(onetime==true)
	{
		initial_time=ts.tv_sec;
		initial_utime=ts.tv_usec;
	}
	onetime=false;

	packet += sizeof(struct ether_header);


	ip = (struct ip*) packet;
	//IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	//int len     = ntohs(ip->ip_len);
//printf("\nip_V = %d\n",ip1->ip_vhl);
	if(((ip->ip_v == 4)))
	{

		//cout<<"Packet received ";
		if((count==0)&&(!first_entry))
		{
			count=2;
		}
		else
		{
			++count;
		}
		if(ip->ip_p == IPPROTO_TCP)
		{
			if((count_tcp==0)&&(!first_entry))
			{
				count_tcp=2;
			}
			else
			{
				++count_tcp;
			}

		}
		else if (ip->ip_p == IPPROTO_UDP)
		{
			if((count_udp==0)&&(!first_entry))
			{
				count_udp=2;
			}
			else
			{
				++count_udp;
			}
		}
		else if (ip->ip_p == IPPROTO_ICMP)
		{
			if((count_icmp==0)&&(!first_entry))
			{
				count_icmp=2;
			}
			else
			{
				++count_icmp;
			}
		}
		else 
		{
			if((count_default==0)&&(!first_entry))
			{
				count_default=2;
			}
			else
			{
				++count_default;
			}
		}


		packet_length=packet_length+packet_len;
		//packet_length=packet_length+(ntohs(capture_len));

	}
}

void signalHandler( int signum )
{
	//cout << "Interrupt signal (" << signum << ") received.\n";
//	pthread_mutex_lock(&lock);
	if(file_flag== false)
		print_screen();
	else
		print_file();
//pthread_mutex_unlock(&lock);
	initial_time=initial_time+epoch;
	packet_length=0;
	count=0;
	count_udp=0;
	count_icmp=0;
	count_tcp=0;
	count_default=0;

}

/*void *print_message_function(void *ptr)
{
	//int i=0;	   
//	signal(2, signalHandler);  

	while(1){
		usleep(epoch*1000000);
		///raise( 2);
		pthread_mutex_lock(&lock);
		signalHandler(2);
		pthread_mutex_unlock(&lock);
	}

	printf("In Thread\n");
return;
}*/
int main(int argc, char *argv[])
{
	char *dev;

	//const char *message1 = "Thread 1";
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	char filename[200];
	char interface[100];
	bool offline=false;
	int c;
	bool r1=false;
	bool r2=false;
//int main_policy;
//struct sched_param main_param;

/*main_policy = SCHED_FIFO;
main_param.sched_priority = 99;
pthread_setschedparam(pthread_self(), main_policy, &main_param);*/
while(1)
{
 static struct option long_options[] =
             {
               /* These options set a flag. */
               {"verbose", no_argument,       0, 'v'},
               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"read",     required_argument,       0, 'r'},
               {"write",  required_argument,       0, 'w'},
               {"int",  required_argument, 0, 'i'},
	       {"track", required_argument ,0 ,'z'},
               {"time",  required_argument, 0, 'T'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;
     
           //c = getopt_long (argc, argv, "vr:w:i:T:",
            //                long_options, &option_index);

	 c = getopt_long (argc, argv, "vr:w:i:T:z:",long_options, &option_index);

	 if (c == -1)
             break;

                switch (c)
                {
                        case 'r':
				r1=true;
                                offline=true;
                                //cout<<"\nFilename -->"<<optarg;
                                strcpy(filename,optarg);
                                break;

                        case 'i':
				r2=true;
                                offline=false;
                                cout<<"\nInterface -->" <<optarg;
                                strcpy(interface,optarg);
                                break;

                        case 'T':
                                cout<<"\nEpoch -->"<<optarg;
                                epoch=atoi(optarg); 
                                break;

                        case 'v':
                                verbose_flag=true;
                                break;
                        case 'w':
                                file_flag=true;
				cout<<"\nWriting the output to the file "<<optarg;
                                strcpy(writefile,optarg);
                                break;
			case 'z':
				tuple_flag=true;
				tuple_mode=atoi(optarg);
				break;
			
                        case '?':
				cout<<"\ntraffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ]\n";
                                if(optopt == 'i')
                                        cout<<"\nOption  requires an argument\n";
                                exit(1);
                                break;
			default:
             			cout<<"\ntraffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ]\n";
				exit(1);
                }
}

if((r1 == true) && (r2==true))
	{
	cout<<"\nCannot enable both live and oofline capture\n";
	exit(1);
	}
if((tuple_mode !=2)&&(tuple_mode !=5))
	{
	cout<<"\nWrong tuple. It can wither 2 or 5\n";
	exit(1);	
	}
	//int ret;
	//pthread_t thread1, thread2;
	if(offline == false)
	{
		//1ret = pthread_create( &thread1, NULL, print_message_function, NULL);
	}
	if ( argc == 1 )
	{
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
	}

	if(offline == false)
	{
		dev = pcap_lookupdev(errbuf);
		if(dev == NULL)
		{ printf("%s\n",errbuf); exit(1); }

		pcap = pcap_open_live(interface,65536,1,0,errbuf);
		if(pcap == NULL)
			cout<<"\nNot able to open Handle for live sniffing\n";
	}
	else
	{
		pcap = pcap_open_offline(filename, errbuf);
	}
	if (pcap == NULL)
	{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
	if(offline ==true)
	{
		while ((packet = pcap_next(pcap, &header)) != NULL)
		{
			dump_packet(packet, header.ts, header.caplen,header.len);
		}
		if(file_flag == false)
			print_screen();
		else
			print_file();

	}
	else
	{
		while ((packet = pcap_next(pcap, &header)) != NULL)
		{
		dump_packet(packet, header.ts, header.caplen,header.len);
		}

	}
	//if(file_flag == true)
		//fclose(fp);
	// terminate
	return 0;
}


