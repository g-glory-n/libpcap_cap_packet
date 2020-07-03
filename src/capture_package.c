#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>

#include <pcap.h>
#include <time.h>

typedef struct {
	char *p_ch_dev_name;
	bpf_u_int32 *p_uint32_net_addr;
	bpf_u_int32 *p_uint32_netmask;
} if_info;


extern void args_parse(int, char **);
extern void init(if_info *);
extern void list_if(if_info *);
extern void get_if_info(if_info *);
extern void open_if(if_info *);
extern void cap_packet(if_info *);
extern void print_packet();
extern void write_to_pcap(void);
extern void close_if(pcap_t *);
extern void quit(if_info *);

extern void sigalrm_response(int);
extern void sigterm_repongse(int);

int int_cap_time_s = 0;
char *p_ch_filter_rule = NULL;
char *p_ch_pcap_file_save_path = NULL;

char *p_ch_err_buf = NULL;
pcap_t *p_pcap_t_0 = NULL;
pcap_dumper_t *p_pcap_dumper_t_0 = NULL;

unsigned int packet_count = 0;
unsigned long cap_byte_count = 0;

int main(int argc, char *argv[])
{
	if_info *p_if_info_0 = NULL;
	p_if_info_0 = (if_info *)malloc(sizeof(if_info));

	args_parse(argc, argv);

	signal(SIGALRM, sigalrm_response); // 注册信号函数
	signal(SIGTERM, sigterm_repongse);

	init(p_if_info_0);

	list_if(p_if_info_0);

	get_if_info(p_if_info_0);

	open_if(p_if_info_0);

	struct bpf_program filter;
	if (pcap_compile(p_pcap_t_0, &filter, p_ch_filter_rule, 1, 0) != 0) { // 编译过滤规则。
		fprintf(stderr, "\n\terr: %s\n", "failed to compile the BPF filter rule!");
		exit(-1);
	}
	if (pcap_setfilter(p_pcap_t_0, &filter) != 0) { // 设置过滤器。
		fprintf(stderr, "\n\terr: %s\n", "failed to applicate the BPF filter rule!");
                exit(-1);
	}

	write_to_pcap(); // 打开文件，在回调函数中写入。

	if (int_cap_time_s != 0)
		alarm(int_cap_time_s);

	cap_packet(p_if_info_0);

	// alarm(int_cap_time_s); // 未收到数据包 cap_packet(p_if_info_0); 不会退出，导致此句无效。
	
	close_if(p_pcap_t_0);

	quit(p_if_info_0);
	
	fprintf(stdout, "number of packets captured in %d seconds: %u\n", int_cap_time_s, packet_count);

	return 0;
}

void sigterm_repongse(int sig)
{
	if (SIGTERM == sig) {
		close_if(p_pcap_t_0);
		fprintf(stdout, "number of packets and bytes captured in %d seconds: %u, %lu\n", int_cap_time_s, packet_count, cap_byte_count);
		exit(0);
	}
}

void sigalrm_response(int sig)
{
	if (SIGALRM == sig) {
	
		close_if(p_pcap_t_0);
		// quit(p_if_info_0);

		fprintf(stdout, "number of packets and bytes captured in %d seconds: %u, %lu\n", int_cap_time_s, packet_count, cap_byte_count);
		exit(0);
	}
}





// int int_cap_time_s = 0;
// char *p_ch_filter_rule = NULL;
// char *p_ch_pcap_file_seve_path = NULL;
void args_parse(int argc, char *argv[])
{
	int_cap_time_s = atoi(argv[1]);
	p_ch_filter_rule = argv[2];
	p_ch_pcap_file_save_path = argv[3];
}

void init(if_info *p_if_info_0)
{
	p_if_info_0->p_ch_dev_name = NULL;
	p_if_info_0->p_uint32_net_addr = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
	p_if_info_0->p_uint32_netmask = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));

	p_ch_err_buf = (char *)malloc(sizeof(char) * PCAP_ERRBUF_SIZE);
}

void list_if(if_info *p_if_info_0)
{
	p_if_info_0->p_ch_dev_name = pcap_lookupdev(p_ch_err_buf);

	if (p_if_info_0->p_ch_dev_name == NULL)
	{
		fprintf(stderr, "\n\terr: %s\n", p_ch_err_buf);
		exit(-1);
	}
	else
		fprintf(stdout, "if info: \n\tif list: \n\t%s\n", p_if_info_0->p_ch_dev_name);

}

void get_if_info(if_info *p_if_info_0)
{
	if (0 != pcap_lookupnet(p_if_info_0->p_ch_dev_name, 
				p_if_info_0->p_uint32_net_addr, 
				p_if_info_0->p_uint32_netmask, 
				p_ch_err_buf)) {
		fprintf(stderr, "\n\terr: \n\t%s/n", p_ch_err_buf);
		exit(-1);
	}
	else {
		fprintf(stdout, "\n\tnet_addr is: \n\t%u.%u.%u.%u\n", 
				(*p_if_info_0->p_uint32_net_addr & 0x000000ff), 
				(*p_if_info_0->p_uint32_net_addr & 0x0000ff00) >> 8, 
				(*p_if_info_0->p_uint32_net_addr & 0x00ff0000) >> 16, 
				(*p_if_info_0->p_uint32_net_addr & 0xff000000) >> 24); // 网络传输为大端传输，所以低字节存放在高地址。
		fprintf(stdout, "\n\tnetmask is: \n\t%u.%u.%u.%u\n", 
				(*p_if_info_0->p_uint32_netmask & 0x000000ff), 
				(*p_if_info_0->p_uint32_netmask & 0x0000ff00) >> 8, 
				(*p_if_info_0->p_uint32_netmask & 0x00ff0000) >> 16, 
				(*p_if_info_0->p_uint32_netmask & 0xff000000) >> 24);
		fprintf(stdout, "\n\n");
	}
}

void open_if(if_info *p_if_info_0)
{
	int to_time = 1000 * int_cap_time_s;
	if ((p_pcap_t_0 = pcap_open_live(p_if_info_0->p_ch_dev_name, 
				65535, 1, 0, p_ch_err_buf)) == NULL) {
		fprintf(stderr, "\n\terr: \n\t%s/n", p_ch_err_buf);
		exit(-1);
	}


}

void cap_packet(if_info *p_if_info_0)
{
//	unsigned int packet_id = 0;
//	if (-1 == pcap_dispatch(p_pcap_t_0, -1, print_packet, (u_char *)&packet_id)) {
//		fprintf(stderr, "\n\terr: \n\tpcap_dispatch/n");
//		exit(-1);
//	}


	struct pcap_pkthdr pkthdr;
	const u_char *p_ch_pack_str = NULL;
	while (1)
	{
		if ((p_ch_pack_str = pcap_next(p_pcap_t_0, &pkthdr)) == NULL) {
			fprintf(stderr, "\n\terr: \n\tpcap_next/n");
			exit(-1);
		}
		else {
			packet_count++;
			pcap_dump((u_char *)p_pcap_dumper_t_0, &pkthdr, p_ch_pack_str);
			printf("\npacket_id is: %u\n", packet_count);
			printf("length of portion present: %d\n", pkthdr.caplen); // 取长
			printf("length this packet: %d\n", pkthdr.len); // 实际长
			printf("recieved time: %s", ctime((const time_t *)&pkthdr.ts.tv_sec)); // 时间戳
			fflush(stdout);

			for (int i = 0; i < pkthdr.len; ++i) {
				cap_byte_count++;
				printf(" %02x", p_ch_pack_str[i]);
				if ((i + 1) % 16 == 0) {
					printf("\n");
				}
			}
			putchar('\n');
			putchar('\n');
		}
	}
}

void print_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	pcap_dump((u_char *)p_pcap_dumper_t_0, pkthdr, packet);
	packet_count++;

	int *packet_id = (int *)arg;
	
	printf("packet_id: %d\n", ++(*packet_id));
	printf("packet length: %d\n", pkthdr->len);
	printf("length of portion present: %d\n", pkthdr->caplen);
	printf("recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	fflush(stdout);

	for (int i = 0; i < pkthdr->len; ++i) {
		cap_byte_count++;
		printf(" %02x", packet[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	
	printf("\n\n");
}

void write_to_pcap(void)
{
	// pcap_dumper_t *p_pcap_dumper_t_0 = NULL;
	p_pcap_dumper_t_0  = pcap_dump_open(p_pcap_t_0, p_ch_pcap_file_save_path);

}

void close_if(pcap_t *p_pcap_t_0)
{
	pcap_dump_close(p_pcap_dumper_t_0);
	fprintf(stdout, "\npcap_file has closed!\n");
	pcap_close(p_pcap_t_0);
	fprintf(stdout, "\nif has closed!\n\n\n");
}

void quit(if_info *p_if_info_0)
{
	p_if_info_0->p_ch_dev_name = NULL;

	free(p_if_info_0->p_uint32_net_addr);
	p_if_info_0->p_uint32_net_addr = NULL;

	free(p_if_info_0->p_uint32_netmask);
	p_if_info_0->p_uint32_netmask = NULL;

	free(p_ch_err_buf);
	p_ch_err_buf= NULL;
	
	free(p_if_info_0);
	p_if_info_0 = NULL;
}
