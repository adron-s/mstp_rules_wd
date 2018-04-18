#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "signals.h"
/* from iproute2 include */
#include <libnetlink.h>
#include <utils.h>
#include <linux/fib_rules.h>
#include <rt_names.h>

int need_exit = 0; //еще не пора выходить
char wd_table_file[255];

#define SH_CMD "/system/xbin/sh"
/* файл по умолчанию с охраняемой таблицей маршрутизации */
#define DEFAULT_WD_TABLE_FILE "/data/local/mstp/default_table"
/* константа взята из исходников netd. это prio рула, который
	 используется для назначения default network */
#define RULE_PRIORITY_DEFAULT_NETWORK 22000

int print_rule(const struct sockaddr_nl *who,
	       struct nlmsghdr *n, void *arg);

int breakable_rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_listen_filter_t handler,
		void *jarg);

//*************************************************************************************
static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb){
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}//-----------------------------------------------------------------------------------

//*************************************************************************************
/* так как system вызов не всегда на андроидах работает => я написал его заменитель */
void exec_cmd(char *cmd){
	char *new_argv[] = { SH_CMD, "-c", cmd, NULL };
	int pid = fork();
	if(pid == 0){
		//child
		execvp(new_argv[0], new_argv);
		perror("exec_cmd failed");
		exit(-10);
	}else{
		//parent
		wait(NULL);
		if(need_exit) //если нас попросили выйти то прибиваем нашего потомка
	 		kill(pid, SIGKILL);
	}
}//-----------------------------------------------------------------------------------

//*************************************************************************************
/* считывает имя охраняемой таблицы из wd_table файла.
	 в случае если файла нет => вернет "\0" */
char *get_wd_table(char **network){
	int fd;
	static char res[255];
	int len;
	char *p = res;
	char *tail = NULL;
	res[0] = '\0';
	fd = open(wd_table_file, O_RDONLY);
	if(fd > 0){
		len = read(fd, res, sizeof(res) - 1);
		res[sizeof(res) - 1] = '\0';
		if(len < 0)
			res[0] = '\0';
		else
			res[len] = '\0'; //оконечим строку
		close(fd);
	}
	//парсим и заменяем '\n' -> '\0'
	for(; *p != '\0'; p++){
		if(*p == '\n' || *p == ':'){
			*p = '\0';
			if(!tail)
				tail = p + 1;
		}
	}
	*network = tail;
	if(!tail){ //если хвост так и не был найден!
		*network = res; //значит структура wd_table файла ошибочна!
		memset(res, 0x0, sizeof(res));
#ifdef DEBUG
		printf("Warning! wd_table_file struct is CORRUPTED!\n");
#endif
	}
	return res;
}//-----------------------------------------------------------------------------------

//*************************************************************************************
/* вызывается при получении очередного msg от netlink сокета */
static int accept_msg(const struct sockaddr_nl *who,
		      struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg){
	FILE *fp = (FILE*)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[FRA_MAX + 1];
	__u32 table;
	char buf[255];
	const char *table_str;
	char *wd_table_str;
	char *wd_network_str;
	unsigned int prio = 0; //ip rule priority
	//если нужно выходить - немедленно прекращаем цикл while(1) из rtnl_listen
	if(need_exit)
		return -100;
	if (n->nlmsg_type == RTM_NEWRULE || n->nlmsg_type == RTM_DELRULE){
#ifdef DEBUG
		print_rule(who, n, arg); //для отладки. нужно раскоментить строчку в Android.mk
#endif
		if (n->nlmsg_type != RTM_DELRULE)
			return 0; //нас интересуют только del rule
		len -= NLMSG_LENGTH(sizeof(*r));
		if(len < 0)
			return 0;
		parse_rtattr(tb, FRA_MAX, RTM_RTA(r), len);
		if(tb[FRA_PRIORITY])
			prio = *(unsigned*)RTA_DATA(tb[FRA_PRIORITY]);
		if(prio != RULE_PRIORITY_DEFAULT_NETWORK)
			return 0; //нас интересуют только события для default network rula.
		table = rtm_get_table(r, tb);
		if(table){
			//получим название таблицы. в любом случае вернет строку!
			table_str = rtnl_rttable_n2a(table, buf, sizeof(buf));
			//получим название таблицы которую мы сторожим и имя сети(oemX) для этой таблицы
			wd_table_str = get_wd_table(&wd_network_str);
			if(!wd_table_str[0]) //если вообще есть что сторожить
				return 0;
			//сравним имена таблиц
			if(strcmp(wd_table_str, table_str) != 0)
				return 0;
			/* если мы дожили до сюда => rule для нашей wd_table с
				 prio DEFAULT_NETWORK только был удалён ! */
#ifdef DEBUG
			printf("Ahhtung! our wd table %s(%d), rule is deleted! network := %s\n",
				wd_table_str, table, wd_network_str);
#endif
			if(wd_network_str[0]){ //восстанавливаем охраняемую сеть в качестве default
				snprintf(buf, sizeof(buf), "ndc network default set %s >/dev/null 2>&1\n",
					wd_network_str);
				exec_cmd(buf);
			}
		}
		return 0;
	}
	return 0;
}//-----------------------------------------------------------------------------------

int main(int argc, char **argv){
	struct rtnl_handle rth;
	unsigned groups = 0;
  daemon(0, 1);//демонизируемся
  setup_sig_kill_handler();
	if(argc < 2)
		strncpy(wd_table_file, DEFAULT_WD_TABLE_FILE, sizeof(wd_table_file) - 1);
	else //в качестве параметра передается путь к файлу с именем охраняемой таблицы
		strncpy(wd_table_file, argv[1], sizeof(wd_table_file) - 1);
	//нам интересны только события для ip rule
	groups |= nl_mgrp(RTNLGRP_IPV4_RULE);
	if (rtnl_open(&rth, groups) < 0){
		perror("Cannot open netlink socket");
		return -1;
	}
	/* инит библиотеки ll. наверное он тут не нужен но пусть будет.
		 в iproute2 везде он есть где делается open. */
	ll_init_map(&rth);
	//слушаем сокет и вызываем обработчик для каждого принятого событи
	breakable_rtnl_listen(&rth, accept_msg, stdout);
	rtnl_close(&rth);
	return 0;
}
