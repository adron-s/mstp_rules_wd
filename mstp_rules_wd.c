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

/* директория где находится mstp */
#define MSTP_DIR "/data/local/mstp"
#define MSTP_BIAND_DIR MSTP_DIR "/bin/android"
#define SH_CMD MSTP_BIAND_DIR "/sh"
#define NDC_CMD MSTP_BIAND_DIR "/ndc"
/* файл по умолчанию с охраняемой таблицей маршрутизации */
#define DEFAULT_WD_TABLE_FILE MSTP_DIR "/default_table"
/* наш pid файл */
#define PID_FILE MSTP_DIR "/run/mstp-rules-wd.pid"
/* константы взята из исходников netd */
/* prio рула, который используется для направления всего
	 трафика с oif xxx в таблицу xxx */
#define RULE_PRIORITY_OUTPUT_INTERFACE 14000
/* prio рула, который используется для назначения default network */
#define RULE_PRIORITY_DEFAULT_NETWORK 22000

int print_rule(const struct sockaddr_nl *who,
	       struct nlmsghdr *n, void *arg);

int breakable_rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_listen_filter_t handler,
		void *jarg);

//*************************************************************************************
static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb){
	__u32 table = r->rtm_table;
	if(tb[RTA_TABLE])
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
#ifdef DEBUG
#define PRINTD(format, args...) { 								 \
	fprintf(stdout, format, ##args); 								 \
	fflush(stdout); 																 \
}
#else
#define PRINTD(...)
#endif
//------------------------------------------------------------------------------------

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
	}else{
		//а файла то и нет => и охранять нечего.
		*network = res;
		return res;
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
		PRINTD("Warning! wd_table_file struct is CORRUPTED!\n");
	}
	return res;
}//-----------------------------------------------------------------------------------

//*************************************************************************************
/* вызывается при получении очередного msg от netlink сокета */
static int accept_msg(const struct sockaddr_nl *who,
		      struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg){
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[FRA_MAX + 1];
	char buf[255];
	const char *table_str;
	/* эти значения актуальны ~только~ если wd_table > 0 ! */
	static char *wd_table_str = NULL;
	static char *wd_network_str = NULL;
	unsigned int prio = 0; //ip rule priority
	//если нужно выходить - немедленно прекращаем цикл while(1) из rtnl_listen
	if(need_exit)
		return -100;
	if(n->nlmsg_type == RTM_NEWRULE || n->nlmsg_type == RTM_DELRULE){
#ifdef DEBUG
		print_rule(who, n, arg); //для отладки. нужно раскоментить строчку в Android.mk
#endif
		len -= NLMSG_LENGTH(sizeof(*r));
		if(len < 0)
			return 0;
		parse_rtattr(tb, FRA_MAX, RTM_RTA(r), len);
		if(tb[FRA_PRIORITY])
			prio = *(unsigned*)RTA_DATA(tb[FRA_PRIORITY]);
		//если это событие add/del: 22000: from all fwmark 0x0/0xffff lookup table xxx
		if(prio != RULE_PRIORITY_DEFAULT_NETWORK)
				return 0; //нас интересуют только события для default network rula.
		//получим название таблицы которую мы сторожим и имя сети(oemX) для этой таблицы
		wd_table_str = get_wd_table(&wd_network_str);
		if(wd_table_str[0] == '\0')
			return 0; //охраняемая таблица не задана
		/* по любому чиху в 22000 руле запускаем восстанавление охраняемой сети
			 в качестве default. лишний раз оно не повредит т.к. ndc умный. тут лучше
			 перебдеть чем недобдеть :-) */
		snprintf(buf, sizeof(buf), "%s network default set %s >/dev/null 2>&1\n",
			NDC_CMD, wd_network_str);
		PRINTD("Executing our cmd %s\n", buf);
		exec_cmd(buf);
	}
	return 0;
}//-----------------------------------------------------------------------------------

//*************************************************************************************
/* выполняет запись нашего PID-а в файл */
void write_pid(void){
	int fd;
	char pid[20];
	fd = creat(PID_FILE, O_WRONLY);
	if(fd < 0){
		perror("Can't create pid file");
		return;
	}
	snprintf(pid, sizeof(pid), "%d", getpid());
	if(write(fd, pid, strlen(pid)) <= 0){
		perror("Can't write pid to file");
	}
	close(fd);
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
	write_pid();
	while(!need_exit){
		PRINTD("do rtnl_open. need_exit = %d\n", need_exit);
		if(rtnl_open(&rth, groups) < 0){
			perror("Cannot open netlink socket");
			return -1;
		}
		/* инит библиотеки ll. наверное он тут не нужен но пусть будет.
			 в iproute2 везде он есть где делается open. */
		ll_init_map(&rth);
		//слушаем сокет и вызываем обработчик для каждого принятого события
		breakable_rtnl_listen(&rth, accept_msg, stdout);
		rtnl_close(&rth);
	}
	unlink(PID_FILE);
	return 0;
}
