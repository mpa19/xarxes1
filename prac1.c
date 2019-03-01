#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <time.h>

#define LONGDADES	78


struct PDU {
  unsigned char tipusPaq[1];
  char nomEquip[7];
  char MAC[13];
  char numAleatori[7];
  char dades[50];
};

time_t raw_time;
struct tm *ptr_ts;

char dadcli[LONGDADES];
struct hostent *ent;
int sock,port,laddr_cli,a;
struct PDU *pdu;
struct PDU *recib;
struct PDU prot;
struct PDU prot2;
struct sockaddr_in	addr_server,addr_cli;
char estat[15];

int registrar(){
  struct timeval tv;
  int select_return, temps;
  fd_set fdread;

  strcpy(prot.numAleatori, "000000");
  prot.tipusPaq[0] = 0x00;
  pdu = &prot;
  recib = &prot2;

  for(int procesos = 0; procesos < 3; procesos++){
    temps = 2;
    tv.tv_sec = temps;
    tv.tv_usec = 0;

    for(int n = 1; n < 9; n++){
      if(n > 2 && temps < 8) temps = temps+2;
      tv.tv_sec = temps;
      FD_ZERO(&fdread);
      FD_SET(sock, &fdread);
      a=sendto(sock,pdu,LONGDADES,0,(struct sockaddr*)&addr_server,sizeof(addr_server));

      time (&raw_time);
      ptr_ts = gmtime(&raw_time);

      strcpy(estat,"WAIT_REG");
      printf("%2d:%02d:%02d: MSG.  =>  Client passa a l'estat: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, estat);
      select_return = select(sock+1,&fdread, NULL, NULL, &tv);

      if(select_return < 0){
        return -1;
      } else if(select_return) {
        recvfrom(sock,recib,LONGDADES,0,(struct sockaddr *)0,(int *)0);
        if(recib->tipusPaq[0] == 0x01) return 1;
        else if (recib->tipusPaq[0] == 0x03) return 0;
        else break;
      }
    }
    sleep(5);
  }
  return 0;
}

/* Guardar datos del client.cfg */
void leerConfig(char* a) {
    char linea[30];
    FILE *fich;
    int cont = 0;
    fich = fopen(a, "r");

    while (fgets(linea, 30, (FILE*) fich)) {
      strtok(linea," ");
      strcpy(linea,strtok(NULL," "));
      linea[strlen(linea) -1] = '\0';

      if(cont == 0){
        strcpy(prot.nomEquip, linea);
      } else if(cont == 1){
        strcpy(prot.MAC,linea);
      } else if(cont == 2){
        ent = gethostbyname(linea);
      } else {
        port = atoi(linea);
      }
      cont++;
    }
}

int alive(){
  for(int a = 0; a < 5; a++) {
    printf("ALIVE!!\n");
    sleep(1);
  }
  return 0;
}


int main(int argc,char *argv[])
{
  /* Carregem les dades de client.cfg a les variables corresponents */
  leerConfig("client.cfg");

	/* Crea un socket INET+DGRAM -> UDP */
	sock=socket(AF_INET,SOCK_DGRAM,0);
	if(sock<0)
	{
		fprintf(stderr,"No puc obrir socket!!!\n");
		perror(argv[0]);
		exit(-1);
	}

	/* Ompla l'estructrura d'adreça amb les adreces on farem el binding (acceptem
	   per qualsevol adreça local */
	memset(&addr_cli,0,sizeof (struct sockaddr_in));
	addr_cli.sin_family=AF_INET;
	addr_cli.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_cli.sin_port=htons(0);

	/* Fem el binding */
	if(bind(sock,(struct sockaddr *)&addr_cli,sizeof(struct sockaddr_in))<0)
	{
		fprintf(stderr,"No puc fer el binding del socket!!!\n");
                exit(-2);
	}

	/* Ompla l'estructrura d'adreça amb l'adreça del servidor on enviem les dades */
	memset(&addr_server,0,sizeof (struct sockaddr_in));
	addr_server.sin_family=AF_INET;
  addr_server.sin_addr.s_addr=INADDR_ANY;
	addr_server.sin_port=htons(port);

  int reg;
  time (&raw_time);
  ptr_ts = gmtime(&raw_time);
  strcpy(estat,"DISCONNECTED");
  printf("%2d:%02d:%02d: MSG.  =>  Equip passa a l'estat: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, estat);

  regis:
  reg = registrar();

  if(reg == 1){
    time (&raw_time);
    ptr_ts = gmtime(&raw_time);
    strcpy(estat,"REGISTERED");
    printf("%2d:%02d:%02d: MSG.  =>  Equip passa a l'estat: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, estat);
  } else if(reg == -1){
    /*sleep(5);
    goto regis;*/
  }

  /* crear hijo */
  /*/pid_t pid = fork();
  if(pid) {
    // pare
    for(int a = 0; a < 10; a++) {
      printf("PARE\n");
      sleep(1);
    }
  } else {
    // Fill
    int al = alive();

    if(al == 0){
      goto regis;
    }*/


    /* TEST GIT */

    
  }
