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
#include <signal.h>
#include <sys/wait.h>

#include <stdbool.h>

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
int sock,port,laddr_cli,a, portTCP, procesos = 1;
struct PDU *pdu;
struct PDU *recib;
struct PDU prot;
struct PDU prot2;
struct PDU *server;
struct sockaddr_in	addr_server,addr_cli;
bool debug = false;


void hora(){
  time (&raw_time);
  ptr_ts = gmtime(&raw_time);
}

void mostraMSG(char estat[], char qui[]){
  hora();
  printf("%2d:%02d:%02d: MSG.  =>  %s passa a l'estat: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, qui, estat);
}

int registrar(){
  struct timeval tv;
  int select_return, temps;
  fd_set fdread;

  strcpy(prot.numAleatori, "000000");
  prot.tipusPaq[0] = 0x00;
  pdu = &prot;
  recib = &prot2;

  while(procesos < 4){
    if(debug) {
      hora();
      printf("%2d:%02d:%02d: DEBUG =>  Registre equip, intent: %i\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, procesos);
    }

    temps = 2;
    tv.tv_sec = temps;
    tv.tv_usec = 0;

    for(int n = 1; n < 9; n++){
      if(n > 2 && temps < 8) temps = temps+2;
      tv.tv_sec = temps;
      FD_ZERO(&fdread);
      FD_SET(sock, &fdread);
      
      if(debug) {
        hora();
        printf("%2d:%02d:%02d: DEBUG =>  Enviat: bytes=%li, comanda=REGISTER_REQ, nom=%s, mac=%s, alea=%s  dades=%s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,sizeof(struct PDU), pdu->nomEquip, pdu->MAC, pdu->numAleatori, pdu->dades);
      }
      sendto(sock,pdu,sizeof(struct PDU),0,(struct sockaddr*)&addr_server,sizeof(addr_server));
      mostraMSG("WAIT_REG","Client");
      select_return = select(sock+1,&fdread, NULL, NULL, &tv);

      if(select_return < 0){
        return -1;
      } else if(select_return) {
        recvfrom(sock,recib,sizeof(struct PDU),0,(struct sockaddr *)0,(int *)0);
        if(recib->tipusPaq[0] == 0x01) return 1;
        else if (recib->tipusPaq[0] == 0x03) return 0;
        else break;
      }
    }

    if(debug) {
      hora();
      printf("%2d:%02d:%02d: INFO  =>  Fallida registre amb servidor: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, ent->h_name);
    }
    sleep(5);
    procesos++;
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
  struct timeval tv;
  int select_return, perduts = 0;
  fd_set fdread;
  bool alive = false;

  FD_ZERO(&fdread);
  FD_SET(sock, &fdread);
  tv.tv_usec = 0;

  while(1){
    tv.tv_sec = 3;

    sendto(sock,pdu,sizeof(struct PDU),0,(struct sockaddr*)&addr_server,sizeof(addr_server));
    select_return = select(sock+1,&fdread, NULL, NULL, &tv);

    if(select_return) {
      recvfrom(sock,recib,sizeof(struct PDU),0,(struct sockaddr *)0,(int *)0);
      if(recib->tipusPaq[0] == 0x11){
        if(strcmp(recib->nomEquip, server->nomEquip) == 0 &&
            strcmp(recib->MAC, server->MAC) == 0 &&
            strcmp(recib->numAleatori, server->numAleatori) == 0){
              if(!alive) {
                mostraMSG("ALIVE", "Equip");
                alive = true;
              }
            } else perduts++;
      } else if(recib->tipusPaq[0] == 0x13){
        return 0;
      } else perduts++;
    } else perduts++;
    if(perduts == 3) return 0;
    sleep(tv.tv_sec);
  }
}

int main(int argc,char *argv[])
{
  /* Mirem les opcions introduides en la comanda */
  int opt;
  char *fichero = "client.cfg";
  while((opt = getopt(argc, argv, ":c:d")) != -1)
      {
          switch(opt)
          {
              case 'c':
                  fichero = optarg;
                  break;
              case 'd':
                  debug = true;
                  break;
          }
      }

  /* Carregem les dades del archiu .cfg a les variables corresponents */
  leerConfig(fichero);

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
  mostraMSG("DISCONNECTED", "Equip");

  regis:
  reg = registrar();

  if(reg == 1){
    mostraMSG("REGISTERED", "Equip");
    strcpy(pdu->numAleatori, recib->numAleatori);
    portTCP = atoi(recib->dades);
    server = recib;
    pdu->tipusPaq[0] = 0x10;
    pid_t pid = fork();
    if(pid) {
      // pare
      pid_t pid2 = fork();

      if(pid2) {
        // Pare, Controla el fills
        pid_t pidFinal = wait(NULL);
        if(pidFinal == pid) {
          kill(pid2, SIGTERM);
          goto regis;
        }
        else kill(pid, SIGTERM);
      } else {
        // Fill 2, Controla la entrada de comandes per consola
        char *escan;
        scanf("%s",escan);
        if(strcmp(escan, "quit")) exit(0);
      }

    } else {
      // Fill 1 Mante ALIVE
      int ret = alive();
      if(ret == 0) {
        mostraMSG("DISCONNECTED (Sense resposta a 3 ALIVES)", "Equip");
        exit(0);
      }
    }
  }
}
