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
struct sockaddr_in	addr_server,addr_cli;
bool debug = false;
char numAlServer[7], nomSever[7], macServer[13];


void hora(){
  time (&raw_time);
  ptr_ts = gmtime(&raw_time);
}

void mostraMSG(char estat[], char qui[]){
  hora();
  printf("%2d:%02d:%02d: MSG.  =>  %s passa a l'estat: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, qui, estat);
}

char* tPaquet(struct PDU *pdu){
  if(pdu->tipusPaq[0] == 0x00) return "REGISTER_REQ";
  else if(pdu->tipusPaq[0] == 0x01) return "REGISTER_ACK";
  else if(pdu->tipusPaq[0] == 0x02) return "REGISTER_NACK";
  else if(pdu->tipusPaq[0] == 0x03) return "REGISTER_REJ";
  else if(pdu->tipusPaq[0] == 0x10) return "ALIVE_INF";
  else if(pdu->tipusPaq[0] == 0x11) return "ALIVE_ACK";
  else if(pdu->tipusPaq[0] == 0x12) return "ALIVE_NACK";
  else if(pdu->tipusPaq[0] == 0x13) return "ALIVE_REJ";
}

int registrar(){
  struct timeval tv;
  int select_return, temps;
  fd_set fdread;


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
        printf("%2d:%02d:%02d: DEBUG =>  Enviat: bytes=%li, comanda=%s, nom=%s, mac=%s, alea=%s  dades=%s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,sizeof(struct PDU), tPaquet(pdu), pdu->nomEquip, pdu->MAC, pdu->numAleatori, pdu->dades);
      }
      sendto(sock,pdu,sizeof(struct PDU),0,(struct sockaddr*)&addr_server,sizeof(addr_server));
      mostraMSG("WAIT_REG","Client");
      select_return = select(sock+1,&fdread, NULL, NULL, &tv);

      if(select_return < 0){
        return -1;
      } else if(select_return) {
        recvfrom(sock,recib,sizeof(struct PDU),0,(struct sockaddr *)0,(int *)0);
        if(debug){
          hora();
          printf("%2d:%02d:%02d: DEBUG =>  Rebut: bytes=%li, comanda=%s, nom=%s, mac=%s, alea=%s  dades=%s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,sizeof(struct PDU), tPaquet(recib), recib->nomEquip, recib->MAC, recib->numAleatori, recib->dades);
        }
        if(recib->tipusPaq[0] == 0x01) {
          procesos++;
          return 1;
        } else if (recib->tipusPaq[0] == 0x03) {
          if(debug){
            hora();
            printf("%2d:%02d:%02d: INFO =>  Petició de registre rebutjada, motiu: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, recib->dades);
          }
          return 0;
        } else {
          if(debug){
            hora();
            printf("%2d:%02d:%02d: INFO =>  Petició de registre errònia, motiu: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, recib->dades);
          }
          break;
        }
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


  tv.tv_usec = 0;

  if(debug){
    hora();
    printf("%2d:%02d:%02d: DEBUG =>  Establert temporitzador per enviament alives\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
  }

  while(1){
    tv.tv_sec = 3;
    FD_ZERO(&fdread);
    FD_SET(sock, &fdread);
    if(debug) {
      hora();
      printf("%2d:%02d:%02d: DEBUG =>  Enviat: bytes=%li, comanda=%s, nom=%s, mac=%s, alea=%s  dades=%s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,sizeof(struct PDU), tPaquet(pdu), pdu->nomEquip, pdu->MAC, pdu->numAleatori, pdu->dades);
    }
    sendto(sock,pdu,sizeof(struct PDU),0,(struct sockaddr*)&addr_server,sizeof(addr_server));
    select_return = select(sock+1,&fdread, NULL, NULL, &tv);
    if(select_return) {
      recvfrom(sock,recib,sizeof(struct PDU),0,(struct sockaddr *)0,(int *)0);
      if(debug){
        hora();
        printf("%2d:%02d:%02d: DEBUG =>  Rebut: bytes=%li, comanda=%s, nom=%s, mac=%s, alea=%s  dades=%s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,sizeof(struct PDU),tPaquet(recib), recib->nomEquip, recib->MAC, recib->numAleatori, recib->dades);
      }

      if(recib->tipusPaq[0] == 0x11){
        if(strcmp(recib->nomEquip, nomSever) == 0 &&
            strcmp(recib->MAC, macServer) == 0 &&
            strcmp(recib->numAleatori, numAlServer) == 0){
              if(!alive) {
                mostraMSG("ALIVE", "Equip");
                alive = true;
              }
              if(debug){
                hora();
                printf("%2d:%02d:%02d: INFO =>  Acceptat ALIVE (Servidor: nom=%s, mac=%s, alea=%s)\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, recib->nomEquip, recib->MAC, recib->numAleatori);
              }
              perduts = 0;
            } else {
              if(debug){
                hora();
                printf("%2d:%02d:%02d: INFO  =>  Error recepció paquet UDP. Servidor incorrecte (correcte: nom=%s, ip=%s, mac=%s, alea=%s))\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, nomSever, inet_ntoa(*((struct in_addr*)ent->h_addr_list[0])), macServer, numAlServer);
              }
              perduts++;
            }
      } else if(recib->tipusPaq[0] == 0x13){
        if(debug){
          hora();
          printf("%2d:%02d:%02d: INFO =>  Recepció d'informació de alive rebutjada, motiu: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, recib->dades);
        }
        return 0;
      } else perduts++;
    } else perduts++;
    if(perduts == 3) {
      if(debug){
        hora();
        printf("%2d:%02d:%02d: DEBUG =>  Cancelat temporitzador per enviament alives\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
      }
      return 0;
    }
    sleep(tv.tv_sec);
  }
}

int main(int argc,char *argv[])
{
  /* Mirem les opcions introduides en la comanda */
  int opt;
  char *fichero = "client.cfg";
  while((opt = getopt(argc, argv, ":c:d")) != -1){
    switch(opt){
      case 'c':
        fichero = optarg;
        break;
      case 'd':
        debug = true;
        break;
      }
    }

    if(debug){
      hora();
      printf("%2d:%02d:%02d: DEBUG =>  Llegits paràmetres línia de comandes\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
    }

  /* Carregem les dades del archiu .cfg a les variables corresponents */
  leerConfig(fichero);

  if(debug){
    hora();
    printf("%2d:%02d:%02d: DEBUG =>  Llegits parametres arxius de configuració\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
  }

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


  if(debug){
    hora();
    printf("%2d:%02d:%02d: DEBUG =>  Inici bucle de servei equip: %s\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec, prot.nomEquip);
  }

  int reg;
  pid_t pid, pid2, pidFinal;

  mostraMSG("DISCONNECTED", "Equip");
  strcpy(prot.numAleatori, "000000");

  regis:
  reg = registrar();

  if(reg == 1){
    mostraMSG("REGISTERED", "Equip");
    if(debug){
      hora();
      printf("%2d:%02d:%02d: INFO  =>  Acceptada subscripció amb servidor: %s (nom: %s, mac: %s, alea: %s, port tcp: %s)\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec,
          ent->h_name, recib->nomEquip, recib-> MAC, recib->numAleatori, recib->dades);
    }
    strcpy(pdu->numAleatori, recib->numAleatori);
    portTCP = atoi(recib->dades);
    strcpy(nomSever, recib->nomEquip);
    strcpy(macServer, recib->MAC);
    strcpy(numAlServer, recib->numAleatori);

    pdu->tipusPaq[0] = 0x10;

    pid = fork();
    if(pid) {
      // pare
      pid2 = fork();

      if(pid2) {
        // Pare, Controla el fills
        esperar:
        pidFinal = wait(NULL);
        if(pidFinal == pid) {
          kill(pid2, SIGKILL);
          if(debug){
            hora();
            printf("%2d:%02d:%02d: DEBUG =>  Finalitzat procés per gestionar alives\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
          }
          goto regis;
        }
        else if(pidFinal == pid2){
          close(sock);
          kill(pid, SIGKILL);
        } else goto esperar;
      } else {
        // Fill 2, Controla la entrada de comandes per consola
        char *escan;
        scanf("%s",escan);
        if(strcmp(escan, "quit")) exit(0);
      }

    } else {
      // Fill 1 Mante ALIVE
      if(debug){
        hora();
        printf("%2d:%02d:%02d: DEBUG =>  Creat procés per gestionar alives\n", ptr_ts->tm_hour,ptr_ts->tm_min,ptr_ts->tm_sec);
      }

      int ret = alive();

      if(ret == 0) {
        mostraMSG("DISCONNECTED (Sense resposta a 3 ALIVES)", "Equip");
        exit(0);
      }
    }
  }
  close(sock);
}