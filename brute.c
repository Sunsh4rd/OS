#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

typedef enum {
   BM_ITER,
   BM_REC,
  } brute_mode_t;

typedef struct config_t {
  int length;
  char * alph;
  char * hash;
  brute_mode_t brute_mode;
} config_t;

typedef struct task_t {
  char password[8];
} task_t;

typedef struct queue_t {
  task_t queue[8];
  int head, tail;
  pthread_mutex_t head_mutex, tail_mutex;
  sem_t empty, full;
} queue_t;

void queue_init (queue_t * queue)
{
  
}

void queue_push (queue_t * queue, task_t * task)
{
  //7
}

void queue_pop (queue_t * queue, task_t * task)
{
  //7
}

typedef bool (*password_handler_t) (config_t * config, char * password);

bool rec (config_t * config, char * password, int pos, password_handler_t password_handler)
{
  int i;
  if ((--pos) < 0)
    return (password_handler (config, password));
  else
    for (i = 0; config -> alph[i]; i++)
      {
	password[pos] = config -> alph[i];
	if (rec (config, password, pos, password_handler))
	  return (true);
      }
  return (false);
}

bool rec_wrapper (config_t * config, char * password, password_handler_t password_handler)
{
  return (rec (config, password, config -> length, password_handler));
}

bool iter (config_t *  config, char * password, password_handler_t password_handler)
{
  int alph_size_1 = strlen(config -> alph) - 1;
  int idx[config -> length];
  int i;

  for (i = 0; i < config -> length; i++)
    {
      idx[i] = 0;
      password[i] = config -> alph[0];
    }

  for (;;)
    {
      if (password_handler (config, password))
	return (true);
      
      for (i = config -> length - 1; (i >= 0) && (idx[i] == alph_size_1); i--)
	{
	  idx[i] = 0;
	  password[i] = config -> alph[0];
	}

      if (i < 0)
	return (false);
      password[i] = config -> alph[++idx[i]];
    }
}

void parse_paras(config_t * config, int argc, char * argv[])
{
  int opt;
  brute_mode_t mode;
  while ((opt = getopt (argc, argv, "a:l:h:ir")) != -1)
    {
      switch (opt)
	{
	case 'l':
	  config -> length = atoi (optarg);
	  break;
	case 'a':
	  config -> alph = optarg;
	  break;
	case 'h':
	  config -> hash = optarg;
	  break;
	case 'i':
	  mode = BM_ITER;
	  config -> brute_mode = mode;
	  break;
	case 'r':
	  mode = BM_REC;
	  config -> brute_mode = mode;
	  break;
	}
    }
}

bool print_password (config_t * config, char * password)
{
  printf ("%s\n", password);
  return (false);
}

bool check_password (config_t * config, char * password)
{
  return (false);
  char * hash = crypt (password, config->hash);
  return (strcmp (config -> hash, hash) == 0);
}

int main (int argc, char * argv[])
{
   config_t config =
    {
     .brute_mode = BM_ITER,
     .length = 3,
     .alph = "01",
     .hash = "wHtCXhpDbCnLI",
    };
  
  parse_paras (&config, argc, argv);
  char password[config.length + 1];
  password[config.length] = '\0';
  bool tmp = true;
  
  switch (config.brute_mode)
    {
    case BM_REC:
      tmp = rec_wrapper (&config, password, check_password);
      break;
    case BM_ITER:
      tmp = iter (&config, password, check_password);
      break;
    }
  if (tmp){
    printf ("password '%s'\n", password);
  }
  else {
    printf ("0\n");
  }
  return (0); 
}
