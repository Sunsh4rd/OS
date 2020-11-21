#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

typedef enum
  {
   BM_ITER,
   BM_REC,
  } brute_mode_t;

typedef enum run_mode_t
  {
   RM_SINGLE,
   RM_MULTI,
  } run_mode_t;

typedef struct config_t {
  int length;
  char * alph;
  char * hash;
  brute_mode_t brute_mode;
  run_mode_t run_mode;
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

typedef struct pc_context_t {
  config_t * config;
  queue_t queue;
} pc_context_t;

void queue_init (queue_t * queue)
{
  queue -> head = 0;
  queue -> tail = 0;
  sem_init (&queue -> empty, 0 , sizeof (queue -> queue) / sizeof (queue -> queue[0]));
  sem_init (&queue -> full, 0 , 0);
  pthread_mutex_init (&queue -> head_mutex, NULL);
  pthread_mutex_init (&queue -> tail_mutex, NULL);
}

void queue_push (queue_t * queue, task_t * task)
{
  sem_wait (&queue -> empty);
  pthread_mutex_lock (&queue -> tail_mutex);
  queue -> queue[queue -> tail] = *task;
  if (++queue -> tail == sizeof (queue -> queue) / sizeof (queue -> queue[0]))
    queue -> tail = 0; 
  pthread_mutex_unlock (&queue -> tail_mutex);
  sem_post (&queue -> full);
}

void queue_pop (queue_t * queue, task_t * task)
{
  sem_wait (&queue -> full);
  pthread_mutex_lock (&queue -> head_mutex);
  *task = queue -> queue[queue -> head];
  if (++queue -> head == sizeof (queue -> queue) / sizeof (queue -> queue[0]))
    queue -> head = 0;
  pthread_mutex_unlock (&queue -> head_mutex);
  sem_post (&queue -> empty);
}

typedef bool (*password_handler_t) (void * context, char * password);

bool rec (config_t * config, char * password, int pos, password_handler_t password_handler, void * context)
{ 
  int i;
  if ((--pos) < 0)
    return (password_handler (context, password));
  else
    for (i = 0; config -> alph[i]; i++)
      {
	password[pos] = config -> alph[i];
	if (rec (config, password, pos, password_handler, context))
	  return (true);
      }
  return (false);
}

bool rec_wrapper (config_t * config, char * password, password_handler_t password_handler, void * context)
{
  return (rec (config, password, config -> length, password_handler, context));
}

bool iter (config_t *  config, char * password, password_handler_t password_handler, void * context)
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
      if (password_handler (context, password))
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
  run_mode_t run;
  while ((opt = getopt (argc, argv, "a:l:h:irsm")) != -1)
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
	case 's':
	  run = RM_SINGLE;
	  config -> run_mode = run;
	  break;
	case 'm':
	  run = RM_MULTI;
	  config -> run_mode = run;
	  break;
	}
    }
}

bool print_password (config_t * config, char * password)
{
  printf ("%s\n", password);
  return (false);
}

bool check_password (void * context, char * password)
{
  config_t * config = context;
  char * hash = crypt (password, config->hash);
  return (strcmp (config -> hash, hash) == 0);
}

bool run_single(config_t * config, char * password)
{
  switch (config -> brute_mode)
    {
    case BM_REC:
      return (rec_wrapper (config, password, check_password, config));
    case BM_ITER:
      return (iter (config, password, check_password, config));
    }
}

void * consumer (void * arg)
{
  pc_context_t * pc_context = arg;
  for (;;)
    {
      task_t task;
      queue_pop (&pc_context->queue, &task);
      if (check_password (arg, task))
	break;
    }
}

bool push_to_queue (void * context, char * password)
{
  pc_context_t * pc_context = context;
  task_t task;
  strcpy (task.password, password);
  queue_push (&pc_context->queue, &task);
  return (false);
}

bool run_multi(config_t * config, char * password)
{
  int i, num_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  pc_context_t pc_context;

  pc_context.config = config;
  queue_init (&pc_context.queue);

  for (i = 0; i < num_cpu; ++i)
    {
      pthread_t id;
      pthread_create (&id, NULL, consumer, &pc_context);
    }

  switch (config -> brute_mode)
    {
    case BM_REC:
      rec_wrapper (config, password, push_to_queue, &pc_context);
      break;
    case BM_ITER:
      iter (config, password, push_to_queue, &pc_context);
      break;
    }
  
}

int main (int argc, char * argv[])
{
  config_t config =
    {
     .brute_mode = BM_ITER,
     .length = 3,
     .alph = "01",
     .hash = "wHtCXhpDbCnLI",
     .run_mode = RM_SINGLE,
    };
  
  parse_paras (&config, argc, argv);
  char password[config.length + 1];
  password[config.length] = '\0';

  bool found = false;
  switch (config.run_mode)
    {
    case RM_SINGLE:
      found = run_single (&config, password);
      break;
    case RM_MULTI:
      found = run_multi (&config, password);
      break;
    }

  if (found)
    printf ("password  '%s'\n", password);
  else
    printf ("0\n");
  
  return (0); 
}
