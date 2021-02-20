#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <crypt.h>

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

#define PASSWORD_LENGTH 8

typedef struct task_t {
  char password[PASSWORD_LENGTH];
  int from, to;
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
  task_t result;
  int tiq;
  pthread_mutex_t tiq_mutex;
  pthread_cond_t tiq_cond;
} pc_context_t;

typedef struct crypt_data_t {
  char * hash;
  struct crypt_data crypt;
} crypt_data_t;

void queue_init (queue_t * queue)
{
  queue -> head = 0;
  queue -> tail = 0;
  sem_init (&queue -> empty, 0 , sizeof (queue -> queue) / sizeof (queue -> queue[0]));
  sem_init (&queue -> full, 0 , 0);
  pthread_mutex_init (&queue -> head_mutex, NULL);
  pthread_mutex_init (&queue -> tail_mutex, NULL);
  memset (&queue->queue, 0, sizeof (queue->queue));
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

typedef bool (*password_handler_t) (void * context, task_t * task);

bool rec (config_t * config, task_t * task, int pos, password_handler_t password_handler, void * context)
{ 
  int i;
  if ((--pos) < task -> to)
    return (password_handler (context, task));
  else
    for (i = task -> from; config -> alph[i]; i++)
      {
	password[pos] = config -> alph[i];
	if (rec (config, task -> from, pos, password_handler, context))
	  return (true);
      }
  return (false);
}

bool rec_wrapper (config_t * config, task_t * task, password_handler_t password_handler, void * context)
{
  return (rec (config, task, config -> length, password_handler, context));
}

bool iter (config_t * config, task_t * task, password_handler_t password_handler, void * context, int from, int to)
{
  int alph_size_1 = strlen(config -> alph) - 1;
  int idx[config -> length];
  int i;
 
  for (i = to; i < from; i++)
    {
      idx[i] = 0;
      password[i] = config -> alph[0];
    }
  
  for (;;)
    {
      if (password_handler (context, password))
	return (true);
      
      for (i = from - 1; (i >= to) && (idx[i] == alph_size_1); i--)
	{
	  idx[i] = 0;
	  password[i] = config -> alph[0];
	}
      if (i < to)
	return (false);
      printf("%d", i);
      password[i] = config -> alph[++idx[i]];
      printf("%s\n", password);
    }
}

void parse_paras (config_t * config, int argc, char * argv[])
{
  int opt;
  brute_mode_t mode;
  run_mode_t run;
  while ((opt = getopt (argc, argv, "a:l:h:irsmf")) != -1)
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
	case 'f':
	  config -> from = atoi (optarg);
	  break;
	}
    }
}

bool print_password (config_t * config, task_t * task)
{
  printf ("%s\n", password);
  return (false);
}

bool check_password (void * context, task_t * task)
{
  crypt_data_t * crypt_data = context;
  char * hash = crypt_r (password, crypt_data->hash, &crypt_data->crypt);
  return (strcmp (crypt_data -> hash, hash) == 0);
}

bool run_single (config_t * config, task_t * task)
{
  crypt_data_t crypt_data;
  crypt_data.crypt.initialized = 0;
  crypt_data.hash = config->hash;

  switch (config -> brute_mode)
    {
    case BM_REC:
      return (rec_wrapper (config, password, check_password, &crypt_data));
    case BM_ITER:
      return (iter (config, password, check_password, &crypt_data, config -> length, 0));
    }
  return (false);
}

void * consumer (void * arg)
{
  pc_context_t * pc_context = arg;
  crypt_data_t crypt_data;
  crypt_data.crypt.initialized = 0;
  crypt_data.hash = pc_context->config->hash;
  
  for (;;)
    {
      task_t task;
      queue_pop (&pc_context -> queue, &task);

      switch (pc_context -> config -> brute_mode)
	{
	case BM_REC:
	  rec_wrapper (pc_context -> config, &task.password, check_password, &pc_context);
	  break;
	case BM_ITER:
	  iter (pc_context -> config, &task.password, check_password, &pc_context);
	  break;
	}
      
      if (check_password (&crypt_data, task.password))
	pc_context -> result = task;

      pthread_mutex_lock (&pc_context -> tiq_mutex);
      --pc_context -> tiq;
      pthread_mutex_unlock (&pc_context -> tiq_mutex);
      
      if (pc_context-> tiq == 0)
	pthread_cond_broadcast (&pc_context -> tiq_cond);
    }
}

bool push_to_queue (void * context, task_t * task)
{
  pc_context_t * pc_context = context;
  task_t task;
  strcpy (task.password, password);
  
  pthread_mutex_lock (&pc_context->tiq_mutex);
  ++pc_context->tiq;
  pthread_mutex_unlock (&pc_context->tiq_mutex);
  
  queue_push (&pc_context->queue, &task);
  return (pc_context->result.password[0]);
}

void run_multi (config_t * config, task_t * task)
{
  int i, num_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  pc_context_t  pc_context;
  
  pc_context.result.password[0] = 0;
  pc_context.config = config;
  pc_context.tiq = 0;
  pthread_mutex_init (&pc_context.tiq_mutex, NULL);
  pthread_cond_init (&pc_context.tiq_cond, NULL);
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
      iter (config, password, push_to_queue, &pc_context, config -> from, 0);
      break;
    }

  pthread_mutex_lock (&pc_context.tiq_mutex);
  while (pc_context.tiq != 0)
    pthread_cond_wait (&pc_context.tiq_cond, &pc_context.tiq_mutex);

  strcpy (password, pc_context.result.password);
}

int main (int argc, char * argv[])
{
  config_t config =
    {
     .brute_mode = BM_ITER,
     .length = 3,
     .alph = "0123456789",
     .hash = "wHtCXhpDbCnLI",
     .run_mode = RM_SINGLE,
    };
  
  parse_paras (&config, argc, argv);
  char password[config.length + 1];
  password[config.length] = '\0';

  switch (config.run_mode)
    {
    case RM_SINGLE:
      run_single (&config, password);
      break;
    case RM_MULTI:
      run_multi (&config, password);
      break;
    }

  if (password[0])
    printf ("password  '%s'\n", password);
  else
    printf ("0\n");
  
  return (0); 
}
