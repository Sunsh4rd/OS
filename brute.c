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
   RM_GEN,
  } run_mode_t;

typedef struct config_t {
  int length;
  char * alph;
  char * hash;
  brute_mode_t brute_mode;
  run_mode_t run_mode;
} config_t;

#define PASSWORD_LENGTH 8

typedef char password_t[PASSWORD_LENGTH];

typedef struct task_t {
  password_t password;
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
  int tiq;
  pthread_mutex_t tiq_mutex;
  pthread_cond_t tiq_cond;
  password_t result;
} pc_context_t;

typedef struct crypt_data_t {
  char * hash;
  struct crypt_data crypt;
} crypt_data_t;

typedef struct iter_state_t {
  config_t * config;
  task_t * task;
  int idx[PASSWORD_LENGTH];
  int alph_size_1;
} iter_state_t;

typedef struct iterator_t {
  iter_state_t iter_state;
  pthread_mutex_t mutex;
  bool finished;
  config_t * config;
  password_t result;
} iterator_t;

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

bool check_password (void * context, task_t * task)
{
  crypt_data_t * crypt_data = context;
  char * hash = crypt_r (task -> password, crypt_data->hash, &crypt_data->crypt);
  return (strcmp (crypt_data -> hash, hash) == 0);
}

typedef bool (*password_handler_t) (void * context, task_t * task);

bool rec (config_t * config, task_t * task, password_handler_t password_handler, void * context, int pos)
{ 
  int i;
  if (pos >= task -> to)
    return (password_handler (context, task));
  else
    for (i = 0; config -> alph[i]; i++)
      {
	task -> password[pos] = config -> alph[i];
	if (rec (config, task, password_handler, context, pos + 1))
	  return (true);
      }
  return (false);
}

bool rec_wrapper (config_t * config, task_t * task, password_handler_t password_handler, void  * context)
{
  return (rec (config, task, password_handler, context, task->from));
}

void iter_state_init (iter_state_t * iter_state, config_t * config, task_t * task)
{
  int i;
  iter_state -> alph_size_1 = strlen (config -> alph) - 1;
  iter_state -> config = config;
  iter_state -> task = task;

  for (i = task -> from; i < task -> to; i++)
    {
      iter_state -> idx[i] = 0;
      task -> password[i] = config -> alph[0];
    }
}

bool iter_state_next (iter_state_t * iter_state)
{
  int i;
  int alph_size_1 = iter_state -> alph_size_1;
  config_t * config = iter_state -> config;
  task_t * task = iter_state->task;
  
  for (i = task -> to - 1; (i >= task -> from) && (iter_state -> idx[i] == alph_size_1); i--)
    {
      iter_state -> idx[i] = 0;
      task -> password[i] = config -> alph[0];
    }
  if (i < task -> from)
    return (false);

  task -> password[i] = config -> alph[++iter_state -> idx[i]];
  return (true);
}

bool iter (config_t * config, task_t * task, password_handler_t password_handler, void  * context)
{
  iter_state_t iter_state;

  iter_state_init (&iter_state, config, task);
  
  for (;;)
    {
      if (password_handler (context, task)) {
	return (true);
      }
      if (!iter_state_next (&iter_state)) {
	return (false);
      }
    }
}

void *  iterator_worker (void * arg)
{
  iterator_t * iterator = arg;
  crypt_data_t crypt_data;

  crypt_data.hash = iterator->config->hash;
  crypt_data.crypt.initialized = 0;
  
  for (;;)
    {
      task_t task;
      bool finished;
      pthread_mutex_lock (&iterator -> mutex);
      finished = iterator -> finished;
      if (!finished)
	{
	  task = *iterator -> iter_state.task;
	  iterator -> finished = !iter_state_next (&iterator -> iter_state);
	}
      pthread_mutex_unlock (&iterator -> mutex);
      
      if (finished)
	break;

      task.to = task.from;
      task.from = 0;

      bool found = false;
      
      switch (iterator -> config -> brute_mode)
	{
	case BM_REC:
	  found = rec_wrapper (iterator -> config, &task, check_password, &crypt_data);
	  break;
	case BM_ITER:
	  found = iter (iterator -> config, &task, check_password, &crypt_data);
     	  break;
	}

      if (found)
	{
	  iterator -> finished = true;
	  strcpy (iterator->result, task.password);
	}
    }
  
  return (NULL);
}


void run_gen (config_t * config, task_t * task) {
  int i,  num_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  pthread_t id [num_cpu];
  iterator_t iterator;

  iterator.config = config;
  task -> from = 2;
  iter_state_init (&iterator.iter_state, config, task);
  pthread_mutex_init (&iterator.mutex, NULL);
  iterator.result[0] = 0;
  iterator.finished = false;
  
  for (i = 0; i < num_cpu; i++) {
    pthread_create (&id[i], NULL, iterator_worker, &iterator);
  }
  iterator_worker (&iterator);

  for (i = 0; i < num_cpu; ++i)
    pthread_join (id[i], NULL);

  memcpy (task->password, iterator.result, sizeof (iterator.result));
}

void parse_paras (config_t * config, int argc, char * argv[])
{
  int opt;
  while ((opt = getopt (argc, argv, "a:l:h:irsmt")) != -1)
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
	  config -> brute_mode = BM_ITER;
	  break;
	case 'r':
	  config -> brute_mode = BM_REC;
	  break;
	case 's':
	  config -> run_mode = RM_SINGLE;
	  break;
	case 'm':
	  config -> run_mode = RM_MULTI;
	  break;
	case 't':
	  config -> run_mode = RM_GEN;
	  break;	  
	}
    }
}

bool print_password (config_t * config, task_t * task)
{
  printf ("%s\n", task -> password);
  return (false);
}


void run_single (config_t * config, task_t * task)
{
  crypt_data_t crypt_data;
  crypt_data.crypt.initialized = 0;
  crypt_data.hash = config->hash;

  switch (config -> brute_mode)
    {
    case BM_REC:
      rec_wrapper (config, task, check_password, &crypt_data);
      break;
    case BM_ITER:
      iter (config, task, check_password, &crypt_data);
      break;
    }
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
      bool found = false;
      
      queue_pop (&pc_context -> queue, &task);
      task.to = task.from;
      task.from = 0;
      switch (pc_context -> config -> brute_mode)
	{
	case BM_REC:
	  found = rec_wrapper (pc_context -> config, &task, check_password, &crypt_data);
	  break;
	case BM_ITER:
	  found = iter (pc_context -> config, &task, check_password, &crypt_data);
     	  break;
	}

      if (found)
	strcpy (pc_context->result, task.password);

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
  
  pthread_mutex_lock (&pc_context->tiq_mutex);
  ++pc_context->tiq;
  pthread_mutex_unlock (&pc_context->tiq_mutex);
  queue_push (&pc_context->queue, task);
  return (pc_context->result[0]);
}

void run_multi (config_t * config, task_t * task)
{
  int i, num_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  pc_context_t pc_context;
  pthread_t id[num_cpu];
  
  pc_context.result[0] = 0;
  pc_context.config = config;
  pc_context.tiq = 0;
  pthread_mutex_init (&pc_context.tiq_mutex, NULL);
  pthread_cond_init (&pc_context.tiq_cond, NULL);
  queue_init (&pc_context.queue);
  task -> from = 2; 
   
  for (i = 0; i < num_cpu; ++i)
    pthread_create (&id[i], NULL, consumer, &pc_context);

  switch (config -> brute_mode)
    {
    case BM_REC:
      rec_wrapper (config, task, push_to_queue, &pc_context);
      break;
    case BM_ITER:
      iter (config, task, push_to_queue, &pc_context);
      break;
    }

  pthread_mutex_lock (&pc_context.tiq_mutex);
  while (pc_context.tiq != 0)
    pthread_cond_wait (&pc_context.tiq_cond, &pc_context.tiq_mutex);

  for (i = 0; i < num_cpu; ++i)
    {
      pthread_cancel (id[i]);
      pthread_join (id[i], NULL);
    }
  strcpy (task->password, pc_context.result);
 }

int main (int argc, char * argv[])
{
  config_t config =
    {
     .brute_mode = BM_ITER,
     .length = 3,
     .alph = "012",
     .hash = "wHtCXhpDbCnLI",
     .run_mode = RM_SINGLE,
    };
  
  parse_paras (&config, argc, argv);
  task_t task =
    {
     .password = "",
     .from = 0,
     .to = config.length,
    };
  task.password[config.length] = 0;
  
  switch (config.run_mode)
    {
    case RM_SINGLE:
      run_single (&config, &task);
      break;
    case RM_MULTI:
      run_multi (&config, &task);
      break;
    case RM_GEN:
      run_gen (&config, &task);
      break;
    }

  if (task.password[0])
     printf ("password  '%s'\n", task.password);
  else
     printf ("password not found\n");

  return (0);
}
