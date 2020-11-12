#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void * fun (void * a)
{
  int i = 0;
  for (;;)
    {
      sleep (4);
      printf ("%d\n", i++);
    }
}

int main ()
{
  pthread_t th, th1;
  pthread_create (&th, NULL, fun, NULL);
  pthread_create (&th1, NULL, fun, NULL);
  pthread_join (th, NULL);
  pthread_join (th1, NULL);
  return (0);
}
