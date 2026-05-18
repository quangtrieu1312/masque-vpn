#ifndef QUEUE_WRAPPER_H
#define QUEUE_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

void* queue_new(int capacity);
int   queue_push(void* queue, void* item);
int   queue_peek(void* queue, void** out);
int   queue_pop(void* queue, void** out);
void  queue_free(void* queue);

#ifdef __cplusplus
}
#endif

#endif
