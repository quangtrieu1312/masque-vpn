#include "queue_wrapper.h"
#include "mpmc_queue.h"

using Queue = es::lockfree::mpmc_queue<void*>;

extern "C" {

void* queue_new(int capacity) {
    return new Queue(static_cast<size_t>(capacity));
}

int queue_push(void* queue, void* item) {
    return static_cast<Queue*>(queue)->push(item) ? 1 : 0;
}

int queue_peek(void* queue, void** out) {
    void* item;
    if (static_cast<Queue*>(queue)->peek(item)) {
        *out = item;
        return 1;
    }
    return 0;
}

int queue_pop(void* queue, void** out) {
    void* item;
    if (static_cast<Queue*>(queue)->pop(item)) {
        *out = item;
        return 1;
    }
    return 0;
}

void queue_free(void* queue) {
    delete static_cast<Queue*>(queue);
}

} // extern "C"
