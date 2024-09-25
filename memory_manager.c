#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct block {
    int size;
    int is_allocated;
    struct block* next_block;
};

void* memory_pool = NULL;

void mem_init(size_t size){
    memory_pool = malloc(size);
    printf("Memory Pool %p\n", memory_pool);
    // Check if memory allocation is successful
    if (memory_pool == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    printf("Memory initialized with size %ld\n", size);
    // Initialize memory pool with blocks
    struct block* current_block = (struct block*)memory_pool;
    current_block->is_allocated = 0;
    current_block->size = size - sizeof(struct block);
    current_block->next_block = NULL;

    printf("Block size %d\n", current_block->size);
}

void* mem_alloc(size_t size) {
    // Pointer to the first block
    struct block* current_block = (struct block*)memory_pool;

    // Loops through all blocks
    while (current_block != NULL) {
        if (current_block->is_allocated == 0 && current_block->size >= size) {
            if (current_block->size >= size + sizeof(struct block)) {

                struct block* new_block = (struct block*)((char*)current_block + sizeof(struct block) + size);
                new_block->size = current_block->size - size + sizeof(struct block);
                new_block->is_allocated = 0;
                new_block->next_block = current_block->next_block;

                current_block->size = size;
                current_block->next_block = new_block;
                current_block->is_allocated = 1;
            } else {

                current_block->is_allocated = 1;
            }

            return (char*)current_block + sizeof(struct block);
        }

        current_block = current_block->next_block;
    }

    return NULL;
}

void mem_free(void* target_block){
    // Mark the block as free
    struct block* block_ptr = (struct block*)((char*)target_block - sizeof(struct block));

    // Mark the block as free
    block_ptr->is_allocated = 0;
    printf("Memory freed\n");
}

void* mem_resize(void* block, size_t size){
    if (block == NULL) {
        return mem_alloc(size);
    }

    // Get the block associated with the current allocated memory
    struct block* block_ptr = (struct block*)((char*)block - sizeof(struct block));

    if (block_ptr->size >= size) {
        // If the current block can accommodate the new size, return the same block
        printf("Current block is large enough, no need to resize\n");
        return block;
    }

    // Allocate a new block
    void* new_mem = mem_alloc(size);
    if (new_mem == NULL) {
        printf("Failed to allocate new memory during resize\n");
        return NULL;
    }

    // Copy the data to the new block
    memcpy(new_mem, block, block_ptr->size);

    // Free the old block
    mem_free(block);

    printf("Memory resized from %p to %p\n", block_ptr, new_mem);
    return new_mem;
}

void mem_deinit(){
    free(memory_pool);
    memory_pool = NULL;
    printf("Memory deinitialized\n");
}
