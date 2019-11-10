#ifndef RENHOOK_MEMORY_ALLOCATOR_H
#define RENHOOK_MEMORY_ALLOCATOR_H

#include <mutex>

namespace renhook
{
    namespace memory
    {
        /**
         * @brief A memory allocator class.
         */
        class allocator
        {
        public:

            allocator() noexcept;
            ~allocator() noexcept;

            allocator(allocator&) = delete;
            allocator(allocator&&) = delete;

            allocator& operator=(const allocator&) = delete;
            allocator& operator=(const allocator&&) = delete;

            /**
             * @brief Return a memory block of 256 bytes.
             *
             * @return The memory block of 256 bytes.
             */
            void* alloc();

            /**
             * @brief Free the allocated memory block.
             *
             * @param[in] address The block's address.
             *
             * @note This function <b>does not</b> check if the address was allocated by this class.
             */
            void free(void* address);

        private:

            struct block
            {
                block* next;
            };
            using blockptr_t = block*;

            struct region
            {
                blockptr_t next_block;
                size_t free_blocks;

                region* prev;
                region* next;
            };
            using regionptr_t = region*;

            /**
             * @brief Return the address of an allocated region.
             *
             * @return The allocated region.
             *
             * @note A region is allocated by calling <a href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc">VirtualAlloc</a>.
             */
            regionptr_t alloc_region();

            size_t m_region_size;
            regionptr_t m_regions;

            std::mutex m_mutex;
        };
    }
}
#endif
