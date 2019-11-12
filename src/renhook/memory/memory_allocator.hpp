#ifndef RENHOOK_MEMORY_ALLOCATOR_H
#define RENHOOK_MEMORY_ALLOCATOR_H

#include <cstdint>
#include <mutex>

namespace renhook
{
    namespace memory
    {
        /**
         * @brief A memory allocator class.
         */
        class memory_allocator
        {
        public:

            /**
             * @brief The size of a block.
             */
            static constexpr size_t block_size = 256;

            memory_allocator() noexcept;
            ~memory_allocator() noexcept;

            memory_allocator(memory_allocator&) = delete;
            memory_allocator(memory_allocator&&) = delete;

            memory_allocator& operator=(const memory_allocator&) = delete;
            memory_allocator& operator=(memory_allocator&&) = delete;

            /**
             * @brief Return a memory block between #lower_bound and #upper_bound.
             *
             * @param lower_bound[in] The lower bound of the memory.
             * @param upper_bound[in] The lower bound of the memory.
             *
             * @return The memory block of \ref block_size bytes.
             */
            void* alloc(uintptr_t lower_bound, uintptr_t upper_bound);

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
             * @brief Allocate a region between #lower_bound and #upper_bound.
             *
             * @param lower_bound[in] The lower bound of the memory.
             * @param upper_bound[in] The lower bound of the memory.
             *
             * @return The allocated region.
             */
            regionptr_t alloc_region(uintptr_t lower_bound, uintptr_t upper_bound);

            /**
             * @brief Try to allocate a region at a specific address.
             *
             * @param address[in] The address where to allocation.

             * @return The allocated region.
             *
             * @note A region is allocated by calling <a href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc">VirtualAlloc</a>.
             */
            regionptr_t try_alloc_region_at_address(uintptr_t address);

            /**
             * @brief Check if a region is in rage of #lower_bound and #upper_bound.
             *
             * @param address       The region address.
             * @param lower_bound[in] The lower bound of the memory.
             * @param upper_bound[in] The lower bound of the memory.
             *
             * @return true if it is.
             * @return false if it is not.
             */
            bool is_region_in_range(uintptr_t address, uintptr_t lower_bound, uintptr_t upper_bound);

            /**
             * @brief The size of a memory.
             *
             */
            size_t m_region_size;

            /**
             * @brief The lowest address accessible to applications.
             *
             */
            uintptr_t m_minimum_address;

            /**
             * @brief The highest address accessible to applications.
             *
             */
            uintptr_t m_maximum_address;

            regionptr_t m_regions;
            std::mutex m_mutex;
        };

        extern memory_allocator global_allocator;
    }
}
#endif
