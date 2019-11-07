#include <renhook/memory/allocator.hpp>

#include <Windows.h>

#include <renhook/exception.hpp>
#include <renhook/memory/utils.hpp>

namespace
{
    constexpr size_t block_size = 256;
}

renhook::memory::allocator::allocator() noexcept
    : m_regions(nullptr)
{
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);

    m_region_size = system_info.dwAllocationGranularity;
}

renhook::memory::allocator::~allocator() noexcept
{
    while (m_regions)
    {
        auto current_region = m_regions;
        m_regions = current_region->next;

        VirtualFree(current_region, 0, MEM_RELEASE);
    }
}

void* renhook::memory::allocator::alloc()
{
    std::lock_guard<std::mutex> _(m_mutex);

    auto region = m_regions;
    if (!region)
    {
        region = alloc_region();
    }

    // If the region doesn't have a free block, check all regions.
    if (region->free_blocks == 0)
    {
        region = region->next;
        while (region)
        {
            // Stop if we find a region with a free block.
            if (region->free_blocks > 0)
            {
                break;
            }

            region = region->next;
        }

        // No region found? Then allocate a new one.
        if (!region)
        {
            region = alloc_region();
        }
    }

    auto block = region->next_block;
    region->next_block = block->next;

    region->free_blocks--;
    return block;
}

void renhook::memory::allocator::free(void* address)
{
    std::lock_guard<std::mutex> _(m_mutex);

    auto region = reinterpret_cast<regionptr_t>(utils::align_down(reinterpret_cast<uintptr_t>(address), m_region_size));
    auto block = static_cast<blockptr_t>(address);

    block->next = region->next_block;
    region->next_block = block;

    region->free_blocks++;

    // Free the region if we reached the maximum number of blocks.
    auto maximum_blocks = m_region_size / block_size - 1;
    if (region->free_blocks == maximum_blocks)
    {
        auto prev = region->prev;
        auto next = region->next;

        if (prev)
        {
            prev->next = next;
        }

        if (next)
        {
            next->prev = prev;
        }

        if (m_regions == region)
        {
            m_regions = nullptr;
        }

        VirtualFree(region, 0, MEM_RELEASE);
    }
}

renhook::memory::allocator::regionptr_t renhook::memory::allocator::alloc_region()
{
    auto region = static_cast<regionptr_t>(VirtualAlloc(nullptr, m_region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!region)
    {
        throw renhook::exception("region allocation failed", GetLastError());
    }

#ifdef _DEBUG
    // In debug fill it with 0xCC, it makes it easier to debug.
    std::memset(region, 0xCC, m_region_size);
#endif

    region->next_block = nullptr;
    region->free_blocks = m_region_size / block_size - 1;

    for (size_t i = region->free_blocks; i > 0; i--)
    {
        auto block_address = reinterpret_cast<char*>(region) + block_size * i;
        auto block = reinterpret_cast<blockptr_t>(block_address);

        block->next = region->next_block;
        region->next_block = block;
    }

    if (m_regions)
    {
        m_regions->prev = region;
    }

    region->prev = nullptr;
    region->next = m_regions;
    m_regions = region;

    return region;
}
