#include <renhook/memory/memory_allocator.hpp>

#include <Windows.h>

#include <renhook/exception.hpp>
#include <renhook/memory/utils.hpp>
#include <renhook/memory/virtual_protect.hpp>

namespace renhook
{
    namespace memory
    {
        renhook::memory::memory_allocator global_allocator;
    }
}

renhook::memory::memory_allocator::memory_allocator() noexcept
    : m_regions(nullptr)
{
    SYSTEM_INFO system_info = { 0 };
    GetSystemInfo(&system_info);

    m_region_size = system_info.dwAllocationGranularity;
    m_minimum_address = reinterpret_cast<uintptr_t>(system_info.lpMinimumApplicationAddress);
    m_maximum_address = reinterpret_cast<uintptr_t>(system_info.lpMaximumApplicationAddress);
}

renhook::memory::memory_allocator::~memory_allocator() noexcept
{
    while (m_regions)
    {
        auto current_region = m_regions;
        m_regions = current_region->next;

        VirtualFree(current_region, 0, MEM_RELEASE);
    }
}

void* renhook::memory::memory_allocator::alloc(uintptr_t lower_bound, uintptr_t upper_bound)
{
    if (lower_bound < m_minimum_address)
    {
        lower_bound = m_minimum_address;
    }

    if (upper_bound > m_maximum_address)
    {
        upper_bound = m_maximum_address;
    }

    std::lock_guard<std::mutex> _(m_mutex);

    auto region = m_regions;
    if (!region)
    {
        region = alloc_region(lower_bound, upper_bound);
    }

    auto region_address = reinterpret_cast<uintptr_t>(region);

    // If the region doesn't have a free block, check all regions.
    if (region->free_blocks == 0 || !is_region_in_range(region_address, lower_bound, upper_bound))
    {
        region = region->next;
        while (region)
        {
            // Stop if we find a region with a free block.
            if (region->free_blocks > 0)
            {
                region_address = reinterpret_cast<uintptr_t>(region);
                if (is_region_in_range(region_address, lower_bound, upper_bound))
                {
                    break;
                }
            }

            region = region->next;
        }

        // No region found? Then allocate a new one.
        if (!region)
        {
            region = alloc_region(lower_bound, upper_bound);
        }
    }

    virtual_protect protection(region, m_region_size, protection::read | protection::write);

    auto block = region->next_block;
    region->next_block = block->next;

    region->free_blocks--;
    return block;
}

void renhook::memory::memory_allocator::free(void* address)
{
    std::lock_guard<std::mutex> _(m_mutex);

    auto region = reinterpret_cast<regionptr_t>(utils::align_down(reinterpret_cast<uintptr_t>(address), m_region_size));
    auto block = static_cast<blockptr_t>(address);

    virtual_protect protection(region, m_region_size, protection::read | protection::write);

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
            virtual_protect protection(prev, m_region_size, protection::write);
            prev->next = next;
        }

        if (next)
        {
            virtual_protect protection(next, m_region_size, protection::write);
            next->prev = prev;
        }

        if (m_regions == region)
        {
            m_regions = nullptr;
        }

        VirtualFree(region, 0, MEM_RELEASE);
    }
}

renhook::memory::memory_allocator::regionptr_t renhook::memory::memory_allocator::alloc_region(uintptr_t lower_bound, uintptr_t upper_bound)
{
    auto middle = (lower_bound + upper_bound) / 2;
    auto alloc_address_lower = utils::align_down(middle, m_region_size);
    auto alloc_address_higher = utils::align_up(middle, m_region_size);

    regionptr_t region = nullptr;

    bool is_lower_in_range = false;
    bool is_upper_in_range = false;

    do
    {
        is_lower_in_range = is_region_in_range(alloc_address_lower, lower_bound, upper_bound);
        if (is_lower_in_range)
        {
            region = try_alloc_region_at_address(alloc_address_lower);
            if (region)
            {
                break;
            }

            alloc_address_lower -= m_region_size;
        }

        is_upper_in_range = is_region_in_range(alloc_address_higher, lower_bound, upper_bound);
        if (is_upper_in_range)
        {
            region = try_alloc_region_at_address(alloc_address_higher);
            if (region)
            {
                break;
            }

            alloc_address_higher += m_region_size;
        }
    } while (is_lower_in_range || is_upper_in_range);

    if (!region)
    {
        throw renhook::exception("no free region found", GetLastError());
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
        virtual_protect protection(m_regions, m_region_size, protection::write);
        m_regions->prev = region;
    }

    region->prev = nullptr;
    region->next = m_regions;
    m_regions = region;

    virtual_protect protection(region, m_region_size, protection::read | protection::execute, true);
    return region;
}

renhook::memory::memory_allocator::regionptr_t renhook::memory::memory_allocator::try_alloc_region_at_address(uintptr_t address)
{
    MEMORY_BASIC_INFORMATION memory_info = { 0 };
    if (!VirtualQuery(reinterpret_cast<void*>(address), &memory_info, sizeof(memory_info)))
    {
        throw renhook::exception("cannot retrieves region information", GetLastError());
    }

    if (memory_info.State == MEM_FREE && memory_info.RegionSize >= m_region_size)
    {
        auto result = static_cast<regionptr_t>(VirtualAlloc(memory_info.BaseAddress, m_region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (result)
        {
            return result;
        }
    }

    return nullptr;
}

bool renhook::memory::memory_allocator::is_region_in_range(uintptr_t address, uintptr_t lower_bound, uintptr_t upper_bound)
{
    return address >= lower_bound && address < upper_bound;
}
