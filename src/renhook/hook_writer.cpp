#include <renhook/hook_writer.hpp>

#include <cstring>
#include <renhook/utils.hpp>

renhook::hook_writer::hook_writer(uint8_t* address)
    : m_address(address)
{
}

renhook::hook_writer::hook_writer(uintptr_t address)
    : hook_writer(reinterpret_cast<uint8_t*>(address))
{
}

void renhook::hook_writer::copy_from(uint8_t* address, size_t length)
{
    std::memcpy(m_address, address, length);
    m_address += length;
}

void renhook::hook_writer::copy_from(uintptr_t address, size_t length)
{
    copy_from(reinterpret_cast<uint8_t*>(address), length);
}

void renhook::hook_writer::write_jump(uintptr_t target_address)
{
    uint8_t bytes[] =
    {
#ifdef _WIN64
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address where to jump.
#else
        0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp [rip+0x??]
#endif
    };

#ifdef _WIN64
    *(reinterpret_cast<uintptr_t*>(&bytes[6])) = target_address;
#else
    *(reinterpret_cast<intptr_t*>(&bytes[1])) = utils::calculate_displacement(reinterpret_cast<uintptr_t>(m_address), target_address, sizeof(bytes));
#endif

    copy_from(bytes, sizeof(bytes));
}

void renhook::hook_writer::write_nops(size_t size)
{
    std::memset(m_address, 0x90, size);
    m_address += size;
}
