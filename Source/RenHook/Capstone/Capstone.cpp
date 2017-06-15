#include <RenHook/RenHook.hpp>
#include <RenHook/Capstone/Capstone.hpp>

RenHook::Capstone::Capstone()
    : m_handle(0)
    , m_instructionInfo(nullptr)
    , m_instructions(0)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) != CS_ERR_OK)
    {
        LOG_ERROR << "Fail to initialize Capstone handle";
    }
}

RenHook::Capstone::~Capstone()
{
    if (m_handle != 0)
    {
        ReleaseInstructions();
        cs_close(&m_handle);
    }
}

const size_t RenHook::Capstone::Disassemble(const uintptr_t Address, const size_t Size)
{
    size_t Result = 0;

    if (m_handle != 0)
    {
        ReleaseInstructions();

        Result = cs_disasm(m_handle, reinterpret_cast<uint8_t*>(Address), Size, Address, 0, &m_instructionInfo);
        m_instructions = Result;
    }

    return Result;
}

const size_t RenHook::Capstone::GetInstructionSize(size_t Index) const
{
    return m_instructionInfo[Index].size;
}

const size_t RenHook::Capstone::GetTotalNumberOfInstruction() const
{
    return m_instructions;
}

void RenHook::Capstone::ReleaseInstructions()
{
    if (m_instructionInfo != nullptr)
    {
        cs_free(m_instructionInfo, m_instructions);
    }
}
