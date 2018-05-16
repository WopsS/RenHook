#include <RenHook/RenHook.hpp>
#include <RenHook/Capstone/Capstone.hpp>

RenHook::Capstone::Capstone()
    : m_handle(0)
    , m_instructionInfo(nullptr)
    , m_instructions(0)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) == CS_ERR_OK)
    {
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    else
    {
        throw std::runtime_error("Fail to initialize Capstone's handle");
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

const size_t RenHook::Capstone::Disassemble(const uintptr_t aAddress, const size_t aSize)
{
    size_t result = 0;

    if (m_handle != 0)
    {
        ReleaseInstructions();

        result = cs_disasm(m_handle, reinterpret_cast<uint8_t*>(aAddress), aSize, aAddress, 0, &m_instructionInfo);
        m_instructions = result;
    }

    return result;
}

cs_insn* RenHook::Capstone::GetInstructionAt(size_t aIndex) const
{
    if (aIndex < 0 || aIndex >= m_instructions)
    {
        return nullptr;
    }

    return &m_instructionInfo[aIndex];
}

const size_t RenHook::Capstone::GetInstructionSize(size_t aIndex) const
{
    if (aIndex < 0 || aIndex >= m_instructions)
    {
        return 0;
    }

    return m_instructionInfo[aIndex].size;
}

const size_t RenHook::Capstone::GetTotalNumberOfInstructions() const
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
