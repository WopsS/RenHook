#pragma once

namespace RenHook
{
    class Capstone
    {
    public:

        Capstone();
        Capstone(const Capstone&) = delete;
        Capstone(Capstone&&) = delete;

        ~Capstone();

        Capstone& operator=(const Capstone&) = delete;

        Capstone& operator=(Capstone&&) = delete;

        size_t Disassemble(uintptr_t aAddress, size_t aSize);

        const cs_insn* GetInstructionAt(size_t aIndex) const;

        size_t GetInstructionSize(size_t aIndex) const;

        size_t GetTotalNumberOfInstructions() const;

    private:

        void ReleaseInstructions();

        csh m_handle;

        cs_insn* m_instructionInfo;

        size_t m_instructions;
    };
}