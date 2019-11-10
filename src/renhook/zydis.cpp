#include <renhook/zydis.hpp>

#include <renhook/exception.hpp>

ZydisDecoder renhook::zydis::m_decoder;
bool renhook::zydis::m_initialized = false;

renhook::zydis::zydis()
{
    if (!m_initialized)
    {
        m_initialized = true;

#ifdef _WIN64
        auto status = ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
        auto status = ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif

        if (!ZYAN_SUCCESS(status))
        {
            throw renhook::exception("decoder initialization failed");
        }
    }
}

std::vector<renhook::zydis::instruction> renhook::zydis::decode(uintptr_t address, size_t length, size_t minimum_decoded_length, size_t& decoded_length)
{
    std::vector<zydis::instruction> instructions;

    decoded_length = 0;
    while (decoded_length < minimum_decoded_length)
    {
        zydis::instruction instr;
        auto instr_address = address + decoded_length;

        auto status = ZydisDecoderDecodeBuffer(&m_decoder, reinterpret_cast<void*>(instr_address), length, &instr.decoded);
        if (!ZYAN_SUCCESS(status))
        {
            break;
        }

        instr.is_relative = instr.decoded.attributes & ZYDIS_ATTRIB_IS_RELATIVE;

        for (size_t i = 0; i < instr.decoded.operand_count; i++)
        {
            auto op = instr.decoded.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
            {
                ZydisCalcAbsoluteAddress(&instr.decoded, &op, instr_address, reinterpret_cast<uint64_t*>(&instr.disp.absolute_address));
                instr.disp.offset = instr.decoded.raw.imm[0].offset;
                instr.disp.size = instr.decoded.raw.imm[0].size;

                break;
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.disp.has_displacement && op.mem.index == ZYDIS_REGISTER_NONE &&
                    (op.mem.base == ZYDIS_REGISTER_NONE || op.mem.base == ZYDIS_REGISTER_EIP || op.mem.base == ZYDIS_REGISTER_RIP))
            {
                ZydisCalcAbsoluteAddress(&instr.decoded, &op, instr_address, reinterpret_cast<uint64_t*>(&instr.disp.absolute_address));
                instr.disp.offset = instr.decoded.raw.disp.offset;
                instr.disp.size = instr.decoded.raw.disp.size;

                break;
            }
        }

        instructions.emplace_back(std::move(instr));
        decoded_length += instr.decoded.length;
    }

    return instructions;
}
