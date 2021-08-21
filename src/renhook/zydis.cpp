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

const renhook::zydis::decoded_info renhook::zydis::decode(uintptr_t address, size_t length, size_t minimum_decoded_length, size_t& decoded_length) const
{
    decoded_info info;
    info.lowest_relative_address = -1;
    info.highest_relative_address = 0;

    decoded_length = 0;
    while (decoded_length < minimum_decoded_length)
    {
        decoded_info::instruction instruction;
        auto instruction_address = address + decoded_length;

        auto status = ZydisDecoderDecodeBuffer(&m_decoder, reinterpret_cast<void*>(instruction_address), length, &instruction);
        if (!ZYAN_SUCCESS(status))
        {
            break;
        }

        instruction.is_relative = instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE;

        // Calculate the absolute address if it is relative.
        if (instruction.is_relative)
        {
            get_absolute_address(instruction_address, instruction, instruction.disp);

            if (instruction.disp.absolute_address < info.lowest_relative_address)
            {
                info.lowest_relative_address = instruction.disp.absolute_address;
            }

            if (instruction.disp.absolute_address > info.highest_relative_address)
            {
                info.highest_relative_address = instruction.disp.absolute_address;
            }

            instruction.add_to_jump_table =
                (instruction.opcode & 0xF0) == 0x70
                || (instruction.opcode_map == ZYDIS_OPCODE_MAP_0F && (instruction.opcode & 0xF0) == 0x80)
                || instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
        }
        else
        {
            instruction.disp.absolute_address = 0;
            instruction.disp.offset = 0;
            instruction.disp.size = 0;
        }

        info.instructions.emplace_back(std::move(instruction));
        decoded_length += instruction.length;
    }

    return info;
}

void renhook::zydis::get_absolute_address(uintptr_t instr_address, const ZydisDecodedInstruction& decoded_instr, decoded_info::instruction::displacement& displacement) const
{
    if (decoded_instr.raw.imm[0].is_relative)
    {
        displacement.absolute_address = instr_address + decoded_instr.length + static_cast<int32_t>(decoded_instr.raw.imm[0].value.s);
        displacement.offset = decoded_instr.raw.imm[0].offset;
        displacement.size = decoded_instr.raw.imm[0].size;
    }
    else if ((decoded_instr.attributes & ZYDIS_ATTRIB_HAS_MODRM) && decoded_instr.raw.modrm.mod == 0 && decoded_instr.raw.modrm.rm == 5)
    {
        displacement.absolute_address = instr_address + decoded_instr.length + static_cast<int32_t>(decoded_instr.raw.disp.value);
        displacement.offset = decoded_instr.raw.disp.offset;
        displacement.size = decoded_instr.raw.disp.size;
    }
}
