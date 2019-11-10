#ifndef RENHOOK_MEMORY_VIRTUAL_PROTECT_H
#define RENHOOK_MEMORY_VIRTUAL_PROTECT_H

#include <cstdint>
#include <renhook/memory/protection_enum.hpp>

namespace renhook
{
    namespace memory
    {
        /**
         * @brief Change protection of the address in a RAII fashion.
         */
        class virtual_protect
        {
        public:

            /**
             * @brief Change protection of the address.
             *
             * @param address[in]           A pointer to the start of the region.
             * @param size[in]              The size of the region.
             * @param new_protection[in]    The new protection.
             * @param permanent[in]         If true the protection is applied permanently.
             *                              If false the protection will be reverted to the original one when object is destroyed.
             */
            virtual_protect(void* address, size_t size, protection new_protection, bool permanent = false);
            virtual_protect(uintptr_t address, size_t size, protection new_protection, bool permanent = false);

            ~virtual_protect() noexcept;

            virtual_protect(virtual_protect&) = delete;
            virtual_protect(virtual_protect&&) = delete;

            virtual_protect& operator=(const virtual_protect&) = delete;
            virtual_protect& operator=(virtual_protect&&) = delete;

        private:

            void* m_address;
            size_t m_size;
            uint32_t m_old_protection;

            bool m_is_permanent;
        };
    }
}
#endif
