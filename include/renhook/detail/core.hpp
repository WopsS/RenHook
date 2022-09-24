#pragma once

#if defined(_MSVC_LANG) && _MSVC_LANG > __cplusplus
#define RENHOOK_CPLUSPLUS _MSVC_LANG
#else
#define RENHOOK_CPLUSPLUS __cplusplus
#endif

#ifdef __has_cpp_attribute
#define RENHOOK_HAS_CPP_ATTRIBUTE(attribute) __has_cpp_attribute(attribute)
#else
#define RENHOOK_HAS_CPP_ATTRIBUTE(attribute) 0
#endif

#define RENHOOK_HAS_CPP17 (RENHOOK_CPLUSPLUS >= 201703L)
#define RENHOOK_HAS_CPP17_ATTRIBUTE(attribute) (RENHOOK_HAS_CPP17 && RENHOOK_HAS_CPP_ATTRIBUTE(attribute))

#if RENHOOK_HAS_CPP17_ATTRIBUTE(nodiscard)
#define RENHOOK_NODISCARD [[nodiscard]]
#else
#define RENHOOK_NODISCARD
#endif
