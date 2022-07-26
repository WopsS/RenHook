#pragma once

#ifdef _MSVC_LANG
#define RENHOOK_CPLUSPLUS _MSVC_LANG
#else
#define RENHOOK_CPLUSPLUS __cplusplus
#endif

#ifndef RENHOOK_HAS_CPP17_ATTRIBUTE
#define RENHOOK_HAS_CPP17_ATTRIBUTE(attribute) (RENHOOK_CPLUSPLUS >= 201703L && __has_cpp_attribute(attribute))
#endif

#ifndef RENHOOK_NODISCARD
#if RENHOOK_HAS_CPP17_ATTRIBUTE(nodiscard)
#define RENHOOK_NODISCARD [[nodiscard]]
#else
#define RENHOOK_NODISCARD
#endif
#endif
