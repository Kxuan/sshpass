#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([sshpass], [1.06])
AM_INIT_AUTOMAKE
AC_COPYRIGHT([Copyright (C) 2006,2008,2011,2016 Shachar Shemesh])
AC_CONFIG_SRCDIR([main.c])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/ioctl.h unistd.h termios.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([select posix_openpt strdup])

AC_ARG_ENABLE([password-prompt],
        [AS_HELP_STRING([--enable-password-prompt=prompt], [Provide alternative ssh password prompt to look for.])],
        [AC_DEFINE_UNQUOTED([PASSWORD_PROMPT], ["$enable_password_prompt"], [Password prompt to use])],
        [AC_DEFINE([PASSWORD_PROMPT], ["[[EMAIL]] password"])])

AC_ARG_ENABLE([otp-prompt],
        [AS_HELP_STRING([--enable-otp-prompt=otp], [Provide alternative ssh OTP prompt to look for.])],
        [AC_DEFINE_UNQUOTED([OTP_PROMPT], ["$enable_otp_prompt"], [OTP prompt to use])],
        [AC_DEFINE([OTP_PROMPT], ["token"])])

AC_CONFIG_FILES([Makefile])
AM_CONFIG_HEADER(config.h)
AC_OUTPUT
