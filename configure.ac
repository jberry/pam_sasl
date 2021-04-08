#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([pam_sasl],[0.1.2],[xworld21@users.sf.net],[],[http://pam-sasl.sourceforge.net/])
AM_INIT_AUTOMAKE([-Wall subdir-objects])

# checks for programs
AC_PROG_CC
AX_PROG_XSLTPROC

# checks for libraries
AC_CHECK_LIB([sasl2],
             [sasl_checkpass],,
             [AC_MSG_ERROR([sasl2 not found])])
AC_CHECK_LIB([pam],
             [pam_get_item],,
             [AC_MSG_ERROR([pam not found])])

# checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h],, [AC_MSG_ERROR([stdlib.h not found])])
AC_CHECK_HEADERS([string.h],, [AC_MSG_ERROR([string.h not found])])
AC_CHECK_HEADERS([syslog.h],, [AC_MSG_ERROR([syslog.h not found])])
AC_CHECK_HEADERS([unistd.h],, [AC_MSG_ERROR([unistd.h not found])])

AC_CHECK_HEADERS([sasl/sasl.h],, [AC_MSG_ERROR([sasl/sasl.h not found])])
AC_CHECK_HEADERS([security/pam_modules.h pam/pam_modules.h],
                 [pam_modules_found=yes; break;])
AS_IF([test "x$pam_modules_found" != "xyes"], [AC_MSG_ERROR([pam_modules.h not found])])
AC_CHECK_HEADERS([pam/pam_constants.h])

# checks for compiler characteristics
AC_C_CONST

# checks for library functions
AC_CHECK_FUNCS([memset strdup])

# libtool
AC_DISABLE_STATIC
AC_ENABLE_SHARED
LT_INIT

# AC_CONFIG
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([src/pam_sasl.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

# Configuration.
AC_ARG_ENABLE([securedir], [AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@])],
              [SECUREDIR=$enableval], [SECUREDIR=$libdir/security])

AC_SUBST([SECUREDIR])

AC_OUTPUT
