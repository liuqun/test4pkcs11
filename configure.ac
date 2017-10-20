# encoding:utf8
AC_INIT([pkcs11-sample-application],[1.0],[liuqun68@gmail.com],[],[https://github.com/liuqun/])

AC_PROG_CC

AC_CHECK_HEADERS

AC_ARG_WITH([p11-kit],
	AS_HELP_STRING([--with-p11-kit],
		[Build with C header files provide by the p11-kit project. Project homepage: http://p11-glue.freedesktop.org/p11-kit.html]
	)
)
AC_ARG_WITH([opencryptoki],
	AS_HELP_STRING([--with-opencryptoki],
		[Build with C header files provide by IBM's openCryptoki project. Project homepage: https://github.com/opencryptoki]
	)
)
if test "x$with_p11_kit" = "xno" && test "x$with_opencryptoki" = "xno"; then
	AC_MSG_ERROR([Configured to build without both p11-kit and openCryptoki!])
fi

# Search for p11-kit:
if test "x$with_p11_kit" != "xno"; then
	PKG_PROG_PKG_CONFIG
	PKG_CHECK_MODULES([P11_KIT], [p11-kit-1],
		[AC_DEFINE([HAVE_P11_KIT], [1], [Define to 1 if you have the p11-kit])],
		[p11_kit_found="no"]
	)
fi

# Search for openCryptoki:
if test "x$with_opencryptoki" != "xno"; then
	AC_CHECK_HEADERS([opencryptoki/pkcs11.h])
fi

# At least one of opencryptoki and p11_kit must be available to us:
if test "x$ac_cv_header_opencryptoki_pkcs11_h" != "xyes" && test "x$p11_kit_found" = "xno"; then :
	AC_MSG_ERROR([Can not build without both p11-kit and openCryptoki!])
fi

# Write config results:
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([src/config.mk])
AC_OUTPUT
