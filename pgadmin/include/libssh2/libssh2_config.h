/* pgadmin/include/libssh2/libssh2_config.h.  Generated from libssh2_config.h.in by configure.  */
/* src/libssh2_config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Define to 1 if you have `alloca', as a function or macro. */
/* #undef HAVE_ALLOCA */

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
/* #undef HAVE_ALLOCA_H */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* disabled non-blocking sockets */
/* #undef HAVE_DISABLED_NONBLOCKING */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `EVP_aes_128_ctr' function. */
#define HAVE_EVP_AES_128_CTR 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* use FIONBIO for non-blocking sockets */
/* #undef HAVE_FIONBIO */

/* Define to 1 if you have the `gettimeofday' function. */
/* #undef HAVE_GETTIMEOFDAY */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* use ioctlsocket() for non-blocking sockets */
/* #undef HAVE_IOCTLSOCKET */

/* use Ioctlsocket() for non-blocking sockets */
/* #undef HAVE_IOCTLSOCKET_CASE */

/* Define if you have the gcrypt library. */
/* #undef HAVE_LIBGCRYPT */

/* Define if you have the ssl library. */
#define HAVE_LIBSSL 1

/* Define if you have the z library. */
#define HAVE_LIBZ 1

/* Define to 1 if the compiler supports the 'long long' data type. */
/* #undef HAVE_LONGLONG */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* use O_NONBLOCK for non-blocking sockets */
#define HAVE_O_NONBLOCK 1

/* Define to 1 if you have the `poll' function. */
/* #undef HAVE_POLL */

/* Define to 1 if you have the select function. */
/* #undef HAVE_SELECT */

/* use SO_NONBLOCK for non-blocking sockets */
/* #undef HAVE_SO_NONBLOCK */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strtoll' function. */
/* #undef HAVE_STRTOLL */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* to make a symbol visible */
/* #undef LIBSSH2_API */

/* Enable "none" cipher -- NOT RECOMMENDED */
/* #undef LIBSSH2_CRYPT_NONE */

/* Enable newer diffie-hellman-group-exchange-sha1 syntax */
/* #undef LIBSSH2_DH_GEX_NEW */

/* Compile in zlib support */
#define LIBSSH2_HAVE_ZLIB 1

/* Use libgcrypt */
/* #undef LIBSSH2_LIBGCRYPT */

/* Enable "none" MAC -- NOT RECOMMENDED */
/* #undef LIBSSH2_MAC_NONE */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
/* #undef LT_OBJDIR */

/* Define to 1 if _REENTRANT preprocessor symbol must be defined. */
/* #undef NEED_REENTRANT */

/* Name of package */
#define PACKAGE "pgadmin3"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "pgadmin-support@postgresql.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "pgadmin3"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "pgadmin3 1.22.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "pgadmin3"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.22.2"

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "1.22.2"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif
