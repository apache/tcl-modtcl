dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(mod_tcl)

APACHE_MODULE(tcl, embedded tcl interpreter, tcl_core.lo tcl_cmds.lo tcl_misc.lo, , yes)

if test "$enable_tcl" != "no"; then
	AC_CHECK_HEADERS(tcl.h inttypes.h int_types.h sys/mman.h)
	AC_CHECK_FUNCS(asprintf mmap)

	dirs="/usr/local/lib /usr/lib"

	found=0

	for directory in $dirs ; do
	    AC_MSG_CHECKING(for tclConfig.sh in $directory)

	    if test -f "$directory/tclConfig.sh" ; then
	        tnm_cv_path_tcl_config=$directory
	        found=1

	        AC_MSG_RESULT(yes)

	        break
	    else
	        AC_MSG_RESULT(no)
	    fi
	done

	if test "$found" -eq 0 ; then
	    AC_MSG_ERROR([tclConfig.sh not found])
	fi

	. $tnm_cv_path_tcl_config/tclConfig.sh

	AC_MSG_CHECKING(for tcl version)
	AC_MSG_RESULT("$TCL_VERSION")

	if test 8 -gt $TCL_MAJOR_VERSION; then
	    AC_MSG_ERROR("tcl 8.0 or later needed")
	fi

	LIBS="$LIBS -L$tnm_cv_path_tcl_config -ltcl$TCL_VERSION"
	INCLUDES="$INCLUDES -I$TCL_PREFIX/include"
	LDFLAGS="$LDFLAGS $TCL_LD_FLAGS"
fi

APACHE_MODPATH_FINISH
