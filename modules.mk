libapachemod_tcl.la: tcl_core.lo tcl_cmds.lo tcl_misc.lo
	$(LINK) tcl_core.lo tcl_cmds.lo tcl_misc.lo
static =  libapachemod_tcl.la
shared = 
