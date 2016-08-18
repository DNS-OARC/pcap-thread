AC_DEFUN([AX_PCAP_THREAD], [
AX_PTHREAD
AC_CHECK_FUNCS([pcap_create pcap_set_tstamp_precision pcap_set_immediate_mode])
AC_CHECK_FUNCS([pcap_set_tstamp_type pcap_setdirection sched_yield])
AC_CHECK_TYPES([pcap_direction_t], [], [], [[#include <pcap/pcap.h>]])
])
