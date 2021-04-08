/*
 * pam_sasl.c
 *
 * Copyright (C) 2007-2011 by Vincenzo Mantova <xworld21@users.sf.net>
 *
 * This file is part of pam_sasl.
 *
 * pam_sasl is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * pam_sasl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pam_sasl.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_MODULES_H
# include <security/pam_modules.h>
#else
# ifdef HAVE_PAM_PAM_MODULES_H
#  include <pam/pam_modules.h>
# endif
# ifdef HAVE_PAM_PAM_CONSTANTS_H
#  include <pam/constants.h>
# endif
#endif

#ifdef HAVE_SASL_SASL_H
# include <sasl/sasl.h>
#endif


static void _log_err(int err, pam_handle_t * pamh, const char *format, ...)
{
  void *service = NULL;
  char logname[256];
  va_list args;

  pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
  if (service != NULL) {
    strncpy(logname, service, sizeof(logname) - 1);
    strncat(logname, "(" PACKAGE ")", sizeof(logname) - sizeof("(" PACKAGE ")"));
  } else
    strncpy(logname, "(" PACKAGE ")", sizeof(logname) - 1);

  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTH);

  va_start(args, format);
  vsyslog(err, format, args);
  va_end(args);

  closelog();
}


static int _bad_user(pam_handle_t * pamh, const char *name, int debug)
{
  _log_err(LOG_ERR, pamh, "bad username");

  return PAM_USER_UNKNOWN;
}


static int _get_pass(pam_handle_t * pamh, char **password)
{
  static struct pam_message message =
    { PAM_PROMPT_ECHO_OFF, "Password: " };
  const struct pam_message *messages[] = { &message };
  struct pam_response *responses = NULL;
  const void *conv = NULL;
  int retval;

  /* If we didn't get a password, and we're allowed to ask
   * the user for one, try it. */
  if (pam_get_item(pamh, PAM_CONV, &conv) != PAM_SUCCESS) {
    _log_err(LOG_CRIT, pamh, "error determining conversation function");
    return PAM_SYSTEM_ERR;
  }
  retval =
    ((const struct pam_conv *) conv)->conv(1, messages, &responses,
					   ((const struct pam_conv *)
					    conv)->appdata_ptr);
  if (retval == PAM_SUCCESS) {
    if (responses == NULL || responses[0].resp_retcode != PAM_SUCCESS) /* No response. */
      retval = PAM_CONV_ERR;
    else if (responses[0].resp != NULL) {       /* Got a response. */
      *password = strdup(responses[0].resp);
      pam_set_item(pamh, PAM_AUTHTOK, *password);
    }
  }

  if (responses != NULL) {
    if (responses[0].resp != NULL) {
      memset(responses[0].resp, 0, strlen(responses[0].resp));
      free(responses[0].resp);
    }
    memset(responses, 0, sizeof(responses));
    free(responses);
  }
  return retval;
}


static int _check_pass(pam_handle_t * pamh, const char *name, const char *password, const char *service, const char *realm, int debug)
{
  struct sasl_conn *conn;
  struct sasl_callback cb = { SASL_CB_LIST_END, NULL, NULL };
  int retval;

  /* Initialize libsasl. */
  retval = sasl_server_init(&cb, service);
  if (retval != SASL_OK) {
    _log_err(LOG_ERR, pamh, "error initializing server: %s",
             sasl_errstring(retval, NULL, NULL));
    return PAM_AUTHINFO_UNAVAIL;
  }
  _log_err(LOG_ERR, pamh, "service: %s", service);

  /* Allocate a new server structure. */
  retval =
    sasl_server_new(service, NULL, realm, NULL, NULL, &cb,
		    SASL_SEC_NOANONYMOUS, &conn);
  if (retval != SASL_OK) {
    _log_err(LOG_ERR, pamh,
             "error allocating server context: %s",
             sasl_errstring(retval, NULL, NULL));
    sasl_done();
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Check the user's password. */
  _log_err(LOG_ERR, pamh, "username: %s", name);
  retval =
    sasl_checkpass(conn, name, strlen(name), password, strlen(password));
  if (retval == SASL_NOUSER) {
    retval = _bad_user(pamh, name, debug);
  } else if (retval != SASL_OK) {
    _log_err(LOG_WARNING, pamh, "error checking password: %s",
             sasl_errstring(retval, NULL, NULL));
    retval = PAM_AUTH_ERR;
  } else
    retval = PAM_SUCCESS;

  /* Good to go. */
  sasl_dispose(&conn);
  sasl_done();
  return retval;
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh,
                    int flags, int argc, const char **argv)
{
  const char *name = NULL, *realm = NULL, *service = NULL;
  char *password = NULL;
  const void *tmp; /* needed for PAM operation: we should never modify the result of pam_get_item */
  const struct passwd *pwbuf;
  char servicename[256];
  int i, retval, secondpass = 1, debug = 0;


  for (i = 0; i < argc; i++)
    if (!strcmp(argv[i], "use_first_pass"))
      secondpass = 0;
    else if (!strcmp(argv[i], "use_authtok"))
      secondpass = 0;
    else if (!strcmp(argv[i], "try_first_pass"))
      secondpass = 1;
    else if (!strncmp(argv[i], "service=", 8))
      service = argv[i] + 8;
    else if (!strncmp(argv[i], "realm=", 6))
      realm = argv[i] + 6;
    else if (!strcmp(argv[i], "debug"))
      debug = 1;
    else
      _log_err(LOG_WARNING, pamh, "unknown argument: %s", argv[i]);

  retval = pam_get_user(pamh, &name, NULL);
  if (retval == PAM_CONV_AGAIN)
    return PAM_INCOMPLETE;
  else if (retval != PAM_SUCCESS)
    return retval;
  else if (!name || name[0] == '-' || name[0] == '+') {
    return _bad_user(pamh, name, debug);
  }
  tmp = NULL;
  retval = pam_get_item(pamh, PAM_AUTHTOK, &tmp);
  if (tmp != NULL)
    password = strdup(tmp);

  if ((retval != PAM_SUCCESS || password == NULL) && secondpass)
    retval = _get_pass(pamh, &password);
  if (retval != PAM_SUCCESS)
    return retval;
  if (password == NULL) {
    _log_err(LOG_WARNING, pamh, "NULL password");
    return PAM_CONV_ERR;
  }

  /* If there was no overriding service given, use the 'sasl-service' service. */
  if (service == NULL) {
    tmp = NULL;
    if(pam_get_item(pamh, PAM_SERVICE, &tmp) != PAM_SUCCESS) {
      _log_err(LOG_CRIT, pamh, "error determining service");
      return PAM_SYSTEM_ERR;
    }
    if (tmp == NULL) {
      service = "sasl";
    } else {
      strncpy(servicename, "sasl-", sizeof(servicename) - 1);
      strncat(servicename, tmp, sizeof(servicename) - sizeof("sasl-"));
      service = servicename;
    }
  }

  retval = _check_pass(pamh, name, password, service, realm, debug);
  memset(password, 0, strlen(password));
  free(password);
  return retval;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
