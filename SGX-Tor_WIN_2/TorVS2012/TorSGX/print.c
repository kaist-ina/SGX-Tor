#include <stdio.h>
#include <string.h>
#include "TorSGX_t.h"
#include "print.h"

void printf(const char *fmt, ...)
{
	char buf[8192] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, 8192, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void puts(const char *s)
{
	ocall_print_string(s);
	ocall_print_string("\n");
}

void log_err(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_ERR: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_notice(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_NOTICE: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_info(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_INFO: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_warn(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_WARN: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}