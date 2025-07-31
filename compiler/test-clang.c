/*
  The code is modified from AFL's LLVM mode.
  I did some minor modification on it, including:
  - add taint tracking arguments.
  - use my llvm passs.
  - use my taint related *.so.

   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *base_path = NULL;  /* Base path to project directory */
static char **cc_params = NULL; /* Parameters passed to the real CC */
static int cc_par_cnt = 0;      /* Parameter count */
static bool is_linking = true;  /* Whether we're linking (true by default) */

/* Allocate and format a string */
char *alloc_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap) + 1;
    va_end(ap);

    char *buf = malloc(len);
    if (!buf)
    {
        perror("malloc");
        exit(1);
    }

    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);

    return buf;
}

/* Find the base path of the project */
static void find_base_path(char *argv0)
{
    char path_buf[PATH_MAX];
    if (!realpath(argv0, path_buf))
    {
        perror("realpath");
        exit(1);
    }

    // Get directory of wrapper
    char *wrapper_dir = dirname(path_buf);

    // Set base_path to parent directory (project root)
    base_path = strdup(dirname(wrapper_dir));
    if (!base_path)
    {
        perror("strdup");
        exit(1);
    }
}

/* Check if we're compiling or linking */
static void detect_compile_mode(int argc, char **argv)
{
    is_linking = true;

    // Check for compile-only flags
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "-E") == 0)
        {
            is_linking = false;
            return;
        }
    }

    // Check if we have input files
    bool has_input = false;
    for (int i = 1; i < argc; i++)
    {
        if (argv[i][0] != '-')
        {
            has_input = true;
            break;
        }
    }

    // If no input files and no output, it's probably just a test
    if (!has_input)
    {
        is_linking = false;
    }
}

/* Edit parameters to add our instrumentation */
static void edit_params(int argc, char **argv)
{
    // Allocate space for parameters (original + our additions)
    cc_params = malloc((argc + 50) * sizeof(char *));
    if (!cc_params)
    {
        perror("malloc");
        exit(1);
    }

    // Use real clang as the compiler
    char *real_cc = getenv("TAINT_REAL_CC");
    if (!real_cc)
    {
        real_cc = "clang";
    }
    cc_params[cc_par_cnt++] = real_cc;

    // Add instrumentation flags from Makefile
    cc_params[cc_par_cnt++] = "-fsanitize=dataflow";

    // Add rule list (adjust path as needed)
    char *rule_list = malloc(strlen(base_path) + 100);
    sprintf(rule_list, "%s/rule/testabi.txt", base_path); // Default rule list
    cc_params[cc_par_cnt++] = "-mllvm";
    cc_params[cc_par_cnt++] = alloc_printf("-dfsan-abilist=%s", rule_list);

    // Add LLVM Pass
    char *pass_path = alloc_printf("%s/lib/MyPass.so", base_path);
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = pass_path;

    // Add debugging flags (needed for ./configure tests)
    // cc_params[cc_par_cnt++] = "-g";
    // cc_params[cc_par_cnt++] = "-O0";

    // Add original arguments
    for (int i = 1; i < argc; i++)
    {
        cc_params[cc_par_cnt++] = argv[i];
    }

    // Only add linking options if we're actually linking
    if (is_linking)
    {
        // 1. Add library search paths (-L)
        char *lib_dir = alloc_printf("-L%s/lib", base_path);
        cc_params[cc_par_cnt++] = lib_dir;

        // 2. Add current directory as library search path
        cc_params[cc_par_cnt++] = "-L.";

        // 3. Link library files (-l)
        cc_params[cc_par_cnt++] = "-lio";
        cc_params[cc_par_cnt++] = "-llog";

        // 4. Add runtime library search paths (-Wl,-rpath)
        char *rpath1 = alloc_printf("-Wl,-rpath=%s/lib", base_path);
        cc_params[cc_par_cnt++] = rpath1;

        // 5. Add current directory as runtime library search path
        cc_params[cc_par_cnt++] = "-Wl,-rpath=.";
    }

    // Terminate parameter array
    cc_params[cc_par_cnt] = NULL;
}

int main(int argc, char **argv)
{
    if (argc < 1)
    {
        fprintf(stderr, "Usage: %s [options] <source files>...\n", argv[0]);
        fprintf(stderr, "Wrapper for taint analysis instrumentation\n");
        return 1;
    }

    // Find project base path
    find_base_path(argv[0]);

    // Detect if we're compiling or linking
    detect_compile_mode(argc, argv);

    // Edit parameters to add instrumentation
    edit_params(argc, argv);

#ifdef DEBUG_CLANG
    // Print command for debugging (only if debugging enabled)
    printf("Executing:");
    for (int i = 0; i < cc_par_cnt; i++)
    {
        printf(" %s", cc_params[i]);
    }
    printf("\n");
#endif

    // Execute the real clang
    execvp(cc_params[0], cc_params);

    // If we get here, execvp failed
    perror("execvp failed");
    return 1;
}