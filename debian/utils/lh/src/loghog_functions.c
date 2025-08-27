// loghog_functions.c
#include "common.h"
#include "loghog_functions.h"

static void safe_system_less(const char *path) {
    char cmd[256 + 64];
    int n = snprintf(cmd, sizeof(cmd), "less -R '%s'", path);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "less invocation path too long\n");
        return;
    }
    (void)system(cmd); // ignore result; less returns non-zero on 'q'
}

void find_logs_command(char *buffer, size_t size, const char *search_path) {
    // Builds the base find+tail command (no filters)
    // Note: we quote the path to support spaces
    (void)snprintf(
        buffer, size,
        "find '%s' -type f \\( -name '*.log' -o -name 'messages' -o -name 'cron' -o -name 'maillog' -o -name 'secure' -o -name 'firewalld' \\) "
        "-exec tail -f -n +1 {} +",
        search_path
    );
}

void display_buffer_with_less(const char *buffer, size_t length) {
    char tmp_filename[] = "/tmp/logsearchXXXXXX";
    int tmp_fd = mkstemp(tmp_filename);
    if (tmp_fd == -1) { perror("mkstemp"); return; }

    FILE *tmp_file = fdopen(tmp_fd, "w+");
    if (!tmp_file) { perror("fdopen"); close(tmp_fd); return; }

    if (buffer && length) {
        (void)fwrite(buffer, 1, length, tmp_file);
        (void)fflush(tmp_file);
    }
    (void)fclose(tmp_file);

    safe_system_less(tmp_filename);
    (void)unlink(tmp_filename);
}

void run_command_with_buffer(const char *cmd, void (*buffer_action)(const char *, size_t)) {
    FILE *proc = popen(cmd, "r");
    if (!proc) { perror("popen"); return; }

    char *output = NULL;
    size_t total = 0;
    char buf[4096];

    while (fgets(buf, sizeof(buf), proc)) {
        size_t len = strlen(buf);
        char *tmp = realloc(output, total + len + 1);
        if (!tmp) { perror("realloc"); free(output); pclose(proc); return; }
        output = tmp;
        memcpy(output + total, buf, len);
        total += len;
        output[total] = '\0';

        fputs(buf, stdout);
        fflush(stdout);
    }

    if (buffer_action) buffer_action(output, total);
    free(output);
    (void)pclose(proc);
}

static void run_with_filter(const char *log_search_path, const char *grep_expr, int color_always) {
    char find_cmd[BUFFER_SIZE];
    find_logs_command(find_cmd, sizeof(find_cmd), log_search_path);

    char *cmd = NULL;
    const char *color = color_always ? "always" : "never";
    if (grep_expr && *grep_expr) {
        if (asprintf(&cmd, "%s | egrep --color=%s -i \"%s\"", find_cmd, color, grep_expr) < 0 || !cmd) {
            perror("asprintf");
            return;
        }
    } else {
        if (asprintf(&cmd, "%s", find_cmd) < 0 || !cmd) { perror("asprintf"); return; }
    }

    run_command_with_buffer(cmd, display_buffer_with_less);
    free(cmd);
}

void live_auth_log(const char *log_search_path) {
    const char *expr =
        "authentication(\\s*failed)?|permission(\\s*denied)?|invalid\\s*(user|password|token)|"
        "(unauthorized|illegal)\\s*(access|attempt)|SQL\\s*injection|cross-site\\s*(scripting|request\\s*Forgery)|"
        "directory\\s*traversal|(brute-?force|DoS|DDoS)\\s*attack|(vulnerability|exploit)\\s*(detected|scan)";
    run_with_filter(log_search_path, expr, 1);
}

void live_error_log(const char *log_search_path) {
    const char *expr =
        "\\b(?:error|fail(?:ed|ure)?|warn(?:ing)?|critical|socket|denied|refused|retry|reset|timeout|dns|network)";
    run_with_filter(log_search_path, expr, 1);
}

void live_log(const char *log_search_path) {
    run_with_filter(log_search_path, NULL, 1);
}

void live_network_log(const char *log_search_path) {
    const char *expr =
        "https?://|ftps?://|telnet://|ssh://|sftp://|ldap(s)?://|nfs://|tftp://|gopher://|"
        "imap(s)?://|pop3(s)?://|smtp(s)?://|rtsp://|rtmp://|mms://|xmpp://|ipp://|xrdp://";
    run_with_filter(log_search_path, expr, 1);
}

void run_regex(const char *log_search_path) {
    char *pattern = get_user_input("\nRegEX > ");
    if (!sanitize_input(pattern)) { free(pattern); return; }
    run_with_filter(log_search_path, pattern, 1);
    free(pattern);
}

void search_ip(const char *log_search_path) {
    char *pattern = get_user_input("\nIP / RegEX > ");
    if (!sanitize_input(pattern)) { free(pattern); return; }
    run_with_filter(log_search_path, pattern, 1);
    free(pattern);
}

void edit_log_paths(char *path) {
    char *new_paths =
        get_user_input("\nCurrent log paths: /var/lib/docker /var/log\n"
                       "ie: /var/lib/docker/containers /opt /nfsshare etc\n"
                       "Enter new log paths (separated by spaces) > ");
    if (!sanitize_input(new_paths)) { free(new_paths); return; }

    strncpy(path, new_paths, BUFFER_SIZE - 1);
    path[BUFFER_SIZE - 1] = '\0';
    free(new_paths);

    printf(ANSI_COLOR_GREEN "Updated log paths: %s\n" ANSI_COLOR_RESET, path);
}

void export_search_results_to_json(const char *log_search_path) {
    char *pattern = get_user_input("\nRegEX / Text > ");
    if (!sanitize_input(pattern)) { free(pattern); return; }

    char find_cmd[BUFFER_SIZE];
    find_logs_command(find_cmd, sizeof(find_cmd), log_search_path);

    char *cmd = NULL;
    if (asprintf(&cmd, "%s | egrep --color=never -i \"%s\"", find_cmd, pattern) < 0 || !cmd) {
        perror("asprintf");
        free(pattern);
        return;
    }

    FILE *proc = popen(cmd, "r");
    if (!proc) { perror("popen"); free(pattern); free(cmd); return; }

    json_object *json_arr = json_object_new_array();
    char buf[4096];

    while (fgets(buf, sizeof(buf), proc)) {
        json_object *obj = json_object_new_object();
        json_object_object_add(obj, "log_entry", json_object_new_string(buf));
        json_object_array_add(json_arr, obj);
    }

    (void)pclose(proc);
    free(cmd);
    free(pattern);

    if (json_object_array_length(json_arr) > 0) {
        const char *outname = "log_search_results.json";
        FILE *out = fopen(outname, "w");
        if (!out) {
            perror("fopen");
        } else {
            fputs(json_object_to_json_string_ext(json_arr, JSON_C_TO_STRING_PRETTY), out);
            fclose(out);
            printf("\nExported search results to %s\n", outname);
        }
    } else {
        printf("\nNo matching log entries found.\n");
    }

    json_object_put(json_arr);
}

void display_help(void) {
    const char *help_text =
        ANSI_COLOR_CYAN "\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n" ANSI_COLOR_RESET
        ANSI_COLOR_CYAN "TAIL MODE\n" ANSI_COLOR_RESET
        ANSI_COLOR_LIGHT_GRAY "Logs are automatically stitched together by timestamp making \n" ANSI_COLOR_RESET
        ANSI_COLOR_LIGHT_GRAY "events easy to follow in real time " ANSI_COLOR_CYAN "(CTRL+C to quit)\n\n" ANSI_COLOR_RESET
        ANSI_COLOR_CYAN "LESS MODE\n" ANSI_COLOR_RESET
        ANSI_COLOR_LIGHT_GRAY "Buffers from tail mode are sent directly to less, a powerful\n" ANSI_COLOR_RESET
        ANSI_COLOR_LIGHT_GRAY "text editing tool that allows for in-depth review, searches and\n" ANSI_COLOR_RESET
        ANSI_COLOR_LIGHT_GRAY "real-time log analysis " ANSI_COLOR_CYAN "(h for help)" ANSI_COLOR_LIGHT_GRAY " or " ANSI_COLOR_CYAN "(q to quit)\n" ANSI_COLOR_RESET
        ANSI_COLOR_CYAN "\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n" ANSI_COLOR_RESET
        ANSI_COLOR_CYAN "MENU OVERVIEW\n\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "A" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Auth (Tail) – security/auth issues in real time\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "E" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Errors (Tail) – error/warn/critical/socket/DNS/etc.\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "L" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Live – all logs, unified by timestamp\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "N" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Network (Tail) – protocol URLs (http/ssh/smtp/...)\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "R" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Regex (Tail) – free-form egrep patterns\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "I" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "IP – IPv4/IPv6 and ranges by regex\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "S" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Set – change monitored log paths\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "J" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "JSON – export filtered results\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "H" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Help – this screen\n" ANSI_COLOR_RESET
        ANSI_COLOR_DARK "[" ANSI_COLOR_LIGHT_GREEN "Q" ANSI_COLOR_DARK "] " ANSI_COLOR_BLUE "Quit\n" ANSI_COLOR_RESET;

    display_buffer_with_less(help_text, strlen(help_text));
}

void main_menu(void) {
    while (1) {
        printf(ANSI_COLOR_GREEN ASCII_ART ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "A" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "uth\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "E" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "rror\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "L" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "ive (all logs)\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "N" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "etwork\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "R" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "egEx\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "I" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "pEx\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "S" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "et dir\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "J" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "sonEx\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "H" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "elp!\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "(" ANSI_COLOR_LIGHT_GREEN "Q" ANSI_COLOR_DARK ")" ANSI_COLOR_LIGHT_GREEN "uit!\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_DARK "\n-" ANSI_COLOR_LIGHT_GRAY "> " ANSI_COLOR_RESET);

        char *option = readline(NULL);
        if (!option) { continue; }

        char opt = option[0];
        switch (opt) {
            case 'A': case 'a': live_auth_log(log_search_path); break;
            case 'E': case 'e': live_error_log(log_search_path); break;
            case 'L': case 'l': live_log(log_search_path); break;
            case 'N': case 'n': live_network_log(log_search_path); break;
            case 'R': case 'r': run_regex(log_search_path); break;
            case 'I': case 'i': search_ip(log_search_path); break;
            case 'S': case 's': edit_log_paths(log_search_path); break;
            case 'J': case 'j': export_search_results_to_json(log_search_path); break;
            case 'H': case 'h': display_help(); break;
            case 'Q': case 'q': free(option); return;
            default: printf(ANSI_COLOR_BLUE "oops!\n" ANSI_COLOR_RESET); break;
        }
        free(option);
    }
}

void sigint_handler(int sig) {
    (void)sig;
    printf("\nReturning to menu...\n");
    fflush(stdout);
}
