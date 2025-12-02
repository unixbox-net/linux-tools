#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <json-c/json.h>
#include <readline/readline.h>
#include <readline/history.h>

#define BUFFER_SIZE 4096
#define ANSI_RESET "\x1b[0m"
#define C_RED "\x1b[31;1m"
#define C_GRN "\x1b[32;1m"
#define C_CYN "\x1b[36;1m"
#define C_MAG "\x1b[35;1m"

static char log_search_path[BUFFER_SIZE] = "/var/log";

static void find_logs_command(char *buffer, size_t size, const char *path) {
  snprintf(buffer, size,
   "find %s -type f \\( -name '*.log' -o -name 'messages' -o -name 'cron' -o -name 'maillog' -o -name 'secure' -o -name '*firewal*' \\) -exec tail -f -n +1 {} +",
   path);
}

static void display_buffer_with_less(const char *buf, size_t len) {
  char tmp[] = "/tmp/logsearchXXXXXX";
  int fd = mkstemp(tmp);
  if (fd == -1) { perror("mkstemp"); return; }
  FILE *f = fdopen(fd, "w+"); if (!f){ perror("fdopen"); close(fd); return; }
  fwrite(buf, 1, len, f); fflush(f);
  char cmd[BUFFER_SIZE]; snprintf(cmd, sizeof(cmd), "less -R %s", tmp);
  system(cmd);
  fclose(f); remove(tmp);
}

static void run_command_with_buffer(const char *cmd, void (*action)(const char*,size_t)) {
  FILE *p = popen(cmd, "r"); if(!p){ perror("popen"); return; }
  char *out = NULL; size_t tot=0; char b[BUFFER_SIZE];
  while (fgets(b, sizeof(b), p)) {
    size_t n=strlen(b);
    char *t = realloc(out, tot+n+1); if(!t){ perror("realloc"); free(out); pclose(p); return; }
    out=t; memcpy(out+tot,b,n); tot+=n; out[tot]='\0';
    fputs(b, stdout); fflush(stdout);
  }
  if(action) action(out?out:"", tot);
  free(out); pclose(p);
}

static char* get_user_input(const char *prompt) {
  char *in = readline(prompt);
  if(in && *in) add_history(in);
  return in;
}
static int sanitize_input(char *in) {
  if(!in || !*in) return 0;
  if(strlen(in) >= BUFFER_SIZE){ printf(C_RED "Input too long\n" ANSI_RESET); return 0; }
  return 1;
}

static void live_auth() {
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE];
  find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=always -i \"authentication(\\s*failed)?|permission(\\s*denied)?|invalid\\s*(user|password|token)|(unauthorized|illegal)\\s*(access|attempt)|SQL\\s*injection|cross-site\\s*(scripting|request\\s*Forgery)|directory\\s*traversal|(brute-?force|DoS|DDoS)\\s*attack|(vulnerability|exploit)\\s*(detected|scan)\"", f);
  run_command_with_buffer(cmd, display_buffer_with_less);
}
static void live_err() {
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE];
  find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=always -i \"\\b(?:error|fail(?:ed|ure)?|warn(?:ing)?|critical|socket|denied|refused|retry|reset|timeout|dns|network)\"", f);
  run_command_with_buffer(cmd, display_buffer_with_less);
}
static void live_all() {
  char f[BUFFER_SIZE]; find_logs_command(f, sizeof(f), log_search_path);
  run_command_with_buffer(f, display_buffer_with_less);
}
static void live_net() {
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE];
  find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=always -i 'https?://|ftps?://|telnet://|ssh://|sftp://|ldap(s)?://|nfs://|tftp://|imap(s)?://|pop3(s)?://|smtp(s)?://|rtsp://|rtmp://|mms://|xmpp://|ipp://|xrdp://'", f);
  run_command_with_buffer(cmd, display_buffer_with_less);
}
static void run_regex() {
  char *re = get_user_input("\nRegEX > "); if(!sanitize_input(re)){ free(re); return; }
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE]; find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=always -i \"%s\"", f, re);
  run_command_with_buffer(cmd, display_buffer_with_less); free(re);
}
static void search_ip() {
  char *re = get_user_input("\nIP / RegEX > "); if(!sanitize_input(re)){ free(re); return; }
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE]; find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=always -i \"%s\"", f, re);
  run_command_with_buffer(cmd, display_buffer_with_less); free(re);
}
static void edit_paths() {
  printf(C_CYN "Current: %s\n" ANSI_RESET, log_search_path);
  char *np = get_user_input("Enter new log paths (space sep) > ");
  if(!sanitize_input(np)){ free(np); return; }
  strncpy(log_search_path, np, BUFFER_SIZE-1); log_search_path[BUFFER_SIZE-1]='\0'; free(np);
  printf(C_GRN "Updated: %s\n" ANSI_RESET, log_search_path);
}
static void export_json() {
  char *re = get_user_input("\nRegEX / Text > "); if(!sanitize_input(re)){ free(re); return; }
  char f[BUFFER_SIZE], cmd[BUFFER_SIZE]; find_logs_command(f, sizeof(f), log_search_path);
  snprintf(cmd, sizeof(cmd), "%s | egrep --color=never -i \"%s\"", f, re);
  FILE *p = popen(cmd,"r"); if(!p){ perror("popen"); free(re); return; }
  json_object *arr = json_object_new_array(); char buf[BUFFER_SIZE]; int n=0;
  while (fgets(buf, sizeof(buf), p)) {
    json_object *o = json_object_new_object();
    json_object_object_add(o, "log_entry", json_object_new_string(buf));
    json_object_array_add(arr, o); n++;
  }
  pclose(p);
  if(n>0){
    const char *fn="log_search_results.json"; FILE *out=fopen(fn,"w");
    if(out){ fputs(json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PRETTY), out); fclose(out); printf("\nExported: %s (pwd)\n", fn); }
    else perror("fopen");
  } else printf("\nNo matching log entries found.\n");
  json_object_put(arr); free(re);
}

static void sigint_handler(int sig){ (void)sig; printf("\n^C — returning to menu...\n"); fflush(stdout); }
static void help() {
  const char *t = "\nLogHog-lite: tail/less/regex over /var/log & container logs.\n"
                  "A) Auth   E) Errors   L) Live   N) Net\n"
                  "R) Regex  I) IP/Regex S) Set    J) Export JSON\n"
                  "H) Help   Q) Quit\n";
  display_buffer_with_less(t, strlen(t));
}

int main(){
  signal(SIGINT, sigint_handler);
  for(;;){
    printf(C_MAG "\n== LogHog-lite ==\n" ANSI_RESET);
    printf("(A)uth (E)rrors (L)ive (N)et  (R)egex (I)P  (S)et  (J)SON  (H)elp  (Q)uit\n> ");
    char *opt = readline(NULL); if(!opt){ clearerr(stdin); continue; }
    char c=opt[0];
    switch(c){
      case 'A': case 'a': live_auth(); break;
      case 'E': case 'e': live_err(); break;
      case 'L': case 'l': live_all(); break;
      case 'N': case 'n': live_net(); break;
      case 'R': case 'r': run_regex(); break;
      case 'I': case 'i': search_ip(); break;
      case 'S': case 's': edit_paths(); break;
      case 'J': case 'j': export_json(); break;
      case 'H': case 'h': help(); break;
      case 'Q': case 'q': free(opt); return 0;
      default: printf("?\n");
    }
    free(opt);
  }
}
