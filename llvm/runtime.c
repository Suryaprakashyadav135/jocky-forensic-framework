/*
 * JOCKY Runtime --- V5.2 ABI (clean, no debug output).
 * Strings and arrays are opaque pointers to C structs.
 * The compiler tracks types; the runtime just implements them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <regex.h>
typedef struct {
    char* data;
    int64_t len;
} JkyString;

typedef struct {
    JkyString** items;
    int64_t count;
} JkyArray;

/* ---------- Constructor helpers ---------- */

static JkyString* make_string(const char* data, size_t len) {
    JkyString* s = malloc(sizeof(JkyString));
    if (!s) return NULL;
    char* buf = malloc(len + 1);
    if (!buf) { free(s); return NULL; }
    memcpy(buf, data, len);
    buf[len] = '\0';
    s->data = buf;
    s->len = (int64_t)len;
    return s;
}
/* XOR-decoded string: original bytes XOR'd with key, then wrapped
 * with a marker the compiler recognizes. Runtime decodes on first use. */
JkyString* jky_decode_str(const char* encoded, int64_t key, int64_t len) {
    if (!encoded || len <= 0) return make_string("", 0);
    char* buf = malloc(len + 1);
    if (!buf) return make_string("", 0);
    for (int64_t i = 0; i < len; i++) {
        buf[i] = encoded[i] ^ (char)key;
    }
    buf[len] = '\0';
    JkyString* s = malloc(sizeof(JkyString));
    s->data = buf;
    s->len = len;
    return s;
}

/* ---------- Primitives ---------- */

JkyString* jky_make_str(const char* cstr) {
    if (!cstr) return make_string("", 0);
    return make_string(cstr, strlen(cstr));
}

JkyString* jky_read_file(const char* path) {
    if (!path) return make_string("", 0);
    FILE* f = fopen(path, "rb");
    if (!f) return make_string("", 0);

    /* Read until EOF --- handles both regular files and /proc virtual files */
    size_t cap = 4096, len = 0;
    char* buf = malloc(cap);
    if (!buf) { fclose(f); return make_string("", 0); }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            if (cap > 1024 * 1024) cap = 1024 * 1024;
            buf = realloc(buf, cap);
            if (!buf) { fclose(f); return make_string("", 0); }
        }
        if (len >= 1024 * 1024) break;
    }
    buf[len] = '\0';
    fclose(f);

    JkyString* s = malloc(sizeof(JkyString));
    s->data = buf;
    s->len = (int64_t)len;
    return s;
}

JkyString* jky_exec_cmd(const char* cmd) {
    if (!cmd) return make_string("", 0);
    FILE* p = popen(cmd, "r");
    if (!p) return make_string("", 0);

    size_t cap = 4096, len = 0;
    char* buf = malloc(cap);
    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, p)) > 0) {
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
    }
    buf[len] = '\0';
    pclose(p);

    JkyString* s = malloc(sizeof(JkyString));
    s->data = buf;
    s->len = (int64_t)len;
    return s;
}

JkyArray* jky_list_dir(const char* path) {
    JkyArray* a = malloc(sizeof(JkyArray));
    a->items = NULL;
    a->count = 0;

    DIR* d = opendir(path);
    if (!d) return a;

    size_t cap = 64;
    a->items = malloc(cap * sizeof(JkyString*));

    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if ((size_t)a->count >= cap) {
            cap *= 2;
            a->items = realloc(a->items, cap * sizeof(JkyString*));
        }
        a->items[a->count++] = make_string(e->d_name, strlen(e->d_name));
    }
    closedir(d);
    return a;
}

/* ---------- Accessors ---------- */

int64_t jky_len_str(JkyString* s) { return s ? s->len : 0; }
int64_t jky_len_arr(JkyArray* a) { return a ? a->count : 0; }

JkyString* jky_index(JkyArray* a, int64_t i) {
    if (!a || i < 0 || i >= a->count) return make_string("", 0);
    return a->items[i];
}

JkyString* jky_concat(JkyString* a, JkyString* b) {
    int64_t la = a ? a->len : 0;
    int64_t lb = b ? b->len : 0;
    char* buf = malloc(la + lb + 1);
    if (a) memcpy(buf, a->data, la);
    if (b) memcpy(buf + la, b->data, lb);
    buf[la + lb] = '\0';

    JkyString* s = malloc(sizeof(JkyString));
    s->data = buf;
    s->len = la + lb;
    return s;
}

JkyString* jky_int_to_str(int64_t n) {
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%ld", (long)n);
    return make_string(buf, (size_t)len);
}

/* ---------- Output ---------- */

void jky_emit(const char* key, JkyString* val) {
    if (!key) key = "?";
    if (!val) {
        printf("EMIT %s = <null>\n", key);
        fflush(stdout);
        return;
    }
    printf("EMIT %s = %.*s\n", key, (int)val->len, val->data);
    fflush(stdout);
}

/* ============================================================
 * Tier 1 primitives --- file, string, array, system
 * ============================================================ */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

/* ---------- File access ---------- */

int64_t jky_file_exists(const char* path) {
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}

int64_t jky_file_size(const char* path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

int64_t jky_file_mtime(const char* path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_mtime;
}

JkyArray* jky_read_file_lines(const char* path) {
    JkyArray* arr = malloc(sizeof(JkyArray));
    arr->items = NULL;
    arr->count = 0;
    if (!path) return arr;

    FILE* f = fopen(path, "rb");
    if (!f) return arr;

    size_t cap = 32;
    arr->items = malloc(cap * sizeof(JkyString*));

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        /* strip trailing newline */
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }
        if ((size_t)arr->count >= cap) {
            cap *= 2;
            arr->items = realloc(arr->items, cap * sizeof(JkyString*));
        }
        arr->items[arr->count++] = make_string(line, len);
    }
    fclose(f);
    return arr;
}

JkyString* jky_read_bytes(const char* path, int64_t offset, int64_t count) {
    if (!path || count <= 0 || offset < 0) return make_string("", 0);

    FILE* f = fopen(path, "rb");
    if (!f) return make_string("", 0);

    fseek(f, (long)offset, SEEK_SET);
    char* buf = malloc(count + 1);
    size_t rd = fread(buf, 1, count, f);
    buf[rd] = '\0';
    fclose(f);

    JkyString* s = malloc(sizeof(JkyString));
    s->data = buf;
    s->len = (int64_t)rd;
    return s;
}

JkyString* jky_readlink(const char* path) {
    if (!path) return make_string("", 0);
    char buf[4096];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0) return make_string("", 0);
    buf[n] = '\0';
    return make_string(buf, (size_t)n);
}

/* ---------- String ops ---------- */

JkyString* jky_substr(JkyString* s, int64_t start, int64_t len) {
    if (!s || start < 0 || start >= s->len || len <= 0) return make_string("", 0);
    int64_t end = start + len;
    if (end > s->len) end = s->len;
    return make_string(s->data + start, (size_t)(end - start));
}

JkyArray* jky_split(JkyString* s, JkyString* delim) {
    JkyArray* arr = malloc(sizeof(JkyArray));
    arr->items = NULL;
    arr->count = 0;
    if (!s || !delim || delim->len == 0) return arr;

    size_t cap = 32;
    arr->items = malloc(cap * sizeof(JkyString*));

    int64_t i = 0;
    int64_t start = 0;
    while (i <= s->len - delim->len) {
        if (memcmp(s->data + i, delim->data, delim->len) == 0) {
            if ((size_t)arr->count >= cap) {
                cap *= 2;
                arr->items = realloc(arr->items, cap * sizeof(JkyString*));
            }
            arr->items[arr->count++] = make_string(s->data + start, i - start);
            i += delim->len;
            start = i;
        } else {
            i++;
        }
    }
    /* last segment */
    if ((size_t)arr->count >= cap) {
        cap *= 2;
        arr->items = realloc(arr->items, cap * sizeof(JkyString*));
    }
    arr->items[arr->count++] = make_string(s->data + start, s->len - start);
    return arr;
}

int64_t jky_find(JkyString* s, JkyString* needle) {
    if (!s || !needle || needle->len == 0) return -1;
    for (int64_t i = 0; i <= s->len - needle->len; i++) {
        if (memcmp(s->data + i, needle->data, needle->len) == 0) return i;
    }
    return -1;
}

JkyString* jky_trim(JkyString* s) {
    if (!s) return make_string("", 0);
    int64_t start = 0, end = s->len;
    while (start < end && isspace((unsigned char)s->data[start])) start++;
    while (end > start && isspace((unsigned char)s->data[end-1])) end--;
    return make_string(s->data + start, (size_t)(end - start));
}

JkyString* jky_lower(JkyString* s) {
    if (!s) return make_string("", 0);
    char* buf = malloc(s->len + 1);
    for (int64_t i = 0; i < s->len; i++) {
        buf[i] = tolower((unsigned char)s->data[i]);
    }
    buf[s->len] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = buf;
    r->len = s->len;
    return r;
}

JkyString* jky_upper(JkyString* s) {
    if (!s) return make_string("", 0);
    char* buf = malloc(s->len + 1);
    for (int64_t i = 0; i < s->len; i++) {
        buf[i] = toupper((unsigned char)s->data[i]);
    }
    buf[s->len] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = buf;
    r->len = s->len;
    return r;
}

int64_t jky_to_int(JkyString* s) {
    if (!s) return 0;
    return (int64_t)atoll(s->data);
}

JkyString* jky_replace(JkyString* s, JkyString* old, JkyString* newv) {
    if (!s || !old || !newv || old->len == 0) return s;
    size_t cap = s->len + 64;
    char* buf = malloc(cap);
    int64_t i = 0, w = 0;
    while (i < s->len) {
        if (i <= s->len - old->len && memcmp(s->data + i, old->data, old->len) == 0) {
            while ((size_t)w + newv->len + 1 > cap) {
                cap *= 2;
                buf = realloc(buf, cap);
            }
            memcpy(buf + w, newv->data, newv->len);
            w += newv->len;
            i += old->len;
        } else {
            if ((size_t)w + 2 > cap) { cap *= 2; buf = realloc(buf, cap); }
            buf[w++] = s->data[i++];
        }
    }
    buf[w] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = buf;
    r->len = w;
    return r;
}

int64_t jky_starts_with(JkyString* s, JkyString* prefix) {
    if (!s || !prefix) return 0;
    if (prefix->len > s->len) return 0;
    return memcmp(s->data, prefix->data, prefix->len) == 0 ? 1 : 0;
}

int64_t jky_ends_with(JkyString* s, JkyString* suffix) {
    if (!s || !suffix) return 0;
    if (suffix->len > s->len) return 0;
    return memcmp(s->data + s->len - suffix->len, suffix->data, suffix->len) == 0 ? 1 : 0;
}

/* ---------- Array ops ---------- */

JkyArray* jky_append(JkyArray* a, JkyString* val) {
    if (!a || !val) return a;
    a->items = realloc(a->items, (a->count + 1) * sizeof(JkyString*));
    a->items[a->count++] = val;
    return a;
}

int64_t jky_contains(JkyArray* a, JkyString* val) {
    if (!a || !val) return 0;
    for (int64_t i = 0; i < a->count; i++) {
        if (a->items[i]->len == val->len &&
            memcmp(a->items[i]->data, val->data, val->len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------- System ---------- */

JkyString* jky_getenv(JkyString* name) {
    if (!name) return make_string("", 0);
    const char* v = getenv(name->data);
    if (!v) return make_string("", 0);
    return make_string(v, strlen(v));
}

int64_t jky_getpid(void) { return (int64_t)getpid(); }
int64_t jky_getuid(void) { return (int64_t)getuid(); }

JkyString* jky_getcwd(void) {
    char buf[4096];
    if (getcwd(buf, sizeof(buf)) == NULL) return make_string("", 0);
    return make_string(buf, strlen(buf));
}


/* ============================================================
 * Tier 2 primitives --- maps, string builders, advanced ops
 * ============================================================ */

typedef struct {
    JkyString** keys;
    JkyString** values;
    int64_t count;
    int64_t cap;
} JkyMap;

JkyMap* jky_map_new(void) {
    JkyMap* m = malloc(sizeof(JkyMap));
    m->cap = 16;
    m->count = 0;
    m->keys = malloc(m->cap * sizeof(JkyString*));
    m->values = malloc(m->cap * sizeof(JkyString*));
    return m;
}

void jky_map_set(JkyMap* m, JkyString* key, JkyString* val) {
    if (!m || !key) return;
    /* Update if key exists */
    for (int64_t i = 0; i < m->count; i++) {
        if (m->keys[i]->len == key->len &&
            memcmp(m->keys[i]->data, key->data, key->len) == 0) {
            m->values[i] = val ? val : make_string("", 0);
            return;
        }
    }
    /* Otherwise append */
    if (m->count >= m->cap) {
        m->cap *= 2;
        m->keys = realloc(m->keys, m->cap * sizeof(JkyString*));
        m->values = realloc(m->values, m->cap * sizeof(JkyString*));
    }
    m->keys[m->count] = key;
    m->values[m->count] = val ? val : make_string("", 0);
    m->count++;
}

JkyString* jky_map_get(JkyMap* m, JkyString* key) {
    if (!m || !key) return make_string("", 0);
    for (int64_t i = 0; i < m->count; i++) {
        if (m->keys[i]->len == key->len &&
            memcmp(m->keys[i]->data, key->data, key->len) == 0) {
            return m->values[i];
        }
    }
    return make_string("", 0);
}

int64_t jky_map_has(JkyMap* m, JkyString* key) {
    if (!m || !key) return 0;
    for (int64_t i = 0; i < m->count; i++) {
        if (m->keys[i]->len == key->len &&
            memcmp(m->keys[i]->data, key->data, key->len) == 0) {
            return 1;
        }
    }
    return 0;
}

int64_t jky_map_size(JkyMap* m) {
    return m ? m->count : 0;
}

JkyString* jky_map_key_at(JkyMap* m, int64_t i) {
    if (!m || i < 0 || i >= m->count) return make_string("", 0);
    return m->keys[i];
}

JkyString* jky_map_val_at(JkyMap* m, int64_t i) {
    if (!m || i < 0 || i >= m->count) return make_string("", 0);
    return m->values[i];
}

/* String builder pattern --- accumulate output in a single string */
JkyString* jky_build_string(JkyArray* parts, JkyString* sep) {
    if (!parts) return make_string("", 0);
    if (parts->count == 0) return make_string("", 0);

    size_t total = 0;
    for (int64_t i = 0; i < parts->count; i++) {
        total += parts->items[i]->len;
        if (i + 1 < parts->count && sep) total += sep->len;
    }

    char* buf = malloc(total + 1);
    size_t w = 0;
    for (int64_t i = 0; i < parts->count; i++) {
        memcpy(buf + w, parts->items[i]->data, parts->items[i]->len);
        w += parts->items[i]->len;
        if (i + 1 < parts->count && sep) {
            memcpy(buf + w, sep->data, sep->len);
            w += sep->len;
        }
    }
    buf[w] = '\0';

    JkyString* r = malloc(sizeof(JkyString));
    r->data = buf;
    r->len = (int64_t)w;
    return r;
}

/* Simple regex match (POSIX extended) */
JkyString* jky_match(JkyString* s, JkyString* pattern) {
    if (!s || !pattern) return make_string("", 0);
    /* Return first matching substring, or empty if no match */
    char* sp = malloc(s->len + 1);
    memcpy(sp, s->data, s->len);
    sp[s->len] = '\0';

    char* pp = malloc(pattern->len + 1);
    memcpy(pp, pattern->data, pattern->len);
    pp[pattern->len] = '\0';

    regex_t regex;
    int ret = regcomp(&regex, pp, REG_EXTENDED);
    if (ret != 0) {
        free(sp); free(pp);
        return make_string("", 0);
    }

    regmatch_t matches[1];
    JkyString* result = make_string("", 0);
    if (regexec(&regex, sp, 1, matches, 0) == 0) {
        int64_t mlen = matches[0].rm_eo - matches[0].rm_so;
        result = make_string(sp + matches[0].rm_so, mlen);
    }
    regfree(&regex);
    free(sp); free(pp);
    return result;
}

int64_t jky_regex_test(JkyString* s, JkyString* pattern) {
    if (!s || !pattern) return 0;
    char* sp = malloc(s->len + 1);
    memcpy(sp, s->data, s->len);
    sp[s->len] = '\0';

    char* pp = malloc(pattern->len + 1);
    memcpy(pp, pattern->data, pattern->len);
    pp[pattern->len] = '\0';

    regex_t regex;
    int ret = regcomp(&regex, pp, REG_EXTENDED);
    if (ret != 0) {
        free(sp); free(pp);
        return 0;
    }
    int matched = (regexec(&regex, sp, 0, NULL, 0) == 0) ? 1 : 0;
    regfree(&regex);
    free(sp); free(pp);
    return matched;
}

/* File write */
int64_t jky_write_file(JkyString* path, JkyString* content) {
    if (!path || !content) return 0;
    FILE* f = fopen(path->data, "wb");
    if (!f) return 0;
    size_t w = fwrite(content->data, 1, content->len, f);
    fclose(f);
    return (int64_t)w;
}

int64_t jky_append_file(JkyString* path, JkyString* content) {
    if (!path || !content) return 0;
    FILE* f = fopen(path->data, "ab");
    if (!f) return 0;
    size_t w = fwrite(content->data, 1, content->len, f);
    fclose(f);
    return (int64_t)w;
}

/* Sleep */
void jky_sleep(int64_t ms) {
    if (ms > 0) usleep((useconds_t)(ms * 1000));
}

/* JSON escape and serialize simple structures to string */
JkyString* jky_json_escape(JkyString* s) {
    if (!s) return make_string("", 0);
    size_t cap = s->len * 2 + 16;
    char* buf = malloc(cap);
    size_t w = 0;
    for (int64_t i = 0; i < s->len; i++) {
        char c = s->data[i];
        if (w + 8 >= cap) { cap *= 2; buf = realloc(buf, cap); }
        if (c == '"' || c == '\\') {
            buf[w++] = '\\';
            buf[w++] = c;
        } else if (c == '\n') {
            buf[w++] = '\\'; buf[w++] = 'n';
        } else if (c == '\r') {
            buf[w++] = '\\'; buf[w++] = 'r';
        } else if (c == '\t') {
            buf[w++] = '\\'; buf[w++] = 't';
        } else if (c < 32) {
            w += snprintf(buf + w, 8, "\\u%04x", c);
        } else {
            buf[w++] = c;
        }
    }
    buf[w] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = buf;
    r->len = (int64_t)w;
    return r;
}

/* ============================================================
 * Tier 3 primitives --- sort, encoding, hashing
 * ============================================================ */

#include <openssl/sha.h>

/* qsort comparator for strings */
static int cmp_string(const void* a, const void* b) {
    JkyString* sa = *(JkyString**)a;
    JkyString* sb = *(JkyString**)b;
    int64_t n = sa->len < sb->len ? sa->len : sb->len;
    int r = memcmp(sa->data, sb->data, n);
    if (r != 0) return r;
    if (sa->len < sb->len) return -1;
    if (sa->len > sb->len) return 1;
    return 0;
}

JkyArray* jky_sort(JkyArray* a) {
    if (!a || a->count < 2) return a;
    qsort(a->items, a->count, sizeof(JkyString*), cmp_string);
    return a;
}

JkyArray* jky_reverse(JkyArray* a) {
    if (!a || a->count < 2) return a;
    int64_t i = 0, j = a->count - 1;
    while (i < j) {
        JkyString* tmp = a->items[i];
        a->items[i] = a->items[j];
        a->items[j] = tmp;
        i++; j--;
    }
    return a;
}

JkyArray* jky_slice(JkyArray* a, int64_t start, int64_t end) {
    JkyArray* r = malloc(sizeof(JkyArray));
    r->items = NULL;
    r->count = 0;
    if (!a) return r;
    if (start < 0) start = 0;
    if (end > a->count) end = a->count;
    if (end <= start) return r;
    r->count = end - start;
    r->items = malloc(r->count * sizeof(JkyString*));
    for (int64_t i = start; i < end; i++) {
        r->items[i - start] = a->items[i];
    }
    return r;
}

JkyArray* jky_unique(JkyArray* a) {
    JkyArray* r = malloc(sizeof(JkyArray));
    r->items = NULL;
    r->count = 0;
    if (!a) return r;

    size_t cap = 32;
    r->items = malloc(cap * sizeof(JkyString*));

    for (int64_t i = 0; i < a->count; i++) {
        int found = 0;
        for (int64_t j = 0; j < r->count; j++) {
            if (r->items[j]->len == a->items[i]->len &&
                memcmp(r->items[j]->data, a->items[i]->data,
                       a->items[i]->len) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            if ((size_t)r->count >= cap) {
                cap *= 2;
                r->items = realloc(r->items, cap * sizeof(JkyString*));
            }
            r->items[r->count++] = a->items[i];
        }
    }
    return r;
}

JkyString* jky_join(JkyArray* a, JkyString* sep) {
    return jky_build_string(a, sep);
}

/* ---------- Base64 ---------- */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

JkyString* jky_base64_encode(JkyString* s) {
    if (!s) return make_string("", 0);
    size_t out_cap = 4 * ((s->len + 2) / 3) + 1;
    char* out = malloc(out_cap);
    size_t w = 0;
    int64_t i = 0;
    while (i < s->len) {
        unsigned char a = s->data[i++];
        unsigned char b = (i < s->len) ? s->data[i++] : 0;
        unsigned char c = (i < s->len) ? s->data[i++] : 0;
        unsigned char triple[3] = {a, b, c};
        int64_t remaining = s->len - (i - 3);
        int pad = 0;
        if (i - 3 < s->len && i - 2 >= s->len) pad = 2;
        else if (i - 2 < s->len && i - 1 >= s->len) pad = 1;
        // Recompute properly: how many of the 3 bytes were real?
        int n_real = 3;
        if (i > s->len) n_real = 3 - (i - s->len);
        (void)remaining;
        (void)pad;

        out[w++] = b64_table[(a >> 2) & 0x3F];
        out[w++] = b64_table[((a & 0x03) << 4) | ((b >> 4) & 0x0F)];
        if (n_real < 2) out[w++] = '=';
        else out[w++] = b64_table[((b & 0x0F) << 2) | ((c >> 6) & 0x03)];
        if (n_real < 3) out[w++] = '=';
        else out[w++] = b64_table[c & 0x3F];

        (void)triple;
    }
    out[w] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = (int64_t)w;
    return r;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

JkyString* jky_base64_decode(JkyString* s) {
    if (!s) return make_string("", 0);
    char* out = malloc(s->len);
    size_t w = 0;
    int buf = 0, bits = 0;
    for (int64_t i = 0; i < s->len; i++) {
        char c = s->data[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = b64_val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[w++] = (char)((buf >> bits) & 0xFF);
        }
    }
    out[w] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = (int64_t)w;
    return r;
}

/* ---------- Hex ---------- */

JkyString* jky_hex_encode(JkyString* s) {
    if (!s) return make_string("", 0);
    char* out = malloc(s->len * 2 + 1);
    for (int64_t i = 0; i < s->len; i++) {
        sprintf(out + i * 2, "%02x", (unsigned char)s->data[i]);
    }
    out[s->len * 2] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = s->len * 2;
    return r;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

JkyString* jky_hex_decode(JkyString* s) {
    if (!s) return make_string("", 0);
    char* out = malloc(s->len / 2 + 1);
    size_t w = 0;
    for (int64_t i = 0; i + 1 < s->len; i += 2) {
        int hi = hex_val(s->data[i]);
        int lo = hex_val(s->data[i + 1]);
        if (hi < 0 || lo < 0) continue;
        out[w++] = (char)((hi << 4) | lo);
    }
    out[w] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = (int64_t)w;
    return r;
}

/* ---------- SHA-256 ---------- */

JkyString* jky_sha256_string(JkyString* s) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)s->data, s->len, hash);
    char* out = malloc(65);
    for (int i = 0; i < 32; i++) {
        sprintf(out + i * 2, "%02x", hash[i]);
    }
    out[64] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = 64;
    return r;
}

JkyString* jky_sha256_file(JkyString* path) {
    if (!path) return make_string("", 0);
    FILE* f = fopen(path->data, "rb");
    if (!f) return make_string("", 0);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(f);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    char* out = malloc(65);
    for (int i = 0; i < 32; i++) {
        sprintf(out + i * 2, "%02x", hash[i]);
    }
    out[64] = '\0';
    JkyString* r = malloc(sizeof(JkyString));
    r->data = out;
    r->len = 64;
    return r;
}
/* String equality: compare contents */
int64_t jky_str_eq(JkyString* a, JkyString* b) {
    if (!a || !b) return 0;
    if (a->len != b->len) return 0;
    return memcmp(a->data, b->data, a->len) == 0 ? 1 : 0;
}

int64_t jky_str_len_bytes(JkyString* s) {
    return s ? s->len : 0;
}

/* ---------- Legacy @command support ---------- */

int64_t jocky_cmd(int64_t cmd_id, int64_t arg_count, int64_t* args) {
    printf("[jocky] cmd_hash=%016lx args=%ld\n",
           (unsigned long)cmd_id, (long)arg_count);
    for (int64_t i = 0; i < arg_count; i++) {
        printf(" arg[%ld] = %016lx\n", (long)i, (unsigned long)args[i]);
    }
    return 0;
}
