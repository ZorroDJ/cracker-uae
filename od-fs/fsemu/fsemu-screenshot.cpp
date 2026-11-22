#define FSEMU_INTERNAL
#include "fsemu-screenshot.h"

#include <time.h>

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "fsapp-bitmap.h"
#include "fs/log.h"
#include "fs/path.h"
#include "fsapp-util.h"
#include "fsemu-application.h"
#include "fsemu-config.h"
#include "fsemu-glib.h"
#include "fsemu-module.h"
#include "fsemu-option.h"

int fsemu_screenshot_log_level = SDL_LOG_PRIORITY_INFO;

static struct {
    bool initialized;
    bool capture;
    // int crop[4];
    char *prefix;
    char *screenshots_dir;
    char *time_str;
    int last_counter;
    char requested_path[FSEMU_PATH_MAX];
    char last_path[FSEMU_PATH_MAX];
    SDL_Mutex *mutex;
} fsemu_screenshot;

// A private copy of the last complete post-planar RGB frame allows snapshots
// while the emulation thread is inside the native debugger (no new frames).
static std::atomic<bool> debug_frame_cache_enabled{false};
static std::mutex debug_frame_mutex, debug_snapshot_mutex;
static std::vector<unsigned char> debug_frame_pixels;
static fsemu_video_frame_t debug_frame;

void fsemu_screenshot_remember_video_frame(fsemu_video_frame_t *frame)
{
    if (!debug_frame_cache_enabled || !frame || !frame->buffer ||
        (frame->depth != 16 && frame->depth != 32) ||
        frame->width <= 0 || frame->height <= 0 || frame->stride <= 0) return;
    uint64_t row = (uint64_t)frame->width * (frame->depth / 8);
    uint64_t size = (uint64_t)frame->stride * frame->height;
    if ((uint64_t)frame->stride < row || size > 64 * 1024 * 1024) return;
    std::lock_guard<std::mutex> lock(debug_frame_mutex);
    debug_frame_pixels.assign((unsigned char *)frame->buffer,
                              (unsigned char *)frame->buffer + size);
    debug_frame.width = frame->width;
    debug_frame.height = frame->height;
    debug_frame.depth = frame->depth;
    debug_frame.stride = frame->stride;
    debug_frame.buffer = debug_frame_pixels.data();
}

static void fsemu_screenshot_lock(void)
{
    fsapp_assert(fsemu_screenshot.initialized);
    SDL_LockMutex(fsemu_screenshot.mutex);
}

static void fsemu_screenshot_unlock(void)
{
    SDL_UnlockMutex(fsemu_screenshot.mutex);
}

static void fsemu_screenshot_prepare_locked(void)
{
    fsemu_screenshot.last_path[0] = 0;
    time_t tm1;
    time(&tm1);
    struct tm *tm2 = localtime(&tm1);
    static char time_buffer[64];
    strftime(time_buffer, 64 - 1, "%y%m%d-%H%M", tm2);
    time_buffer[64 - 1] = '\0';

    if (fsemu_screenshot.time_str) {
        free(fsemu_screenshot.time_str);
    }
    fsemu_screenshot.time_str = strdup(time_buffer);
}

void fsemu_screenshot_capture(void)
{
    fsemu_screenshot_log("Scheduling screenshot capture\n");
    fsemu_screenshot_lock();
    fsemu_screenshot.capture = true;
    fsemu_screenshot.requested_path[0] = '\0';
    fsemu_screenshot_prepare_locked();
    fsemu_screenshot_unlock();
}

void fsemu_screenshot_capture_to(const char *path)
{
    fsemu_screenshot_log("Scheduling screenshot capture to %s\n",
                         path && path[0] ? path : "(default)");
    fsemu_screenshot_lock();
    fsemu_screenshot.capture = true;
    if (path && path[0]) {
        snprintf(fsemu_screenshot.requested_path,
                 sizeof(fsemu_screenshot.requested_path), "%s", path);
    } else {
        fsemu_screenshot.requested_path[0] = '\0';
    }
    fsemu_screenshot_prepare_locked();
    fsemu_screenshot_unlock();
}

const char *fsemu_screenshot_last_path(void)
{
    static thread_local char path[FSEMU_PATH_MAX];
    fsemu_screenshot_lock();
    snprintf(path, sizeof(path), "%s", fsemu_screenshot.last_path);
    fsemu_screenshot_unlock();
    return path;
}

bool fsemu_screenshot_should_capture(void)
{
    fsemu_screenshot_lock();
    bool capture = fsemu_screenshot.capture;
    fsemu_screenshot_unlock();
    return capture;
}

void fsemu_screenshot_confirm_captured(void)
{
    fsemu_screenshot.capture = false;
}

/*
int fsemu_screenshot_crop(int *x, int *y, int *w, int *h)
{
    *x = fsemu_screenshot.crop[0];
    *y = fsemu_screenshot.crop[1];
    *w = fsemu_screenshot.crop[2];
    *h = fsemu_screenshot.crop[3];
    return (fsemu_screenshot.crop[2] && fsemu_screenshot.crop[3]);
}

void fsemu_screenshot_set_crop(int x, int y, int w, int h)
{
    fsemu_screenshot.crop[0] = x;
    fsemu_screenshot.crop[1] = y;
    fsemu_screenshot.crop[2] = w;
    fsemu_screenshot.crop[3] = h;
}
*/

/*
static const char *fsemu_screenshots_dir(void)
{
    const char *screenshots_dir = NULL;
    if (screenshots_dir != NULL) {
        return screenshots_dir;
    }
    if (fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR")[0]) {
        screenshots_dir = fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR");
    } else {
        screenshots_dir = "/tmp";
    }
    return screenshots_dir;
}
*/
static const char *fsemu_screenshot_prefix(void)
{
    fsapp_assert(fsemu_screenshot.initialized);

    if (fsemu_screenshot.prefix == NULL) {
        if (fsapp_util_get_env("FSEMU_SCREENSHOTS_PREFIX")[0]) {
            fsemu_screenshot.prefix = strdup(fsapp_util_get_env("FSEMU_SCREENSHOTS_PREFIX"));
        } else if (fsemu_application_name()) {
            fsemu_screenshot.prefix = strdup(fsemu_application_name());
        } else {
            fsemu_screenshot.prefix = strdup("FS-Emu");
        }
    }
    //     return screenshots_base;
    // }
    // if (fsapp_util_get_env("FSEMU_SCREENSHOTS_prefix")[0]) {
    //     screenshots_base = fsapp_util_get_env("FSEMU_SCREENSHOTS_prefix");
    // } else {
    //     screenshots_base = "screenshot";
    // }

    return fsemu_screenshot.prefix;
}

const char *fsemu_screenshot_path(void)
{
    return fsemu_screenshot_path_for_type("");
}

const char *fsemu_screenshot_dir(void)
{
    fsapp_assert(fsemu_screenshot.initialized);

    if (fsemu_screenshot.screenshots_dir == NULL) {
        if (fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR")[0]) {
            fsemu_screenshot.screenshots_dir = strdup(fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR"));
        } else {
            const char *app_base_dir = fsemu_application_base_dir();
            // const char *app_data_dir = fsemu_application_data_dir();
            fsemu_screenshot.screenshots_dir = FS_JoinPath(app_base_dir, "Screenshots");
        }
        fsemu_screenshot_log("Using screenshots directory: %s\n", fsemu_screenshot.screenshots_dir);

        if (!FS_IsDirectory(fsemu_screenshot.screenshots_dir)) {
            int error = g_mkdir_with_parents(fsemu_screenshot.screenshots_dir, 0755);
            if (error) {
                fsemu_application_log_warning("Could not create screenshots directory %s\n",
                                              fsemu_screenshot.screenshots_dir);
            }
        }
    }

    return fsemu_screenshot.screenshots_dir;
}

// FIXME: Deprecated
const char *fsemu_screenshot_path_for_type(const char *type)
{
    int counter = 0;
    static char buffer[FSEMU_PATH_MAX];
    const char *base = fsemu_screenshot_prefix();
    const char *dir = fsemu_screenshot_dir();
    // time_t tm1;
    // time(&tm1);
    // struct tm *tm2 = localtime(&tm1);
    // static char time_buffer[64];
    // strftime(time_buffer, 64 - 1, "%y%m%d%H%M", tm2);
    // time_buffer[64 - 1] = '\0';
    while (true) {
        if (type && type[0]) {
            snprintf(buffer, FSEMU_PATH_MAX - 1, "%s/%s_%s_%s_%02d.png", dir, base, type,
                     fsemu_screenshot.time_str, counter);
        } else {
            snprintf(buffer, FSEMU_PATH_MAX - 1, "%s/%s_%s_%02d.png", dir, base,
                     fsemu_screenshot.time_str, counter);
        }
        buffer[FSEMU_PATH_MAX - 1] = '\0';
        if (SDL_GetPathInfo(buffer, NULL)) {
            counter += 1;
        } else {
            break;
        }
    }
    fsemu_screenshot.last_counter = counter;
    fsemu_screenshot_log("Screenshot: %s\n", buffer);
    return buffer;
}

// FIXME: Move to fsemu-video
static SDL_Surface *fsemu_video_surface_from_frame(fsemu_video_frame_t *frame)
{
    fsapp_assert(frame->depth == 16 || frame->depth == 32);
    int pitch = frame->stride > 0 ? frame->stride
                                  : (frame->width * frame->depth / 8);
    // FIXME: We should definitively have frame->format!
    SDL_PixelFormat format;
    if (frame->depth == 16) {
        format = SDL_PIXELFORMAT_RGB565;
    } else if (frame->depth == 32) {
#ifdef FSEMU_CPU_BIGENDIAN
        uint32_t set_alpha = 0x000000ff;
#else
        uint32_t set_alpha = 0xff000000;
#endif
        format = SDL_PIXELFORMAT_BGRA32;
        // We're really using RGBx, not RGBA, so make sure to set alpha value
        // to full intensity.
        uint32_t *pixels = (uint32_t *)frame->buffer;
        for (int y = 0; y < frame->height; y++) {
            for (int x = 0; x < frame->width; x++) {
                pixels[x] |= set_alpha;
            }
            pixels += pitch / 4;
        }
    } else {
        fsapp_assert(false);
        // Should not happen, depth should be either 16 or 32
        return NULL;
    }

    fsemu_screenshot_log_debug("width %d height %d depth %d pitch %d format %d\n", frame->width,
                               frame->height, frame->depth, pitch, (int)format);
    SDL_Surface *surface =
        SDL_CreateSurfaceFrom(frame->width, frame->height, format, frame->buffer, pitch);
    return surface;
}

// ----------------------------------------------------------------------

void fsemu_screenshot_capture_video_frame(fsemu_video_frame_t *frame)
{
    fsemu_screenshot_lock();
    if (!fsemu_screenshot.capture) {
        fsemu_screenshot_unlock();
        return;
    }

    // For simplicity (?) we always generate 32-bit PNG screenshots
    SDL_Surface *dst = SDL_CreateSurface(frame->width, frame->height, SDL_PIXELFORMAT_RGBA32);
    // SDL_Surface *dst = SDL_CreateRGBSurfaceWithFormat(
    //      0, frame->width, frame->height, 32, SDL_PIXELFORMAT_RGBX8888);
    SDL_Surface *src = fsemu_video_surface_from_frame(frame);
    SDL_Rect rect = {0, 0, frame->width, frame->height};
    bool converted = src && dst && SDL_BlitSurface(src, &rect, dst, &rect);

    const char *path;
    if (fsemu_screenshot.requested_path[0]) {
        path = fsemu_screenshot.requested_path;
    } else {
        path = fsemu_screenshot_path_for_type("Full");
    }
    if (converted && fsapp_bitmap_save_png_file_from_rgba_data(
            path, dst->pixels, frame->width, frame->height) == 0) {
        snprintf(fsemu_screenshot.last_path, sizeof(fsemu_screenshot.last_path),
                 "%s", path);
    }
    fsemu_screenshot.requested_path[0] = '\0';
    SDL_DestroySurface(src);
    SDL_DestroySurface(dst);
    fsemu_screenshot.capture = false;
    free(fsemu_screenshot.time_str);
    fsemu_screenshot.time_str = NULL;
    fsemu_screenshot_unlock();
}

// ----------------------------------------------------------------------

static void fsemu_screenshot_quit(void)
{
}

// ----------------------------------------------------------------------------


// ----------------------------------------------------------------------------
// Debug command server (loopback TCP). Enabled with --debug_server=1 or
// --debug_server_port=<port>. It is intentionally opt-in.

#ifndef _WIN32

#include "fsemu-frame.h"
#include "fsemu-quit.h"

extern "C" void cracker_uae_debug_regs(char *out, int size);
extern "C" int cracker_uae_debug_readmem(unsigned int addr, unsigned char *out,
                                          int len);
extern "C" void fsuae_messages_post_insert_floppy(const char *path);
extern "C" void fsuae_messages_post_reset(void);
extern "C" bool fsuae_messages_post_libtrace(const char *command);
extern "C" int cracker_uae_debug_command(const char *command, char *out, int size);
extern "C" void cracker_uae_debug_release(void);

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define DBG_PATH_MAX FSEMU_PATH_MAX

static void dbg_reply(int fd, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);
    int n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (n < 0) {
        va_end(ap);
        return;
    }
    std::vector<char> buf((size_t)n + 1);
    vsnprintf(buf.data(), buf.size(), fmt, ap);
    va_end(ap);
    // Preserve framing for large native debugger dumps. Dot-stuff payload
    // lines so a literal '.' from the console cannot terminate a response.
    std::string wire;
    bool start = true;
    for (int i = 0; i < n; i++) {
        if (start && buf[i] == '.') wire += '.';
        wire += buf[i];
        start = buf[i] == '\n';
    }
    if (!start) wire += '\n';
    wire += ".\n";
    size_t sent = 0;
    while (sent < wire.size()) {
        ssize_t written = send(fd, wire.data() + sent, wire.size() - sent, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        sent += written;
    }
}

static int dbg_read_line(int fd, char *buf, int size)
{
    int n = 0;
    bool overflow = false;
    while (1) {
        char c;
        int r = recv(fd, &c, 1, 0);
        if (r <= 0) {
            return -1;
        }
        if (c == '\n') {
            break;
        }
        if (c != '\r') {
            if (n < size - 1) buf[n++] = c;
            else overflow = true;
        }
    }
    buf[n] = '\0';
    return overflow ? -2 : n;
}

static void dbg_ensure_parent_dir(const char *path)
{
    char *dir = g_path_get_dirname(path);
    if (dir && strcmp(dir, ".") != 0 && strcmp(dir, "/") != 0) {
        g_mkdir_with_parents(dir, 0755);
    }
    g_free(dir);
}

static void *dbg_client_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    char line[10000]; // same line capacity as the native debugger console
    dbg_reply(fd, "OK cracker-uae debug server ready");
    while (1) {
        int length = dbg_read_line(fd, line, sizeof(line));
        if (length == -2) {
            dbg_reply(fd, "ERR command exceeds 9999 bytes; discarded");
            continue;
        }
        if (length < 0) break;
        if (!strncasecmp(line, "ping", 4)) {
            dbg_reply(fd, "PONG");
        } else if (!strncasecmp(line, "help", 4)) {
            dbg_reply(fd,
                      "OK commands: ping, help, frames, regs, mem <hexaddr> <len>, "
                      "floppy <path>, reset, libtrace config|output|task|enable <value>, "
                      "debug [UAE command|status|detach], screenshot [path], quit");
        } else if (!strncmp(line, "debug", 5) && (!line[5] || line[5] == ' ')) {
            const char *command = line + 5;
            while (*command == ' ') command++;
            if (!strcmp(command, "detach")) {
                cracker_uae_debug_release();
                dbg_reply(fd, "OK debug release requested");
            } else {
                std::vector<char> output(256 * 1024 + 1024, 0);
                cracker_uae_debug_command(command, output.data(), output.size());
                dbg_reply(fd, "%s", output.data());
            }
        } else if (!strncasecmp(line, "frames", 6)) {
            dbg_reply(fd, "OK frames %d", fsemu_frame_counter());
        } else if (!strncasecmp(line, "regs", 4)) {
            char rb[1024];
            cracker_uae_debug_regs(rb, sizeof(rb));
            dbg_reply(fd, "OK regs\n%s", rb);
        } else if (!strncasecmp(line, "mem", 3)) {
            unsigned int addr = 0;
            int len = 0;
            if (sscanf(line, "mem %x %d", &addr, &len) == 2 && len > 0) {
                if (len > 256) {
                    len = 256;
                }
                unsigned char mbuf[256];
                char out[8192];
                int pos = 0;
                cracker_uae_debug_readmem(addr, mbuf, len);
                for (int i = 0; i < len; i += 16) {
                    pos += snprintf(out + pos, sizeof(out) - pos, "%08X:", addr + i);
                    for (int j = 0; j < 16 && i + j < len; j++) {
                        pos += snprintf(out + pos, sizeof(out) - pos, " %02X", mbuf[i + j]);
                    }
                    pos += snprintf(out + pos, sizeof(out) - pos, "\n");
                }
                dbg_reply(fd, "OK mem %08X %d\n%s", addr, len, out);
            } else {
                dbg_reply(fd, "ERR usage: mem <hexaddr> <len>");
            }
        } else if (!strncasecmp(line, "floppy", 6)) {
            char *p = line + 6;
            while (*p == ' ') {
                p++;
            }
            if (*p) {
                fsuae_messages_post_insert_floppy(p);
                dbg_reply(fd, "OK floppy %s", p);
            } else {
                dbg_reply(fd, "ERR usage: floppy <path>");
            }
        } else if (!strncasecmp(line, "reset", 5)) {
            cracker_uae_debug_release();
            fsuae_messages_post_reset();
            dbg_reply(fd, "OK reset");
        } else if (!strncmp(line, "libtrace ", 9)) {
            const char *arg = line + 9;
            bool valid = (!strncmp(arg, "config ", 7) && arg[7]) ||
                         !strncmp(arg, "output ", 7) ||
                         !strncmp(arg, "task ", 5) ||
                         !strcmp(arg, "enable 0") || !strcmp(arg, "enable 1");
            if (!valid) {
                dbg_reply(fd, "ERR usage: libtrace config|output|task|enable <value>");
            } else if (!fsuae_messages_post_libtrace(arg)) {
                dbg_reply(fd, "ERR emulation channel not ready");
            } else {
                dbg_reply(fd, "OK libtrace control queued; reset to install configuration");
            }
        } else if (!strncasecmp(line, "screenshot", 10)) {
            std::lock_guard<std::mutex> request_lock(debug_snapshot_mutex);
            char *p = line + 10;
            while (*p == ' ') {
                p++;
            }
            const char *path = *p ? p : NULL;
            if (path) {
                dbg_ensure_parent_dir(path);
            }
            fsemu_screenshot_capture_to(path);
            {
                std::lock_guard<std::mutex> frame_lock(debug_frame_mutex);
                if (!debug_frame_pixels.empty()) {
                    fsemu_screenshot_capture_video_frame(&debug_frame);
                }
            }
            for (int i = 0; i < 5000 && fsemu_screenshot_should_capture(); i++) {
                SDL_Delay(1);
            }
            if (fsemu_screenshot_should_capture()) {
                dbg_reply(fd, "ERR screenshot timeout");
            } else {
                const char *saved = fsemu_screenshot_last_path();
                if (saved && saved[0]) {
                    dbg_reply(fd, "OK screenshot %s", saved);
                } else {
                    dbg_reply(fd, "ERR screenshot failed");
                }
            }
        } else if (!strncasecmp(line, "quit", 4) ||
                   !strncasecmp(line, "exit", 4)) {
            dbg_reply(fd, "OK quitting");
            cracker_uae_debug_release();
            fsemu_quit_maybe();
            break;
        } else if (line[0]) {
            dbg_reply(fd, "ERR unknown command");
        }
    }
    close(fd);
    return NULL;
}

static void *dbg_listen_thread(void *arg)
{
    int lfd = (int)(intptr_t)arg;
    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, dbg_client_thread,
                           (void *)(intptr_t)cfd) == 0) {
            pthread_detach(th);
        } else {
            close(cfd);
        }
    }
    return NULL;
}

static void fsemu_debug_server_init(void)
{
    static bool started = false;
    if (started) {
        return;
    }
    int port = fsemu_option_int_default(FSEMU_OPTION_DEBUG_SERVER_PORT, 0);
    int enabled = fsemu_option_enabled(FSEMU_OPTION_DEBUG_SERVER) || port > 0;
    if (!enabled) {
        const char *env_enabled = getenv("CRACKER_UAE_DEBUG_SERVER");
        const char *env_port = getenv("CRACKER_UAE_DEBUG_SERVER_PORT");
        if (env_enabled && env_enabled[0] && strcmp(env_enabled, "0") != 0) {
            enabled = 1;
        }
        if (env_port && env_port[0]) {
            port = atoi(env_port);
            enabled = 1;
        }
    }
    if (!enabled) {
        return;
    }
    if (port <= 0) {
        port = 23456;
    }
    started = true;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        fsemu_screenshot_log("Debug server: socket() failed: %s\n", strerror(errno));
        return;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fsemu_screenshot_log("Debug server: bind 127.0.0.1:%d failed: %s\n", port, strerror(errno));
        close(lfd);
        return;
    }
    listen(lfd, 4);
    debug_frame_cache_enabled = true;
    fsemu_screenshot_log("Debug server listening on 127.0.0.1:%d\n", port);
    pthread_t th;
    if (pthread_create(&th, NULL, dbg_listen_thread,
                       (void *)(intptr_t)lfd) == 0) {
        pthread_detach(th);
    }
}

#else

static void fsemu_debug_server_init(void)
{
}

#endif // !_WIN32


void fsemu_screenshot_init(void)
{
    if (FSEMU_MODULE_INIT(screenshot)) {
        return;
    }
    fsemu_application_init();

    fsemu_screenshot.mutex = SDL_CreateMutex();

    const char *prefix = fsemu_option_const_string(FSEMU_OPTION_SCREENSHOTS_OUTPUT_PREFIX);
    if (prefix) {
        fsemu_screenshot.prefix = g_strdup(prefix);
    } else {
        // The program's name (fsemu_application_set_name), which it sets before the video starts.
        fsemu_screenshot.prefix = strdup(fsemu_application_name());
    }

    // if (fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR")[0]) {
    //     fsemu_screenshot.screenshots_dir =
    //         strdup(fsapp_util_get_env("FSEMU_SCREENSHOTS_DIR"));
    // } else {
    //     const char *app_base_dir = fsemu_application_base_dir();
    //     // const char *app_data_dir = fsemu_application_data_dir();
    //     fsemu_screenshot.screenshots_dir =
    //         g_build_filename(app_base_dir, "Screenshots", NULL);
    // }
    // fsemu_screenshot_log("Using screenshots directory: %s\n",
    //                      fsemu_screenshot.screenshots_dir);

    fsemu_debug_server_init();
}
