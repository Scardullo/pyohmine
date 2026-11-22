/* Clock overlay: a layer-shell label with the full date and time, shown just below waybar's clock
 * module. Same placement rules as claude-osd / volume-osd (overlay layer, never takes the keyboard,
 * reserves no space, lets clicks through), and the same look as the theme switchers' name label
 * (rofi-name-label): 30pt BigBlueTermPlus, theme background, accent text and border.
 *
 *     Sunday, November 22, 2026
 *         3:45:07 PM
 *
 * Shows when:
 *   - the pointer is over waybar's clock module (polled from Hyprland's socket, the module found
 *     through waybar's accessibility tree by its "HH:MM AM" text), for as long as it stays there
 *     plus HOVER_MS;
 *   - it gets SIGUSR1 (`pkill -USR1 -x clock-osd`, bound to SUPER+T in hyprland.lua and the
 *     module's on-click): toggles it on the focused monitor, for up to PINNED_MS.
 *
 * Colors come from ~/.local/bin/volume-osd-colors (the active theme's palette), re-read on each show.
 *
 * Build: gcc -O2 clock-osd.c -o ~/.local/bin/clock-osd -lm \
 *            $(pkg-config --cflags --libs gtk-layer-shell-0 gtk+-3.0 atspi-2 json-glib-1.0)
 */
#include <gtk/gtk.h>
#include <gtk-layer-shell.h>
#include <atspi/atspi.h>
#include <json-glib/json-glib.h>
#include <glib-unix.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FONT        "30pt \"BigBlueTermPlus Nerd Font Mono\""   /* same as rofi-name-label */
#define GAP_BELOW   6      /* px between the bar and the overlay */
#define EDGE_MARGIN 10     /* keep this far from the monitor's sides */
#define HOVER_MS    300    /* how long it stays up after the pointer leaves the module */
#define PINNED_MS   10000  /* how long a keybind toggle keeps it up */
#define POLL_MS     100    /* pointer poll interval */

#define DATE_ICON "\U000f00ed"   /* nf-md-calendar */
#define TIME_ICON "\U000f0954"   /* nf-md-clock_outline */

typedef struct { char name[64]; int x, y, w, h, bar; gboolean focused; } Mon;
typedef struct { int frame_w, x, w; } Mod;

static Mon mons[8];
static int nmons;
static gint64 mons_at;
static Mod mods[8];
static int nmods;
static gint64 mods_at;

static GtkWidget *win, *box, *date_lbl, *time_lbl;
static GtkCssProvider *css;
static char cur_mon[64];
static gint64 visible_until;
static gboolean was_in_bar;
static GRegex *clock_re;

/* ---------- Hyprland ---------- */

static JsonNode *hypr(const char *cmd) {
    const char *rt = g_getenv("XDG_RUNTIME_DIR"), *sig = g_getenv("HYPRLAND_INSTANCE_SIGNATURE");
    if (!rt || !sig) return NULL;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s/hypr/%s/.socket.sock", rt, sig);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;
    struct timeval tv = { 0, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0 || write(fd, cmd, strlen(cmd)) < 0) {
        close(fd);
        return NULL;
    }
    GString *s = g_string_new(NULL);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) g_string_append_len(s, buf, n);
    close(fd);
    JsonNode *node = json_from_string(s->str, NULL);
    g_string_free(s, TRUE);
    return node;
}

static double num(JsonObject *o, const char *key) {
    JsonNode *n = o ? json_object_get_member(o, key) : NULL;
    if (!n || !JSON_NODE_HOLDS_VALUE(n)) return 0;
    GType t = json_node_get_value_type(n);
    return t == G_TYPE_INT64 ? json_node_get_int(n) : t == G_TYPE_DOUBLE ? json_node_get_double(n) : 0;
}

static void load_monitors(void) {
    JsonNode *n = hypr("j/monitors");
    if (!n) return;
    if (JSON_NODE_HOLDS_ARRAY(n)) {
        JsonArray *arr = json_node_get_array(n);
        nmons = 0;
        for (guint i = 0; i < json_array_get_length(arr) && nmons < 8; i++) {
            JsonObject *o = json_array_get_object_element(arr, i);
            Mon *m = &mons[nmons++];
            double scale = num(o, "scale");
            if (scale <= 0) scale = 1;
            int w = num(o, "width"), h = num(o, "height");
            if ((int)num(o, "transform") % 2) { int t = w; w = h; h = t; }
            m->w = lround(w / scale);
            m->h = lround(h / scale);
            m->x = num(o, "x");
            m->y = num(o, "y");
            JsonArray *r = json_object_get_array_member(o, "reserved");
            m->bar = (r && json_array_get_length(r) > 1) ? json_array_get_int_element(r, 1) : 0;
            m->focused = json_object_get_boolean_member(o, "focused");
            g_strlcpy(m->name, json_object_get_string_member(o, "name"), sizeof m->name);
        }
    }
    json_node_unref(n);
    mons_at = g_get_monotonic_time();
}

static Mon *monitor_at(int x, int y) {
    for (int i = 0; i < nmons; i++)
        if (x >= mons[i].x && x < mons[i].x + mons[i].w && y >= mons[i].y && y < mons[i].y + mons[i].h)
            return &mons[i];
    return NULL;
}

static Mon *focused_monitor(void) {
    for (int i = 0; i < nmons; i++) if (mons[i].focused) return &mons[i];
    return nmons ? &mons[0] : NULL;
}

/* ---------- waybar's clock module, via accessibility ---------- */

static void find_label(AtspiAccessible *a, int frame_w, int depth) {
    if (depth > 12 || nmods >= 8) return;
    if (atspi_accessible_get_role(a, NULL) == ATSPI_ROLE_LABEL) {
        gchar *name = atspi_accessible_get_name(a, NULL);
        if (name && g_regex_match(clock_re, name, 0, NULL)) {
            AtspiComponent *c = atspi_accessible_get_component_iface(a);
            if (c) {
                AtspiRect *e = atspi_component_get_extents(c, ATSPI_COORD_TYPE_WINDOW, NULL);
                if (e && e->width > 0) mods[nmods++] = (Mod){ frame_w, e->x, e->width };
                g_free(e);
                g_object_unref(c);
            }
        }
        g_free(name);
        return;
    }
    int k = atspi_accessible_get_child_count(a, NULL);
    for (int i = 0; i < k; i++) {
        AtspiAccessible *ch = atspi_accessible_get_child_at_index(a, i, NULL);
        if (ch) { find_label(ch, frame_w, depth + 1); g_object_unref(ch); }
    }
}

static int waybar_pids(guint *pids, int max) {
    int n = 0;
    GDir *d = g_dir_open("/proc", 0, NULL);
    if (!d) return 0;
    const char *e;
    while ((e = g_dir_read_name(d)) && n < max) {
        if (!g_ascii_isdigit(e[0])) continue;
        g_autofree char *path = g_strdup_printf("/proc/%s/comm", e), *comm = NULL;
        if (g_file_get_contents(path, &comm, NULL, NULL) && strcmp(g_strchomp(comm), "waybar") == 0)
            pids[n++] = strtoul(e, NULL, 10);
    }
    g_dir_close(d);
    return n;
}

/* Only waybar is ever queried (see claude-osd.c for why). */
static void load_modules(void) {
    nmods = 0;
    mods_at = g_get_monotonic_time();
    guint pids[8];
    int npids = waybar_pids(pids, 8);
    if (!npids) return;
    AtspiAccessible *desk = atspi_get_desktop(0);
    if (!desk) return;
    int napps = atspi_accessible_get_child_count(desk, NULL);
    for (int i = 0; i < napps; i++) {
        AtspiAccessible *app = atspi_accessible_get_child_at_index(desk, i, NULL);
        if (!app) continue;
        guint pid = atspi_accessible_get_process_id(app, NULL);
        gboolean is_waybar = FALSE;
        for (int p = 0; p < npids; p++) if (pids[p] == pid) is_waybar = TRUE;
        if (is_waybar) {
            int nf = atspi_accessible_get_child_count(app, NULL);
            for (int f = 0; f < nf; f++) {
                AtspiAccessible *frame = atspi_accessible_get_child_at_index(app, f, NULL);
                if (!frame) continue;
                AtspiComponent *c = atspi_accessible_get_component_iface(frame);
                if (c) {
                    AtspiRect *e = atspi_component_get_extents(c, ATSPI_COORD_TYPE_SCREEN, NULL);
                    if (e) find_label(frame, e->width, 0);
                    g_free(e);
                    g_object_unref(c);
                }
                g_object_unref(frame);
            }
        }
        g_object_unref(app);
    }
    g_object_unref(desk);
}

static Mod *module_for(Mon *m) {
    for (int i = 0; i < nmods; i++) if (mods[i].frame_w == m->w) return &mods[i];
    return NULL;
}

/* ---------- overlay ---------- */

static void update_text(void) {
    time_t t = time(NULL);
    struct tm lt;
    localtime_r(&t, &lt);
    char d[64], h[32];
    strftime(d, sizeof d, "%A, %B %-d, %Y", &lt);
    strftime(h, sizeof h, "%I:%M:%S %p", &lt);
    g_autofree char *ds = g_strdup_printf(DATE_ICON "  %s", d);
    g_autofree char *hs = g_strdup_printf(TIME_ICON "  %s", h[0] == '0' ? h + 1 : h);
    gtk_label_set_text(GTK_LABEL(date_lbl), ds);
    gtk_label_set_text(GTK_LABEL(time_lbl), hs);
}

static void load_theme(void) {
    gchar *out = NULL;
    gchar *cmd = g_build_filename(g_get_home_dir(), ".local/bin/volume-osd-colors", NULL);
    char bg[32] = "#14141c", fg[32] = "#e8e8f0", acc[32] = "#8aadf4";
    int r = 12;
    if (g_spawn_command_line_sync(cmd, &out, NULL, NULL, NULL) && out)
        sscanf(out, "%31s %31s %31s %d", bg, fg, acc, &r);
    g_free(out);
    g_free(cmd);
    /* Same rules as rofi-name-popup's label: radius 14, or 0 when hyprland rounding is 0. */
    g_autofree char *style = g_strdup_printf(
        "window { background: transparent; }"
        "#osd { background: %s; border: 2px solid %s; border-radius: %dpx; padding: 16px 40px; }"
        "label { font: " FONT "; color: %s; }",
        bg, acc, r > 0 ? 14 : 0, acc);
    gtk_css_provider_load_from_data(css, style, -1, NULL);
}

static GdkMonitor *gdk_monitor_for(Mon *m) {
    GdkDisplay *d = gdk_display_get_default();
    for (int i = 0; i < gdk_display_get_n_monitors(d); i++) {
        GdkMonitor *gm = gdk_display_get_monitor(d, i);
        GdkRectangle g;
        gdk_monitor_get_geometry(gm, &g);
        if (g.x == m->x && g.y == m->y) return gm;
    }
    return NULL;
}

/* Centre the overlay under the clock module of monitor m (or the monitor's centre if not found). */
static void place(Mon *m) {
    int w = 0;
    gtk_widget_get_preferred_width(box, NULL, &w);
    Mod *md = module_for(m);
    int left = (md ? md->x + md->w / 2 : m->w / 2) - w / 2;
    left = CLAMP(left, EDGE_MARGIN, MAX(EDGE_MARGIN, m->w - w - EDGE_MARGIN));
    gtk_layer_set_margin(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, left);
}

static void show_on(Mon *m, int ms) {
    gboolean visible = gtk_widget_get_visible(win);
    if (visible && strcmp(cur_mon, m->name) != 0) { gtk_widget_hide(win); visible = FALSE; }
    if (!visible) {
        load_theme();
        update_text();
        gtk_layer_set_monitor(GTK_WINDOW(win), gdk_monitor_for(m));
        g_strlcpy(cur_mon, m->name, sizeof cur_mon);
    }
    gtk_window_resize(GTK_WINDOW(win), 1, 1);   /* shrink to fit */
    place(m);
    if (!visible) gtk_widget_show(win);

    gint64 until = g_get_monotonic_time() + (gint64)ms * 1000;
    if (until > visible_until) visible_until = until;
}

static void hide(void) {
    gtk_widget_hide(win);
    visible_until = 0;
}

static gboolean on_toggle(gpointer data) {
    if (gtk_widget_get_visible(win)) { hide(); return G_SOURCE_CONTINUE; }
    load_monitors();
    load_modules();
    Mon *m = focused_monitor();
    if (m) show_on(m, PINNED_MS);
    return G_SOURCE_CONTINUE;
}

static gboolean tick(gpointer data) {
    gint64 now = g_get_monotonic_time();
    if (now - mons_at > 2 * G_USEC_PER_SEC) load_monitors();

    JsonNode *n = hypr("j/cursorpos");
    if (n && JSON_NODE_HOLDS_OBJECT(n)) {
        JsonObject *o = json_node_get_object(n);
        int cx = num(o, "x"), cy = num(o, "y");
        Mon *m = monitor_at(cx, cy);
        gboolean in_bar = m && m->bar > 0 && cy - m->y < m->bar;
        if (in_bar) {
            if (!was_in_bar || now - mods_at > G_USEC_PER_SEC) load_modules();
            Mod *md = module_for(m);
            int lx = cx - m->x;
            if (md && lx >= md->x && lx < md->x + md->w) show_on(m, HOVER_MS);
        }
        was_in_bar = in_bar;
    }
    if (n) json_node_unref(n);

    if (gtk_widget_get_visible(win)) {
        if (now >= visible_until) hide();
        else update_text();
    }
    return G_SOURCE_CONTINUE;
}

static void on_realize(GtkWidget *w, gpointer data) {
    cairo_region_t *empty = cairo_region_create();
    gtk_widget_input_shape_combine_region(w, empty);
    cairo_region_destroy(empty);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    g_autofree char *lock = g_build_filename(g_get_user_runtime_dir(), "clock-osd.lock", NULL);
    int lfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX | LOCK_NB) < 0) return 0;

    /* waybar's clock text, e.g. "03:45 PM" or "15:45" */
    clock_re = g_regex_new("^\\s*\\d{1,2}:\\d{2}(:\\d{2})?(\\s*[AaPp][Mm])?\\s*$", 0, 0, NULL);

    gtk_init(&argc, &argv);
    atspi_init();
    atspi_set_timeout(500, 2000);

    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_namespace(GTK_WINDOW(win), "clock-osd");
    gtk_layer_set_layer(GTK_WINDOW(win), GTK_LAYER_SHELL_LAYER_OVERLAY);
    gtk_layer_set_keyboard_mode(GTK_WINDOW(win), GTK_LAYER_SHELL_KEYBOARD_MODE_NONE);
    gtk_layer_set_exclusive_zone(GTK_WINDOW(win), 0);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_TOP, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, TRUE);
    gtk_layer_set_margin(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_TOP, GAP_BELOW);
    gtk_widget_set_app_paintable(win, TRUE);
    GdkVisual *rgba = gdk_screen_get_rgba_visual(gtk_widget_get_screen(win));
    if (rgba) gtk_widget_set_visual(win, rgba);
    g_signal_connect(win, "realize", G_CALLBACK(on_realize), NULL);

    css = gtk_css_provider_new();
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
                                              GTK_STYLE_PROVIDER_PRIORITY_USER);

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_name(box, "osd");
    date_lbl = gtk_label_new(NULL);
    time_lbl = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(box), date_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), time_lbl, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(win), box);
    load_theme();
    update_text();
    gtk_widget_show_all(box);
    gtk_widget_realize(win);

    load_monitors();
    g_unix_signal_add(SIGUSR1, on_toggle, NULL);
    g_timeout_add(POLL_MS, tick, NULL);

    gtk_main();
    return 0;
}
