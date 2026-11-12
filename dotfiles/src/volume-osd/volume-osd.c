/* Volume overlay: a small layer-shell panel (icon + horizontal bar filled to the current volume)
 * that appears just below waybar's volume module, on the overlay layer. It never takes the
 * keyboard, reserves no space, and lets clicks through, so Hyprland's windows are unaffected.
 *
 * Shows when:
 *   - the default sink's volume or mute changes (libpulse, works with pipewire-pulse), on the
 *     focused monitor, for SHOW_MS;
 *   - the pointer is over waybar's volume module. Waybar has no hover hook, so the module's
 *     position is read from waybar's accessibility tree (the label starting with a volume icon)
 *     and the pointer is polled from Hyprland's socket.
 *
 * Colors come from ~/.local/bin/volume-osd-colors (the active theme's palette), re-read each time
 * the overlay appears, so it follows theme changes.
 *
 * Build: gcc -O2 volume-osd.c -o ~/.local/bin/volume-osd -lm \
 *            $(pkg-config --cflags --libs gtk-layer-shell-0 gtk+-3.0 atspi-2 json-glib-1.0 \
 *                                         libpulse libpulse-mainloop-glib)
 */
#include <gtk/gtk.h>
#include <gtk-layer-shell.h>
#include <atspi/atspi.h>
#include <json-glib/json-glib.h>
#include <pulse/pulseaudio.h>
#include <pulse/glib-mainloop.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OSD_WIDTH   520
#define GAP_BELOW   6      /* px between the bar and the overlay */
#define EDGE_MARGIN 10     /* keep this far from the monitor's sides */
#define SHOW_MS     1500   /* how long it stays up after a volume change */
#define HOVER_MS    300    /* how long it stays up after the pointer leaves the module */
#define POLL_MS     100    /* pointer poll interval */
#define BAR_HEIGHT  20

/* Same icons as waybar's pulseaudio module (config.jsonc). */
#define ICON_LOW   ""
#define ICON_MID   ""
#define ICON_HIGH  ""
#define ICON_MUTED "\U000f0581"

typedef struct { char name[64]; int x, y, w, h, bar; gboolean focused; } Mon;
typedef struct { int frame_w, x, w; } Mod;   /* volume label in a waybar of width frame_w */

static Mon mons[8];
static int nmons;
static gint64 mons_at;
static Mod mods[8];
static int nmods;
static gint64 mods_at;

static GtkWidget *win, *icon, *bar_area;
static GtkCssProvider *css;
static GdkRGBA accent = { 0.54, 0.68, 0.96, 1 };
static int radius = 12;
static char cur_mon[64];
static gint64 visible_until;
static gboolean was_in_bar;

static double vol;
static gboolean muted, have_vol;
static pa_glib_mainloop *pa_ml;
static pa_context *pa_ctx;

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
    JsonNode *n = json_object_get_member(o, key);
    if (!n || !JSON_NODE_HOLDS_VALUE(n)) return 0;
    return json_node_get_value_type(n) == G_TYPE_INT64 ? json_node_get_int(n) : json_node_get_double(n);
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

/* ---------- waybar's volume module, via accessibility ---------- */

static gboolean is_volume_text(const char *t) {
    return g_str_has_prefix(t, ICON_LOW) || g_str_has_prefix(t, ICON_MID) ||
           g_str_has_prefix(t, ICON_HIGH) || g_str_has_prefix(t, ICON_MUTED);
}

static void find_label(AtspiAccessible *a, int frame_w, int depth) {
    if (depth > 12 || nmods >= 8) return;
    if (atspi_accessible_get_role(a, NULL) == ATSPI_ROLE_LABEL) {
        gchar *name = atspi_accessible_get_name(a, NULL);
        if (name && is_volume_text(name)) {
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

/* Only waybar is ever queried. The PID comes from the a11y bus daemon, not the app itself, so
 * other apps (Firefox in particular) never receive an AT-SPI call. Querying them would switch on
 * their accessibility engines, and Firefox's is slow enough to freeze it. */
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

/* Each waybar is matched to its monitor by width (layer surfaces have no global position). */
static Mod *module_for(Mon *m) {
    for (int i = 0; i < nmods; i++) if (mods[i].frame_w == m->w) return &mods[i];
    return NULL;
}

/* ---------- overlay ---------- */

static void load_theme(void) {
    gchar *out = NULL;
    gchar *cmd = g_build_filename(g_get_home_dir(), ".local/bin/volume-osd-colors", NULL);
    char bg[32] = "#14141c", fg[32] = "#e8e8f0", acc[32] = "#8aadf4";
    int r = 12;
    if (g_spawn_command_line_sync(cmd, &out, NULL, NULL, NULL) && out)
        sscanf(out, "%31s %31s %31s %d", bg, fg, acc, &r);
    g_free(out);
    g_free(cmd);
    radius = r;
    gdk_rgba_parse(&accent, acc);
    g_autofree char *style = g_strdup_printf(
        "window { background: transparent; }"
        "#osd { background: alpha(%s, 0.95); border: 4px solid %s; border-radius: %dpx;"
        " padding: 20px 32px; }"
        "#icon { color: %s; font: 32px \"JetBrainsMono Nerd Font\"; }",
        bg, acc, r * 2, acc);
    gtk_css_provider_load_from_data(css, style, -1, NULL);
}

static void update_icon(void) {
    const char *t = muted ? ICON_MUTED : vol < 1.0 / 3 ? ICON_LOW : vol < 2.0 / 3 ? ICON_MID : ICON_HIGH;
    gtk_label_set_text(GTK_LABEL(icon), t);
    gtk_widget_queue_draw(bar_area);
}

static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r) {
    if (r <= 0) { cairo_rectangle(cr, x, y, w, h); return; }
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -G_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, G_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, G_PI / 2, G_PI);
    cairo_arc(cr, x + r, y + r, r, G_PI, 3 * G_PI / 2);
    cairo_close_path(cr);
}

static gboolean draw_bar(GtkWidget *w, cairo_t *cr, gpointer data) {
    double W = gtk_widget_get_allocated_width(w), H = gtk_widget_get_allocated_height(w);
    double x = 2, y = floor((H - BAR_HEIGHT) / 2) + 2, bw = W - 4, bh = BAR_HEIGHT - 4;
    double r = radius > 0 ? bh / 2 : 0;
    double frac = CLAMP(vol, 0, 1);

    if (frac > 0) {   /* fill, clipped to the bar's shape */
        cairo_save(cr);
        rounded_rect(cr, x, y, bw, bh, r);
        cairo_clip(cr);
        cairo_rectangle(cr, x, y, bw * frac, bh);
        cairo_set_source_rgba(cr, accent.red, accent.green, accent.blue, muted ? 0.35 : 1);
        cairo_fill(cr);
        cairo_restore(cr);
    }
    rounded_rect(cr, x, y, bw, bh, r);   /* outline */
    gdk_cairo_set_source_rgba(cr, &accent);
    cairo_set_line_width(cr, 4);
    cairo_stroke(cr);
    return FALSE;
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

/* Put the overlay under the volume module of monitor m (or top-right if waybar isn't found). */
static void show_on(Mon *m, int ms) {
    Mod *md = module_for(m);
    int left = md ? md->x + md->w / 2 - OSD_WIDTH / 2 : m->w - OSD_WIDTH - EDGE_MARGIN;
    left = CLAMP(left, EDGE_MARGIN, MAX(EDGE_MARGIN, m->w - OSD_WIDTH - EDGE_MARGIN));

    gboolean visible = gtk_widget_get_visible(win);
    if (visible && strcmp(cur_mon, m->name) != 0) { gtk_widget_hide(win); visible = FALSE; }
    if (!visible) {
        load_theme();
        gtk_layer_set_monitor(GTK_WINDOW(win), gdk_monitor_for(m));
        g_strlcpy(cur_mon, m->name, sizeof cur_mon);
    }
    gtk_layer_set_margin(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, left);
    if (!visible) gtk_widget_show_all(win);

    gint64 until = g_get_monotonic_time() + (gint64)ms * 1000;
    if (until > visible_until) visible_until = until;
}

static void on_volume_change(void) {
    load_monitors();
    load_modules();   /* the label's width can change with the number */
    Mon *m = focused_monitor();
    if (m) show_on(m, SHOW_MS);
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

    if (gtk_widget_get_visible(win) && now >= visible_until) gtk_widget_hide(win);
    return G_SOURCE_CONTINUE;
}

/* Clicks go through the overlay to whatever is underneath. */
static void on_realize(GtkWidget *w, gpointer data) {
    cairo_region_t *empty = cairo_region_create();
    gtk_widget_input_shape_combine_region(w, empty);
    cairo_region_destroy(empty);
}

/* ---------- PulseAudio / PipeWire ---------- */

static void pa_connect(void);

static void sink_cb(pa_context *c, const pa_sink_info *i, int eol, void *u) {
    if (eol || !i) return;
    double v = (double)pa_cvolume_avg(&i->volume) / PA_VOLUME_NORM;
    gboolean mu = i->mute != 0;
    gboolean changed = have_vol && (fabs(v - vol) > 0.0005 || mu != muted);
    vol = v; muted = mu; have_vol = TRUE;
    update_icon();
    if (changed) on_volume_change();
}

static void server_cb(pa_context *c, const pa_server_info *i, void *u) {
    if (i && i->default_sink_name)
        pa_operation_unref(pa_context_get_sink_info_by_name(c, i->default_sink_name, sink_cb, NULL));
}

static void pa_query(pa_context *c) { pa_operation_unref(pa_context_get_server_info(c, server_cb, NULL)); }

static void subscribe_cb(pa_context *c, pa_subscription_event_type_t t, uint32_t idx, void *u) { pa_query(c); }

static gboolean pa_retry(gpointer data) { pa_connect(); return G_SOURCE_REMOVE; }

static void state_cb(pa_context *c, void *u) {
    switch (pa_context_get_state(c)) {
    case PA_CONTEXT_READY:
        pa_context_set_subscribe_callback(c, subscribe_cb, NULL);
        pa_operation_unref(pa_context_subscribe(c, PA_SUBSCRIPTION_MASK_SINK | PA_SUBSCRIPTION_MASK_SERVER, NULL, NULL));
        pa_query(c);
        break;
    case PA_CONTEXT_FAILED:
    case PA_CONTEXT_TERMINATED:   /* audio server restarted: reconnect, without popping up */
        pa_context_unref(c);
        pa_ctx = NULL;
        have_vol = FALSE;
        g_timeout_add_seconds(2, pa_retry, NULL);
        break;
    default:
        break;
    }
}

static void pa_connect(void) {
    pa_ctx = pa_context_new(pa_glib_mainloop_get_api(pa_ml), "volume-osd");
    pa_context_set_state_callback(pa_ctx, state_cb, NULL);
    if (pa_context_connect(pa_ctx, NULL, PA_CONTEXT_NOFAIL, NULL) < 0) {
        pa_context_unref(pa_ctx);
        pa_ctx = NULL;
        g_timeout_add_seconds(2, pa_retry, NULL);
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    /* One instance only. */
    g_autofree char *lock = g_build_filename(g_get_user_runtime_dir(), "volume-osd.lock", NULL);
    int lfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX | LOCK_NB) < 0) return 0;

    gtk_init(&argc, &argv);
    atspi_init();
    atspi_set_timeout(500, 2000);

    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_namespace(GTK_WINDOW(win), "volume-osd");
    gtk_layer_set_layer(GTK_WINDOW(win), GTK_LAYER_SHELL_LAYER_OVERLAY);
    gtk_layer_set_keyboard_mode(GTK_WINDOW(win), GTK_LAYER_SHELL_KEYBOARD_MODE_NONE);
    gtk_layer_set_exclusive_zone(GTK_WINDOW(win), 0);   /* reserve nothing; sit below the bar */
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

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 28);
    gtk_widget_set_name(box, "osd");
    gtk_widget_set_size_request(box, OSD_WIDTH, -1);
    icon = gtk_label_new(ICON_HIGH);
    gtk_widget_set_name(icon, "icon");
    gtk_widget_set_size_request(icon, 44, -1);
    gtk_label_set_xalign(GTK_LABEL(icon), 0.5);
    bar_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(bar_area, TRUE);
    gtk_widget_set_size_request(bar_area, -1, 44);
    g_signal_connect(bar_area, "draw", G_CALLBACK(draw_bar), NULL);
    gtk_box_pack_start(GTK_BOX(box), icon, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), bar_area, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(win), box);
    gtk_widget_realize(win);

    load_monitors();
    pa_ml = pa_glib_mainloop_new(NULL);
    pa_connect();
    g_timeout_add(POLL_MS, tick, NULL);

    gtk_main();
    return 0;
}
