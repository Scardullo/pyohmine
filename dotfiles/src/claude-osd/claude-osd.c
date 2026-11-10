/* Claude usage overlay: a layer-shell panel listing the plan's usage limits (session, weekly, ...)
 * with a bar for each and when it resets. Same look and placement rules as volume-osd: it appears
 * just below waybar's Claude module (custom/claude, the label starting with ✻), on the overlay
 * layer, never takes the keyboard, reserves no space and lets clicks through.
 *
 * Shows when:
 *   - the pointer is over waybar's Claude module (polled from Hyprland's socket, the module found
 *     through waybar's accessibility tree), for as long as it stays there plus HOVER_MS;
 *   - it gets SIGUSR1 (`pkill -USR1 -x claude-osd`, bound in hyprland.lua and the module's
 *     on-click): toggles it on the focused monitor, for up to PINNED_MS.
 *
 * Data comes from ~/.local/bin/claude-usage, which caches it in $XDG_RUNTIME_DIR/claude-usage.json;
 * each time the overlay appears it asks for a refresh and re-reads the cache every second while up.
 * Colors come from ~/.local/bin/volume-osd-colors (the active theme's palette), re-read on each show.
 *
 * Build: gcc -O2 claude-osd.c -o ~/.local/bin/claude-osd -lm \
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

#define OSD_WIDTH   440
#define GAP_BELOW   6      /* px between the bar and the overlay */
#define EDGE_MARGIN 10     /* keep this far from the monitor's sides */
#define HOVER_MS    300    /* how long it stays up after the pointer leaves the module */
#define PINNED_MS   10000  /* how long a keybind toggle keeps it up */
#define POLL_MS     100    /* pointer poll interval */
#define BAR_HEIGHT  16
#define MAX_ROWS    4

#define ICON "\uE4A0"      /* Claude mascot, same glyph as the waybar module (claude-usage) */

typedef struct { char name[64]; int x, y, w, h, bar; gboolean focused; } Mon;
typedef struct { int frame_w, x, w; } Mod;

static Mon mons[8];
static int nmons;
static gint64 mons_at;
static Mod mods[8];
static int nmods;
static gint64 mods_at;

typedef struct { GtkWidget *box, *label, *pct, *bar, *reset; double frac; } Row;
static Row rows[MAX_ROWS];

static GtkWidget *win, *plan_lbl, *foot_lbl;
static GtkCssProvider *css;
static GdkRGBA accent = { 0.54, 0.68, 0.96, 1 };
static int radius = 12;
static char cur_mon[64];
static gint64 visible_until, data_at;
static gboolean was_in_bar, pinned;
static char *cache_path, *usage_cmd;

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

static const char *str(JsonObject *o, const char *key) {
    JsonNode *n = o ? json_object_get_member(o, key) : NULL;
    return (n && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING)
        ? json_node_get_string(n) : "";
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

/* ---------- waybar's Claude module, via accessibility ---------- */

static void find_label(AtspiAccessible *a, int frame_w, int depth) {
    if (depth > 12 || nmods >= 8) return;
    if (atspi_accessible_get_role(a, NULL) == ATSPI_ROLE_LABEL) {
        gchar *name = atspi_accessible_get_name(a, NULL);
        if (name && g_str_has_prefix(name, ICON)) {
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

static void load_modules(void) {
    nmods = 0;
    mods_at = g_get_monotonic_time();
    AtspiAccessible *desk = atspi_get_desktop(0);
    if (!desk) return;
    int napps = atspi_accessible_get_child_count(desk, NULL);
    for (int i = 0; i < napps; i++) {
        AtspiAccessible *app = atspi_accessible_get_child_at_index(desk, i, NULL);
        if (!app) continue;
        gchar *name = atspi_accessible_get_name(app, NULL);
        if (name && strcmp(name, "waybar") == 0) {
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
        g_free(name);
        g_object_unref(app);
    }
    g_object_unref(desk);
}

static Mod *module_for(Mon *m) {
    for (int i = 0; i < nmods; i++) if (mods[i].frame_w == m->w) return &mods[i];
    return NULL;
}

/* ---------- data ---------- */

static char *duration(gint64 s) {
    if (s <= 0) return g_strdup("now");
    gint64 d = s / 86400, h = s % 86400 / 3600, m = s % 3600 / 60;
    if (d) return g_strdup_printf("%" G_GINT64_FORMAT "d %" G_GINT64_FORMAT "h", d, h);
    if (h) return g_strdup_printf("%" G_GINT64_FORMAT "h %" G_GINT64_FORMAT "m", h, m);
    return g_strdup_printf("%" G_GINT64_FORMAT "m", MAX(m, 1));
}

/* "Resets 8:50 PM  ·  in 1h 34m", with the weekday when it isn't today ("Sat 8:00 AM"). */
static char *reset_text(gint64 at, gint64 now) {
    if (at <= 0) return g_strdup("Reset time unknown");
    time_t t = at, n = now;
    struct tm lt, ln;
    localtime_r(&t, &lt);
    localtime_r(&n, &ln);
    gboolean today = lt.tm_yday == ln.tm_yday && lt.tm_year == ln.tm_year;
    char day[16] = "", hm[16];
    if (!today) strftime(day, sizeof day, "%a ", &lt);
    strftime(hm, sizeof hm, "%I:%M %p", &lt);
    g_autofree char *in = duration(at - now);
    return g_strdup_printf("Resets %s%s  ·  in %s", day, hm[0] == '0' ? hm + 1 : hm, in);
}

static void load_data(void) {
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;
    JsonParser *p = json_parser_new();
    JsonObject *o = NULL;
    if (json_parser_load_from_file(p, cache_path, NULL) && JSON_NODE_HOLDS_OBJECT(json_parser_get_root(p)))
        o = json_node_get_object(json_parser_get_root(p));

    const char *plan = str(o, "plan");
    g_autofree char *plan_up = g_strdup(plan);
    if (plan_up[0]) plan_up[0] = g_ascii_toupper(plan_up[0]);
    gtk_label_set_text(GTK_LABEL(plan_lbl), plan_up);

    JsonArray *arr = (o && json_object_has_member(o, "rows")) ? json_object_get_array_member(o, "rows") : NULL;
    int n = arr ? MIN((int)json_array_get_length(arr), MAX_ROWS) : 0;
    for (int i = 0; i < MAX_ROWS; i++) {
        Row *r = &rows[i];
        if (i >= n) { gtk_widget_hide(r->box); continue; }
        JsonObject *ro = json_array_get_object_element(arr, i);
        double pct = num(ro, "percent");
        r->frac = CLAMP(pct / 100.0, 0, 1);
        gtk_label_set_text(GTK_LABEL(r->label), str(ro, "label"));
        g_autofree char *ps = g_strdup_printf("%.0f%%", pct);
        gtk_label_set_text(GTK_LABEL(r->pct), ps);
        g_autofree char *rs = reset_text((gint64)num(ro, "resets_at"), now);
        gtk_label_set_text(GTK_LABEL(r->reset), rs);
        GtkStyleContext *sc = gtk_widget_get_style_context(r->pct);
        gtk_style_context_remove_class(sc, "warn");
        gtk_style_context_remove_class(sc, "crit");
        if (pct >= 90) gtk_style_context_add_class(sc, "crit");
        else if (pct >= 70) gtk_style_context_add_class(sc, "warn");
        gtk_widget_show_all(r->box);
        gtk_widget_queue_draw(r->bar);
    }

    const char *err = str(o, "error");
    gint64 ok_at = (gint64)num(o, "ok_at");
    g_autofree char *foot = NULL;
    if (!o) foot = g_strdup("Loading…");
    else if (err[0] && !ok_at) foot = g_strdup(err);
    else {
        g_autofree char *d = duration(now - ok_at);
        g_autofree char *ago = now - ok_at < 60 ? g_strdup("just now") : g_strdup_printf("%s ago", d);
        foot = err[0] ? g_strdup_printf("%s  ·  updated %s", err, ago) : g_strdup_printf("Updated %s", ago);
    }
    gtk_label_set_text(GTK_LABEL(foot_lbl), foot);
    g_object_unref(p);
    data_at = g_get_monotonic_time();
}

static void refresh(void) {
    g_spawn_command_line_async(usage_cmd, NULL);   /* rewrites the cache; tick re-reads it */
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
        " padding: 18px 26px; }"
        "label { color: %s; font: 13px \"JetBrainsMono Nerd Font\"; }"
        "#icon { color: %s; font: 28px \"Claude Mascot\", \"JetBrainsMono Nerd Font\"; }"
        "#title { font-size: 16px; font-weight: bold; }"
        "#plan { color: %s; font-weight: bold; }"
        ".rowname { font-weight: bold; }"
        ".pct { color: %s; font-weight: bold; font-size: 15px; }"
        ".pct.warn { color: mix(%s, #e5c07b, 0.6); }"
        ".pct.crit { color: mix(%s, #e06c75, 0.7); }"
        ".reset, #foot { color: alpha(%s, 0.65); font-size: 12px; }",
        bg, acc, r * 2, fg, acc, acc, acc, acc, acc, fg);
    gtk_css_provider_load_from_data(css, style, -1, NULL);
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
    Row *row = data;
    double W = gtk_widget_get_allocated_width(w), H = gtk_widget_get_allocated_height(w);
    double x = 1.5, y = floor((H - BAR_HEIGHT) / 2) + 1.5, bw = W - 3, bh = BAR_HEIGHT - 3;
    double r = radius > 0 ? bh / 2 : 0;
    if (row->frac > 0) {
        cairo_save(cr);
        rounded_rect(cr, x, y, bw, bh, r);
        cairo_clip(cr);
        cairo_rectangle(cr, x, y, bw * row->frac, bh);
        gdk_cairo_set_source_rgba(cr, &accent);
        cairo_fill(cr);
        cairo_restore(cr);
    }
    rounded_rect(cr, x, y, bw, bh, r);
    gdk_cairo_set_source_rgba(cr, &accent);
    cairo_set_line_width(cr, 3);
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

/* Put the overlay under the Claude module of monitor m (or top-right if waybar isn't found). */
static void show_on(Mon *m, int ms) {
    Mod *md = module_for(m);
    int left = md ? md->x + md->w / 2 - OSD_WIDTH / 2 : m->w - OSD_WIDTH - EDGE_MARGIN;
    left = CLAMP(left, EDGE_MARGIN, MAX(EDGE_MARGIN, m->w - OSD_WIDTH - EDGE_MARGIN));

    gboolean visible = gtk_widget_get_visible(win);
    if (visible && strcmp(cur_mon, m->name) != 0) { gtk_widget_hide(win); visible = FALSE; }
    if (!visible) {
        load_theme();
        load_data();
        refresh();
        gtk_layer_set_monitor(GTK_WINDOW(win), gdk_monitor_for(m));
        g_strlcpy(cur_mon, m->name, sizeof cur_mon);
    }
    gtk_layer_set_margin(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, left);
    if (!visible) gtk_widget_show(win);

    gint64 until = g_get_monotonic_time() + (gint64)ms * 1000;
    if (until > visible_until) visible_until = until;
}

static void hide(void) {
    gtk_widget_hide(win);
    pinned = FALSE;
    visible_until = 0;
}

static gboolean on_toggle(gpointer data) {
    if (gtk_widget_get_visible(win)) { hide(); return G_SOURCE_CONTINUE; }
    load_monitors();
    load_modules();
    Mon *m = focused_monitor();
    if (m) { pinned = TRUE; show_on(m, PINNED_MS); }
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
        else if (now - data_at > G_USEC_PER_SEC) load_data();
    }
    return G_SOURCE_CONTINUE;
}

static void on_realize(GtkWidget *w, gpointer data) {
    cairo_region_t *empty = cairo_region_create();
    gtk_widget_input_shape_combine_region(w, empty);
    cairo_region_destroy(empty);
}

static GtkWidget *label(const char *name, const char *cls, float xalign) {
    GtkWidget *l = gtk_label_new(NULL);
    if (name) gtk_widget_set_name(l, name);
    if (cls) gtk_style_context_add_class(gtk_widget_get_style_context(l), cls);
    gtk_label_set_xalign(GTK_LABEL(l), xalign);
    return l;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    g_autofree char *lock = g_build_filename(g_get_user_runtime_dir(), "claude-osd.lock", NULL);
    int lfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX | LOCK_NB) < 0) return 0;

    cache_path = g_build_filename(g_get_user_runtime_dir(), "claude-usage.json", NULL);
    g_autofree char *helper = g_build_filename(g_get_home_dir(), ".local/bin/claude-usage", NULL);
    usage_cmd = g_strdup_printf("%s --refresh", helper);

    gtk_init(&argc, &argv);
    atspi_init();
    atspi_set_timeout(500, 2000);

    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_namespace(GTK_WINDOW(win), "claude-osd");
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

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_name(box, "osd");
    gtk_widget_set_size_request(box, OSD_WIDTH, -1);

    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *icon = label("icon", NULL, 0.5);
    gtk_label_set_text(GTK_LABEL(icon), ICON);
    GtkWidget *title = label("title", NULL, 0);
    gtk_label_set_text(GTK_LABEL(title), "Claude usage");
    plan_lbl = label("plan", NULL, 1);
    gtk_box_pack_start(GTK_BOX(head), icon, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(head), title, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(head), plan_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), head, FALSE, FALSE, 0);

    for (int i = 0; i < MAX_ROWS; i++) {
        Row *r = &rows[i];
        r->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        r->label = label(NULL, "rowname", 0);
        r->pct = label(NULL, "pct", 1);
        gtk_box_pack_start(GTK_BOX(top), r->label, TRUE, TRUE, 0);
        gtk_box_pack_end(GTK_BOX(top), r->pct, FALSE, FALSE, 0);
        r->bar = gtk_drawing_area_new();
        gtk_widget_set_size_request(r->bar, -1, BAR_HEIGHT + 4);
        g_signal_connect(r->bar, "draw", G_CALLBACK(draw_bar), r);
        r->reset = label(NULL, "reset", 0);
        gtk_box_pack_start(GTK_BOX(r->box), top, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(r->box), r->bar, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(r->box), r->reset, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), r->box, FALSE, FALSE, 0);
    }

    foot_lbl = label("foot", NULL, 1);
    gtk_box_pack_start(GTK_BOX(box), foot_lbl, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(win), box);
    gtk_widget_show_all(box);
    gtk_widget_realize(win);

    load_monitors();
    g_unix_signal_add(SIGUSR1, on_toggle, NULL);
    g_timeout_add(POLL_MS, tick, NULL);

    gtk_main();
    return 0;
}
