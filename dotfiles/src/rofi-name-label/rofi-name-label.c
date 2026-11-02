/* Name label and colored panel for the theme switchers: small overlays that can never take the
 * keyboard, unlike a second rofi. The panel sits behind the see-through rofi grid, so the grid
 * appears to change color. Reads one line per update from stdin and exits at end of input:
 *
 *     name <TAB> background <TAB> accent <TAB> label top px <TAB> label radius px
 *
 * An empty name hides the label and leaves the panel as it is. Prints "ready" once the panel is
 * on screen, so rofi can open on top of it.
 *
 * Usage: rofi-name-label PANEL_TOP PANEL_WIDTH PANEL_HEIGHT PANEL_RADIUS
 *
 * Build: gcc -O2 rofi-name-label.c -o ~/.local/bin/rofi-name-label \
 *            $(pkg-config --cflags --libs gtk-layer-shell-0 gtk+-3.0)
 */
#include <gtk/gtk.h>
#include <gtk-layer-shell.h>
#include <string.h>

#define FONT "30pt \"BigBlueTermPlus Nerd Font Mono\""
#define MIN_WIDTH 280

static GtkWidget *window, *label, *panel_window;
static GtkCssProvider *css;
static const char *panel_radius;

static void update(char **f) {
    if (!f[0] || !f[0][0] || !f[1] || !f[2] || !f[3] || !f[4]) {
        gtk_widget_hide(window);
        return;
    }
    g_autofree char *style = g_strdup_printf(
        "window { background: transparent; }"
        "#name { font: %s; color: %s; background: %s; border: 2px solid %s;"
        " border-radius: %spx; padding: 16px 40px; min-width: %dpx; }"
        "#panel { background: alpha(%s, 0.95); border: 2px solid %s; border-radius: %spx; }",
        FONT, f[2], f[1], f[2], f[4], MIN_WIDTH, f[1], f[2], panel_radius);
    gtk_css_provider_load_from_data(css, style, -1, NULL);
    gtk_label_set_text(GTK_LABEL(label), f[0]);
    gtk_layer_set_margin(GTK_WINDOW(window), GTK_LAYER_SHELL_EDGE_TOP, atoi(f[3]));
    gtk_window_resize(GTK_WINDOW(window), 1, 1);   /* shrink to fit a shorter name */
    gtk_widget_show_all(window);
    gtk_widget_show_all(panel_window);
}

static gboolean on_panel_shown(GtkWidget *widget, GdkEvent *event, gpointer data) {
    gdk_display_sync(gdk_display_get_default());
    puts("ready");
    fflush(stdout);
    return FALSE;
}

static GtkWidget *new_overlay(const char *name) {
    GtkWidget *w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(w));
    gtk_layer_set_namespace(GTK_WINDOW(w), name);
    gtk_layer_set_layer(GTK_WINDOW(w), GTK_LAYER_SHELL_LAYER_OVERLAY);
    gtk_layer_set_keyboard_mode(GTK_WINDOW(w), GTK_LAYER_SHELL_KEYBOARD_MODE_NONE);
    gtk_layer_set_anchor(GTK_WINDOW(w), GTK_LAYER_SHELL_EDGE_TOP, TRUE);
    GdkVisual *visual = gdk_screen_get_rgba_visual(gtk_widget_get_screen(w));
    if (visual) gtk_widget_set_visual(w, visual);
    return w;
}

static gboolean on_input(GIOChannel *in, GIOCondition cond, gpointer data) {
    g_autofree char *line = NULL;
    gsize end = 0;
    GIOStatus status = g_io_channel_read_line(in, &line, NULL, &end, NULL);
    if (status == G_IO_STATUS_AGAIN) return TRUE;
    if (status != G_IO_STATUS_NORMAL) {
        gtk_main_quit();
        return FALSE;
    }
    line[end] = '\0';
    g_auto(GStrv) fields = g_strsplit(line, "\t", 5);
    update(fields);
    return TRUE;
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    if (argc != 5) {
        fputs("usage: rofi-name-label PANEL_TOP PANEL_WIDTH PANEL_HEIGHT PANEL_RADIUS\n", stderr);
        return 1;
    }
    panel_radius = argv[4];

    panel_window = new_overlay("rofi-name-panel");
    gtk_layer_set_margin(GTK_WINDOW(panel_window), GTK_LAYER_SHELL_EDGE_TOP, atoi(argv[1]));
    GtkWidget *panel = gtk_event_box_new();
    gtk_widget_set_name(panel, "panel");
    gtk_widget_set_size_request(panel, atoi(argv[2]), atoi(argv[3]));
    gtk_container_add(GTK_CONTAINER(panel_window), panel);
    g_signal_connect(panel_window, "map-event", G_CALLBACK(on_panel_shown), NULL);

    window = new_overlay("rofi-name-label");
    label = gtk_label_new("");
    gtk_widget_set_name(label, "name");
    gtk_container_add(GTK_CONTAINER(window), label);

    css = gtk_css_provider_new();
    gtk_style_context_add_provider_for_screen(gtk_widget_get_screen(window),
        GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GIOChannel *in = g_io_channel_unix_new(0);
    g_io_add_watch(in, G_IO_IN | G_IO_HUP, on_input, NULL);

    gtk_main();
    return 0;
}
