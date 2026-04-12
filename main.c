#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

/* ── State ── */
static int counter = 0;
static GtkWidget *counter_label;
static GtkWidget *entry;
static GtkWidget *output_label;

/* ── Callbacks ── */
static void on_increment(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    counter++;
    char buf[64];
    snprintf(buf, sizeof(buf), "Count: <b>%d</b>", counter);
    gtk_label_set_markup(GTK_LABEL(counter_label), buf);
}

static void on_decrement(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    counter--;
    char buf[64];
    snprintf(buf, sizeof(buf), "Count: <b>%d</b>", counter);
    gtk_label_set_markup(GTK_LABEL(counter_label), buf);
}

static void on_reset(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    counter = 0;
    gtk_label_set_markup(GTK_LABEL(counter_label), "Count: <b>0</b>");
}

static void on_greet(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    const char *name = gtk_editable_get_text(GTK_EDITABLE(entry));
    char buf[256];
    if (name && strlen(name) > 0)
        snprintf(buf, sizeof(buf), "Hello, <b>%s</b>! 👋", name);
    else
        snprintf(buf, sizeof(buf), "Hello, <b>World</b>! 👋");
    gtk_label_set_markup(GTK_LABEL(output_label), buf);
}

/* ── Build UI ── */
static void activate(GtkApplication *app, gpointer data) {
    (void)data;

    /* Window */
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "GTK4 Demo");
    gtk_window_set_default_size(GTK_WINDOW(window), 420, 360);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);

    /* Root vertical box */
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(root, 24);
    gtk_widget_set_margin_bottom(root, 24);
    gtk_widget_set_margin_start(root, 32);
    gtk_widget_set_margin_end(root, 32);
    gtk_window_set_child(GTK_WINDOW(window), root);

    /* ── Section 1: Counter ── */
    GtkWidget *sec1 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sec1), "<span size='large' weight='bold'>Counter</span>");
    gtk_widget_set_halign(sec1, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(root), sec1);

    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_margin_top(sep1, 4);
    gtk_widget_set_margin_bottom(sep1, 12);
    gtk_box_append(GTK_BOX(root), sep1);

    counter_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(counter_label), "Count: <b>0</b>");
    gtk_widget_set_halign(counter_label, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_bottom(counter_label, 12);
    gtk_box_append(GTK_BOX(root), counter_label);

    GtkWidget *btn_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_row, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_bottom(btn_row, 24);
    gtk_box_append(GTK_BOX(root), btn_row);

    GtkWidget *btn_dec = gtk_button_new_with_label("−");
    GtkWidget *btn_inc = gtk_button_new_with_label("+");
    GtkWidget *btn_rst = gtk_button_new_with_label("Reset");

    gtk_widget_set_size_request(btn_dec, 64, 36);
    gtk_widget_set_size_request(btn_inc, 64, 36);
    gtk_widget_set_size_request(btn_rst, 80, 36);

    gtk_box_append(GTK_BOX(btn_row), btn_dec);
    gtk_box_append(GTK_BOX(btn_row), btn_inc);
    gtk_box_append(GTK_BOX(btn_row), btn_rst);

    g_signal_connect(btn_inc, "clicked", G_CALLBACK(on_increment), NULL);
    g_signal_connect(btn_dec, "clicked", G_CALLBACK(on_decrement), NULL);
    g_signal_connect(btn_rst, "clicked", G_CALLBACK(on_reset),     NULL);

    /* ── Section 2: Greeter ── */
    GtkWidget *sec2 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sec2), "<span size='large' weight='bold'>Greeter</span>");
    gtk_widget_set_halign(sec2, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(root), sec2);

    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_margin_top(sep2, 4);
    gtk_widget_set_margin_bottom(sep2, 12);
    gtk_box_append(GTK_BOX(root), sep2);

    entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Enter your name…");
    gtk_widget_set_margin_bottom(entry, 8);
    gtk_box_append(GTK_BOX(root), entry);

    GtkWidget *btn_greet = gtk_button_new_with_label("Greet");
    gtk_widget_set_halign(btn_greet, GTK_ALIGN_START);
    gtk_widget_set_margin_bottom(btn_greet, 12);
    gtk_box_append(GTK_BOX(root), btn_greet);
    g_signal_connect(btn_greet, "clicked", G_CALLBACK(on_greet), NULL);

    output_label = gtk_label_new("Hello, World! 👋");
    gtk_widget_set_halign(output_label, GTK_ALIGN_START);
    gtk_label_set_selectable(GTK_LABEL(output_label), TRUE);
    gtk_box_append(GTK_BOX(root), output_label);

    gtk_window_present(GTK_WINDOW(window));
}

/* ── Entry point ── */
int main(int argc, char *argv[]) {
    GtkApplication *app = gtk_application_new(
        "com.example.gtk4demo",
        G_APPLICATION_DEFAULT_FLAGS
    );
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
