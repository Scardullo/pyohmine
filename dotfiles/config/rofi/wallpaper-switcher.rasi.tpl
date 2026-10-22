configuration {
    modi: "dmenu";
    show-icons: true;
    font: "JetBrainsMono Nerd Font 13";
}

* {
    bg:         __BG__;
    bg-alt:     __BG_ALT__;
    fg:         __FG__;
    selected:   __ACCENT__;
    border-col: __ACCENT__;

    background-color: transparent;
    text-color: @fg;
}

window {
    width: 900px;
    border: 2px;
    border-color: @border-col;
    border-radius: __RADIUS_18__;
    padding: 20px;
    background-color: @bg;
}

mainbox {
    children: [ listview ];
}

listview {
    columns: 4;
    lines: 5;
    spacing: 12px;
    fixed-height: true;
    fixed-columns: true;
    scrollbar: false;
}

element {
    children: [ element-icon ];
    padding: 6px;
    border-radius: __RADIUS_12__;
    border: 2px;
    border-color: transparent;
}

element-icon {
    size: 200px;
    border-radius: __RADIUS_8__;
    horizontal-align: 0.5;
}

element selected.normal {
    background-color: @bg-alt;
    border-color: @selected;
}
