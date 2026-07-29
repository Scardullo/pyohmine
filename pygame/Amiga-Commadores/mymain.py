import pickle, os, threading, itertools, glob
from pygame import *
from math import *
from random import *
import pygame.gfxdraw as gfxdraw
from level_colors import *

vec = math.Vector2
GRAVITY = 0.6
global_tick = 0


WHITE = (255,255,255)
BLACK = (0,0,0)
RED = (255,0,0)
LIME_GREEN = (176,250,20)
DARK_GREEN = (107,190,0)
BLUE = (0,150,255)
LIGHT_BLUE = (93,210,255)
PINK = (255,171,199)
PURPLE = (197,73,219)
GREY = (100,100,100)
LIGHT_GREY = (180,180,180)
DARK_ORANGE = (255,68,11)
LIGHT_ORANGE = (255,147,97)
DARK_BROWN = (119,68,21)
LIGHT_BROWN = (170,102,34)
YELLOW = (240,201,0)
GOLD = (190,140,0)

mixer.pre_init(44100, -16, 1, 512)
mixer.init()
init()

os.environ['SDL_VIDEO_CENTERED'] = '1'
size = width, height = 960, 640
screen = display.set_mode(size, DOUBLEBUF)
screen_rect = screen.get_rect()
display.set_icon(transform.scale(image.load('images/icon.png'), (256,256)))
display.set_caption('Loading...')
alpha_screen = Surface(size, SRCALPHA).convert_alpha()
alpha_screen.fill((0,0,0,50))
myClock = time.Clock()
FPS = 60
mode = 'menu'
running = True
ani_counter = 0

def mul_lines(f_path, t, s, wid, f_color=BLACK):
    f = font.Font(f_path, s)
    lines = []
    while f.size(t)[0] > wid:
        pos = len(t)
        while f.size(t[0:pos])[0] > wid:
            pos = t.rfind(' ', 0, pos)
            if pos == -1:
                pos = len(t)
                break
        lines.append(t[0:pos])
        t = t[pos+1:]
    lines.append(t)

    totHeight = f.size(lines[0])[1] * len(lines)
    surf = Surface((wid, totHeight), SRCALPHA)
    surf.fill((0,0,0,0))
    for p in range(len(lines)):
        lineFont = f.render(lines[p], True, f_color)
        lineFontRect = lineFont.get_rect()
        lineFontRect.midtop = surf.get_width()//2, p * lineFont.get_height()
        surf.blit(lineFont, lineFontRect)
    return surf

def get_image(sheet, pos):
    img = Surface((pos[2], pos[3]), SRCALPHA)
    img.fill((255,255,255,0))
    img.blit(sheet, img.get_rect(), pos)
    return img

def get_cos(file_path):
    f = open(file_path).read().strip()
    co_list = f.split('\n')
    for pos in range(len(co_list)):
        co_list[pos] = co_list[pos].split(' ')
        for s in range(4):
            co_list[pos][s] = int(co_list[pos][s])
    return co_list

def color_change(surf, r, g, b, a=255):
    surf = surf.copy()
    w, h = surf.get_size()
    for x in range(w):
        for y in range(h):
            if surf.get_at((x,y))[3] > 0:
                surf.set_at((x,y), (r,g,b,a))
    return surf

def darken(surf, a=75):
    surf = surf.copy()
    a_surf = Surface(surf.get_size(), SRCALPHA)
    a_surf.fill((0,0,0,a))
    surf.blit(a_surf, (0,0))
    return surf

def alpha_pic(pic, alpha_value):
    pic_w, pic_h = pic.get_size()
    for x in range(pic_w):
        for y in range(pic_h):
            px_color = pic.get_at((x,y))
            if px_color.a != 0:
                pic.set_at((x,y), (px_color[0], px_color[1], px_color[2], alpha_value))
    return pic

off_screen = False
def player_scroll():
    global all_sprites, player, off_screen
    go_ahead = False

    if player.rect.left > width - width//5 or player.rect.right < width//5:
        off_screen = True

    if off_screen:
        move_by = (player.rect.centerx - screen_rect.centerx) / 20
        go_ahead = True
        if abs(player.rect.centerx - screen_rect.centerx) < width//8:
            off_screen = False
    else:
        if player.rect.left < width // 4:
            move_by = -abs(player.vel.x)
            go_ahead = True
        elif player.rect.right > width - width // 4:
            move_by = abs(player.vel.x)
            go_ahead = True

    if go_ahead:
        rounded_move_by = round(move_by)
        for s in all_sprites:
            s.rect.x -= rounded_move_by
            if s in enemies:
                s.pos[0] -= rounded_move_by
        for ba in back_back_sprites:
            ba.rect.x -= rounded_move_by
        for ba in back_front_sprites:
            ba.rect.x -= rounded_move_by
        for fr in front_sprites:
            fr.rect.x -= rounded_move_by
        for eb in end_blocks:
            eb.rect.x -= rounded_move_by
        for cd in change_dirs:
            cd.rect.x -= rounded_move_by
        player.pos.x -= move_by
        background_rect.x -= rounded_move_by / 2
        player_spawn_point[0] -= rounded_move_by

def level_creator(pic, player_type, background=0):
    global player, current_background, background_rect, player_spawn_point, gems_collected, total_gems_in_level, flags
    if current_level >= 6:
        current_background = 2
    else:
        current_background = 0
    background_rect = backgrounds[current_background].get_rect()

    for s in all_sprites:
        s.kill()
    for s in front_sprites:
        s.kill()
    for s in back_back_sprites:
        s.kill()
    for s in back_front_sprites:
        s.kill()
    flags = []

    p_width, p_height = pic.get_size()

    player = Player(player_type=player_type)

    gems_collected = all_gems_collected[current_level-1]
    player_spawn_point = None

    total_gems_in_level = find_gems(current_level-1)

    for x in range(p_width):
        for y in range(p_height):
            c = pic.get_at((x,y))
            pos = (player.size*16*x, height - p_height*player.size*16 + player.size*16*y + (255-c.a)*player_size*16)
            c = c[:3]

            if c == (200, 200, 200):
                player.pos = vec(pos[0], pos[1])
                player_spawn_point = list(pos)

            elif c in platform_colors:
                tmp = Platform(pos, texture=platform_colors.index(c))
                all_sprites.add(tmp)

            elif c == col['backblock dirt']:
                tmp = BackBlock(pos, 0, touching=True)
                back_back_sprites.add(tmp)
            elif c == col['backblock stone']:
                tmp = BackBlock(pos, 9, touching=True)
                back_back_sprites.add(tmp)

            elif c == col['backblock dirt always']:
                tmp = BackBlock(pos, 0, touching=False)
                back_back_sprites.add(tmp)
            elif c == col['backblock stone always']:
                tmp = BackBlock(pos, 9, touching=False)
                back_back_sprites.add(tmp)

            elif c == col['jump pad']:
                tmp = JumpPad(pos)

            elif c == col['door']:
                tmp = Door(pos, locked=False)
                back_back_sprites.add(tmp)

            elif c in enemy_colors:
                tmp = Enemy(pos, typ=enemy_colors.index(c))
                all_sprites.add(tmp)

            elif c == col['wave']:
                tmp = Water(pos, type=2)
                front_sprites.add(tmp)

            elif c == col['water']:
                tmp = Water(pos, type=3)
                front_sprites.add(tmp)

            elif c == col['left_wave']:
                tmp = Water(pos, type=8)
                front_sprites.add(tmp)

            elif c == col['right_wave']:
                tmp = Water(pos, type=9)
                front_sprites.add(tmp)

            elif c == col['lava top']:
                tmp = Lava(pos, type=4)
                front_sprites.add(tmp)

            elif c == col['lava']:
                tmp = Lava(pos, type=5)
                front_sprites.add(tmp)

            elif c == col['bridge']:
                tmp = Bridge(pos)

            elif c == col['checkpoint']:
                tmp = Checkpointk(pos)
                back_back_sprites.add(tmp)

            elif c in block_colors:
                tmp = LockedBlock(pos, block_colors.index(c))

            elif c in close_key_colors:
                tmp = Key(pos, close_key_colors.index(c), find_closest=True)

            elif c in key_colors:
                tmp = Key(pos, key_colors.index(c), find_closest=False)

            elif c in gem_colors:
                if not gems_collected[gem_colors.index(c)]:
                    tmp = Gem(pos, gem_colors.index(c), collected=False)
                else:
                    tmp = Gem(pos, gem_colors.index(c), collected=True)
                front_sprites.add(tmp)

            elif c == (5,5,5):
                EndLevel(pos)
            elif c == (0,0,160):
                ChangeDir(pos)
    
    for bridge in bridges:
        found = False
        for bb in back_blocks:
            if bb.rect.colliderect(bridge.rect) and bb.touching and not found:
                back_front_sprites.add(bridge)
                found = True
        for w in waters:
            if w.rect.colliderect(bridge.rect) and w.touching and not found:
                back_back_sprites.add(bridge)
                found = True

        if not found:
            front_sprites.add(bridge)

    for k in keys:
        found = False
        for bb in back_blocks:
            if bb.rect.colliderect(k.rect) and bb.touching and not found:
                back_front_sprites.add(k)
                found = True
        if not found:
            front_sprites.add(k)

    for lb in locked_blocks:
        found = False
        for bb in back_blocks:
            if bb.rect.colliderect(lb.rect):
                back_front_sprites.add(lb)
                found = True
        if not found:
            all_sprites.add(lb)

    for jp in jump_pads:
        found = False
        for bb in back_blocks:
            if bb.rect.colliderect(jp.rect) and bb.touching and not found:
                back_front_sprites.add(jp)
                found = True
        if not found:
            front_sprites.add(jp)

ani_pics = []
fire_ball_img = get_image(image.load('images/miscSheet.png'), get_cos('images/miscCo.txt')[8])
fire_ball_img = transform.scale(fire_ball_img, (64,64))

for i in range(359, -1, -10):
    ani_pics.append(transform.scale(fire_ball_img, i))

def loading_animation(delay):
    for c in itertools.cycle(ani_pics):
        if loading_images_done:
            break
        screen.fill(BLACK)
        tmpRect = c.get_rect()
        tmpRect.center = width - randint(49,51), height - randint(49,51)
        screen.blit(c, tmpRect)
        display.flip()
        time.wait(delay)

def load_images():
    global title_text_render, title_text_rect, player_sheet, player_cos, misc_sheet, misc_cos, misc_sheet2, misc_cos2, platform_sheet, platform_cos
    global decor_sheet, decor_cos, box_sheet, box_cos, back_sheet, back_cos, background_img, menu_back, menu_back_rect
    global sound_sheet, menu_loop1, menu_songs, menu_songs_index, control_fonts, arrow_right_black, backgrounds
    global arrow_left_black, arrow_down_black, arrow_up_black, arrow_right_white, arrow_left_white, arrow_down_white
    global arrow_up_white, controls_image, controls_image_rect, x_image, background_sheet, background_sheet_rect, all_levels
    global level1, enemy_sheet, enemy_cos, hud_sheet, hud_cos, heart_images, water_sheet, water_cos, flag_sheet, flag_cos
    global reset_level_img, reset_level_rect, reset_level_img_hover, previous_checkpoint_img, previous_checkpoint_rect
    global previous_checkpoint_img_hover, pause_img, pause_img_hover, pause_rect, resume_img, resume_img_hover, resume_rect
    global exit_img, exit_img_hover, exit_rect, empty_gem, actual_gem_images, checkpoint_img, checkpoint_rect, checkpoint_img_hover

    title_text_render = mul_lines('fonts/Gameboy.ttf', 'Alien Adventures', 36, font.Font('fonts/GameBoy.ttf', 36).size('Adventures')[0]+10)
    title_text_rect = title_text_render.get_rect()
    title_text_rect.topleft = 100, 100

    player_sheet = image.load('images/playerSheet.png')
    player_cos = get_cos('images/playerCo.txt')

    enemy_sheet = image.load('images/enemySheet.png')
    enemy_cos = get_cos('images/enemyCo.txt')

    misc_sheet = image.load('images/miscSheet.png')
    misc_cos = get_cos('images/miscCo.txt')
    misc_sheet2 = image.load('images/miscSheet2.png')
    misc_cos2 = get_cos('images/miscCo2.txt')

    flag_sheet = image.load('images/flagSheet.png')
    flag_cos = get_cos('images/flagCo.txt')

    hud_sheet = image.load('images/hudSheet.png')
    hud_cos = get_cos('images/hudCo.txt')

    heart_images = []
    for i in [4,2,0]:
        h = get_image(hud_sheet, hud_cos[i])
        h = transform.scale(h, (h.get_width()*2, h.get_height()*2))
        heart_images.append(h)

    empty_gem = get_image(misc_sheet, misc_cos[25])
    empty_gem = transform.scale(empty_gem, (int(empty_gem.get_width()*2.5), int(empty_gem.get_height()*2.5)))

    actual_gem_images = [
                        get_image(misc_sheet, misc_cos[17]),
                        get_image(misc_sheet, misc_cos[18]),
                        get_image(misc_sheet, misc_cos[19]),
                        get_image(misc_sheet, misc_cos[20])]
    
    for i in range(len(actual_gem_images)):
        actual_gem_images[i] = transform.scale(actual_gem_images[i], (int(actual_gem_images[i].get_width()*2.5), int(actual_gem_images[i].get_height()*2.5)))

        pause_img = image.load('images/icons/pauseBlack.png')
        pause_rect = pause_img.get_rect()
        pause_img = transform.scale(pause_img, (pause_rect.width//3, pause_rect.height//3))
        pause_rect = pause_img.get_rect()
        pause_rect.topright = width - 25, 25

        pause_img_hover = image.load('images/icons/pauseWhite.png')
        pause_img_hover = transform.scale(pause_img_hover, (pause_img_hover.get_width()//3, pause_img_hover.get_height()//3))
        
