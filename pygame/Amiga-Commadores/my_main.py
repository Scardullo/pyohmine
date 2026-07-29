import pickle, os, threading, itertools, glob
from pygame import *
from math import *
from random import *
import pygame.gfxdraw as gfxdraw
from level_colors import *

vec = math.Vector2
GRAVITY = 0.6
global_tick = 0

# Colors
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
				continue
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
	img = Surface((pos[2],pos[3]), SRCALPHA)
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

def level_creator(pic,player_type,background=0):
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
		
			pos = (player.size*16*x, height - p_height*player.size*16 + player.size*16*y + (255-c.a)*player.size*16)
			
			c = c[:3]

			if c == (200, 200, 200):
				player.pos = vec(pos[0], pos[1])
				
				player_spawn_point = list(pos)

			elif c in platform_colors:
				tmp = Platform(pos,texture=platform_colors.index(c))
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
				tmp = Enemy(pos, type=enemy_colors.index(c))
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
				tmp = Lava(pos,type=4)
				front_sprites.add(tmp)

			elif c == col['lava']:
				tmp = Lava(pos,type=5)
				front_sprites.add(tmp)

			elif c == col['bridge']:
				tmp = Bridge(pos)

			elif c == col['checkpoint']:
				tmp = Checkpoint(pos)
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
			if w.rect.colliderect(bridge.rect) and bb.touching and not found:
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
	ani_pics.append(transform.rotate(fire_ball_img, i))


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

	title_text_render = mul_lines('fonts/GameBoy.ttf', 'Alien Adventures', 36, font.Font('fonts/GameBoy.ttf', 36).size('Adventures')[0]+10)
	title_text_rect = title_text_render.get_rect()
	title_text_rect.topleft = 100,100

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
	pause_rect.topright = width-25, 25

	pause_img_hover = image.load('images/icons/pauseWhite.png')
	pause_img_hover = transform.scale(pause_img_hover, (pause_img_hover.get_width()//3, pause_img_hover.get_height()//3))

	previous_checkpoint_img = image.load('images/icons/checkpointBlack.png')
	previous_checkpoint_rect = previous_checkpoint_img.get_rect()
	previous_checkpoint_img = transform.scale(previous_checkpoint_img, (previous_checkpoint_rect.width//3, previous_checkpoint_rect.height//3))
	previous_checkpoint_rect = previous_checkpoint_img.get_rect()
	previous_checkpoint_rect.topright = pause_rect.x - 25, 25

	previous_checkpoint_img_hover = image.load('images/icons/checkpointWhite.png')
	previous_checkpoint_img_hover = transform.scale(previous_checkpoint_img_hover, (previous_checkpoint_img_hover.get_width()//3, previous_checkpoint_img_hover.get_height()//3))

	reset_level_img = image.load('images/icons/returnBlack.png')
	reset_level_rect = reset_level_img.get_rect()
	reset_level_img = transform.scale(reset_level_img, (reset_level_rect.width//2,reset_level_rect.height//2))
	reset_level_rect = reset_level_img.get_rect()
	reset_level_rect.topright = width - 50, height//2

	reset_level_img_hover = image.load('images/icons/returnWhite.png')
	reset_level_img_hover = transform.scale(reset_level_img_hover, (reset_level_img_hover.get_width()//2, reset_level_img_hover.get_height()//2))

	resume_img = image.load('images/icons/resumeBlack.png')
	resume_rect = resume_img.get_rect()
	resume_img = transform.scale(resume_img, (resume_rect.width//2, resume_rect.height//2))
	resume_rect = resume_img.get_rect()
	resume_rect.bottomright = width - 50, reset_level_rect.top - 25

	resume_img_hover = image.load('images/icons/resumeWhite.png')
	resume_img_hover = transform.scale(resume_img_hover, (resume_img_hover.get_width()//2, resume_img_hover.get_height()//2))

	exit_img = image.load('images/icons/exitBlack.png')
	exit_rect = exit_img.get_rect()
	exit_img = transform.scale(exit_img, (exit_rect.width//2, exit_rect.height//2))
	exit_rect = exit_img.get_rect()
	exit_rect.topright = width - 50, reset_level_rect.bottom + 25

	exit_img_hover = image.load('images/icons/exitWhite.png')
	exit_img_hover = transform.scale(exit_img_hover, (exit_img_hover.get_width()//2, exit_img_hover.get_height()//2))

	checkpoint_img = image.load('images/icons/checkpointBlack.png')
	checkpoint_rect = checkpoint_img.get_rect()
	checkpoint_img = transform.scale(checkpoint_img, (checkpoint_rect.width//2, checkpoint_rect.height//2))
	checkpoint_rect = checkpoint_img.get_rect()
	checkpoint_rect.topright = pause_rect.x - 25, 25

	checkpoint_img_hover = image.load('images/icons/checkpointWhite.png')
	checkpoint_img_hover = transform.scale(checkpoint_img_hover, (checkpoint_img_hover.get_width()//2, checkpoint_img_hover.get_height()//2))

	platform_sheet = image.load('images/platformSheet.png')
	platform_cos = get_cos('images/platformCo.txt')

	decor_sheet = image.load('images/decorSheet.png')
	decor_cos = get_cos('images/decorCo.txt')

	water_sheet = image.load('images/waterSheet.png')
	water_cos = get_cos('images/waterCo.txt')

	back_sheet = image.load('images/backgroundSheet.png').convert()
	back_cos = get_cos('images/backgroundCo.txt')

	backgrounds = []
	for i in back_cos:
		tmp = get_image(back_sheet, i)
		backgrounds.append(transform.scale(tmp, (tmp.get_width()*6, tmp.get_height()*6)))

	menu_back = image.load('images/menuBack.png').convert()
	menu_back = transform.scale(menu_back, (menu_back.get_width() * 4, menu_back.get_height() * 4))
	menu_back_rect = menu_back.get_rect()
	menu_back_rect.topleft = -128, -128

	arrow_left_black = image.load('images/backArrowBlack.png')
	arrow_right_black = transform.rotate(arrow_left_black, 180)
	arrow_down_black = transform.rotate(arrow_left_black, 90)
	arrow_up_black = transform.rotate(arrow_left_black, 270)

	arrow_left_white = image.load('images/backArrowWhite.png')
	arrow_right_white = transform.rotate(arrow_left_white, 180)
	arrow_down_white = transform.rotate(arrow_left_white, 90)
	arrow_up_white = transform.rotate(arrow_left_white, 270)

	sound_sheet = image.load('images/Sound.png')
	sound_sheet = transform.scale(sound_sheet, (sound_sheet.get_width() * 2, sound_sheet.get_height() * 2))

	controls_image = image.load('images/controls.png')
	controls_image = transform.scale(controls_image, (controls_image.get_width() * 2, controls_image.get_height() * 2))
	controls_image_rect = controls_image.get_rect()
	controls_image_rect.topleft = width+64*3,-height+64*3

	x_image = image.load('images/x.png')

	all_levels = [
	image.load('levels/level1.png'), 
	image.load('levels/level2.png'), 
	image.load('levels/level3.png'), 
	image.load('levels/level4.png'),
	image.load('levels/level5.png'),
	image.load('levels/level6.png'),
	image.load('levels/level7.png'),
	image.load('levels/level8.png'),
	image.load('levels/level9.png')]

	mixer.music.load('sound/menu_loop.ogg')
	
	time.wait(1000)

def do_loading(target, args=[]):
	global loading_images_done
	
	loading_images_done = False
	l = threading.Thread(target=target, args=args)
	l.start()
	t = threading.Thread(target=loading_animation, args=[10])
	t.start()

	while not loading_images_done:
		if not l.is_alive():
			loading_images_done = True

do_loading(load_images)

def scroll(d, background=False, player=False):
	global buttons, mx, my, menu_back_rect, menu_back, let_go, ani_counter, control_fonts
	for i in range(91):
		screen.fill(WHITE)
		if background:
			if d == 'right':
				menu_back_rect.x -= round(2.3 * cos(radians(i)))	
			elif d == 'left':
				menu_back_rect.x += round(2.3 * cos(radians(i)))	
			elif d == 'up':
				menu_back_rect.y += round(2.3 * cos(radians(i)))	
			elif d == 'down':
				menu_back_rect.y -= round(2.3 * cos(radians(i)))	

		screen.blit(menu_back, menu_back_rect)
		screen.blit(alpha_screen, (0,0))

		if player:
			if d == 'right':
				preview_player_rect.x -= round(16.58 * cos(radians(i)))
			elif d == 'left':
				preview_player_rect.x += round(16.58 * cos(radians(i)))
			elif d == 'up':
				preview_player_rect.y += round(11.06 * cos(radians(i)))
			elif d == 'down':
				preview_player_rect.y -= round(11.06 * cos(radians(i)))
		
		current_animation = preview_animations[current_preview_player][int(ani_counter)%2]
		
		tmp = round(4*sin(radians(ani_counter*70)))
		
		gfxdraw.filled_circle(screen,preview_player_rect.centerx,preview_player_rect.centery,196+tmp,(buttons[current_preview_player].hover_color+(100,)))
		draw.circle(screen,buttons[current_preview_player].button_color,preview_player_rect.center,196+tmp,5)
		
		if mx < preview_player_rect.centerx:
			screen.blit(transform.flip(current_animation, 1, 0), preview_player_rect)
		else:
			screen.blit(current_animation, preview_player_rect)
		ani_counter += 0.04
		
		for b in range(len(buttons)):
			if d == 'right':
				buttons[b].pos[0] -= round(16.58 * cos(radians(i)))
				buttons[b].rect.x -= round(16.58 * cos(radians(i)))
			elif d == 'left':
				buttons[b].pos[0] += round(16.58 * cos(radians(i)))
				buttons[b].rect.x += round(16.58 * cos(radians(i)))
			elif d == 'up':
				buttons[b].pos[1] += round(11.06 * cos(radians(i)))
				buttons[b].rect.y += round(11.06 * cos(radians(i)))
			elif d == 'down':
				buttons[b].pos[1] -= round(11.06 * cos(radians(i)))
				buttons[b].rect.y -= round(11.06 * cos(radians(i)))
			screen.blit(buttons[b].image, buttons[b].rect)
		
		if d == 'right':
			controls_image_rect.x -= round(16.58 * cos(radians(i)))
		elif d == 'left':
			controls_image_rect.x += round(16.58 * cos(radians(i)))
		elif d == 'up':
			controls_image_rect.y += round(11.06 * cos(radians(i)))
		elif d == 'down':
			controls_image_rect.y -= round(11.06 * cos(radians(i)))

		if d == 'right':
			title_text_rect.x -= round(16.58 * cos(radians(i)))
		elif d == 'left':
			title_text_rect.x += round(16.58 * cos(radians(i)))
		elif d == 'up':
			title_text_rect.y += round(11.06 * cos(radians(i)))
		elif d == 'down':
			title_text_rect.y -= round(11.06 * cos(radians(i)))
		
		gfxdraw.box(screen,(controls_image_rect.centerx - controls_back[0]/2, controls_image_rect.centery - controls_back[1]/2, controls_back[0], controls_back[1]),(GREY + (150,)))
		screen.blit(controls_image,controls_image_rect)
		gfxdraw.box(screen, (title_text_rect.x - 50, title_text_rect.y - 50, title_text_rect.width + 100, title_text_rect.height + 100), GREY+(100,))
		screen.blit(title_text_render, title_text_rect)
		
		event.pump()
		mx, my = mouse.get_pos()
		display.flip()
		time.wait(3)
	let_go = False

def fade_out(s_copy, delay=1):
	a_surf = Surface(size, SRCALPHA)
	for i in range(0, 256, 2):
		screen.blit(s_copy, (0,0))
		a_surf.fill((0,0,0,i))
		screen.blit(a_surf, (0,0))
		display.flip()
		time.wait(delay)

def circle_out(s_copy, delay=3, ingame = False):
	a_surf = Surface(size, SRCALPHA)
	for i in range(min(width, height), -1, -delay):
		screen.blit(s_copy, (0,0))
		a_surf.fill((0,0,0))
		if ingame:
			draw.circle(a_surf, (255,255,255,0), (player.rect.x+player.rect.width//2,player.rect.y+player.rect.height//2), i)
		else:
			draw.circle(a_surf, (255,255,255,0), (width//2, height//2), i)
		screen.blit(a_surf, (0,0))
		display.flip()
	a_surf.fill((0,0,0))
	screen.blit(a_surf, (0,0))
	display.flip()
	time.wait(10)

def level_complete(screen_copy, title='Level Complete!', transition_time=60, main_background_color=LIGHT_BROWN, title_background_color=DARK_BROWN):
	global running, mx, my, current_level, mode, levels_unlocked
	
	popup_surf = Surface((width-256, height-256), SRCALPHA)
	popup_rect = popup_surf.get_rect()
	popup_rect.center = width//2, height//2	
	
	title_font = font.Font('fonts/GameBoy.ttf', 16).render(title, False, BLACK)
	title_rect = title_font.get_rect()
	title_rect.x = 10

	exit_rect.center = popup_rect.width/4, popup_rect.height - 100
	reset_level_rect.center = popup_rect.width/2, popup_rect.height - 100
	resume_rect.center = popup_rect.width * 3/4, popup_rect.height - 100
	
	gems_img, gems_rect = make_gem_image(current_level-1, find_gems(current_level-1))
	gems_img = transform.scale(gems_img, (gems_rect.width*2, gems_rect.height*2))
	gems_rect = gems_img.get_rect()
	gems_rect.center = popup_rect.width/2, popup_rect.height/3

	draw.rect(popup_surf, main_background_color, (0,0,popup_rect.width, popup_rect.height))
	draw.rect(popup_surf, title_background_color, (0, 0, popup_rect.width, title_rect.height))
	popup_surf.blit(title_font, title_rect)
	popup_surf.blit(exit_img, exit_rect)
	popup_surf.blit(reset_level_img, reset_level_rect)
	popup_surf.blit(resume_img, resume_rect)
	popup_surf.blit(gems_img, gems_rect)
	a = 0	
	for i in range(0, 121, 5):		
		a += 5
		screen.fill(WHITE)
		alpha_screen.fill((0,0,0,a))	
		screen.blit(screen_copy, (0,0))		

		coeff = popup_rect.width / sin(radians(121))							
		new_x = coeff * sin(radians(i))											
		new_y = coeff*popup_rect.height/popup_rect.width * sin(radians(i))		
		scaled_popup_surf = transform.scale(popup_surf, (round(new_x), round(new_y)))	
		scaled_popup_rect = scaled_popup_surf.get_rect()
		scaled_popup_rect.center = width//2, height//2			
		alpha_screen.blit(scaled_popup_surf, scaled_popup_rect)

		screen.blit(alpha_screen, (0,0))	
		display.flip()
		myClock.tick(FPS)

	outcome = None
	while outcome == None:	
		let_go = False
		for evt in event.get():
			if evt.type == QUIT:
				p_text = "Are you sure you want to exit?"
				if popup("QUIT", p_text, ['Yes', 'No'], screen.copy(), main_background_color=current_theme[0], title_background_color=current_theme[1]):
					outcome = 'exit'
					running = False

			if evt.type == KEYDOWN:
				if evt.key == K_RETURN:
					outcome = True

			if evt.type == MOUSEBUTTONUP:
				if evt.button == 1:
					let_go = True

		mx, my = mouse.get_pos()
		screen.fill(WHITE)
		alpha_screen.fill((0,0,0,a))
		screen.blit(screen_copy, (0,0))

		draw.rect(popup_surf, main_background_color, (0,0,popup_rect.width, popup_rect.height))
		draw.rect(popup_surf, title_background_color, (0, 0, popup_rect.width, title_rect.height))
		popup_surf.blit(title_font, title_rect)
		if exit_rect.collidepoint((mx - popup_rect.x, my - popup_rect.y)):
			gfxdraw.filled_circle(popup_surf, exit_rect.centerx, exit_rect.centery, 30, current_theme[1])
			if let_go:
				mode = 'menu'
				mixer.music.load('sound/menu_loop.ogg')
				mixer.music.play(-1)
				outcome = 'menu'
			popup_surf.blit(exit_img_hover, exit_rect)
		else:
			popup_surf.blit(exit_img, exit_rect)

		if reset_level_rect.collidepoint((mx - popup_rect.x, my - popup_rect.y)):
			gfxdraw.filled_circle(popup_surf, reset_level_rect.centerx, reset_level_rect.centery, 30, current_theme[1])
			popup_surf.blit(reset_level_img_hover, reset_level_rect)
			if let_go:
				do_loading(level_creator, args=[all_levels[current_level-1], current_preview_player])
				outcome = 'restart'
		else:
			popup_surf.blit(reset_level_img, reset_level_rect)

		if resume_rect.collidepoint((mx - popup_rect.x, my - popup_rect.y)):
			gfxdraw.filled_circle(popup_surf, resume_rect.centerx, resume_rect.centery, 30, current_theme[1])
			popup_surf.blit(resume_img_hover, resume_rect)
			if let_go:
				current_level += 1

				if current_level > len(all_levels):
					mode = 'menu'
				else:
					level_creator(all_levels[current_level-1], current_preview_player)
				
				outcome = True

		else:
			popup_surf.blit(resume_img, resume_rect)

		popup_surf.blit(gems_img, gems_rect)
		screen.blit(alpha_screen, (0,0))
		screen.blit(popup_surf,popup_rect)
		display.flip()
		myClock.tick(FPS)

	alpha_screen.fill((0,0,0,50))
	let_go = False
	return outcome

def popup(title, header_txt, button_text, screen_copy, transition_time=60, main_background_color=LIGHT_BROWN, title_background_color=DARK_BROWN, main_button_color=(0,200,0), pics=[]):
	global running, mx, my, let_go
	popup_surf = Surface((width-256, height-256))
	popup_rect = popup_surf.get_rect()
	popup_rect.center = width//2, height//2

	option_buttons = []
	step = popup_rect.width / (len(button_text)+1)
	for n,t in enumerate(button_text):
		tmp = Button(t, [0,0])
		if n == 0:
			tmp.hover_color = main_button_color
		tmp.rect.center = step*(n+1), popup_rect.height - popup_rect.height//4
		tmp.pos = tmp.rect.topleft
		option_buttons.append(tmp)
	header_font = mul_lines('fonts/GameBoy.ttf', header_txt, 22, popup_rect.width-100)
	header_rect = header_font.get_rect()
	header_rect.midbottom = popup_rect.width//2, popup_rect.top + (option_buttons[0].rect.top - popup_rect.top)//2

	title_font = font.Font('fonts/GameBoy.ttf', 20).render(title, False, BLACK)
	title_rect = title_font.get_rect()
	title_rect.x = 10

	close_button = Button('', [popup_rect.width - title_rect.height*2, -1], dim=[title_rect.height*2,title_rect.height*2], pic=transform.scale(x_image, (16,16)), rad=2, h_color=RED, color=(175,0,0))
	option_buttons.append(close_button)

	draw.rect(popup_surf, main_background_color, (0,0,popup_rect.width, popup_rect.height))
	draw.rect(popup_surf, title_background_color, (0, 0, popup_rect.width, title_rect.height))
	popup_surf.blit(title_font, title_rect)
	popup_surf.blit(header_font, header_rect)

	for b in option_buttons:
		b.button_hover(mx - popup_rect.x, my - popup_rect.y, surf=popup_surf)

	for p,r in pics:
		popup_surf.blit(p,r)

	a = 0	
	for i in range(0, 121, 5):		
		a += 5
		screen.fill(WHITE)
		alpha_screen.fill((0,0,0,a))
		screen.blit(screen_copy, (0,0))		

		coeff = popup_rect.width / sin(radians(121))							
		new_x = coeff * sin(radians(i))											
		new_y = coeff*popup_rect.height/popup_rect.width * sin(radians(i))		
		scaled_popup_surf = transform.scale(popup_surf, (round(new_x), round(new_y)))	
		scaled_popup_rect = scaled_popup_surf.get_rect()
		scaled_popup_rect.center = width//2, height//2			
		alpha_screen.blit(scaled_popup_surf, scaled_popup_rect)

		screen.blit(alpha_screen, (0,0))	
		display.flip()
		myClock.tick(FPS)
	
	outcome = None
	pop_out = False
	while outcome == None:
		let_go = False
		for evt in event.get():
			if evt.type == QUIT:
				running = False
				outcome = False

			if evt.type == KEYDOWN:
				if evt.key == K_RETURN:
					outcome = True

			if evt.type == MOUSEBUTTONUP:
				if evt.button == 1:
					let_go = True

		mx, my = mouse.get_pos()
		screen.fill(WHITE)
		alpha_screen.fill((0,0,0,a))
		screen.blit(screen_copy, (0,0))

		draw.rect(popup_surf, main_background_color, (0,0,popup_rect.width, popup_rect.height))
		draw.rect(popup_surf, title_background_color, (0, 0, popup_rect.width, title_rect.height))
		popup_surf.blit(title_font, title_rect)
		popup_surf.blit(header_font, header_rect)

		for b in option_buttons:
			b.button_hover(mx - popup_rect.x, my - popup_rect.y, surf=popup_surf)
			if b.rect.collidepoint((mx - popup_rect.x, my - popup_rect.y)) and let_go:
				if b.text == button_text[0]:
					outcome = True
				elif b.text == button_text[1]:
					outcome = False
					pop_out = True

		for p,r in pics:
			popup_surf.blit(p,r)

		if close_button.rect.collidepoint((mx - popup_rect.x, my - popup_rect.y)) and let_go:
			outcome = False
			pop_out = True

		screen.blit(alpha_screen, (0,0))
		screen.blit(popup_surf,popup_rect)
		display.flip()
		myClock.tick(FPS)

	if pop_out:
		for i in range(120, -1, -5):		
			a -= 5
			screen.fill(WHITE)
			alpha_screen.fill((0,0,0,a))
			screen.blit(screen_copy, (0,0))		

			coeff = popup_rect.width / sin(radians(121))							
			new_x = coeff * sin(radians(i))											
			new_y = coeff*popup_rect.height/popup_rect.width * sin(radians(i))		
			scaled_popup_surf = transform.scale(popup_surf, (round(new_x), round(new_y)))	
			scaled_popup_rect = scaled_popup_surf.get_rect()
			scaled_popup_rect.center = width//2, height//2			
			alpha_screen.blit(scaled_popup_surf, scaled_popup_rect)

			screen.blit(alpha_screen, (0,0))	
			display.flip()
			myClock.tick(FPS)

	alpha_screen.fill((0,0,0,50))
	let_go = False
	return outcome

def pause(s_copy):
	global running, let_go, mode, mx, my, screen_copy

	a_surf = Surface(size, SRCALPHA)
	a_surf.fill((0,0,0,152))
	
	side_bar_surf = Surface((150,height))
	side_bar_rect = side_bar_surf.get_rect()
	side_bar_rect.right = width

	paused_txt = "Paused"
	paused_render = font.Font('fonts/GameBoy.ttf', 20).render(paused_txt, True, BLACK)
	paused_rect = paused_render.get_rect()
	paused_rect.topleft = 10, 10
	
	resume_rect.center = side_bar_rect.width//2, side_bar_rect.height//2 - 75
	reset_level_rect.center = side_bar_rect.width//2, side_bar_rect.height//2
	exit_rect.center = side_bar_rect.width//2, side_bar_rect.height//2 + 75

	side_bar_surf.fill(current_theme[0])
	side_bar_surf.blit(resume_img, resume_rect)
	side_bar_surf.blit(reset_level_img, reset_level_rect)
	side_bar_surf.blit(exit_img, exit_rect)
	gfxdraw.box(side_bar_surf, (0, 0, side_bar_rect.width, paused_rect.bottom + 5), current_theme[1])
	side_bar_surf.blit(paused_render, paused_rect)
	display.flip()
	
	a = 0
	animation_speed = 5
	for i in range(width, width - side_bar_rect.width-1, -animation_speed):
		a += animation_speed
		screen.blit(s_copy,(0,0))
		a_surf.fill((0,0,0,a))
		screen.blit(a_surf,(0,0))
		side_bar_rect.topleft = i, 0
		screen.blit(side_bar_surf, side_bar_rect)
		screen_copy = screen.copy()    
		display.flip()				  

	result = None
	while result == None:
		let_go = False
		for evt in event.get():
			if evt.type == QUIT:
				p_text = "Are you sure you want to exit?"
				if popup("QUIT", p_text, ['Yes', 'No'], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1]):
					result = 'exit'
					running = False

			elif evt.type == KEYDOWN:
				if evt.key == K_ESCAPE:
					p_text = "Are you sure you want to exit?"
					if popup("QUIT", p_text, ['Yes', 'No'], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1]):
						result = 'exit'
						running = False
				if evt.key == K_RETURN:
					result = 'resume'

			elif evt.type == MOUSEBUTTONDOWN:
				if evt.button == 1:
					pass

			elif evt.type == MOUSEBUTTONUP:
				if evt.button == 1:
					let_go = True

		mx, my = mouse.get_pos()
		smx,smy = mx - side_bar_rect.x, my
		side_bar_surf.fill(current_theme[0])
		screen.blit(s_copy, (0,0))
		screen.blit(a_surf, (0,0))
		gfxdraw.box(side_bar_surf, (0, 0, side_bar_rect.width, paused_rect.bottom + 5), current_theme[1])
		side_bar_surf.blit(paused_render, paused_rect)

		if resume_rect.collidepoint((smx,smy)):
			gfxdraw.filled_circle(side_bar_surf, resume_rect.centerx,resume_rect.centery, 25,current_theme[1])
			side_bar_surf.blit(resume_img_hover, resume_rect)
			if let_go:
				result = 'resume'
		else:
			side_bar_surf.blit(resume_img, resume_rect)

		if reset_level_rect.collidepoint((smx,smy)):
			gfxdraw.filled_circle(side_bar_surf, reset_level_rect.centerx,reset_level_rect.centery, 25,current_theme[1])
			side_bar_surf.blit(reset_level_img_hover, reset_level_rect)
			if let_go:
				if popup("Reset Level", "Are you sure you want to reset the level? All level progress will be lost.", [" Reset ", "Cancel"], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1], main_button_color=(200,0,0)):
					result = 'reset'
					read_data()
					level_creator(all_levels[current_level-1], current_preview_player)
		else: side_bar_surf.blit(reset_level_img, reset_level_rect)

		if exit_rect.collidepoint((smx,smy)):
			gfxdraw.filled_circle(side_bar_surf, exit_rect.centerx,exit_rect.centery, 25,current_theme[1])
			side_bar_surf.blit(exit_img_hover, exit_rect)
			if let_go:
				if popup("Go Home", "Are you sure you want to exit to the menu? All level progress will be lost.", ["Exit", "Cancel"], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1], main_button_color=(200,0,0)):
					read_data()
					mixer.music.load('sound/menu_loop.ogg')
					mixer.music.play(-1)
					result = 'menu'
		else:
			side_bar_surf.blit(exit_img, exit_rect)

		screen.blit(side_bar_surf, side_bar_rect)
		display.flip()
		myClock.tick()
		display.set_caption('Alien Adventures')
		screen_copy = screen.copy()

	if result not in ['menu', 'exit']:
		a = 150 + animation_speed
		for i in range(width - side_bar_rect.width, width+1, animation_speed):
			a -= animation_speed
			screen.blit(s_copy,(0,0))
			screen.blit(a_surf,(0,0))
			a_surf.fill((0,0,0,a))
			side_bar_rect.topleft = i, 0
			screen.blit(side_bar_surf, side_bar_rect)
			display.flip()

	if result == 'exit':
		running = False
	elif result == 'resume':
		pass
	elif result == 'menu':
		mode = 'menu'
	return result

def find_gems(level_num):
	gem_count = 0
	lev = all_levels[level_num]
	for x in range(lev.get_width()):
		for y in range(lev.get_height()):
			c = lev.get_at((x,y))[:3]
			if c in gem_colors: gem_count += 1
	return gem_count

def make_gem_image(level_num, gem_num):
	gems_surf = Surface((int(gem_num*16*2.5), int(16*2.5)), SRCALPHA)
	gems_surf.fill((255,255,255,0))
	gems_rect = gems_surf.get_rect()
	for i in range(gem_num):
		if all_gems_collected[level_num][i]:		
			img = actual_gem_images[i]		
		else:
			img = get_image(misc_sheet, misc_cos[25])	
			img = transform.scale(img,(int(img.get_width()*2.5), int(img.get_height()*2.5)))
		imgRect = img.get_rect()
		imgRect.left = i*16*2.5
		gems_surf.blit(img, imgRect)
	gems_rect.center = (width-256)/2, (height-256)/2 - 50
	return (gems_surf, gems_rect)

def read_data():
	global music_bool, current_theme, levels_unlocked, all_gems_collected 
	with open('data.txt', 'r') as f:
		music_bool = f.readline()
		music_bool = int(music_bool[music_bool.index('=')+1:])
		current_theme = f.readline()
		current_theme = themes[int(current_theme[current_theme.index('=')+1:])]
		levels_unlocked = f.readline()
		levels_unlocked = int(levels_unlocked[levels_unlocked.find('=')+1:])
		all_gems_collected = []
		for i in range(10):
			g = f.readline()
			g = g[:-1].split(' ')
			g = list(map(int, g))
			all_gems_collected.append(g)

def write_data():
	with open('data.txt', 'w') as f:
		f.write('music=%i\ncurrent theme=%i\nlevels unlocked=%i\n' % (int(music_bool), themes.index(current_theme), levels_unlocked))
		for i in all_gems_collected:
			f.write('{0} {1} {2} {3}\n'.format(*i))
		f.close()

class Button:
	def __init__(self, txt, pos, dim=[192,64], color = GREY, h_color = LIGHT_GREY, rad=12, pic=None, m_lines=False):
		self.text, self.dim, self.button_color, self.hover_color, self.rad, self.pos, self.pic, self.m_lines = txt, dim, color, h_color, rad, pos, pic, m_lines
		self.image = Surface(dim, SRCALPHA)
		self.rect = self.image.get_rect()
		self.old_pic = None
		self.make_image(self.button_color, BLACK)

	def make_image(self, new_button_col, new_text_col):
		self.image.fill((255,255,255,0))
		self.rect = self.image.get_rect()
		tmp = Rect(self.rect.x+self.rad//2, self.rect.y+self.rad//2, self.rect.width-self.rad, self.rect.height-self.rad)
		draw.rect(self.image, new_button_col, tmp, self.rad)
		draw.rect(self.image, new_button_col, tmp)
		
		if self.pic != None and self.pic != self.old_pic:
			pic_rect = self.pic.get_rect()
			pic_rect.center = self.rect.center
			self.image.blit(self.pic, pic_rect)
		else:
			self.make_font(self.text, color=new_text_col)
		self.rect.topleft = self.pos

	def make_font(self, txt, color=BLACK, size=20):
		if self.pic == None:
			if self.m_lines:
				f = mul_lines('fonts/GameBoy.ttf', self.text, size, self.rect.width)
			else:
				f = font.Font('fonts/GameBoy.ttf', size).render(txt, False, color)
		else:
			f = self.pic
		f_rect = f.get_rect()
		f_rect.center = self.rect.center
		self.image.blit(f, f_rect)

	def not_hovering(self):
		if self.text.lower() == 'back':
			self.pic = arrow_left_black
		if self.text.lower() == ' back ':
			self.pic = arrow_down_black
		if self.text.lower() == '  back  ':
			self.pic = arrow_left_black
		if self.text.lower() == '   back   ':
			self.pic = arrow_up_black
		if self.text.lower() == '    back    ':
			self.pic = arrow_right_black
		self.make_image(self.button_color, BLACK)

	def hovering(self):
		if 'level' in self.text.lower():
			if int(self.text[-2:]) <= levels_unlocked:
				self.hover_color = (0,255,0)
			else:
				self.hover_color = (255,0,0)
		if self.text.lower() == 'back':
			self.pic = arrow_left_white
		if self.text.lower() == ' back ':
			self.pic = arrow_down_white
		if self.text.lower() == '  back  ':
			self.pic = arrow_left_white
		if self.text.lower() == '   back   ':
			self.pic = arrow_up_white
		if self.text.lower() == '    back    ':
			self.pic = arrow_right_white
		self.make_image(self.hover_color, WHITE)

	def button_hover(self, mx, my, surf=screen):
		global music_bool, current_preview_player, mode, current_level, screen_copy, current_theme, levels_unlocked, let_go, all_gems_collected
		if self.rect.collidepoint((mx, my)):
			self.hovering()

			if 'player' in self.text.lower():
				current_preview_player = int(self.text[-1])-1

			if let_go:
				if self.text.lower() == "start": scroll('right', True, True)
				elif self.text.lower() == "options": scroll('up', True, True)
				elif self.text.lower() == "controls": scroll('right', True, True)
				elif self.text.lower() == "reset":
					if popup("RESET DATA", "Are you sure you want to reset all data? This includes levels unlocked and default settings.", [" Reset ", "Go Back"], screen_copy, main_button_color=(200,0,0), main_background_color=(255,100,100), title_background_color=(150,0,0)):
						music_bool, levels_unlocked = True, 1
						all_gems_collected = []
						for i in range(10):
							all_gems_collected.append([0,0,0,0])
						let_go = False
				elif self.text.lower() == "themes": scroll('left', True, True)
				elif self.text.lower() == "back": scroll('left', True, True)
				elif self.text.lower() == " back ": scroll('down', True, True)
				elif self.text.lower() == "  back  ": scroll('left', True, True)
				elif self.text.lower() == "   back   ": scroll('up', True, True)
				elif self.text.lower() == "    back    ": scroll('right', True, True)

				elif self.text.lower() == "music":
					if music_bool: music_bool = False
					else: music_bool = True

				elif "player " in self.text.lower():
					scroll('down', True, True)

				elif 'level' in self.text.lower():
					if int(self.text[-2:]) <= levels_unlocked:
						if int(self.text[-2:]) != 1:
							gems_in_level = find_gems(int(self.text[-2:])-1)
							t = [make_gem_image(int(self.text[-2:])-1, gems_in_level)]
						else:
							t = []

						if popup("Level " + str(self.text[-2:]), '', ["Play", "Cancel"], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1], pics=t):
							current_level = int(self.text[-2:])
							mixer.music.fadeout(1000)
							circle_out(screen.copy())
							mixer.music.stop()
							mode = 'game'
							do_loading(level_creator, args=[all_levels[current_level-1], current_preview_player])

				elif 'theme ' in self.text.lower():
					current_theme = themes[int(self.text[-1])-1]

				mx, my=mouse.get_pos()
		else:
			self.not_hovering()

		self.old_pic = self.pic
		surf.blit(self.image, self.rect)

music_bool = True
music_on_pic = get_image(sound_sheet, (0,32,32,32))
music_off_pic = get_image(sound_sheet, (32,32,32,32))

themes = [(LIME_GREEN,DARK_GREEN), (LIGHT_BLUE, BLUE), (PINK, PURPLE), (LIGHT_BROWN, DARK_BROWN), (LIGHT_ORANGE, DARK_ORANGE), (YELLOW, GOLD)]
current_theme = themes[0]
read_data()

buttons = [	Button("Player 1", [width+64*10, 64*1], dim=[64*4,64*2], color=(107,190,0), h_color=(176,250,20)),
			Button("Player 2", [width+64*10, 64*4], dim=[64*4,64*2], color=(0,137,220), h_color=(93,210,255)),
			Button("Player 3", [width+64*10, 64*7], dim=[64*4,64*2], color=(197,73,219), h_color=(255,143,180)),
			Button("music", [64*8, 64*-7], dim=[64,64], pic = music_on_pic),
			Button("Start", [64*10, 64*5]),
			Button("Options", [64*10, 64*7]),
			Button("Back", [64*16, 64*1], dim=[64,64], pic=arrow_left_black),
			Button(" Back ", [64*1, 64*-9], dim=[64,64], pic=arrow_down_black),
			Button("  Back  ", [64*16, 64*-9], dim=[64,64], pic=arrow_left_black),
			Button("   Back   ", [64*16, 64*11], dim=[64,64], pic=arrow_up_black),
			Button("    Back    ", [-64*14, -64*9], dim=[64,64], pic=arrow_right_black),
			Button("Controls", [64*10, 64*-5]),
			Button("Themes", [64*10, 64*-7]),
			Button("Theme 1", [-64*12, -64*7], dim=[64*4, 64], h_color=themes[0][0], color=themes[0][1]),
			Button("Theme 2", [-64*12, -64*5], dim=[64*4, 64], h_color=themes[1][0], color=themes[1][1]),
			Button("Theme 3", [-64*12, -64*3], dim=[64*4, 64], h_color=themes[2][0], color=themes[2][1]),
			Button("Theme 4", [-64*7, -64*7], dim=[64*4, 64], h_color=themes[3][0], color=themes[3][1]),
			Button("Theme 5", [-64*7, -64*5], dim=[64*4, 64], h_color=themes[4][0], color=themes[4][1]),
			Button("Theme 6", [-64*7, -64*3], dim=[64*4, 64], h_color=themes[5][0], color=themes[5][1]),
			Button("Reset", [64*10, 64*-3])]

for i in range(9):
	buttons.append(Button("Level " + str(i+1), [width + 64 + 960/3*(i%3), height + 192 + (i//3)*128], dim=[64*3, 64]))

class Player(sprite.Sprite):
	def __init__(self, player_type=0, pos=[width//2,height//2]):
		self.size = 2
		self.delay = 5
		self.health = 6
		self.lives = 5
		self.lives_image = get_image(player_sheet, player_cos[33 + player_type])
		self.lives_image = transform.scale(self.lives_image, (self.lives_image.get_width() * 2, self.lives_image.get_height() * 2))
		sprite.Sprite.__init__(self)

		self.all_images = list(transform.scale(get_image(player_sheet, player_cos[i]),(self.size*player_cos[i][2],self.size*player_cos[i][3])) for i in range(11*player_type, 11*player_type+11))
		self.running_images = self.all_images[9:11]
		self.swimming_pic = self.all_images[7:9]
		self.jumping_pic = self.all_images[2]
		self.ducking_pic = self.all_images[3]
		self.idle_pic = self.all_images[0]

		self.image = self.all_images[0]
		self.rect = self.image.get_rect()

		self.pos = vec(pos[0], pos[1])
		self.vel = vec(0,0)
		self.acc = vec(0,0)
		self.fric = -0.15
		self.jumping_height = -8.5 * self.size
		self.water_delay = 0

		self.jumping = True
		self.ducking = False
		self.in_water = False
		self.behind_wall = False
		self.invincible = False
		self.dir = 'right'

		self.hurt_counter = 0
		self.image_on = 1

	def move(self):
		global GRAVITY, levels_unlocked
		self.acc = vec(0,GRAVITY*self.size)

		kp = key.get_pressed()
		if kp[K_RIGHT]:
			self.acc.x = 0.5 * self.size
			self.dir = 'right'

		if kp[K_LEFT]:
			self.acc.x = -0.5 * self.size
			self.dir = 'left'

		if self.vel.y > 1 and not self.in_water:
			self.jumping = True

		under_a_block = False
		if not self.jumping and not self.in_water:
			self.rect.y -= 5
			p = sprite.spritecollide(self, platforms, False)
			lb = sprite.spritecollide(self, locked_blocks, False)
			self.rect.y += 5
			if p or lb:
				self.ducking = True
				under_a_block = True

		if kp[K_SPACE] and not self.jumping and not under_a_block:
			self.vel.y = self.jumping_height
			self.jumping = True

		self.ducking = False
		if kp[K_DOWN] and not self.jumping and not self.in_water or under_a_block:
			self.ducking = True
		# if under_a_block:
		# 	self.ducking = True

		if not self.in_water:
			if self.ducking:
				self.fric = -0.5
			else:
				self.fric = -0.15

		self.acc.x += self.vel.x * self.fric
		self.vel.x += self.acc.x
		self.vel.y += self.acc.y
		self.pos.x += self.vel.x
		self.pos.y += self.vel.y

		if self.rect.top > height+player.size*16*2:
			self.respawn()
			self.health = 6
			self.lives -= 1

		##### COLISIONS #####
		self.rect.centerx = self.pos.x
		h = sprite.spritecollide(self, platforms, False)
		if h:
			hits = h[-1]
			if self.vel.x > 0:
				self.pos.x = hits.rect.left - self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
			if self.vel.x < 0:
				self.pos.x = hits.rect.right + self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
		h = sprite.spritecollide(self, locked_blocks, False)
		if h:
			hits = h[-1]
			if self.vel.x > 0:
				self.pos.x = hits.rect.left - self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
			if self.vel.x < 0:
				self.pos.x = hits.rect.right + self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
		self.rect.centerx = self.pos.x
		h = sprite.spritecollide(self, jump_pads, False)
		if h:
			hits = h[-1]
			if hits.rect.collidepoint(self.rect.midleft) or hits.rect.collidepoint(self.rect.topleft):
				self.pos.x = hits.rect.right + self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
			elif hits.rect.collidepoint(self.rect.midright) or hits.rect.collidepoint(self.rect.topright):
				self.pos.x = hits.rect.left - self.rect.width/2
				self.vel.x = 0
				self.acc.x = 0
		h = sprite.spritecollide(self, enemies, False)
		if h:
			hits = h[-1]
			if not hits.dead and not self.invincible:
				self.invincible = True
				self.health -= 1
				self.vel = vec(-8 * self.size, -6 * self.size)
				self.jumping = True
				self.pos.y += self.vel.y
		self.rect.centerx = self.pos.x

		self.rect.bottom = self.pos.y
		h = sprite.spritecollide(self, platforms, False)
		if h:
			hits = h[-1]
			if self.vel.y > 0:
				self.pos.y = hits.rect.top
				self.landed()
			if self.vel.y < 0:
				self.pos.y = hits.rect.bottom + self.rect.height
				self.vel.y = 0
		h = sprite.spritecollide(self, locked_blocks, False)
		if h:
			hits = h[-1]
			if self.vel.y > 0:
				self.pos.y = hits.rect.top
				self.landed()
			if self.vel.y < 0:
				self.pos.y = hits.rect.bottom + self.rect.height
				self.vel.y = 0
		h = sprite.spritecollide(self, jump_pads, False)
		if h:
			hits = h[-1]
			if hits.rect.collidepoint(self.rect.bottomleft) or hits.rect.collidepoint(self.rect.midbottom) or hits.rect.collidepoint(self.rect.bottomright):
				self.pos.y = hits.rect.top
				self.vel.y = 5
				hits.active = True
				if hits.ani_counter > 4:
					self.vel.y = -12 * self.size
					self.jumping = True
		h = sprite.spritecollide(self, enemies, False)
		if h:
			for hits in h:
				if self.vel.y > 0:
					if not hits.dead:
						self.pos.y -= 10
						self.vel.y = -8.5 * self.size
						hits.health -= 1
						hits.die()
		h = sprite.spritecollide(self, bridges, False)
		if h:
			for hits in h:
				if not kp[K_DOWN]:
					if self.vel.y > 7*player.size:
						if hits.rect.colliderect(self.rect):
							self.pos.y = hits.rect.top
							self.vel.y = 0
							self.acc.y = 0
							self.jumping = False
					elif self.vel.y > 0 and (hits.rect.collidepoint(self.rect.midbottom) or hits.rect.collidepoint(self.rect.bottomright) or hits.rect.collidepoint(self.rect.bottomleft)):
						self.pos.y = hits.rect.top
						self.vel.y = 0
						self.acc.y = 0
						self.jumping = False

		self.rect.bottom = self.pos.y

		h = sprite.spritecollide(self, keys, False)
		if h:
			for hits in h:
				if not hits.picked_up:
					
					if hits.close:
						dists = []
						for block in locked_blocks:
							if block.color == hits.color:
								dists.append(hypot(hits.rect.centerx-block.rect.centerx, hits.rect.centery-block.rect.centery))
						if dists:
							smallest_dist = min(dists)
							for block in locked_blocks:
								if block.color == hits.color:
									if hypot(hits.rect.centerx-block.rect.centerx, hits.rect.centery-block.rect.centery) == smallest_dist:
										block.kill()
					else:
						for block in locked_blocks:
							if block.color == hits.color:
								block.kill()

				hits.picked_up = True

		h = sprite.spritecollide(self, gems, False)
		if h:
			for hits in h:
				if not hits.picked_up:
					hits.picked_up = True
					gems_collected[hits.color] = 1

		for bb in back_blocks:
			if bb.touching and bb.rect.colliderect(self.rect):
				self.behind_wall = True
				break
			else: self.behind_wall = False

		h = sprite.spritecollide(self, waters, False)
		if h:
			self.in_water = True
			for water_block in h:
				if water_block.type == 2 and water_block.rect.collidepoint(self.rect.midbottom):
					self.jumping_height = -5 * self.size
					break
				else:
					self.jumping_height = -2 * self.size
		else:
			self.in_water = False

		if not h:
			h = sprite.spritecollide(self, lavas, False)
			if h:
				if not self.invincible:
					self.invincible = True
					self.health -= 1
				self.in_water = True
				for lava_block in h:
					if lava_block.type == 4 and lava_block.rect.collidepoint(self.rect.midbottom):
						self.jumping_height = -5 * self.size
						break
					else:
						self.jumping_height = -2 * self.size
			else:
				self.in_water = False

		if sprite.spritecollide(self, end_blocks, False):
			if current_level+1 <= len(all_levels):
				levels_unlocked = max(levels_unlocked, current_level+1)
			write_data()
			level_complete(screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1])

		if self.in_water:
			GRAVITY = 0.1
			self.vel.y = min(5, self.vel.y)		# So player doesn't 'fall' too fast in water
			self.vel.y = max(-5*self.size, self.vel.y)	# So player doesn't go flying when they hit a jump pad in water
			self.fric = -0.3

			self.jumping = False
		else:
			GRAVITY = 0.6
			self.fric = -0.1
			self.jumping_height = -8.5 * self.size

		if self.invincible:
			self.injure()

	# If the player lands on a platform or any surface like a platform
	def landed(self):
		self.acc.y = 0
		self.vel.y = 0
		self.jumping = False

	# Finds the farthest chackpoint. If here are none, brings player back to spawn point
	def respawn(self, beginning=False):
		found = False
		if not beginning:
			for i in range(len(flags)-1, -1, -1):
				if flags[i].activated and not found:
					found = True
					self.pos.x, self.pos.y = flags[i].rect.midbottom
					self.vel = vec(0,0)

			if not found:
				self.pos.x, self.pos.y = player_spawn_point
				self.rect.midbottom = self.pos

	# Does all animations for all states of the player
	def animate(self):
		if self.image_on:
			if self.jumping:
				if self.dir == 'right':
					self.image = self.jumping_pic
				elif self.dir == 'left':
					self.image = transform.flip(self.jumping_pic, True, False)
			elif self.ducking:
				if self.dir == 'right':
					self.image = self.ducking_pic
				elif self.dir == 'left':
					self.image = transform.flip(self.ducking_pic, True, False)
			elif self.in_water:
				if self.dir == 'right':
					self.image = self.swimming_pic[(global_tick//10) % len(self.running_images)]
				elif self.dir == 'left':
					self.image = transform.flip(self.swimming_pic[(global_tick//10) % len(self.running_images)], True, False)
			else:
				if abs(self.vel.x) > 1:
					if self.dir == 'right':
						self.image = self.running_images[(global_tick//self.delay) % len(self.running_images)]
					elif self.dir == 'left':
						self.image = transform.flip(self.running_images[(global_tick//self.delay) % len(self.running_images)], True, False)
				else:
					self.image = self.idle_pic
		else:
			self.image = Surface(self.image.get_size(), SRCALPHA)
			self.image.fill((255,255,255,0))

		self.rect = self.image.get_rect()

		self.rect.midbottom = self.pos

	# Hurt effect for the player. Switches between opaque and transparent to show that the player is hurt
	def injure(self):
		self.hurt_counter += 1
		self.invincible = True

		if self.hurt_counter % 8 == 0:			#
			self.image_on = 1 - self.image_on	# Alternate between on and off with some delay
		if self.hurt_counter == 90: 	#
			self.invincible = False		# Stops the 'invincible' effect
			self.image_on = 1			#
			self.hurt_counter = 0		#

# Class for enemy. Includes animating, moving, dying...
class Enemy(sprite.Sprite):
	def __init__(self, pos, type=1):
		sprite.Sprite.__init__(self)
		enemies.add(self)
		self.type = type

		# Blob enemies
		if self.type in [1,2]:
			self.move_by = 2
			self.health = 1
		# Fly enemies
		else:
			self.move_by = 1
			self.health = 2

		# Direction the enemy is moving (blob moves left and right, fly moves up and down)
		self.dir = -1

		# Holds animation for the current enemy type
		self.moving_images = [get_image(enemy_sheet, enemy_cos[3*self.type]), get_image(enemy_sheet, enemy_cos[3*self.type+1])]
		for img in range(len(self.moving_images)):
			self.moving_images[img] = transform.scale(self.moving_images[img], (self.moving_images[img].get_width()*player.size, self.moving_images[img].get_height()*player.size))
		# Image for when the enemy dies
		self.dead_image = get_image(enemy_sheet, enemy_cos[3*self.type+2])
		self.dead_image = transform.scale(self.dead_image, (self.dead_image.get_width()*player.size, self.dead_image.get_height()*player.size))
		self.image = self.moving_images[0]
		self.rect = self.image.get_rect()
		self.pos = [pos[0], pos[1] + player.size*16 + 1]
		self.rect.bottomleft = self.pos

		# Animation counters
		self.frame = 0
		self.ani_counter = 0
		self.ani_counter_max = 10
		self.death_counter = -10
		self.dead = False

	# Animated the enemy
	def make_img(self):
		self.ani_counter += 1

		if not self.dead:
			if self.ani_counter >= self.ani_counter_max:
				self.ani_counter = 0
				self.frame += 1
			self.death_counter = -10
			if self.type in [0,1]:
				if self.dir == -1:
					self.image = self.moving_images[self.frame%len(self.moving_images)]
				if self.dir == 1:
					self.image = transform.flip(self.moving_images[self.frame%len(self.moving_images)], True, False)
			else:
				self.image = self.moving_images[self.frame%len(self.moving_images)]
				if self.rect.centerx < player.rect.centerx:
					self.image = transform.flip(self.image, True, False)

		else:
			self.image = self.dead_image
			if self.type == 2:
				if self.death_counter <= 90:
					self.death_counter += 1
					self.pos[1] += self.death_counter
				else:
					self.pos[1] += 10
					if self.rect.top > height:
						self.kill()
						self.death_counter = -10
			else:
				if self.ani_counter >= 45:
					if self.health > 0:
						self.dead = False
						self.death_counter = 0
						self.ani_counter = 0
					else:
						self.kill()

		self.rect = self.image.get_rect()
		self.rect.bottomleft = self.pos

	# Moves the enemy
	def move(self):
		if self.type in [0,1]:
			self.pos[0] += (self.move_by) * self.dir

			# Change direction when hitting platforms
			h = sprite.spritecollide(self, platforms, False)
			if h:
				for hits in h:
					if hits.texture in [1,3,4,5,6, 10,12,13,14,15]:	# Hits platform's edge or wall
						self.dir *= -1
						self.pos[0] += self.dir*5
						break

			# Special invisible blocks that the enemies can detect to change direction
			hits = sprite.spritecollide(self, change_dirs, False)
			if hits:
				self.dir *= -1
				self.pos[0] += self.dir*5

			# Change direction when hitting jump pads
			h = sprite.spritecollide(self, jump_pads, False)
			if h:
				self.dir *= -1
				self.pos[0] += (self.move_by) * self.dir * 2

		else:
			self.pos[1] += (self.move_by) * self.dir
			hits = sprite.spritecollide(self, platforms, False)
			if hits:
				self.dir *= -1
				self.pos[1] += self.dir*5

			hits = sprite.spritecollide(self, change_dirs, False)
			if hits:
				self.dir *= -1
				self.pos[1] += self.dir*5

			if self.rect.top <= 0 or self.rect.bottom >= height:
				self.dir *= -1
				self.pos[1] += self.dir*5

	# Lets the enemy class know to run the dead animation
	def die(self):
		self.dead = True
		self.frame = 0

# Creates a platform object.
class Platform(sprite.Sprite):
	def __init__(self, pos, texture=4):
		sprite.Sprite.__init__(self)
		platforms.add(self)
		self.texture = texture

		self.image = get_image(platform_sheet, platform_cos[self.texture])
		self.rect = self.image.get_rect()
		self.image = transform.scale(self.image, (self.rect.width * player.size,self.rect.height * player.size))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

# Creates jump pad object
class JumpPad(sprite.Sprite):
	def __init__(self, pos):
		sprite.Sprite.__init__(self)
		jump_pads.add(self)
		# Jump pad animation. Boing Boing!
		self.images = [get_image(misc_sheet2,misc_cos2[7]),get_image(misc_sheet2,misc_cos2[6]),get_image(misc_sheet2,misc_cos2[5])]
		self.images.append(self.images[1])
		self.images.append(self.images[0])
		for img in range(len(self.images)):
			self.rect = self.images[img].get_rect()
			self.images[img] = transform.scale(self.images[img], (self.rect.width * player.size,self.rect.height * player.size))
		self.image = self.images[0]
		self.rect = self.image.get_rect()

		self.pos = pos[0] + player.size*16/2, pos[1] + player.size*16
		self.rect.midbottom = self.pos

		# Counters
		self.active = False
		self.ani_counter = 0
		self.ani_counter_max = 15

	# Animates if jumped on
	def activate(self):
		if self.active:
			self.ani_counter += 1
			tmp = self.rect.bottomright
			self.image = self.images[(self.ani_counter//3)%len(self.images)]
			self.rect = self.image.get_rect()
			self.rect.bottomright = tmp
			if self.ani_counter >= self.ani_counter_max:
				self.ani_counter = 0
				self.active = False

# End of the level. Player enter the door to complete level
class Door(sprite.Sprite):
	def __init__(self, pos, locked=False):
		sprite.Sprite.__init__(self)
		doors.add(self)
		self.locked = locked
		self.image = get_image(decor_sheet, decor_cos[14 - int(self.locked)])
		self.image = transform.scale(self.image, (self.image.get_width()*player.size, self.image.get_height()*player.size))
		self.rect = self.image.get_rect()
		self.rect.bottomleft = pos[0], pos[1] + player.size*16

		self.outline_image = color_change(self.image, 255,255,255)
		self.outline_rect = self.outline_image.get_rect()
		self.outline_image = transform.scale(self.outline_image, (self.outline_rect.width + 16, self.outline_rect.height + 10))
		self.outline_rect = self.outline_image.get_rect()
		self.outline_rect.midbottom = self.rect.midbottom

	# If the player is in a 50 pixel radius, the door is 'enterable'
	def highlight(self):
		global mode, current_level, levels_unlocked
		# Check distance
		dist = hypot(player.rect.centerx - self.rect.centerx, player.rect.centery - self.rect.centery)
		if dist < 50:
			self.outline_rect = self.outline_image.get_rect()
			self.outline_rect.midbottom = self.rect.midbottom
			screen.blit(self.outline_image, self.outline_rect)
			interact_font = font.Font('fonts/GameBoy.ttf', 24).render("W", True, BLACK)
			interact_rect = interact_font.get_rect()
			interact_rect.midbottom = self.outline_rect.midtop
			screen.blit(interact_font, interact_rect)
			if hit_w:
				if current_level+1 <= len(all_levels):
					levels_unlocked = max(levels_unlocked, current_level+1)
				# Save level progress
				write_data()
				level_complete(screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1])
# Special block used in level 5 instead of a door. If the player touches this invisible block, they complete the level 
class EndLevel(sprite.Sprite):
	def __init__(self, pos):
		sprite.Sprite.__init__(self)
		end_blocks.add(self)
		self.image = Surface((player.size*16, player.size*16), SRCALPHA)
		self.image.fill((255,255,255,0))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

# Another invisible block that only the enemes can detect. They use it to switch direction.
class ChangeDir(sprite.Sprite):
	def __init__(self, pos):
		sprite.Sprite.__init__(self)
		change_dirs.add(self)
		self.image = Surface((player.size*16, player.size*16), SRCALPHA)
		self.image.fill((255,255,255,0))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

# Player can swim in the water. The water animates
class Water(sprite.Sprite):
	def __init__(self, pos, type=4):
		sprite.Sprite.__init__(self)
		waters.add(self)
		self.type, self.pos  = type, pos
		if self.type in [6,8,10]:
			self.alpha_wave_images = [get_image(water_sheet, water_cos[self.type]), get_image(water_sheet, water_cos[self.type+1])]
		elif self.type in [7,9,11]:
			self.alpha_wave_images = [get_image(water_sheet, water_cos[self.type-1]), get_image(water_sheet, water_cos[self.type])]
			for pos in range(len(self.alpha_wave_images)):
				self.alpha_wave_images[pos] = transform.flip(self.alpha_wave_images[pos], True, False)
		else: 
			self.alpha_wave_images = [get_image(water_sheet, water_cos[self.type])]
			self.alpha_wave_images.append(transform.flip(self.alpha_wave_images[0], True, False))

		for pic in range(len(self.alpha_wave_images)):
			self.alpha_wave_images[pic] = transform.scale(self.alpha_wave_images[pic], (self.alpha_wave_images[pic].get_width()*player.size, self.alpha_wave_images[pic].get_height()*player.size))
			self.alpha_wave_images[pic] = alpha_pic(self.alpha_wave_images[pic], 150)

		self.image = self.alpha_wave_images[0]
		self.rect = self.image.get_rect()
		self.rect.topleft = self.pos

		self.ani_counter = 0
		self.ani_counter_max = 20
		self.frame = 0

	def animate(self):
		self.ani_counter += 1
		if self.ani_counter >= self.ani_counter_max:
			self.ani_counter = 0
			self.frame += 1
			if self.frame >= len(self.alpha_wave_images):
				self.frame = 0

		self.image = self.alpha_wave_images[self.frame]

# Player should try to stay away from this. Playe gets hurt from this, but can still swim in it like it is water
class Lava(sprite.Sprite):
	def __init__(self, pos, type):
		sprite.Sprite.__init__(self)
		self.type, self.pos = type, pos
		lavas.add(self)
		if self.type in [4,5]:
			self.images = [get_image(water_sheet, water_cos[self.type])]
			self.images.append(transform.flip(self.images[0], True, False))

		for pos in range(len(self.images)):
			self.images[pos] = transform.scale(self.images[pos], (self.images[pos].get_width()*player.size, self.images[pos].get_height()*player.size))

		self.image = self.images[0]
		self.rect = self.image.get_rect()
		self.rect.topleft = self.pos

		self.ani_counter = 0
		self.ani_counter_max = 15
		self.frame = 0

	def animate(self):
		self.ani_counter += 0.5
		if self.ani_counter >= self.ani_counter_max:
			self.ani_counter = 0
			self.frame += 1
			if self.frame >= len(self.images):
				self.frame = 0

		self.image = self.images[self.frame]

# Player can jump and land on it from underneath, unlike a platform
class Bridge(sprite.Sprite):
	def __init__(self, pos):
		sprite.Sprite.__init__(self)
		bridges.add(self)
		tmp = get_image(misc_sheet2, misc_cos2[10])
		self.image = transform.scale(tmp, (tmp.get_width()*player.size, tmp.get_height()*player.size))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

# Player can respawn to the latest checkpoint they got. Saves progress...
class Checkpoint(sprite.Sprite):
	def __init__(self, pos):
		sprite.Sprite.__init__(self)
		flags.append(self)
		self.active_image = [self.make_active_flag(1), self.make_active_flag(2)]
		self.not_active_image = get_image(flag_sheet, flag_cos[0])
		self.not_active_image = transform.scale(self.not_active_image, (self.not_active_image.get_width()*player.size, self.not_active_image.get_height()*player.size))
		self.image = self.not_active_image
		self.rect = self.image.get_rect()
		self.rect.bottomleft = pos[0], pos[1] + player.size*16
		self.activated = False
		self.ani_counter = 0

	# If player gets passed it, the flag will become active
	def make_active_flag(self,type):
		img = Surface((24, 48), SRCALPHA)
		pole_img = get_image(flag_sheet, flag_cos[0])
		pole_rect = pole_img.get_rect()
		img.blit(pole_img, pole_rect)
		flag_img = get_image(flag_sheet, flag_cos[type])
		flag_rect = flag_img.get_rect()
		flag_rect.topleft = pole_rect.centerx, pole_rect.top + 6
		img.blit(flag_img, flag_rect)
		return transform.scale(img, (img.get_width()*player.size, img.get_height()*player.size))

	# animation
	def update(self):
		self.ani_counter += 0.06
		if self.activated:
			self.image = self.active_image[int(self.ani_counter)%len(self.active_image)]
		else:
			self.image = self.not_active_image

# Locked blocks can be unlocked by keys. They disappear when key is collected, allowing the player to get past them
class LockedBlock(sprite.Sprite):
	def __init__(self, pos, color):
		sprite.Sprite.__init__(self)
		locked_blocks.add(self)
		self.color = color
		self.image = get_image(misc_sheet, misc_cos[4 + self.color])
		self.image = transform.scale(self.image, (self.image.get_width()*player.size, self.image.get_height()*player.size))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

# Can unlock all locked blocks of the same color or only the closest locked block of the same color
class Key(sprite.Sprite):
	def __init__(self, pos, color, find_closest=False):
		sprite.Sprite.__init__(self)
		keys.add(self)
		self.pos, self.color, self.close = pos, color, find_closest
		self.image = get_image(misc_sheet, misc_cos[self.color])
		self.image = transform.scale(self.image, (self.image.get_width()*player.size, self.image.get_height()*player.size))
		self.rect = self.image.get_rect()
		self.rect.topleft = pos
		self.picked_up = False
		self.ani_counter = -10
		self.floating_counter = 0

	# Hovering animation
	def animate(self):
		self.floating_counter += 0.1
		self.floating_counter = self.floating_counter
		self.rect.y = self.pos[1] + 5*sin(self.floating_counter)

	# Collecting animation
	def collect(self):
		if not self.picked_up:
			self.ani_counter = -10
		else:
			if self.ani_counter <= 90:
				self.ani_counter += 1
				self.rect.y += self.ani_counter
			else:
				self.rect.y += 10
				if self.rect.top > height:
					self.kill()
					self.picked_up = False
					self.ani_counter = -10

# Special collectible. Add a challenge for the player
class Gem(sprite.Sprite):
	def __init__(self, pos, color, collected = False):
		sprite.Sprite.__init__(self)
		gems.add(self)
		self.pos, self.color, self.collected = pos, color, collected
		if not self.collected:
			self.images = [
			get_image(misc_sheet, misc_cos[13 + self.color]),
			get_image(misc_sheet, misc_cos[17 + self.color]),
			get_image(misc_sheet, misc_cos[21 + self.color])]
			self.images.append(self.images[1])
		else:
			self.images = [get_image(misc_sheet, misc_cos[26]), get_image(misc_sheet, misc_cos[27])]

		for pic in range(len(self.images)):
			self.images[pic] = transform.scale(self.images[pic], (self.images[pic].get_width()*player.size, self.images[pic].get_height()*player.size))

		self.image = self.images[0]
		self.rect = self.image.get_rect()
		self.rect.topleft = pos

		self.picked_up = False
		self.ani_counter = -10
		self.growing_counter = 0

		self.present_max = 9

		self.ani_counter = -10
		self.present_counter = -self.present_max
		self.big_gem_image = transform.scale(self.images[1], (256,256))
		self.big_gem_rect = self.big_gem_image.get_rect()
		self.big_gem_rect.midbottom = width/2, 0
		self.pos = width//2, height//2

	# Pulsing animation
	def animate(self):
		self.growing_counter += 0.1
		self.image = self.images[int(self.growing_counter)%len(self.images)]

	# Collect animation, similar to the key animation
	def collect(self):
		if not self.picked_up:
			self.ani_counter = -10
		else:
			if not self.collected and self.ani_counter == -10:
				self.present(screen_copy)
			if self.ani_counter <= 90:
				self.ani_counter += 1
				self.rect.y += self.ani_counter
			else:
				self.rect.y += 10
				if self.rect.top > height:
					self.kill()
					self.picked_up = False
					self.ani_counter = -10

	# The presentation of the gem when collected
	def present(self, s_copy):
		a = 0
		a_surf = Surface(size, SRCALPHA)
		a_surf.fill((0,0,0,a))
		while self.present_counter <= self.present_max:
			screen.blit(s_copy, (0,0))
			a_surf.fill((0,0,0,int(a)))
			screen.blit(a_surf, (0,0))

			if self.present_counter < 0:
				a += 2
				self.present_counter += 0.15
			elif self.present_counter > 0:
				a -= 2
				self.present_counter += 0.15

			self.big_gem_rect.centery = self.pos[1] + self.present_counter**3

			screen.blit(self.big_gem_image, self.big_gem_rect)
			display.flip()
			myClock.tick(60)

# Allows some areas to be hidden until the user touches it, making it visible
class BackBlock(sprite.Sprite):
	def __init__(self, pos, type, touching=True):
		sprite.Sprite.__init__(self)
		back_blocks.add(self)
		self.type, self.touching = type, touching
		self.dark_image = darken(get_image(platform_sheet, platform_cos[self.type+4]))
		self.dark_image = transform.scale(self.dark_image, (self.dark_image.get_width()*player.size, self.dark_image.get_height()*player.size))
		self.norm_image = get_image(platform_sheet, platform_cos[self.type+4])
		self.norm_image = transform.scale(self.norm_image, (self.norm_image.get_width()*player.size, self.norm_image.get_height()*player.size))
		self.image = self.norm_image
		self.rect = self.image.get_rect()
		self.pos = pos
		self.active = False
		self.rect.topleft = self.pos

	# checks if the user is touching the hidden blocks
	def update(self):
		if self.touching:
			if player.behind_wall:
				self.image = self.dark_image
			else:
				self.image = self.norm_image
		else:
			if self.image != self.dark_image:
				self.image = self.dark_image

# Preview player on main menu
current_preview_player = 0
preview_animations = []		# stores the walking animation for all three players
for p in range(3):			# for the three different players
	tmp = []
	for i in [9, 10]:		# the index of the walking animations
		pic = get_image(player_sheet, player_cos[p*11 + i])
		tmp.append(transform.scale(pic, (pic.get_width()*8, pic.get_height()*8)))	# add pic
	preview_animations.append(tmp)	# add to master list

preview_player_rect = preview_animations[0][0].get_rect()
preview_player_rect.topleft = 64*20, 64*4

# HUD Player lives text
player_lives_string = ''
player_lives_render = None

# Level Stuff
current_level = 9
current_background = 0

background_rect = backgrounds[current_background].get_rect()
background_rect.topleft = 0, 0

### SPRITE GROUPS ###
end_blocks = sprite.Group()
change_dirs = sprite.Group()
all_sprites = sprite.Group()
back_back_sprites = sprite.Group()
back_front_sprites = sprite.Group()
front_sprites = sprite.Group()
enemies = sprite.Group()
platforms = sprite.Group()
back_blocks = sprite.Group()
locked_blocks = sprite.Group()
keys = sprite.Group()
gems = sprite.Group()
jump_pads = sprite.Group()
bushes = sprite.Group()
doors = sprite.Group()
waters = sprite.Group()
lavas = sprite.Group()
bridges = sprite.Group()
flags = []
#####################

# gems collected in the current level
gems_collected = all_gems_collected[current_level-1]

# Make a temporary player to pass into the level_creator
player = Player(player_type=0, pos=[width//2, height//2])
# Makes current level
level_creator(all_levels[current_level-1], current_preview_player)

# Music
mixer.music.set_volume(0)
mixer.music.play(-1)

# Main running loop
while running:
	let_go, space_down, hit_w = False, False, False
	for evt in event.get():
		if evt.type == QUIT:
			p_text = "Are you sure you want to exit?"
			result = popup("QUIT", p_text, ['Yes', 'No'], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1])
			if result: running = False

		elif evt.type == KEYDOWN:
			if evt.key == K_ESCAPE:
				if mode == 'game':
					# Used this try statement because the program would crash if you hit escape during the loading animation
					try:
						pause(screen_copy)
					except NameError: pass
				else:
					# Same here ^^
					try:
						p_text = "Are you sure you want to exit?"
						result = popup("QUIT", p_text, ['Yes', 'No'], screen_copy, main_background_color=current_theme[0], title_background_color=current_theme[1])
						if result: running = False
					except NameError: pass

			elif evt.key == K_SPACE:
				space_down = True

			elif evt.key == K_w:
				hit_w = True

			# Reset the level
			elif evt.key == K_r:
				if mode == 'game':
					level_creator(all_levels[current_level-1], current_preview_player)

			# Respawn at closest checkpoint
			elif evt.key == K_t:
				if mode == 'game':
					player.respawn(beginning=False)

		elif evt.type == MOUSEBUTTONUP:
			if evt.button == 1:
				let_go = True

	mx, my = mouse.get_pos()
	mb = mouse.get_pressed()

	if mode == 'menu':
		if not mixer.music.get_busy():
			mixer.music.load('sound/menu_loop.ogg')
			mixer.music.play(-1)
		screen.fill(WHITE)
		screen.blit(menu_back, menu_back_rect)
		screen.blit(alpha_screen, (0,0))

		## MUSIC STUFF ##

		if music_bool and buttons[3].pic != music_on_pic:
			buttons[3].pic = music_on_pic
		elif not music_bool and buttons[3].pic != music_off_pic:
			buttons[3].pic = music_off_pic

		if music_bool and mixer.music.get_volume() != 0.6: mixer.music.set_volume(0.6)
		elif not music_bool and mixer.music.get_volume() != 0: mixer.music.set_volume(0)
		#################

		## PREVIEW PLAYER ##
		current_animation = preview_animations[current_preview_player][int(ani_counter)%2]
		tmp = round(4*sin(radians(ani_counter*70)))

		gfxdraw.filled_circle(screen,preview_player_rect.centerx,preview_player_rect.centery,196+tmp,(buttons[current_preview_player].hover_color+(100,)))
		draw.circle(screen,buttons[current_preview_player].button_color,preview_player_rect.center,196+tmp,5)

		# Player direction
		if mx < preview_player_rect.centerx:
			screen.blit(transform.flip(current_animation, 1, 0), preview_player_rect)
		else:
			screen.blit(current_animation, preview_player_rect)
		#####################

		# Main title
		gfxdraw.box(screen, (title_text_rect.x - 50, title_text_rect.y - 50, title_text_rect.width + 100, title_text_rect.height + 100), GREY+(100,))
		screen.blit(title_text_render, title_text_rect)

		# Controls screen
		controls_back = 64*10,64*6
		gfxdraw.box(screen,(controls_image_rect.centerx - controls_back[0]/2, controls_image_rect.centery - controls_back[1]/2, controls_back[0], controls_back[1]),(GREY + (150,)))
		screen.blit(controls_image,controls_image_rect)

		# Button update
		for b in buttons:
			b.button_hover(mx,my)

	elif mode == 'game':
		if not mixer.music.get_busy():
			mixer.music.load('sound/upbeat_loop.ogg')
			mixer.music.play(-1)
		screen.fill(WHITE)

		# Stitches the backgrounds together for the whole length of the level
		for i in range(-backgrounds[current_background].get_width(), all_levels[current_level-1].get_width()*player.size*16, backgrounds[current_background].get_width()):
			screen.blit(backgrounds[current_background], (background_rect.x+i, background_rect.y))

		# Player updates
		player.move()
		player_scroll()

		### OBJECT UPDATES ###
		for d in doors:
			d.highlight()
		for e in enemies:
			if not e.dead:
				e.move()
			e.make_img()
		for jp in jump_pads:
			jp.activate()
		for wa in waters:
			wa.animate()
		for la in lavas:
			la.animate()
		for bb in back_blocks:
			bb.update()
		for k in keys:
			if not k.picked_up:
				k.animate()
			k.collect()

		for g in gems:
			if not g.picked_up:
				g.animate()
			g.collect()

		for fl in flags:
			if player.rect.right > fl.rect.left and player.rect.bottom <= fl.rect.bottom:
				if not fl.activated:
					fl.activated = True
			fl.update()
		######################

		player.animate()
		# Draw this group at the back
		back_back_sprites.draw(screen)
		# Only if player touches hidden blocks
		if player.behind_wall:
			back_front_sprites.draw(screen)

		# Player in the middle
		screen.blit(player.image, player.rect)
		# In front of player
		front_sprites.draw(screen); all_sprites.draw(screen)

		# Health HUD
		for i in range(3):
			if i >= player.health/2:
				screen.blit(heart_images[2], (25 + i*50, 25))
		for i in range(0, player.health-1, 2):
			screen.blit(heart_images[0], (25 + i*25,25))
		if player.health % 2:
			screen.blit(heart_images[1], (25 + (player.health-1)*25, 25))

		# Gems HUD
		for n,g in enumerate(gems_collected):
			if n < total_gems_in_level:
				if not g:
					screen.blit(empty_gem, (width/2 + (n - total_gems_in_level/2) * 50, 25))
				elif g:
					screen.blit(actual_gem_images[n], (width/2 + (n - total_gems_in_level/2) * 50, 25))

		# Lives HUD
		if player_lives_string != 'x ' + str(player.lives):
			player_lives_string = 'x ' + str(player.lives)
			if current_level >= 6:
				player_lives_render = font.Font('fonts/GameBoy.ttf', 20).render(player_lives_string, True, WHITE)
			else:
				player_lives_render = font.Font('fonts/GameBoy.ttf', 20).render(player_lives_string, True, BLACK)

		screen.blit(player.lives_image, (25 , 100))
		screen.blit(player_lives_render, (75,100))

		# Pause Button
		if pause_rect.collidepoint((mx,my)):
			gfxdraw.filled_circle(screen,pause_rect.centerx,pause_rect.centery,pause_rect.width*2//3,current_theme[0]+(220,))
			screen.blit(pause_img_hover, pause_rect)
			if let_go:
				pause(screen_copy)
		else:
			screen.blit(pause_img, pause_rect)

		# Respawn at previous checkpoint button
		if previous_checkpoint_rect.collidepoint((mx,my)):
			gfxdraw.filled_circle(screen,previous_checkpoint_rect.centerx,previous_checkpoint_rect.centery,previous_checkpoint_rect.width*2//3,current_theme[0]+(220,))
			screen.blit(previous_checkpoint_img_hover, previous_checkpoint_rect)
			if let_go: player.respawn(beginning=False)
		else: screen.blit(previous_checkpoint_img, previous_checkpoint_rect)

		# Checks if player is has run out of health
		if player.health == 0:
			player.lives -= 1
			player.respawn(beginning=False)
		# Checks if player is has run out of lives
		if player.lives < 0:
			read_data()		# All gems got in the session are reset.
			level_creator(all_levels[current_level-1], current_preview_player)	# Remake the level
			player.lives = 5

	display.flip()
	screen_copy = screen.copy()

	myClock.tick(FPS)
	dt = myClock.get_fps()
	display.set_caption('Alien Adventures')
	ani_counter += 0.2
	global_tick += 1

quit()

# Updates settings
if mode == 'menu':
	write_data()
