#!/usr/bin/env python3

import pygame
from os import listdir
from os.path import isfile, join
from pygame import mixer

pygame.init()
pygame.display.set_caption("pyohmine ninjas")

WIDTH, HEIGHT = 1000, 800
FPS = 60
PLAYER_VEL = 5
CULL_MARGIN = 300
BLOCK_SIZE = 96

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)

window = pygame.display.set_mode((WIDTH, HEIGHT))

TITLE_FONT = pygame.font.SysFont("Arial", 72, bold=True)
HEADING_FONT = pygame.font.SysFont("Arial", 40, bold=True)
LABEL_FONT = pygame.font.SysFont("Arial", 26, bold=True)
BIG_FONT = pygame.font.SysFont("Arial", 64, bold=True)

CHARACTERS = ["NinjaFrog", "MaskDude", "PinkMan", "VirtualGuy"]

clock = pygame.time.Clock()


# ---------------------------------------------------------------------------
# asset helpers
# ---------------------------------------------------------------------------

def flip(sprites):
    return [pygame.transform.flip(sprite, True, False) for sprite in sprites]


def load_sprite_sheets(dir1, dir2, width, height, direction=False):
    path = join("assets", dir1, dir2)
    images = [f for f in listdir(path) if isfile(join(path, f))]

    all_sprites = {}

    for image in images:
        sprite_sheet = pygame.image.load(join(path, image)).convert_alpha()

        sprites = []
        for i in range(sprite_sheet.get_width() // width):
            surface = pygame.Surface((width, height), pygame.SRCALPHA, 32)
            rect = pygame.Rect(i * width, 0, width, height)
            surface.blit(sprite_sheet, (0, 0), rect)
            sprites.append(pygame.transform.scale2x(surface))

        if direction:
            all_sprites[image.replace(".png", "") + "_right"] = sprites
            all_sprites[image.replace(".png", "") + "_left"] = flip(sprites)
        else:
            all_sprites[image.replace(".png", "")] = sprites

    return all_sprites


def load_sprite_3dir(dir1, dir2, dir3, width, height):
    path = join("assets", dir1, dir2, dir3)
    images = [f for f in listdir(path) if isfile(join(path, f))]

    all_sprites = {}

    for image in images:
        sprite_sheet = pygame.image.load(join(path, image)).convert_alpha()

        sprites = []
        for i in range(sprite_sheet.get_width() // width):
            surface = pygame.Surface((width, height), pygame.SRCALPHA, 32)
            rect = pygame.Rect(i * width, 0, width, height)
            surface.blit(sprite_sheet, (0, 0), rect)
            sprites.append(pygame.transform.scale2x(surface))
            all_sprites[image.replace(".png", "")] = sprites

    return all_sprites


# Terrain.png is a 4-column x 3-row sheet of block styles; column 1/row 0 is
# the grass/dirt block levels 1 & 2 use, column 0/row 0 is the stone-framed
# block level 3 uses, and column 3/row 1 is the red brick level 4 uses.
TERRAIN_COLUMNS = [0, 96, 192, 272]
TERRAIN_ROWS = [0, 64, 128]

# The floating-platform column (col 3, row 0) holds 3 stacked thin plank
# skins instead of a normal block -- each is 48x5 native pixels.
FLOATING_PLATFORM_X = TERRAIN_COLUMNS[3]
FLOATING_PLATFORM_SKIN_Y = [0, 16, 32]


def get_block(size, col=1, row=0):
    path = join("assets", "Terrain", "Terrain.png")
    image = pygame.image.load(path).convert_alpha()
    surface = pygame.Surface((size, size), pygame.SRCALPHA, 32)
    rect = pygame.Rect(TERRAIN_COLUMNS[col], TERRAIN_ROWS[row], size, size)
    surface.blit(image, (0, 0), rect)
    return pygame.transform.scale2x(surface)


ALL_CHARACTER_SPRITES = {
    name: load_sprite_sheets("MainCharacters", name, 32, 32, True)
    for name in CHARACTERS
}


# ---------------------------------------------------------------------------
# entities
# ---------------------------------------------------------------------------

class Player(pygame.sprite.Sprite):
    GRAVITY = 1
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height, sprites):
        super().__init__()
        self.sprites = sprites
        self.rect = pygame.Rect(x, y, width, height)
        self.x_vel = 0
        self.y_vel = 0
        self.mask = None
        self.direction = "right"
        self.animation_count = 0
        self.fall_count = 0
        self.jump_count = 0
        self.hit = False
        self.hit_count = 0
        self.player_hit = 0
        self.sprite = self.sprites["idle_right"][0]
        self.update()

    def jump(self):
        self.y_vel = -self.GRAVITY * 8
        self.animation_count = 0
        self.jump_count += 1
        if self.jump_count == 1:
            self.fall_count = 0

    def move(self, dx, dy):
        self.rect.x += dx
        self.rect.y += dy

    def make_hit(self):
        if not self.hit:
            self.hit = True
            self.player_hit += 1
            self.hit_count = 0

    def move_left(self, vel):
        self.x_vel = -vel
        if self.direction != "left":
            self.direction = "left"
            self.animation_count = 0

    def move_right(self, vel):
        self.x_vel = vel
        if self.direction != "right":
            self.direction = "right"
            self.animation_count = 0

    def loop(self, fps):
        self.y_vel += min(1, (self.fall_count / fps) * self.GRAVITY)
        self.move(self.x_vel, self.y_vel)

        if self.hit:
            self.hit_count += 1
        if self.hit_count > fps * 2:
            self.hit = False
            self.hit_count = 0

        self.fall_count += 1
        self.update_sprite()

    def landed(self):
        self.fall_count = 0
        self.y_vel = 0
        self.jump_count = 0

    def hit_head(self):
        self.y_vel *= -1

    def update_sprite(self):
        sprite_sheet = "idle"
        if self.hit:
            sprite_sheet = "hit"
        elif self.y_vel < 0:
            if self.jump_count == 1:
                sprite_sheet = "jump"
            elif self.jump_count == 2:
                sprite_sheet = "double_jump"
        elif self.y_vel > self.GRAVITY * 2:
            sprite_sheet = "fall"
        elif self.x_vel != 0:
            sprite_sheet = "run"

        sprite_sheet_name = sprite_sheet + "_" + self.direction
        sprites = self.sprites[sprite_sheet_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.sprite = sprites[sprite_index]
        self.animation_count += 1
        self.update()

    def update(self):
        self.rect = self.sprite.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.sprite)

    def draw(self, win, offset_x):
        win.blit(self.sprite, (self.rect.x - offset_x, self.rect.y))


class Checkpoints(pygame.sprite.Sprite):
    def __init__(self, x, y, width, height, name=None):
        super().__init__()
        self.rect = pygame.Rect(x, y, width, height)
        self.image = pygame.Surface((width, height), pygame.SRCALPHA)
        self.width = width
        self.height = height
        self.name = name

    def draw(self, win, offset_x):
        win.blit(self.image, (self.rect.x - offset_x, self.rect.y))

    def in_view(self, offset_x, width, margin=CULL_MARGIN):
        return self.rect.right >= offset_x - margin and self.rect.left <= offset_x + width + margin


class Object(pygame.sprite.Sprite):
    def __init__(self, x, y, width, height, name=None):
        super().__init__()
        self.rect = pygame.Rect(x, y, width, height)
        self.image = pygame.Surface((width, height), pygame.SRCALPHA)
        self.width = width
        self.height = height
        self.name = name

    def draw(self, win, offset_x):
        win.blit(self.image, (self.rect.x - offset_x, self.rect.y))

    def in_view(self, offset_x, width, margin=CULL_MARGIN):
        return self.rect.right >= offset_x - margin and self.rect.left <= offset_x + width + margin


class Block(Object):
    def __init__(self, x, y, size, col=1, row=0):
        super().__init__(x, y, size, size)
        block = get_block(size, col, row)
        self.image.blit(block, (0, 0))
        self.mask = pygame.mask.from_surface(self.image)


class Fire(Object):
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height):
        super().__init__(x, y, width, height, "fire")
        self.fire = load_sprite_sheets("Traps", "Fire", width, height)
        self.image = self.fire["off"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "off"

    def on(self):
        self.animation_name = "on"

    def off(self):
        self.animation_name = "off"

    def loop(self):
        sprites = self.fire[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.animation_count // self.ANIMATION_DELAY > len(sprites):
            self.animation_count = 0


class Fruits(Object):
    ANIMATION_DELAY = 3
    SPRITES = load_sprite_sheets("Items", "Fruits", 32, 32)

    def __init__(self, x, y, width, height, animation_name):
        super().__init__(x, y, width, height, "fruits")
        self.fruits = self.SPRITES
        self.animation_name = animation_name
        self.kind = animation_name  # remembers the fruit type even after off() switches to "Collected"
        self.image = self.fruits[self.animation_name][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.collected = False

    def on(self):
        pass

    def off(self):
        self.animation_name = "Collected"
        self.collected = True

    def update_sprite(self):
        sprites = self.fruits[self.animation_name]
        sprite_index = (self.animation_count // self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

    def loop(self):
        self.update_sprite()
        self.animation_count += 1

        if self.animation_count // self.ANIMATION_DELAY > len(self.fruits[self.animation_name]):
            self.animation_count = 0


FRUIT_ICONS = {
    name: sprites[0]
    for name, sprites in Fruits.SPRITES.items()
}


class Flag(Checkpoints):
    ANIMATION_DELAY = 3
    SPRITES = load_sprite_3dir("Items", "Checkpoints", "Checkpoint", 64, 64)

    def __init__(self, x, y, width, height):
        super().__init__(x, y, width, height, "flag")
        self.flag = self.SPRITES
        self.image = self.flag["Checkpoint (Flag Idle)(64x64)"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Checkpoint (Flag Idle)(64x64)"

    def on(self):
        self.animation_name = "Checkpoint (Flag Idle)(64x64)"

    def off(self):
        self.animation_name = "Checkpoint (Flag Out) (64x64)"

    def loop(self):
        sprites = self.flag[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.animation_count // self.ANIMATION_DELAY > len(sprites):
            self.animation_count = 0


class RockHead(Object):
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height, y_stop):
        super().__init__(x, y, width, height, "rockhead")
        self.rockhead = load_sprite_sheets("Traps", "rockhead", width, height)
        self.image = self.rockhead["Blink (42x42)"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Blink (42x42)"
        self.y_vel = 1
        self.y_stop = y_stop
        self.direction = "down"

    def move_down(self):
        self.rect.y += self.y_vel

    def move_up(self):
        self.rect.y -= self.y_vel

    def loop(self):
        sprites = self.rockhead[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.animation_count // self.ANIMATION_DELAY > len(sprites):
            self.animation_count = 0

        if self.rect.y <= self.y_stop and self.direction == "down":
            self.move_down()
        elif self.rect.y >= self.y_stop:
            self.direction = "up"
            self.move_up()
        elif self.rect.y == 0 and self.direction == "up":
            self.direction = "down"
            self.move_down()
        elif self.rect.y <= self.y_stop and self.direction == "up":
            self.move_up()


class Saw(Object):
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height, x_right, x_left, speed=3):
        super().__init__(x, y, width, height, "saw")
        self.saw = load_sprite_sheets("Traps", "Saw", width, height)
        self.image = self.saw["on"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "on"
        self.x_vel = speed
        self.x_right = x_right
        self.x_left = x_left
        self.direction = "right"

    def move_right(self):
        self.rect.x += self.x_vel

    def move_left(self):
        self.rect.x -= self.x_vel

    def loop(self):
        sprites = self.saw[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.animation_count // self.ANIMATION_DELAY > len(sprites):
            self.animation_count = 0

        if self.rect.x <= self.x_right and self.direction == "right":
            self.move_right()
        elif self.rect.x >= self.x_right and self.direction == "right":
            self.direction = "left"
            self.move_left()

        if self.rect.x >= self.x_left and self.direction == "left":
            self.move_left()
        elif self.rect.x <= self.x_left and self.direction == "left":
            self.direction = "right"
            self.move_right()


class Spikehead_x(Object):
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height, x_right, x_left, speed=3):
        super().__init__(x, y, width, height, "spikehead_x")
        self.spikehead_x = load_sprite_sheets("Traps", "spikehead", width,
                                              height)
        self.image = self.spikehead_x["Idle"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Idle"
        self.x_vel = speed
        self.x_right = x_right
        self.x_left = x_left
        self.direction = "right"

    def move_right(self):
        self.rect.x += self.x_vel

    def move_left(self):
        self.rect.x -= self.x_vel

    def loop(self):
        sprites = self.spikehead_x[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.animation_count // self.ANIMATION_DELAY > len(sprites):
            self.animation_count = 0

        if self.rect.x <= self.x_right and self.direction == "right":
            self.move_right()
        elif self.rect.x >= self.x_right and self.direction == "right":
            self.direction = "left"
            self.move_left()

        if self.rect.x >= self.x_left and self.direction == "left":
            self.move_left()
        elif self.rect.x <= self.x_left and self.direction == "left":
            self.direction = "right"
            self.move_right()


class Spikes(Object):
    """Static ground spikes - touch them and you're hit. No animation."""

    def __init__(self, x, y, width=16, height=16):
        super().__init__(x, y, width, height, "spikes")
        sprites = load_sprite_sheets("Traps", "Spikes", width, height)
        self.image = sprites["Idle"][0]
        self.mask = pygame.mask.from_surface(self.image)


class Trampoline(Object):
    """Launches the player upward instead of letting them land normally."""
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width=28, height=28, launch_vel=-12):
        super().__init__(x, y, width, height, "trampoline")
        self.sprites = load_sprite_sheets("Traps", "Trampoline", width, height)
        self.animation_name = "Idle"
        self.image = self.sprites[self.animation_name][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.bouncing = False
        self.launch_vel = launch_vel

    def bounce(self):
        self.animation_name = "Jump (28x28)"
        self.animation_count = 0
        self.bouncing = True

    def loop(self):
        sprites = self.sprites[self.animation_name]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.image = sprites[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.bouncing and self.animation_count // self.ANIMATION_DELAY >= len(sprites):
            self.animation_name = "Idle"
            self.animation_count = 0
            self.bouncing = False


class FloatingPlatform(Object):
    """A thin solid platform (Terrain.png's [0][4] plank tiles) that ferries
    the player back and forth between x_left and x_right, like Saw/Spikehead_x."""
    NATIVE_TILE_WIDTH = 48
    NATIVE_HEIGHT = 5

    def __init__(self, x, y, x_right, x_left, width=96, speed=3, skin=0):
        height = self.NATIVE_HEIGHT * 2
        super().__init__(x, y, width, height, "floating_platform")

        sheet = pygame.image.load(join("assets", "Terrain", "Terrain.png")).convert_alpha()
        bar_y = FLOATING_PLATFORM_SKIN_Y[skin]
        native_width = width // 2
        tile = pygame.Surface((native_width, self.NATIVE_HEIGHT), pygame.SRCALPHA, 32)
        for i in range(0, native_width, self.NATIVE_TILE_WIDTH):
            tile.blit(sheet, (i, 0), pygame.Rect(FLOATING_PLATFORM_X, bar_y, self.NATIVE_TILE_WIDTH, self.NATIVE_HEIGHT))
        self.image = pygame.transform.scale2x(tile)
        self.mask = pygame.mask.from_surface(self.image)

        self.x_vel = speed
        self.x_right = x_right
        self.x_left = x_left
        self.direction = "right"
        self.dx = 0  # how far this platform moved last frame -- lets a
                     # standing player be carried along with it

    def loop(self):
        start_x = self.rect.x

        if self.rect.x <= self.x_right and self.direction == "right":
            self.rect.x += self.x_vel
        elif self.rect.x >= self.x_right and self.direction == "right":
            self.direction = "left"

        if self.rect.x >= self.x_left and self.direction == "left":
            self.rect.x -= self.x_vel
        elif self.rect.x <= self.x_left and self.direction == "left":
            self.direction = "right"

        self.dx = self.rect.x - start_x


# ---------------------------------------------------------------------------
# background / drawing / collision
# ---------------------------------------------------------------------------

def get_background(name):
    tile = pygame.image.load(join("assets", "Background", name)).convert()
    width, height = tile.get_size()

    background = pygame.Surface((WIDTH, HEIGHT))
    for i in range(WIDTH // width + 1):
        for j in range(HEIGHT // height + 1):
            background.blit(tile, (i * width, j * height))

    return background


def draw(window, background, player, objects, checkpoints, offset_x):
    window.blit(background, (0, 0))

    for obj in objects:
        obj.draw(window, offset_x)

    for check in checkpoints:
        check.draw(window, offset_x)

    player.draw(window, offset_x)


def handle_vertical_collision(player, objects, dy):
    collided_objects = []
    for obj in objects:
        if pygame.sprite.collide_mask(player, obj):
            if obj.name == "trampoline":
                if dy > 0:
                    player.rect.bottom = obj.rect.top
                    player.y_vel = obj.launch_vel
                    player.fall_count = 0
                    player.jump_count = 1
                    obj.bounce()
                # else: still overlapping mid-launch (ascending) -- ignore it
                # instead of falling through to the hit_head branch below,
                # which would flip y_vel and cut the bounce short.
            elif obj.name == "floating_platform":
                if dy >= 0:
                    player.rect.bottom = obj.rect.top
                    player.landed()
                    player.rect.x += obj.dx  # ride the platform along with it
                else:
                    player.rect.top = obj.rect.bottom
                    player.hit_head()
            elif dy > 0:
                player.rect.bottom = obj.rect.top
                player.landed()
            elif dy < 0:
                player.rect.top = obj.rect.bottom
                player.hit_head()

            collided_objects.append(obj)

    # A player resting on a platform still drifts a couple px away from it
    # between frames (gravity's fall_count keeps climbing even at rest),
    # which makes exact mask overlap intermittent -- fine for static ground
    # (the 1px vertical snap is invisible) but it made riding a moving
    # platform jerky, since the horizontal carry below only fired on the
    # frames mask overlap happened to catch. Use a loose rect check instead
    # so a standing player keeps getting carried every frame.
    for obj in objects:
        if obj in collided_objects or obj.name != "floating_platform":
            continue
        standing = (
            dy >= 0
            and 0 <= obj.rect.top - player.rect.bottom <= 10
            and player.rect.right > obj.rect.left
            and player.rect.left < obj.rect.right
        )
        if standing:
            player.rect.bottom = obj.rect.top
            player.landed()
            player.rect.x += obj.dx
            collided_objects.append(obj)

    return collided_objects


def collide(player, objects, dx):
    # Only the rect moves here; the sprite (and therefore the mask) is
    # unchanged, so there's no need to pay for player.update()'s
    # pygame.mask.from_surface() call on every probe.
    player.rect.x += dx
    collided_object = None
    for obj in objects:
        if pygame.sprite.collide_mask(player, obj):
            collided_object = obj
            break

    player.rect.x -= dx
    return collided_object


def check_point(player, checkpoints, dx):
    player.rect.x += dx
    collided_object = None
    for chk in checkpoints:
        if pygame.sprite.collide_mask(player, chk):
            collided_object = chk
            break

    player.rect.x -= dx
    return collided_object


def handle_move(player, objects, checkpoints, flag, fruits):
    keys = pygame.key.get_pressed()

    player.x_vel = 0
    collide_left = collide(player, objects, -PLAYER_VEL * 2)
    collide_right = collide(player, objects, PLAYER_VEL * 2)
    chk_left = check_point(player, checkpoints, -PLAYER_VEL * 2)
    chk_right = check_point(player, checkpoints, PLAYER_VEL * 2)

    if keys[pygame.K_LEFT] and not collide_left:
        player.move_left(PLAYER_VEL)
    if keys[pygame.K_RIGHT] and not collide_right:
        player.move_right(PLAYER_VEL)

    vertical_collide = handle_vertical_collision(player, objects, player.y_vel)
    to_check = [collide_left, collide_right, *vertical_collide, chk_left,
                chk_right]

    for obj in to_check:
        if obj and obj.name in ("fire", "rockhead", "saw", "spikehead_x", "spikes"):
            player.make_hit()
        elif obj and obj.name == "flag":
            flag.off()

    # Fruits are a pickup, not solid ground -- check overlap directly instead
    # of routing them through collide()/handle_vertical_collision(), which
    # would otherwise treat them as something the player can stand/bump on.
    for fruit in fruits:
        if not fruit.collected and pygame.sprite.collide_mask(player, fruit):
            fruit.off()

    reached_flag = pygame.sprite.collide_mask(player, flag) is not None
    return reached_flag


# ---------------------------------------------------------------------------
# level 1 -- matches the original ninja-frog.py layout
# ---------------------------------------------------------------------------

def build_level_1():
    block_size = BLOCK_SIZE

    cherry = Fruits((block_size * 39) - 44, HEIGHT - (block_size + 60), 32, 32, "Cherries")
    bananas = Fruits(WIDTH * 2 + (block_size * 5), block_size * 3, 32, 32, "Bananas")
    fruits = [cherry, bananas]

    fire_positions = [block_size * 7 - 70, block_size * 7 - 35, block_size * 7, block_size * 7 + 35]
    fires = []
    for pos in fire_positions:
        f = Fire(pos, HEIGHT - block_size - 64, 16, 32)
        f.on()
        fires.append(f)

    rockheads = [
        RockHead(7, block_size * 2, 42, 42, 530),
        RockHead(block_size * 3 + 3, 0, 42, 42, 340),
        RockHead(block_size * 7 + 4, -200, 42, 42, 150),
    ]

    spikeheads = [
        Spikehead_x(block_size * 37, HEIGHT - (block_size * 2), 54, 52, block_size * 41, block_size * 36),
        Spikehead_x(block_size * 38, HEIGHT - (block_size * 4), 54, 52, block_size * 40, block_size * 37),
    ]

    saws = [Saw(block_size * 11, 0, 38, 42, (WIDTH * 2) - 90, block_size * 11)]

    trampolines = []
    spikes = []

    flag = Flag((WIDTH * 5) - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    floor = [
        Block(i * block_size, HEIGHT - block_size, block_size)
        for i in range(-WIDTH // block_size, (WIDTH * 2) // block_size)
    ]
    floor2 = [
        Block(i * block_size, block_size, block_size)
        for i in range((block_size * 11) // block_size, (WIDTH * 2) // block_size)
    ]
    floor3 = [
        Block(i * block_size, HEIGHT - block_size, block_size)
        for i in range((block_size * 33) // block_size, WIDTH * 5 // block_size)
    ]
    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size),
        Block(block_size * 3, HEIGHT - block_size * 4, block_size),
        Block(block_size * 7, HEIGHT - block_size * 6, block_size),
        Block((WIDTH * 2) + (block_size * 4), block_size * 4, block_size),
        Block((WIDTH * 2) + (block_size * 5), block_size * 4, block_size),
        Block((WIDTH * 2) + (block_size * 6), block_size * 4, block_size),
        Block(block_size * 35, HEIGHT - (block_size * 2), block_size),
        Block(block_size * 42, HEIGHT - (block_size * 2), block_size),
        Block(block_size * 37, HEIGHT - (block_size * 3), block_size),
        Block(block_size * 38, HEIGHT - (block_size * 3), block_size),
        Block(block_size * 39, HEIGHT - (block_size * 3), block_size),
        Block(block_size * 40, HEIGHT - (block_size * 3), block_size),
    ]

    blocks = [*floor, *floor2, *floor3, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines]

    return {
        "name": "Level 1",
        "background": get_background("Purple.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


# ---------------------------------------------------------------------------
# level 2 -- longer, denser, a different color palette
# ---------------------------------------------------------------------------

def build_level_2():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 7

    fruits = [
        Fruits(block_size * 7, HEIGHT - block_size * 5 - 50, 32, 32, "Strawberry"),
        Fruits(block_size * 20, HEIGHT - block_size * 4 - 60, 32, 32, "Kiwi"),
        Fruits(block_size * 45, HEIGHT - block_size * 5 - 40, 32, 32, "Melon"),
        Fruits(block_size * 33, HEIGHT - block_size * 4 - 60, 32, 32, "Pineapple"),
        Fruits(57 * block_size, HEIGHT - block_size * 4 - 50, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 9, block_size * 26, block_size * 48, block_size * 58):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 17, -150, 42, 42, 380),
        RockHead(block_size * 33, 0, 42, 42, 300),
        RockHead(block_size * 52, -200, 42, 42, 420),
    ]

    spikeheads = [
        Spikehead_x(block_size * 13, HEIGHT - block_size * 2, 54, 52, block_size * 16, block_size * 12, speed=4),
        Spikehead_x(block_size * 29, HEIGHT - block_size * 2, 54, 52, block_size * 32, block_size * 27, speed=4),
        Spikehead_x(block_size * 43, HEIGHT - block_size * 2, 54, 52, block_size * 46, block_size * 41, speed=4),
        Spikehead_x(block_size * 61, HEIGHT - block_size * 2, 54, 52, block_size * 65, block_size * 60, speed=4),
    ]

    saws = [
        Saw(block_size * 21, HEIGHT - block_size * 5, 38, 42, block_size * 24, block_size * 18, speed=4),
        Saw(block_size * 55, HEIGHT - block_size * 5, 38, 42, block_size * 60, block_size * 55, speed=4),
    ]

    spikes = [
        Spikes(block_size * 7, HEIGHT - block_size - 32),
        Spikes(block_size * 7 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 24, HEIGHT - block_size - 32),
        Spikes(block_size * 24 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 39, HEIGHT - block_size - 32),
        Spikes(block_size * 63, HEIGHT - block_size - 32),
        Spikes(block_size * 63 + 32, HEIGHT - block_size - 32),
    ]

    trampolines = [
        Trampoline(block_size * 17, HEIGHT - block_size - 56),
        Trampoline(block_size * 30, HEIGHT - block_size - 56),
        Trampoline(block_size * 46, HEIGHT - block_size - 56),
    ]

    flag = Flag(level_end - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    floor = [
        Block(i * block_size, HEIGHT - block_size, block_size)
        for i in range(-WIDTH // block_size, level_end // block_size)
    ]

    band_a = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size)
        for i in range(18, 24)
    ]
    band_b = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size)
        for i in range(31, 40)
    ]
    band_c = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size)
        for i in range(47, 52)
    ]
    band_d = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size)
        for i in range(55, 59)
    ]

    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size),
        Block(block_size * 4, HEIGHT - block_size * 4, block_size),
        Block(block_size * 6, HEIGHT - block_size * 5, block_size),
        Block(block_size * 7, HEIGHT - block_size * 5, block_size),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size),
    ]

    blocks = [*floor, *band_a, *band_b, *band_c, *band_d, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines]

    return {
        "name": "Level 2",
        "background": get_background("Green.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


# ---------------------------------------------------------------------------
# level 3 -- longer than level 2, same difficulty, stone-block terrain
# ---------------------------------------------------------------------------

def build_level_3():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 8

    fruits = [
        Fruits(block_size * 6, HEIGHT - block_size * 5 - 50, 32, 32, "Apple"),
        Fruits(block_size * 16, HEIGHT - block_size * 5 - 40, 32, 32, "Bananas"),
        Fruits(block_size * 26, HEIGHT - block_size * 4 - 60, 32, 32, "Cherries"),
        Fruits(block_size * 36, HEIGHT - block_size * 5 - 50, 32, 32, "Strawberry"),
        Fruits(block_size * 46, HEIGHT - block_size * 4 - 60, 32, 32, "Kiwi"),
        Fruits(block_size * 56, HEIGHT - block_size * 5 - 40, 32, 32, "Melon"),
        Fruits(block_size * 66, HEIGHT - block_size * 5 - 40, 32, 32, "Pineapple"),
        Fruits(76 * block_size, HEIGHT - block_size * 5 - 40, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 9, block_size * 26, block_size * 40, block_size * 58, block_size * 72):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 17, -150, 42, 42, 380),
        RockHead(block_size * 33, 0, 42, 42, 300),
        RockHead(block_size * 52, -200, 42, 42, 420),
        RockHead(block_size * 70, -150, 42, 42, 360),
    ]

    spikeheads = [
        Spikehead_x(block_size * 13, HEIGHT - block_size * 2, 54, 52, block_size * 16, block_size * 12, speed=4),
        Spikehead_x(block_size * 29, HEIGHT - block_size * 2, 54, 52, block_size * 32, block_size * 27, speed=4),
        Spikehead_x(block_size * 43, HEIGHT - block_size * 2, 54, 52, block_size * 46, block_size * 41, speed=4),
        Spikehead_x(block_size * 61, HEIGHT - block_size * 2, 54, 52, block_size * 65, block_size * 60, speed=4),
        Spikehead_x(block_size * 75, HEIGHT - block_size * 2, 54, 52, block_size * 76, block_size * 73, speed=4),
    ]

    saws = [
        Saw(block_size * 21, HEIGHT - block_size * 5, 38, 42, block_size * 24, block_size * 18, speed=4),
        Saw(block_size * 55, HEIGHT - block_size * 5, 38, 42, block_size * 60, block_size * 55, speed=4),
        Saw(block_size * 70, HEIGHT - block_size * 5, 38, 42, block_size * 77, block_size * 72, speed=4),
    ]

    spikes = [
        Spikes(block_size * 7, HEIGHT - block_size - 32),
        Spikes(block_size * 7 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 24, HEIGHT - block_size - 32),
        Spikes(block_size * 24 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 39, HEIGHT - block_size - 32),
        Spikes(block_size * 63, HEIGHT - block_size - 32),
        Spikes(block_size * 63 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 73, HEIGHT - block_size - 32),
        Spikes(block_size * 73 + 32, HEIGHT - block_size - 32),
    ]

    trampolines = [
        Trampoline(block_size * 17, HEIGHT - block_size - 56),
        Trampoline(block_size * 30, HEIGHT - block_size - 56),
        Trampoline(block_size * 46, HEIGHT - block_size - 56),
        Trampoline(block_size * 65, HEIGHT - block_size - 56),
        Trampoline(block_size * 76, HEIGHT - block_size - 56),
    ]

    flag = Flag(level_end - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    floor = [
        Block(i * block_size, HEIGHT - block_size, block_size, col=0)
        for i in range(-WIDTH // block_size, level_end // block_size)
    ]

    band_a = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=0)
        for i in range(18, 24)
    ]
    band_b = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=0)
        for i in range(31, 40)
    ]
    band_c = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=0)
        for i in range(47, 52)
    ]
    band_d = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=0)
        for i in range(55, 59)
    ]
    band_e = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=0)
        for i in range(66, 72)
    ]

    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size, col=0),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size, col=0),
        Block(block_size * 4, HEIGHT - block_size * 4, block_size, col=0),
        Block(block_size * 6, HEIGHT - block_size * 5, block_size, col=0),
        Block(block_size * 7, HEIGHT - block_size * 5, block_size, col=0),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size, col=0),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size, col=0),
    ]

    blocks = [*floor, *band_a, *band_b, *band_c, *band_d, *band_e, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines]

    return {
        "name": "Level 3",
        "background": get_background("Gray.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


# ---------------------------------------------------------------------------
# level 4 -- harder & longer than level 3, uses floating platforms to cross
# hazard-filled gaps in the ground, red brick terrain
# ---------------------------------------------------------------------------

def build_level_4():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 9

    fruits = [
        Fruits(block_size * 6, HEIGHT - block_size * 4 - 50, 32, 32, "Apple"),
        Fruits(block_size * 16, HEIGHT - block_size * 5 - 40, 32, 32, "Bananas"),
        # sits above the fall-death pit -- only reachable by riding gauntlet A
        Fruits(block_size * 29, HEIGHT - block_size * 3 - 60, 32, 32, "Cherries"),
        Fruits(block_size * 42, HEIGHT - block_size * 4 - 50, 32, 32, "Strawberry"),
        Fruits(block_size * 54, HEIGHT - block_size * 5 - 40, 32, 32, "Kiwi"),
        # sits above the fall-death pit -- only reachable by riding gauntlet B
        Fruits(block_size * 65, HEIGHT - block_size * 4 - 70, 32, 32, "Melon"),
        Fruits(block_size * 78, HEIGHT - block_size * 4 - 50, 32, 32, "Pineapple"),
        # atop the final sky-ascent island
        Fruits(block_size * 88, HEIGHT - block_size * 7 - 50, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 9, block_size * 38, block_size * 84):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 17, -150, 42, 42, 380),
        RockHead(block_size * 45, 0, 42, 42, 300),
        RockHead(block_size * 76, -200, 42, 42, 420),
    ]

    spikeheads = [
        Spikehead_x(block_size * 13, HEIGHT - block_size * 2, 54, 52, block_size * 16, block_size * 12, speed=5),
        Spikehead_x(block_size * 44, HEIGHT - block_size * 2, 54, 52, block_size * 47, block_size * 43, speed=5),
        Spikehead_x(block_size * 78, HEIGHT - block_size * 2, 54, 52, block_size * 81, block_size * 77, speed=5),
    ]

    saws = [
        Saw(block_size * 20, HEIGHT - block_size * 5, 38, 42, block_size * 24, block_size * 18, speed=4),
        Saw(block_size * 55, HEIGHT - block_size * 5, 38, 42, block_size * 59, block_size * 54, speed=4),
    ]

    spikes = []

    trampolines = [
        Trampoline(block_size * 24, HEIGHT - block_size - 56),
        Trampoline(block_size * 47, HEIGHT - block_size - 56),
        Trampoline(block_size * 52, HEIGHT - block_size - 56),
    ]

    # gauntlet A: 3 platforms ferrying the player across a bottomless pit
    floating_platforms = [
        FloatingPlatform(block_size * 25, HEIGHT - block_size * 3, block_size * 27, block_size * 25, speed=3, skin=0),
        FloatingPlatform(block_size * 28, HEIGHT - block_size * 3 - 30, block_size * 30, block_size * 27, speed=3, skin=1),
        FloatingPlatform(block_size * 31, HEIGHT - block_size * 3, block_size * 33, block_size * 30, speed=3, skin=2),
    ]

    # gauntlet B: higher & faster, 4 platforms across a second, wider pit
    floating_platforms += [
        FloatingPlatform(block_size * 60, HEIGHT - block_size * 4, block_size * 62, block_size * 60, speed=4, skin=0),
        FloatingPlatform(block_size * 63, HEIGHT - block_size * 4 - 40, block_size * 65, block_size * 62, speed=4, skin=1),
        FloatingPlatform(block_size * 66, HEIGHT - block_size * 4, block_size * 68, block_size * 65, speed=4, skin=2),
        FloatingPlatform(block_size * 69, HEIGHT - block_size * 4 - 40, block_size * 71, block_size * 68, speed=4, skin=0),
    ]

    # sky ascent: a diagonal staircase of platforms up to the final island
    floating_platforms += [
        FloatingPlatform(block_size * 82, HEIGHT - block_size * 3, block_size * 84, block_size * 81, speed=3, skin=1),
        FloatingPlatform(block_size * 86, HEIGHT - block_size * 5, block_size * 88, block_size * 85, speed=3, skin=0),
    ]

    flag = Flag(level_end - (block_size * 5), 5, 64, 64)
    flag.on()

    # gauntlet A/B have no floor beneath them -- missing gauntlet A's fire
    # trench or gauntlet B's spike canyon jumps means falling clean off the
    # bottom of the screen, which triggers the same Game Over as the hit counter
    pit_ranges = [range(25, 34), range(60, 72)]

    floor = [
        Block(i * block_size, HEIGHT - block_size, block_size, col=3, row=1)
        for i in range(-WIDTH // block_size, level_end // block_size)
        if not any(i in pit for pit in pit_ranges)
    ]

    band_a = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=3, row=1)
        for i in range(18, 23)
    ]
    band_b = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=3, row=1)
        for i in range(41, 46)
    ]
    # supports the Kiwi fruit -- otherwise it floats with nothing beneath it
    band_c = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=3, row=1)
        for i in range(53, 58)
    ]
    # supports the Pineapple fruit, kept clear of the rockhead at index 76
    band_d = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=3, row=1)
        for i in range(78, 82)
    ]
    sky_island = [
        Block(i * block_size, HEIGHT - block_size * 7, block_size, col=3, row=1)
        for i in range(87, 90)
    ]

    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size, col=3, row=1),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size, col=3, row=1),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size, col=3, row=1),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size, col=3, row=1),
    ]

    blocks = [*floor, *band_a, *band_b, *band_c, *band_d, *sky_island, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines, *floating_platforms]

    return {
        "name": "Level 4",
        "background": get_background("Blue.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "floating_platforms": floating_platforms,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


# ---------------------------------------------------------------------------
# level 5 -- longest & hardest, level 1's grass-block terrain and background
# ---------------------------------------------------------------------------

def build_level_5():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 11

    fruits = [
        Fruits(block_size * 6, HEIGHT - block_size * 4 - 50, 32, 32, "Apple"),
        Fruits(block_size * 17, HEIGHT - block_size * 4 - 50, 32, 32, "Bananas"),
        # sits above pit gauntlet A -- only reachable by riding a platform
        Fruits(block_size * 25, HEIGHT - block_size * 3 - 60, 32, 32, "Cherries"),
        Fruits(block_size * 40, HEIGHT - block_size * 4 - 50, 32, 32, "Strawberry"),
        Fruits(block_size * 52, HEIGHT - block_size * 5 - 70, 32, 32, "Kiwi"),
        # sits above pit gauntlet B -- only reachable by riding a platform
        Fruits(block_size * 64, HEIGHT - block_size * 4 - 100, 32, 32, "Melon"),
        Fruits(block_size * 82, HEIGHT - block_size * 4 - 50, 32, 32, "Pineapple"),
        # atop the final sky-ascent island, over pit gauntlet C
        Fruits(block_size * 105, HEIGHT - block_size * 6 - 60, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 10, block_size * 35, block_size * 47, block_size * 75, block_size * 90):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 19, -150, 42, 42, 340),
        RockHead(block_size * 38, 0, 42, 42, 300),
        RockHead(block_size * 56, -200, 42, 42, 420),
        RockHead(block_size * 78, -150, 42, 42, 360),
        RockHead(block_size * 97, -200, 42, 42, 420),
    ]

    spikeheads = [
        Spikehead_x(block_size * 13, HEIGHT - block_size * 2, 54, 52, block_size * 16, block_size * 12, speed=5),
        Spikehead_x(block_size * 42, HEIGHT - block_size * 2, 54, 52, block_size * 45, block_size * 41, speed=5),
        Spikehead_x(block_size * 57, HEIGHT - block_size * 2, 54, 52, block_size * 59, block_size * 56, speed=5),
        Spikehead_x(block_size * 85, HEIGHT - block_size * 2, 54, 52, block_size * 88, block_size * 84, speed=5),
        Spikehead_x(block_size * 97, HEIGHT - block_size * 2, 54, 52, block_size * 99, block_size * 96, speed=5),
    ]

    saws = [
        Saw(block_size * 36, HEIGHT - block_size * 5, 38, 42, block_size * 40, block_size * 34, speed=6),
        Saw(block_size * 80, HEIGHT - block_size * 5, 38, 42, block_size * 84, block_size * 79, speed=6),
        Saw(block_size * 95, HEIGHT - block_size * 5, 38, 42, block_size * 99, block_size * 94, speed=6),
    ]

    spikes = [
        Spikes(block_size * 8, HEIGHT - block_size - 32),
        Spikes(block_size * 8 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 43, HEIGHT - block_size - 32),
        Spikes(block_size * 43 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 76, HEIGHT - block_size - 32),
        Spikes(block_size * 76 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 91, HEIGHT - block_size - 32),
    ]

    trampolines = [
        Trampoline(block_size * 37, HEIGHT - block_size - 56),
        # on the floor block leading up to band_d, with just enough runway
        # that the bounce arcs onto the band's top surface instead of
        # smacking into its underside while still ascending directly beneath it
        Trampoline(block_size * 79, HEIGHT - block_size - 56),
        Trampoline(block_size * 49, HEIGHT - block_size - 56),
        Trampoline(block_size * 60, HEIGHT - block_size - 56),
        Trampoline(block_size * 100, HEIGHT - block_size - 56),
    ]

    # gauntlet A: crosses a bottomless pit
    floating_platforms = [
        FloatingPlatform(block_size * 21, HEIGHT - block_size * 3, block_size * 23, block_size * 21, speed=3, skin=0),
        FloatingPlatform(block_size * 24, HEIGHT - block_size * 3 - 30, block_size * 26, block_size * 23, speed=3, skin=1),
        FloatingPlatform(block_size * 27, HEIGHT - block_size * 3, block_size * 29, block_size * 26, speed=3, skin=2),
    ]

    # gauntlet B: wider pit, higher & faster platforms
    floating_platforms += [
        FloatingPlatform(block_size * 61, HEIGHT - block_size * 4, block_size * 63, block_size * 61, speed=4, skin=0),
        FloatingPlatform(block_size * 64, HEIGHT - block_size * 4 - 40, block_size * 66, block_size * 63, speed=4, skin=1),
        FloatingPlatform(block_size * 67, HEIGHT - block_size * 4, block_size * 69, block_size * 66, speed=4, skin=2),
        FloatingPlatform(block_size * 70, HEIGHT - block_size * 4 - 40, block_size * 72, block_size * 69, speed=4, skin=0),
    ]

    # gauntlet C: the widest pit, fastest platforms, ending in the sky ascent
    floating_platforms += [
        FloatingPlatform(block_size * 102, HEIGHT - block_size * 3, block_size * 104, block_size * 101, speed=4, skin=1),
        FloatingPlatform(block_size * 104, HEIGHT - block_size * 4, block_size * 106, block_size * 103, speed=4, skin=2),
        FloatingPlatform(block_size * 106, HEIGHT - block_size * 5, block_size * 108, block_size * 105, speed=4, skin=0),
    ]

    flag = Flag(level_end - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    pit_ranges = [range(21, 30), range(61, 73), range(101, 109)]

    floor = [
        Block(i * block_size, HEIGHT - block_size, block_size, col=1)
        for i in range(-WIDTH // block_size, level_end // block_size)
        if not any(i in pit for pit in pit_ranges)
    ]

    band_a = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=1)
        for i in range(16, 20)
    ]
    band_b = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=1)
        for i in range(38, 43)
    ]
    band_c = [
        Block(i * block_size, HEIGHT - block_size * 5, block_size, col=1)
        for i in range(50, 55)
    ]
    band_d = [
        Block(i * block_size, HEIGHT - block_size * 4, block_size, col=1)
        for i in range(80, 84)
    ]
    sky_island = [
        Block(i * block_size, HEIGHT - block_size * 6, block_size, col=1)
        for i in range(104, 107)
    ]

    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size, col=1),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size, col=1),
        Block(block_size * 4, HEIGHT - block_size * 4, block_size, col=1),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size, col=1),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size, col=1),
    ]

    blocks = [*floor, *band_a, *band_b, *band_c, *band_d, *sky_island, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines, *floating_platforms]

    return {
        "name": "Level 5",
        "background": get_background("Purple.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "floating_platforms": floating_platforms,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


LEVELS = [
    {"title": "Level 1", "builder": build_level_1, "icon": "01.png"},
    {"title": "Level 2", "builder": build_level_2, "icon": "02.png"},
    {"title": "Level 3", "builder": build_level_3, "icon": "03.png"},
    {"title": "Level 4", "builder": build_level_4, "icon": "04.png"},
    {"title": "Level 5", "builder": build_level_5, "icon": "05.png"},
]


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def draw_text(surface, text, font, color, center):
    surf = font.render(text, True, color)
    rect = surf.get_rect(center=center)
    surface.blit(surf, rect)
    return rect


PANEL_TEXTURE = pygame.image.load(join("assets", "Background", "Brown.png")).convert()


def draw_panel(surface, rect):
    panel = pygame.Surface(rect.size, pygame.SRCALPHA)
    tile_w, tile_h = PANEL_TEXTURE.get_size()
    for i in range(rect.width // tile_w + 1):
        for j in range(rect.height // tile_h + 1):
            panel.blit(PANEL_TEXTURE, (i * tile_w, j * tile_h))
    pygame.draw.rect(panel, BLACK, panel.get_rect(), 3)
    surface.blit(panel, rect.topleft)


def draw_collected_fruits(surface, fruits):
    x, y, spacing = 16, 16, 38
    for fruit in fruits:
        if fruit.collected:
            surface.blit(FRUIT_ICONS[fruit.kind], (x, y))
            x += spacing


LIVES_START = 3


class LivesIcon:
    """Small looping idle-facing-right animation of the player, used in the lives HUD."""
    ANIMATION_DELAY = 3
    SIZE = 40

    def __init__(self, sprites):
        self.frames = [pygame.transform.scale(frame, (self.SIZE, self.SIZE))
                       for frame in sprites["idle_right"]]
        self.animation_count = 0

    def loop(self):
        self.animation_count += 0

    @property
    def image(self):
        return self.frames[(self.animation_count // self.ANIMATION_DELAY) % len(self.frames)]


def draw_lives_hud(surface, icon_image, lives_left):
    margin, gap = 16, 10
    x_surf = LABEL_FONT.render("X", True, BLACK)
    count_surf = LABEL_FONT.render(str(lives_left), True, BLACK)

    total_width = icon_image.get_width() + gap + x_surf.get_width() + gap + count_surf.get_width()
    x = WIDTH - margin - total_width
    center_y = margin + icon_image.get_height() // 2

    surface.blit(icon_image, (x, margin))
    x += icon_image.get_width() + gap

    surface.blit(x_surf, x_surf.get_rect(midleft=(x, center_y)))
    x += x_surf.get_width() + gap

    surface.blit(count_surf, count_surf.get_rect(midleft=(x, center_y)))


class Button:
    def __init__(self, image, center, scale=4, label=None):
        w, h = image.get_size()
        self.image = pygame.transform.scale(image, (int(w * scale), int(h * scale)))
        self.rect = self.image.get_rect(center=center)
        self.label = label

    def draw(self, surface, mouse_pos):
        hovered = self.rect.collidepoint(mouse_pos)
        if hovered:
            pygame.draw.rect(surface, BLACK, self.rect.inflate(10, 10), 3, border_radius=8)
        surface.blit(self.image, self.rect)
        if self.label:
            draw_text(surface, self.label, LABEL_FONT, BLACK,
                      (self.rect.centerx, self.rect.bottom + 18))
        return hovered

    def clicked(self, mouse_pos, mouse_click):
        return mouse_click and self.rect.collidepoint(mouse_pos)


def load_button(name):
    return pygame.image.load(join("assets", "Menu", "Buttons", name)).convert_alpha()


BTN_IMAGES = {
    "play": load_button("Play.png"),
    "levels": load_button("Levels.png"),
    "restart": load_button("Restart.png"),
    "close": load_button("Close.png"),
    "back": load_button("Back.png"),
}

LEVEL_ICONS = [
    pygame.image.load(join("assets", "Menu", "Levels", lvl["icon"])).convert_alpha()
    for lvl in LEVELS
]


def get_click():
    click = False
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            return "quit", click
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            click = True
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
            return "escape", click
    return None, click


# ---------------------------------------------------------------------------
# menu background -- a snapshot of level 1 with the player standing on the
# floor, dimmed slightly so the panels/black text stand out over it
# ---------------------------------------------------------------------------

def make_menu_background():
    level = build_level_1()
    # idle sprites are native 32x32 but load_sprite_sheets scale2x's them to
    # 64x64, so the sprite must start 64px above the floor to sit flush on it
    player = Player(100, HEIGHT - BLOCK_SIZE - 64, 50, 50, ALL_CHARACTER_SPRITES["NinjaFrog"])
    player.update_sprite()

    background = pygame.Surface((WIDTH, HEIGHT))
    objects_in_view = [obj for obj in level["objects"] if obj.in_view(0, WIDTH)]
    draw(background, level["background"], player, objects_in_view, [], 0)

    dim = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)
    dim.fill((0, 0, 0, 90))
    background.blit(dim, (0, 0))

    return background


# ---------------------------------------------------------------------------
# screens
# ---------------------------------------------------------------------------

def main_menu_screen(snapshot):
    panel = pygame.Rect(0, 0, 640, 400)  # width kept wide enough for the "pyohmine ninjas" title
    panel.center = (WIDTH // 2, HEIGHT // 2)

    entries = [
        ("play", BTN_IMAGES["play"], "Play"),
        ("levels", BTN_IMAGES["levels"], "Levels"),
        ("quit", BTN_IMAGES["close"], "Close"),
    ]
    spacing = 200
    start_x = WIDTH // 2 - spacing * (len(entries) - 1) / 2
    buttons = [
        (result, Button(image, (int(start_x + i * spacing), panel.top + 260), label=label))
        for i, (result, image, label) in enumerate(entries)
    ]

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action in ("quit",):
            return "quit"

        mouse = pygame.mouse.get_pos()

        window.blit(snapshot, (0, 0))
        draw_panel(window, panel)
        draw_text(window, "pyohmine ninjas", TITLE_FONT, BLACK, (WIDTH // 2, panel.top + 70))

        for _, btn in buttons:
            btn.draw(window, mouse)

        pygame.display.update()

        if click:
            for result, btn in buttons:
                if btn.clicked(mouse, click):
                    return result


def level_select_screen(snapshot):
    icon_scale = 6
    max_spacing = 260
    panel_width = 860
    n = len(LEVELS)
    # shrink icon spacing (instead of letting the panel grow past the
    # screen) once there are enough levels that max_spacing would overflow it
    spacing = min(max_spacing, (panel_width - 160) / (n - 1)) if n > 1 else 0
    start_x = WIDTH // 2 - spacing * (n - 1) / 2

    level_buttons = []
    for i, lvl in enumerate(LEVELS):
        btn = Button(LEVEL_ICONS[i], (int(start_x + i * spacing), HEIGHT // 2),
                    scale=icon_scale, label=lvl["title"])
        level_buttons.append(btn)

    back_btn = Button(BTN_IMAGES["back"], (100, HEIGHT - 80), scale=3, label="Back")

    panel = pygame.Rect(0, 0, panel_width, 420)
    panel.center = (WIDTH // 2, HEIGHT // 2 - 20)

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit", None
        if action == "escape":
            return "back", None

        mouse = pygame.mouse.get_pos()

        window.blit(snapshot, (0, 0))
        draw_panel(window, panel)
        draw_text(window, "Choose a Level", HEADING_FONT, BLACK, (WIDTH // 2, panel.top + 50))

        for btn in level_buttons:
            btn.draw(window, mouse)
        back_btn.draw(window, mouse)

        pygame.display.update()

        if click:
            for i, btn in enumerate(level_buttons):
                if btn.clicked(mouse, click):
                    return "select", i
            if back_btn.clicked(mouse, click):
                return "back", None


def character_select_screen(snapshot, preselected="NinjaFrog"):
    selected = preselected
    tile_size = 170
    spacing = 210
    start_x = WIDTH // 2 - spacing * (len(CHARACTERS) - 1) / 2
    y = HEIGHT // 2 - 30

    portraits = {}
    for name in CHARACTERS:
        frame = ALL_CHARACTER_SPRITES[name]["idle_right"][0]
        portraits[name] = pygame.transform.scale(frame, (tile_size, tile_size))

    play_btn = Button(BTN_IMAGES["play"], (WIDTH // 2, HEIGHT - 150), label="Start")
    back_btn = Button(BTN_IMAGES["back"], (100, HEIGHT - 80), scale=3, label="Back")

    panel = pygame.Rect(0, 0, 820, 460)
    panel.center = (WIDTH // 2, HEIGHT // 2 - 40)

    tile_rects = {}
    for i, name in enumerate(CHARACTERS):
        rect = pygame.Rect(0, 0, tile_size + 20, tile_size + 20)
        rect.center = (int(start_x + i * spacing), y)
        tile_rects[name] = rect

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit", None
        if action == "escape":
            return "back", None

        mouse = pygame.mouse.get_pos()

        window.blit(snapshot, (0, 0))
        draw_panel(window, panel)
        draw_text(window, "Choose Your Ninja", HEADING_FONT, BLACK, (WIDTH // 2, panel.top + 50))

        for name, rect in tile_rects.items():
            border = 5 if name == selected else 1
            pygame.draw.rect(window, BLACK, rect, border, border_radius=10)
            portrait_rect = portraits[name].get_rect(center=rect.center)
            window.blit(portraits[name], portrait_rect)
            draw_text(window, name, LABEL_FONT, BLACK, (rect.centerx, rect.bottom + 22))

        draw_text(window, f"Selected: {selected}", LABEL_FONT, BLACK,
                  (WIDTH // 2, panel.top + 100))

        play_btn.draw(window, mouse)
        back_btn.draw(window, mouse)

        pygame.display.update()

        if click:
            for name, rect in tile_rects.items():
                if rect.collidepoint(mouse):
                    selected = name
            if play_btn.clicked(mouse, click):
                return "confirm", selected
            if back_btn.clicked(mouse, click):
                return "back", None


def pause_overlay():
    """Draws over whatever is already on screen (the frozen gameplay frame)."""
    entries = [
        ("resume", BTN_IMAGES["back"], "Resume"),
        ("restart", BTN_IMAGES["restart"], "Restart"),
        ("levels", BTN_IMAGES["levels"], "Levels"),
        ("quit", BTN_IMAGES["close"], "Close"),
    ]
    spacing = 170
    panel = pygame.Rect(0, 0, spacing * (len(entries) - 1) + 300, 360)
    panel.center = (WIDTH // 2, HEIGHT // 2)

    start_x = WIDTH // 2 - spacing * (len(entries) - 1) / 2
    buttons = [
        (result, Button(image, (int(start_x + i * spacing), panel.top + 220), scale=3, label=label))
        for i, (result, image, label) in enumerate(entries)
    ]

    base = window.copy()

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit"
        if action == "escape":
            return "resume"

        mouse = pygame.mouse.get_pos()

        window.blit(base, (0, 0))
        draw_panel(window, panel)
        draw_text(window, "Paused", HEADING_FONT, BLACK, (WIDTH // 2, panel.top + 60))

        for _, btn in buttons:
            btn.draw(window, mouse)

        pygame.display.update()

        if click:
            for result, btn in buttons:
                if btn.clicked(mouse, click):
                    return result


def end_of_level_overlay(title, has_next):
    entries = []
    if has_next:
        entries.append(("next", BTN_IMAGES["play"], "Next Level"))
    entries.append(("restart", BTN_IMAGES["restart"], "Restart"))
    entries.append(("levels", BTN_IMAGES["levels"], "Levels"))
    entries.append(("quit", BTN_IMAGES["close"], "Close"))

    spacing = 170
    panel = pygame.Rect(0, 0, spacing * (len(entries) - 1) + 300, 360)
    panel.center = (WIDTH // 2, HEIGHT // 2)

    start_x = WIDTH // 2 - spacing * (len(entries) - 1) / 2
    buttons = [
        (result, Button(image, (int(start_x + i * spacing), panel.top + 220), scale=3, label=label))
        for i, (result, image, label) in enumerate(entries)
    ]

    base = window.copy()

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit"

        mouse = pygame.mouse.get_pos()

        window.blit(base, (0, 0))
        draw_panel(window, panel)
        draw_text(window, title, HEADING_FONT, BLACK, (WIDTH // 2, panel.top + 60))

        for _, btn in buttons:
            btn.draw(window, mouse)

        pygame.display.update()

        if click:
            for result, btn in buttons:
                if btn.clicked(mouse, click):
                    return result


def play_level(level_index, character_name):
    level = LEVELS[level_index]["builder"]()
    start_x, start_y = level["start_pos"]
    player = Player(start_x, start_y, 50, 50, ALL_CHARACTER_SPRITES[character_name])
    lives_icon = LivesIcon(player.sprites)

    objects = level["objects"]
    checkpoints = [level["flag"]]
    flag = level["flag"]
    fruits = level["fruits"]

    offset_x = 0
    scroll_area_width = 300
    run = True

    while run:
        clock.tick(FPS)

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return "quit"
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_SPACE and player.jump_count < 2:
                    player.jump()
                if event.key == pygame.K_ESCAPE:
                    visible = [o for o in objects if o.in_view(offset_x, WIDTH)]
                    visible += [f for f in fruits if f.in_view(offset_x, WIDTH)]
                    draw(window, level["background"], player, visible,
                        [c for c in checkpoints if c.in_view(offset_x, WIDTH)], offset_x)
                    draw_collected_fruits(window, fruits)
                    draw_lives_hud(window, lives_icon.image, max(0, LIVES_START - player.player_hit))
                    pygame.display.update()
                    result = pause_overlay()
                    if result == "resume":
                        continue
                    return result

        frame_start_x = player.rect.x

        player.loop(FPS)
        lives_icon.loop()
        flag.loop()

        for f in level["fires"]:
            if f.in_view(offset_x, WIDTH):
                f.loop()
        for r in level["rockheads"]:
            if r.in_view(offset_x, WIDTH):
                r.loop()
        for s in level["spikeheads"]:
            if s.in_view(offset_x, WIDTH):
                s.loop()
        for t in level["trampolines"]:
            if t.in_view(offset_x, WIDTH):
                t.loop()
        for fruit in fruits:
            if fruit.in_view(offset_x, WIDTH):
                fruit.loop()
        for saw in level["saws"]:
            if saw.in_view(offset_x, WIDTH):
                saw.loop()
        for fp in level.get("floating_platforms", []):
            if fp.in_view(offset_x, WIDTH):
                fp.loop()

        objects_in_view = [obj for obj in objects if obj.in_view(offset_x, WIDTH)]
        fruits_in_view = [f for f in fruits if f.in_view(offset_x, WIDTH)]
        checkpoints_in_view = [c for c in checkpoints if c.in_view(offset_x, WIDTH)]

        reached_flag = handle_move(player, objects_in_view, checkpoints_in_view, flag, fruits)

        draw(window, level["background"], player, [*objects_in_view, *fruits_in_view],
             checkpoints_in_view, offset_x)
        draw_collected_fruits(window, fruits)
        draw_lives_hud(window, lives_icon.image, max(0, LIVES_START - player.player_hit))
        pygame.display.update()

        if player.player_hit >= 100 or player.rect.top > HEIGHT:
            has_next = level_index + 1 < len(LEVELS)
            result = end_of_level_overlay("Game Over", False)
            return result

        if reached_flag:
            has_next = level_index + 1 < len(LEVELS)
            result = end_of_level_overlay("Level Complete!", has_next)
            if result == "next":
                return ("play_index", level_index + 1)
            return result

        # Use the player's actual on-screen displacement this frame, not just
        # x_vel -- x_vel only reflects keyboard input, so riding a moving
        # floating platform (which shifts rect.x directly) wouldn't scroll
        # the camera at all, letting the player get pinned to the screen edge.
        actual_dx = player.rect.x - frame_start_x
        if (
            (player.rect.right - offset_x >= WIDTH - scroll_area_width and actual_dx > 0)
            or (player.rect.left - offset_x <= scroll_area_width and actual_dx < 0)
        ):
            offset_x += actual_dx

    return "levels"


# ---------------------------------------------------------------------------
# main state machine
# ---------------------------------------------------------------------------

def main():
    mixer.music.load(join("assets", "upbeat_loop.ogg"))
    mixer.music.play(-1)

    snapshot = make_menu_background()

    state = "menu"
    selected_character = "NinjaFrog"
    pending_level_index = 0

    while True:
        if state == "menu":
            result = main_menu_screen(snapshot)
            if result == "quit":
                break
            elif result == "play":
                pending_level_index = 0
                state = "characters_from_menu"
            elif result == "levels":
                state = "levels"

        elif state == "levels":
            result, level_index = level_select_screen(snapshot)
            if result == "quit":
                break
            elif result == "back":
                state = "menu"
            elif result == "select":
                pending_level_index = level_index
                state = "characters_from_levels"

        elif state in ("characters_from_menu", "characters_from_levels"):
            result, character = character_select_screen(snapshot, selected_character)
            if result == "quit":
                break
            elif result == "back":
                state = "menu" if state == "characters_from_menu" else "levels"
            elif result == "confirm":
                selected_character = character
                state = ("playing", pending_level_index)

        elif isinstance(state, tuple) and state[0] == "playing":
            result = play_level(state[1], selected_character)
            if result == "quit":
                break
            elif result == "restart":
                state = ("playing", state[1])
            elif result == "levels" or result == "Game Over" or result is None:
                state = "levels"
            elif isinstance(result, tuple) and result[0] == "play_index":
                state = ("playing", result[1])
            else:
                state = "levels"

    pygame.quit()
    quit()


if __name__ == "__main__":
    main()
