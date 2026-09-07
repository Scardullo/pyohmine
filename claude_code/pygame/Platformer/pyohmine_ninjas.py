#!/usr/bin/env python3

import math
import pygame
from functools import lru_cache
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


@lru_cache(maxsize=None)
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


@lru_cache(maxsize=None)
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


@lru_cache(maxsize=None)
def _terrain_sheet():
    path = join("assets", "Terrain", "Terrain.png")
    return pygame.image.load(path).convert_alpha()


def get_block(size, col=1, row=0):
    image = _terrain_sheet()
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
        self.on_ice = False
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

        sheet = _terrain_sheet()
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


class DropPlatform(Object):
    """A stationary platform (fans humming, "on") over a pit that stays solid
    until the player lands on it -- the fans cut out ("off") and after a beat
    it falls away, forcing the player to keep moving instead of camping on it,
    unlike FloatingPlatform's side-to-side ferrying."""
    ANIMATION_DELAY = 4
    SPRITES = load_sprite_sheets("Traps", "Falling Platforms", 32, 10)
    STAND_DELAY = 25   # frames standing before it drops
    RECOVER_RATE = 2   # timer decay per frame once the player steps off
    FALL_SPEED = 14    # faster than the player falls, so the two separate
                        # cleanly instead of "landed()" re-triggering mid-fall

    def __init__(self, x, y, width=96, height=30):
        super().__init__(x, y, width, height, "drop_platform")

        self.on_frames = [pygame.transform.scale(f, (width, height)) for f in self.SPRITES["On (32x10)"]]
        self.off_frame = pygame.transform.scale(self.SPRITES["Off"][0], (width, height))
        self.image = self.on_frames[0]
        self.mask = pygame.mask.from_surface(self.image)

        self.dx = 0  # stationary -- handle_vertical_collision still reads
                     # this to carry a standing player, so it must exist
        self.standing = False  # set by handle_vertical_collision each frame
        self.timer = 0
        self.falling = False
        self.animation_count = 0

    def loop(self):
        if self.falling:
            self.rect.y += self.FALL_SPEED
            return

        if self.standing:
            self.timer += 1
        else:
            self.timer = max(0, self.timer - self.RECOVER_RATE)

        if self.timer >= self.STAND_DELAY:
            self.falling = True
            self.image = self.off_frame
            # empty mask -- collide_mask never matches again once it drops
            self.mask = pygame.mask.Mask(self.image.get_size())
        elif self.timer > 0:
            # fans have cut out the moment the player landed -- it's coming down
            self.image = self.off_frame
            self.mask = pygame.mask.from_surface(self.image)
        else:
            self.image = self.on_frames[(self.animation_count // self.ANIMATION_DELAY) % len(self.on_frames)]
            self.mask = pygame.mask.from_surface(self.image)
            self.animation_count += 1

        self.standing = False


class SpringPad(Object):
    """A high-powered spring pad (Traps/Arrow sprite) that launches the
    player much higher than a Trampoline -- used to reach the elevator
    shafts and high platforms in levels 6/7."""
    ANIMATION_DELAY = 3
    SPRITES = load_sprite_sheets("Traps", "Arrow", 18, 18)

    def __init__(self, x, y, width=18, height=18, launch_vel=-18):
        super().__init__(x, y, width, height, "spring_pad")
        self.idle_frames = self.SPRITES["Idle (18x18)"]
        self.hit_frames = self.SPRITES["Hit (18x18)"]
        self.animation_name = "idle"
        self.image = self.idle_frames[0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.bouncing = False
        self.launch_vel = launch_vel

    def bounce(self):
        self.animation_name = "hit"
        self.animation_count = 0
        self.bouncing = True

    def loop(self):
        frames = self.hit_frames if self.animation_name == "hit" else self.idle_frames
        sprite_index = (self.animation_count // self.ANIMATION_DELAY) % len(frames)
        self.image = frames[sprite_index]
        self.animation_count += 1

        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))
        self.mask = pygame.mask.from_surface(self.image)

        if self.bouncing and self.animation_count // self.ANIMATION_DELAY >= len(frames):
            self.animation_name = "idle"
            self.animation_count = 0
            self.bouncing = False


class Fan(Object):
    """A floor-mounted fan (Traps/Fan sprite) that blows a continuous updraft
    in the column above it -- float up through it instead of jumping, the
    way a FloatingPlatform ferries you sideways. Not solid and not a hazard:
    handled entirely outside the objects/collision list (see play_level)."""
    ANIMATION_DELAY = 4
    SPRITES = load_sprite_sheets("Traps", "Fan", 24, 8)
    UPDRAFT_HEIGHT = BLOCK_SIZE * 6
    LIFT = -8
    # A player naturally holds right while riding the updraft (to clear
    # whatever wall the fan is boosting them over), so the "column" can't be
    # a narrow strip -- at LIFT px/frame it takes UPDRAFT_HEIGHT/LIFT frames
    # to reach full height, during which PLAYER_VEL*that-many-frames of
    # rightward drift happens. REACH_RIGHT must comfortably cover that
    # (6 blocks -- more than the drift up to a 5-block wall) or the player
    # exits the updraft horizontally long before clearing the wall's height.
    REACH_LEFT = 60
    REACH_RIGHT = BLOCK_SIZE * 6

    def __init__(self, x, y, width=24, height=8):
        super().__init__(x, y, width, height, "fan")
        self.on_frames = self.SPRITES["On (24x8)"]
        self.image = self.on_frames[0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0

    def loop(self):
        self.image = self.on_frames[(self.animation_count // self.ANIMATION_DELAY) % len(self.on_frames)]
        self.animation_count += 1
        self.rect = self.image.get_rect(topleft=(self.rect.x, self.rect.y))

    def in_column(self, player):
        return (
            self.rect.top - self.UPDRAFT_HEIGHT <= player.rect.bottom <= self.rect.bottom + 40
            and self.rect.centerx - self.REACH_LEFT < player.rect.centerx < self.rect.centerx + self.REACH_RIGHT
        )


class SwingingBall(Object):
    """A spiked wrecking ball on a chain that swings like a pendulum from a
    fixed pivot point, unlike Saw/Spikehead_x's straight-line patrol."""
    _ball_native = pygame.image.load(join("assets", "Traps", "Spiked Ball", "Spiked Ball.png")).convert_alpha()
    _chain_native = pygame.image.load(join("assets", "Traps", "Spiked Ball", "Chain.png")).convert_alpha()
    BALL = pygame.transform.scale2x(_ball_native)
    CHAIN = pygame.transform.scale2x(_chain_native)

    def __init__(self, pivot_x, pivot_y, length, max_angle=55, speed=0.045):
        size = self.BALL.get_width()
        super().__init__(pivot_x - size // 2, pivot_y + length - size // 2, size, size, "swinging_ball")
        self.image = self.BALL
        self.mask = pygame.mask.from_surface(self.image)
        self.pivot_x = pivot_x
        self.pivot_y = pivot_y
        self.length = length
        self.max_angle = math.radians(max_angle)
        self.speed = speed
        self.t = 0

    def loop(self):
        self.t += 1
        angle = self.max_angle * math.sin(self.t * self.speed)
        self.rect.centerx = int(self.pivot_x + self.length * math.sin(angle))
        self.rect.centery = int(self.pivot_y + self.length * math.cos(angle))

    def draw(self, win, offset_x):
        cx, cy = self.rect.center
        link_h = self.CHAIN.get_height()
        steps = max(1, int(self.length // link_h))
        for i in range(steps):
            t = (i + 0.5) / steps
            lx = self.pivot_x + (cx - self.pivot_x) * t
            ly = self.pivot_y + (cy - self.pivot_y) * t
            rect = self.CHAIN.get_rect(center=(lx - offset_x, ly))
            win.blit(self.CHAIN, rect)
        win.blit(self.image, (self.rect.x - offset_x, self.rect.y))


class VerticalPlatform(Object):
    """A chain-suspended platform (Traps/Platforms sprite) that rides up and
    down between y_top and y_bottom instead of side to side. Shares
    FloatingPlatform's object name so the existing landing/carry collision
    logic in handle_vertical_collision applies unchanged."""
    NATIVE_WIDTH = 32
    NATIVE_HEIGHT = 8
    _sheet = pygame.image.load(join("assets", "Traps", "Platforms", "Grey On (32x8).png")).convert_alpha()
    _chain_native = pygame.image.load(join("assets", "Traps", "Platforms", "Chain.png")).convert_alpha()
    # a plain loop, not a comprehension -- comprehensions get their own scope
    # and can't see _sheet/NATIVE_WIDTH from the enclosing class body
    FRAMES = []
    for _i in range(_sheet.get_width() // NATIVE_WIDTH):
        FRAMES.append(pygame.transform.scale2x(_sheet.subsurface((_i * NATIVE_WIDTH, 0, NATIVE_WIDTH, NATIVE_HEIGHT))))
    CHAIN = pygame.transform.scale2x(_chain_native)
    ANIMATION_DELAY = 5

    def __init__(self, x, y, y_top, y_bottom, speed=2, anchor_y=0):
        width, height = self.FRAMES[0].get_size()
        super().__init__(x, y, width, height, "floating_platform")
        self.image = self.FRAMES[0]
        self.mask = pygame.mask.from_surface(self.image)
        self.y_top = y_top
        self.y_bottom = y_bottom
        self.y_vel = speed
        self.direction = "down"
        self.anchor_y = anchor_y
        self.dx = 0  # stationary in x -- handle_vertical_collision still
                     # reads this to (not) carry a standing player sideways
        self.animation_count = 0

    def loop(self):
        if self.rect.y >= self.y_bottom and self.direction == "down":
            self.direction = "up"
        elif self.rect.y <= self.y_top and self.direction == "up":
            self.direction = "down"
        self.rect.y += self.y_vel if self.direction == "down" else -self.y_vel

        self.image = self.FRAMES[(self.animation_count // self.ANIMATION_DELAY) % len(self.FRAMES)]
        self.animation_count += 1
        self.mask = pygame.mask.from_surface(self.image)

    def draw(self, win, offset_x):
        link_h = self.CHAIN.get_height()
        cx = self.rect.centerx - offset_x - self.CHAIN.get_width() // 2
        y = self.anchor_y
        bottom = self.rect.centery
        while y < bottom:
            win.blit(self.CHAIN, (cx, y))
            y += link_h
        win.blit(self.image, (self.rect.x - offset_x, self.rect.y))


class IceBlock(Object):
    """A slippery floor tile (Sand Mud Ice sheet's icy variant) -- standing on
    it reduces the player's traction, so movement keeps sliding after a
    direction key is released instead of stopping immediately (see the
    on_ice branch in handle_move)."""
    _sheet = pygame.image.load(join("assets", "Traps", "Sand Mud Ice", "Sand Mud Ice (16x6).png")).convert_alpha()
    _tile = _sheet.subsurface((128, 0, 48, 48))

    def __init__(self, x, y, size=BLOCK_SIZE):
        super().__init__(x, y, size, size, "ice")
        self.image = pygame.transform.scale(self._tile, (size, size))
        self.mask = pygame.mask.from_surface(self.image)


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
            if obj.name in ("trampoline", "spring_pad"):
                if dy > 0:
                    player.rect.bottom = obj.rect.top
                    player.y_vel = obj.launch_vel
                    player.fall_count = 0
                    player.jump_count = 1
                    obj.bounce()
                # else: still overlapping mid-launch (ascending) -- ignore it
                # instead of falling through to the hit_head branch below,
                # which would flip y_vel and cut the bounce short.
            elif obj.name in ("floating_platform", "drop_platform"):
                if dy >= 0:
                    player.rect.bottom = obj.rect.top
                    player.landed()
                    player.rect.x += obj.dx  # ride the platform along with it
                    if obj.name == "drop_platform":
                        obj.standing = True
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
        if obj in collided_objects or obj.name not in ("floating_platform", "drop_platform"):
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
            if obj.name == "drop_platform":
                obj.standing = True
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

    # On ice, momentum carries over between frames instead of snapping to 0
    # the instant no key is held, so releasing a direction keeps sliding.
    if player.on_ice:
        player.x_vel *= 0.97
        if abs(player.x_vel) < 0.3:
            player.x_vel = 0
    else:
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

    player.on_ice = any(obj and obj.name == "ice" for obj in vertical_collide)

    for obj in to_check:
        if obj and obj.name in ("fire", "rockhead", "saw", "spikehead_x", "spikes", "swinging_ball"):
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


# ---------------------------------------------------------------------------
# level 6 -- "Wind Spire": as long as level 5, but built around a completely
# different toolkit instead of more/faster pits -- a slick ice slide, a
# swinging wrecking ball, a spring-pad-powered elevator shaft, and a fan
# updraft, with only a short nod to the old ferry/drop-platform pit near the
# end. Blue-gray brick terrain.
# ---------------------------------------------------------------------------

def build_level_6():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 11

    fruits = [
        Fruits(block_size * 6, HEIGHT - block_size * 4 - 50, 32, 32, "Apple"),
        # sits over the ice slide
        Fruits(block_size * 15, HEIGHT - block_size * 4 - 50, 32, 32, "Bananas"),
        # timed past the swinging ball
        Fruits(block_size * 27, HEIGHT - block_size * 4 - 50, 32, 32, "Cherries"),
        # atop the elevator shaft's landing platform
        Fruits(block_size * 41, 352 - 50, 32, 32, "Strawberry"),
        # in open air just past the fan wall, grabbed mid-flight
        Fruits(block_size * 60, 300, 32, 32, "Kiwi"),
        Fruits(block_size * 64, HEIGHT - block_size * 4 - 50, 32, 32, "Melon"),
        # over the pit gauntlet
        Fruits(block_size * 74, HEIGHT - block_size * 3 - 60, 32, 32, "Pineapple"),
        Fruits(block_size * 110, HEIGHT - block_size * 4 - 50, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 8, block_size * 32, block_size * 66, block_size * 90):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 30, -150, 42, 42, 340),
        RockHead(block_size * 65, -200, 42, 42, 400),
        RockHead(block_size * 100, -180, 42, 42, 380),
    ]

    spikeheads = [
        Spikehead_x(block_size * 50, HEIGHT - block_size * 2, 54, 52, block_size * 53, block_size * 49, speed=5),
        Spikehead_x(block_size * 82, HEIGHT - block_size * 2, 54, 52, block_size * 85, block_size * 81, speed=5),
        Spikehead_x(block_size * 102, HEIGHT - block_size * 2, 54, 52, block_size * 105, block_size * 101, speed=5),
    ]

    saws = [
        Saw(block_size * 88, HEIGHT - block_size * 5, 38, 42, block_size * 92, block_size * 86, speed=6),
    ]

    # right where the ice ends -- overshoot the slide and you skid into these
    spikes = [
        Spikes(block_size * 20, HEIGHT - block_size - 32),
        Spikes(block_size * 20 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 92, HEIGHT - block_size - 32),
    ]

    trampolines = [
        Trampoline(block_size * 98, HEIGHT - block_size - 56),
    ]

    # the spring pad (Traps/Arrow) launches much higher than a trampoline --
    # a ballistic arc, not a straight shot up, so the landing platform below
    # sits well clear of the pad's x position and past the arc's apex, or the
    # player would just bonk its underside on the way up instead of landing
    spring_pads = [SpringPad(block_size * 36, HEIGHT - block_size - 36)]
    trampolines += spring_pads

    # a fan-powered updraft carries the player up and over a solid wall that
    # blocks the floor path entirely -- there's no ground route around it,
    # only up and over, clearing its height before drifting right past it
    fans = [Fan(block_size * 56, HEIGHT - block_size - 16)]
    wall = [
        Block(block_size * 58, HEIGHT - block_size - k * block_size, block_size, col=2, row=1)
        for k in range(1, 6)
    ]

    # one big pendulum wrecking ball -- swings low enough to threaten the
    # floor, so crossing means timing the walk past its low point
    swinging_balls = [
        SwingingBall(block_size * 23, 250, 400, max_angle=45, speed=0.03),
    ]

    # elevator shaft: the spring pad's arc lands on the wide platform below
    # (see shaft_landing), then a vertical platform -- boarded at a standstill,
    # no ballistic timing needed -- carries the rest of the way up
    floating_platforms = [
        VerticalPlatform(block_size * 44, 352, y_top=100, y_bottom=352, speed=2),
    ]

    # a compact pit -- one ferry, one drop platform -- as the only callback
    # to the old gauntlet style, much shorter than before
    floating_platforms += [
        FloatingPlatform(block_size * 71, HEIGHT - block_size * 3, block_size * 73, block_size * 71, speed=4, skin=0),
        FloatingPlatform(block_size * 76, HEIGHT - block_size * 3, block_size * 78, block_size * 76, speed=4, skin=2),
    ]
    drop_platforms = [
        DropPlatform(block_size * 74, HEIGHT - block_size * 3),
    ]

    flag = Flag(level_end - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    ice_range = range(12, 20)
    pit_ranges = [range(71, 79)]

    floor = [
        (IceBlock(i * block_size, HEIGHT - block_size) if i in ice_range
         else Block(i * block_size, HEIGHT - block_size, block_size, col=2, row=1))
        for i in range(-WIDTH // block_size, level_end // block_size)
        if not any(i in pit for pit in pit_ranges)
    ]

    # elevator shaft: a wide landing pad well past the spring pad's arc apex
    # (so it's caught while descending, not bonked from below), then the
    # vertical platform continues to a landing at the top
    shaft_landing = [
        Block(i * block_size, 352, block_size, col=2, row=1)
        for i in range(39, 44)
    ]
    shaft_top = [
        Block(i * block_size, 100, block_size, col=2, row=1)
        for i in range(45, 48)
    ]
    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size, col=2, row=1),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size, col=2, row=1),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size, col=2, row=1),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size, col=2, row=1),
    ]

    blocks = [*floor, *shaft_landing, *shaft_top, *wall, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines,
               *floating_platforms, *drop_platforms, *swinging_balls]

    return {
        "name": "Level 6",
        "background": get_background("Pink.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "floating_platforms": floating_platforms,
        "drop_platforms": drop_platforms,
        "swinging_balls": swinging_balls,
        "fans": fans,
        "fruits": fruits,
        "flag": flag,
        "start_pos": (100, 100),
    }


# ---------------------------------------------------------------------------
# level 7 -- "Frozen Depths": longer than level 6 (and every other level),
# equally advanced -- the same new toolkit (ice, pendulum, spring-pad shaft,
# fan wall) recombined with a second pendulum and a longer pit gauntlet
# instead of just faster/denser versions of the old formula. Teal terrain.
# ---------------------------------------------------------------------------

def build_level_7():
    block_size = BLOCK_SIZE
    level_end = WIDTH * 13

    fruits = [
        Fruits(block_size * 6, HEIGHT - block_size * 4 - 50, 32, 32, "Apple"),
        # sits over the ice slide
        Fruits(block_size * 15, HEIGHT - block_size * 4 - 50, 32, 32, "Bananas"),
        # timed past the first swinging ball
        Fruits(block_size * 29, HEIGHT - block_size * 4 - 50, 32, 32, "Cherries"),
        # atop the elevator shaft's landing platform
        Fruits(block_size * 47, 352 - 50, 32, 32, "Strawberry"),
        # in open air just past the fan wall, grabbed mid-flight
        Fruits(block_size * 70, 300, 32, 32, "Kiwi"),
        Fruits(block_size * 78, HEIGHT - block_size * 4 - 50, 32, 32, "Melon"),
        # timed past the second swinging ball
        Fruits(block_size * 87, HEIGHT - block_size * 4 - 50, 32, 32, "Melon"),
        # over the pit gauntlet
        Fruits(block_size * 102, HEIGHT - block_size * 3 - 60, 32, 32, "Pineapple"),
        Fruits(block_size * 130, HEIGHT - block_size * 4 - 50, 32, 32, "Orange"),
    ]

    fires = []
    for base in (block_size * 8, block_size * 35, block_size * 62, block_size * 90, block_size * 124):
        for off in (0, 35):
            f = Fire(base + off, HEIGHT - block_size - 64, 16, 32)
            f.on()
            fires.append(f)

    rockheads = [
        RockHead(block_size * 4, 0, 42, 42, 260),
        RockHead(block_size * 32, -150, 42, 42, 340),
        RockHead(block_size * 72, -200, 42, 42, 400),
        RockHead(block_size * 92, -180, 42, 42, 380),
        RockHead(block_size * 112, -200, 42, 42, 420),
    ]

    spikeheads = [
        Spikehead_x(block_size * 55, HEIGHT - block_size * 2, 54, 52, block_size * 58, block_size * 54, speed=5),
        Spikehead_x(block_size * 76, HEIGHT - block_size * 2, 54, 52, block_size * 79, block_size * 75, speed=5),
        Spikehead_x(block_size * 93, HEIGHT - block_size * 2, 54, 52, block_size * 96, block_size * 92, speed=5),
        Spikehead_x(block_size * 118, HEIGHT - block_size * 2, 54, 52, block_size * 121, block_size * 117, speed=5),
    ]

    saws = [
        Saw(block_size * 60, HEIGHT - block_size * 5, 38, 42, block_size * 64, block_size * 58, speed=6),
        Saw(block_size * 111, HEIGHT - block_size * 5, 38, 42, block_size * 115, block_size * 109, speed=6),
    ]

    # right where the ice ends -- overshoot the slide and you skid into these
    spikes = [
        Spikes(block_size * 25, HEIGHT - block_size - 32),
        Spikes(block_size * 25 + 32, HEIGHT - block_size - 32),
        Spikes(block_size * 130, HEIGHT - block_size - 32),
    ]

    trampolines = [
        Trampoline(block_size * 72, HEIGHT - block_size - 56),
    ]

    # ballistic spring-pad arc -- the landing platform below sits well past
    # the arc's apex, so it's caught while descending, not bonked from below
    spring_pads = [SpringPad(block_size * 42, HEIGHT - block_size - 36)]
    trampolines += spring_pads

    # fan-powered updraft -- carries the player up and over a solid wall that
    # blocks the floor path entirely, no ground route around it
    fans = [Fan(block_size * 66, HEIGHT - block_size - 16)]
    wall = [
        Block(block_size * 68, HEIGHT - block_size - k * block_size, block_size, col=0, row=2)
        for k in range(1, 6)
    ]

    # two big pendulum wrecking balls, spaced far apart -- each swings low
    # enough to threaten the floor, so crossing means timing the walk past
    swinging_balls = [
        SwingingBall(block_size * 26, 250, 400, max_angle=45, speed=0.03),
        SwingingBall(block_size * 84, 250, 400, max_angle=42, speed=0.035),
    ]

    # elevator shaft: spring pad up to the wide landing, then a vertical
    # platform -- boarded at a standstill, no ballistic timing needed --
    # carries the rest of the way up
    floating_platforms = [
        VerticalPlatform(block_size * 50, 352, y_top=100, y_bottom=352, speed=2),
    ]

    # a longer pit than level 6's -- two ferries alternating with two drop
    # platforms, the extra length that makes this level longer overall
    floating_platforms += [
        FloatingPlatform(block_size * 98, HEIGHT - block_size * 3, block_size * 100, block_size * 98, speed=4, skin=0),
        FloatingPlatform(block_size * 103, HEIGHT - block_size * 3, block_size * 105, block_size * 103, speed=4, skin=2),
    ]
    drop_platforms = [
        DropPlatform(block_size * 101, HEIGHT - block_size * 3),
        DropPlatform(block_size * 106, HEIGHT - block_size * 3),
    ]

    flag = Flag(level_end - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()

    ice_range = range(12, 24)
    pit_ranges = [range(97, 109)]

    floor = [
        (IceBlock(i * block_size, HEIGHT - block_size) if i in ice_range
         else Block(i * block_size, HEIGHT - block_size, block_size, col=0, row=2))
        for i in range(-WIDTH // block_size, level_end // block_size)
        if not any(i in pit for pit in pit_ranges)
    ]

    # elevator shaft: a wide landing pad well past the spring pad's arc apex,
    # then the vertical platform continues to a landing at the top
    shaft_landing = [
        Block(i * block_size, 352, block_size, col=0, row=2)
        for i in range(45, 50)
    ]
    shaft_top = [
        Block(i * block_size, 100, block_size, col=0, row=2)
        for i in range(51, 54)
    ]

    extra_blocks = [
        Block(0, HEIGHT - block_size * 2, block_size, col=0, row=2),
        Block(block_size * 2, HEIGHT - block_size * 3, block_size, col=0, row=2),
        Block(level_end - block_size * 6, HEIGHT - block_size * 2, block_size, col=0, row=2),
        Block(level_end - block_size * 5, HEIGHT - block_size * 2, block_size, col=0, row=2),
    ]

    blocks = [*floor, *shaft_landing, *shaft_top, *wall, *extra_blocks]
    objects = [*blocks, *fires, *rockheads, *spikeheads, *saws, *spikes, *trampolines,
               *floating_platforms, *drop_platforms, *swinging_balls]

    return {
        "name": "Level 7",
        "background": get_background("Yellow.png"),
        "objects": objects,
        "fires": fires,
        "rockheads": rockheads,
        "spikeheads": spikeheads,
        "saws": saws,
        "trampolines": trampolines,
        "floating_platforms": floating_platforms,
        "drop_platforms": drop_platforms,
        "swinging_balls": swinging_balls,
        "fans": fans,
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
    {"title": "Level 6", "builder": build_level_6, "icon": "06.png"},
    {"title": "Level 7", "builder": build_level_7, "icon": "07.png"},
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
        self.animation_count += 1

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

    def draw(self, surface, mouse_pos, offset=(0, 0)):
        draw_rect = self.rect.move(offset)
        hovered = draw_rect.collidepoint(mouse_pos)
        if hovered:
            pygame.draw.rect(surface, BLACK, draw_rect.inflate(10, 10), 3, border_radius=8)
        surface.blit(self.image, draw_rect)
        if self.label:
            draw_text(surface, self.label, LABEL_FONT, BLACK,
                      (draw_rect.centerx, draw_rect.bottom + 18))
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


SLIDE_STEPS = 30


def slide_menu_in(panel_rect, direction, render_frame):
    """Eases a menu onto screen from off one edge of the window.

    render_frame(offset) must draw one full frame of the menu (background +
    panel + buttons) shifted by the given (dx, dy) pixel offset -- reuse the
    exact same drawing code the menu's interactive loop already uses, just
    called with a non-zero offset while sliding and offset=(0, 0) once at rest.

    The offset itself follows a sine ease-out curve "cos velocity /
    sin position", fast at the start,
    smoothly decelerating into place, instead of moving at a constant speed.

    Only ever two things get drawn each frame -- the frozen background and
    the menu itself -- regardless of how far off-screen the menu currently
    is, so there's no per-pixel or per-object cost tied to how much of it is
    still out of view (SDL clips off-screen blits for free).
    """
    if direction == "top":
        start_offset = (0, -panel_rect.bottom)
    elif direction == "bottom":
        start_offset = (0, HEIGHT - panel_rect.top)
    elif direction == "left":
        start_offset = (-panel_rect.right, 0)
    elif direction == "right":
        start_offset = (WIDTH - panel_rect.left, 0)
    else:
        raise ValueError(f"unknown slide direction: {direction!r}")

    for step in range(SLIDE_STEPS + 1):
        clock.tick(FPS)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return "quit"

        eased = math.sin((step / SLIDE_STEPS) * (math.pi / 2))
        remaining = 1 - eased
        offset = (round(start_offset[0] * remaining), round(start_offset[1] * remaining))

        render_frame(offset)
        pygame.display.update()
    return None


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

    def render(offset=(0, 0), mouse=(-1, -1)):
        window.blit(snapshot, (0, 0))
        draw_panel(window, panel.move(offset))
        draw_text(window, "pyohmine ninjas", TITLE_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 70 + offset[1]))
        for _, btn in buttons:
            btn.draw(window, mouse, offset=offset)

    if slide_menu_in(panel, "top", render) == "quit":
        return "quit"

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action in ("quit",):
            return "quit"

        mouse = pygame.mouse.get_pos()
        render(mouse=mouse)
        pygame.display.update()

        if click:
            for result, btn in buttons:
                if btn.clicked(mouse, click):
                    return result


def level_select_screen(snapshot):
    max_spacing = 260
    max_panel_width = 940  # leaves a margin against WIDTH=1000 either side
    n = len(LEVELS)
    # grow the panel to fit more levels (up to the screen-width cap), then
    # shrink icon spacing -- and finally icon scale -- once even the widest
    # panel can't give every icon its full-size spacing
    panel_width = min(max_panel_width, 160 + max_spacing * (n - 1)) if n > 1 else 300
    spacing = min(max_spacing, (panel_width - 160) / (n - 1)) if n > 1 else 0
    icon_scale = min(6, max(3, (spacing - 30) / 19)) if n > 1 else 6
    start_x = WIDTH // 2 - spacing * (n - 1) / 2

    level_buttons = []
    for i, lvl in enumerate(LEVELS):
        btn = Button(LEVEL_ICONS[i], (int(start_x + i * spacing), HEIGHT // 2),
                    scale=icon_scale, label=lvl["title"])
        level_buttons.append(btn)

    back_btn = Button(BTN_IMAGES["back"], (100, HEIGHT - 80), scale=3, label="Back")

    panel = pygame.Rect(0, 0, panel_width, 420)
    panel.center = (WIDTH // 2, HEIGHT // 2 - 20)

    def render(offset=(0, 0), mouse=(-1, -1)):
        window.blit(snapshot, (0, 0))
        draw_panel(window, panel.move(offset))
        draw_text(window, "Choose a Level", HEADING_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 50 + offset[1]))

        for btn in level_buttons:
            btn.draw(window, mouse, offset=offset)
        back_btn.draw(window, mouse, offset=offset)

    if slide_menu_in(panel, "bottom", render) == "quit":
        return "quit", None

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit", None
        if action == "escape":
            return "back", None

        mouse = pygame.mouse.get_pos()
        render(mouse=mouse)
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

    def render(offset=(0, 0), mouse=(-1, -1)):
        window.blit(snapshot, (0, 0))
        draw_panel(window, panel.move(offset))
        draw_text(window, "Choose Your Ninja", HEADING_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 50 + offset[1]))

        for name, rect in tile_rects.items():
            draw_rect = rect.move(offset)
            border = 5 if name == selected else 1
            pygame.draw.rect(window, BLACK, draw_rect, border, border_radius=10)
            portrait_rect = portraits[name].get_rect(center=draw_rect.center)
            window.blit(portraits[name], portrait_rect)
            draw_text(window, name, LABEL_FONT, BLACK, (draw_rect.centerx, draw_rect.bottom + 22))

        draw_text(window, f"Selected: {selected}", LABEL_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 100 + offset[1]))

        play_btn.draw(window, mouse, offset=offset)
        back_btn.draw(window, mouse, offset=offset)

    if slide_menu_in(panel, "left", render) == "quit":
        return "quit", None

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit", None
        if action == "escape":
            return "back", None

        mouse = pygame.mouse.get_pos()
        render(mouse=mouse)
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

    def render(offset=(0, 0), mouse=(-1, -1)):
        window.blit(base, (0, 0))
        draw_panel(window, panel.move(offset))
        draw_text(window, "Paused", HEADING_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 60 + offset[1]))
        for _, btn in buttons:
            btn.draw(window, mouse, offset=offset)

    if slide_menu_in(panel, "right", render) == "quit":
        return "quit"

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit"
        if action == "escape":
            return "resume"

        mouse = pygame.mouse.get_pos()
        render(mouse=mouse)
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

    def render(offset=(0, 0), mouse=(-1, -1)):
        window.blit(base, (0, 0))
        draw_panel(window, panel.move(offset))
        draw_text(window, title, HEADING_FONT, BLACK,
                  (WIDTH // 2 + offset[0], panel.top + 60 + offset[1]))
        for _, btn in buttons:
            btn.draw(window, mouse, offset=offset)

    if slide_menu_in(panel, "bottom", render) == "quit":
        return "quit"

    while True:
        clock.tick(FPS)
        action, click = get_click()
        if action == "quit":
            return "quit"

        mouse = pygame.mouse.get_pos()
        render(mouse=mouse)
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
    scroll_area_width = 200

    while True:
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
        for dp in level.get("drop_platforms", []):
            if dp.in_view(offset_x, WIDTH):
                dp.loop()
        for sb in level.get("swinging_balls", []):
            if sb.in_view(offset_x, WIDTH):
                sb.loop()
        for fan in level.get("fans", []):
            if fan.in_view(offset_x, WIDTH):
                fan.loop()

        objects_in_view = [obj for obj in objects if obj.in_view(offset_x, WIDTH)]
        fruits_in_view = [f for f in fruits if f.in_view(offset_x, WIDTH)]
        fans_in_view = [f for f in level.get("fans", []) if f.in_view(offset_x, WIDTH)]
        checkpoints_in_view = [c for c in checkpoints if c.in_view(offset_x, WIDTH)]

        reached_flag = handle_move(player, objects_in_view, checkpoints_in_view, flag, fruits)

        # Fans aren't solid, so they bypass handle_move/collision entirely --
        # anyone standing in the updraft column just gets carried straight up.
        for fan in fans_in_view:
            if fan.in_column(player):
                player.y_vel = fan.LIFT
                player.fall_count = 0
                player.jump_count = 1

        draw(window, level["background"], player, [*objects_in_view, *fruits_in_view, *fans_in_view],
             checkpoints_in_view, offset_x)
        draw_collected_fruits(window, fruits)
        draw_lives_hud(window, lives_icon.image, max(0, LIVES_START - player.player_hit))
        pygame.display.update()

        if player.player_hit >= 100 or player.rect.top > HEIGHT:
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
            elif result == "levels":
                state = "levels"
            elif isinstance(result, tuple) and result[0] == "play_index":
                state = ("playing", result[1])
            else:
                state = "levels"

    pygame.quit()
    quit()


if __name__ == "__main__":
    main()
