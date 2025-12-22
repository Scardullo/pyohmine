import os
import random
import math
import pygame
from os import listdir
from os.path import isfile, join
from pygame import mixer

pygame.init()

mixer.music.load('assets/upbeat_loop.ogg')
mixer.music.play(-1)

pygame.display.set_caption("Platformer")

WIDTH, HEIGHT = 1000, 800
FPS = 60
PLAYER_VEL = 5

window = pygame.display.set_mode((WIDTH, HEIGHT))


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


def load_sprite_3dir(dir1, dir2, dir3, width, height, direction=False):
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


def get_block(size):
    path = join("assets", "Terrain", "Terrain.png")
    image = pygame.image.load(path).convert_alpha()
    surface = pygame.Surface((size, size), pygame.SRCALPHA, 32)
    rect = pygame.Rect(96, 0, size, size)
    surface.blit(image, (0, 0), rect)
    return pygame.transform.scale2x(surface)


class Player(pygame.sprite.Sprite):
    COLOR = (255, 0, 0)
    GRAVITY = 1
    SPRITES = load_sprite_sheets("MainCharacters", "NinjaFrog", 32, 32, True)
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height):
        super().__init__()
        self.rect = pygame.Rect(x, y, width, height)
        self.x_vel = 0
        self.y_vel = 0
        self.mask = None
        self.direction = "left"
        self.animation_count = 0
        self.fall_count = 0
        self.jump_count = 0
        self.hit = False
        self.hit_count = 0
        self.player_hit = 0

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
        if not self.hit:  # Only count a new hit if not already in 'hit' state
            self.hit = True
            self.player_hit += 1
            self.hit_count = 0  # reset hit timer

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
        sprites = self.SPRITES[sprite_sheet_name]
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


class Block(Object):
    def __init__(self, x, y, size):
        super().__init__(x, y, size, size)
        block = get_block(size)
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
        self.image = self.fruits[self.animation_name][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.hit = False

    def on(self):
        self.animation_name = self.animation_name

    def off(self):
        self.animation_name = "Collected"

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


class Flag(Checkpoints):
    ANIMATION_DELAY = 3
    SPRITES = load_sprite_3dir("Items", "Checkpoints", "Checkpoint", 64, 64)

    def __init__(self, x, y, width, height):
        super().__init__(x, y, width, height, "flag")
        self.flag = load_sprite_3dir("Items", "Checkpoints", "Checkpoint",
                                     width, height)
        self.image = self.flag["Checkpoint (Flag Idle)(64x64)"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Checkpoint (Flag Idle)(64x64)"

    def on(self):
        self.animation_name = "Checkpoint (Flag Idle)(64x64)"

    def off(self):
        self.animation_name = "Checkpoint (Flag Out) (64x64)"

    def update_sprite(self):
        sprite_sheet = "Checkpoint (Flag Idle)(64x64)"
        sprites = self.SPRITES[sprite_sheet]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.sprite = sprites[sprite_index]
        self.animation_count += 1
        self.update()

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

        self.update_sprite()


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

    def __init__(self, x, y, width, height, x_right, x_left):
        super().__init__(x, y, width, height, "saw")
        self.saw = load_sprite_sheets("Traps", "Saw", width, height)
        self.image = self.saw["on"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "on"
        self.x_vel = 3
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

    def __init__(self, x, y, width, height, x_right, x_left):
        super().__init__(x, y, width, height, "spikehead_x")
        self.spikehead_x = load_sprite_sheets("Traps", "spikehead", width,
                                              height)
        self.image = self.spikehead_x["Idle"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Idle"
        self.x_vel = 3
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


def get_background(name):
    image = pygame.image.load(join("assets", "Background", name))
    _, _, width, height = image.get_rect()
    tiles = []

    for i in range(WIDTH // width + 1):
        for j in range(HEIGHT // height + 1):
            pos = (i * width, j * height)
            tiles.append(pos)

    return tiles, image


def draw(window, background, bg_image, player, objects, checkpoints, offset_x):
    for tile in background:
        window.blit(bg_image, tile)

    for obj in objects:
        obj.draw(window, offset_x)

    for check in checkpoints:
        check.draw(window, offset_x)

    player.draw(window, offset_x)
    pygame.display.update()


def handle_vertical_collision(player, objects, dy):
    collided_objects = []
    for obj in objects:
        if pygame.sprite.collide_mask(player, obj):
            if dy > 0:
                player.rect.bottom = obj.rect.top
                player.landed()
            elif dy < 0:
                player.rect.top = obj.rect.bottom
                player.hit_head()

            collided_objects.append(obj)

    return collided_objects


def collide(player, objects, dx):
    player.move(dx, 0)
    player.update()
    collided_object = None
    for obj in objects:
        if pygame.sprite.collide_mask(player, obj):
            collided_object = obj
            break

    player.move(-dx, 0)
    player.update()
    return collided_object


def check_point(player, checkpoints, dx):
    player.move(dx, 0)
    player.update()
    collided_object = None
    for chk in checkpoints:
        if pygame.sprite.collide_mask(player, chk):
            collided_object = chk
            break

    player.move(-dx, 0)
    player.update()
    return collided_object


def handle_move(player, objects, checkpoints, flag, cherry, bananas):
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
    if keys[pygame.K_LEFT] and not chk_left:
        player.move_left(PLAYER_VEL)
    if keys[pygame.K_RIGHT] and not chk_right:
        player.move_right(PLAYER_VEL)

    vertical_collide = handle_vertical_collision(player, objects, player.y_vel)
    to_check = [collide_left, collide_right, *vertical_collide, chk_left,
                chk_right]

    for obj in to_check:
        if obj and obj.name == "fire":
            player.make_hit()
        elif obj and obj.name == "rockhead":
            player.make_hit()
        elif obj and obj.name == "saw":
            player.make_hit()
        elif obj and obj.name == "spikehead_x":
            player.make_hit()
        elif obj and obj.name == "flag":
            flag.off()
        elif obj and obj.name == "fruits":
            if obj.animation_name == "Cherries":
                cherry.off()
            elif obj.animation_name == "Bananas":
                bananas.off()

# ==============================
#   OBJECT CREATION FUNCTIONS
# ==============================

def create_fruits(block_size):
    """Create fruit collectibles."""
    cherry = Fruits((block_size * 39) - 44, HEIGHT - (block_size + 60), 32, 32, "Cherries")
    bananas = Fruits(WIDTH * 2 + (block_size * 5), block_size * 3, 32, 32, "Bananas")

    cherry.on()
    bananas.on()

    return [cherry, bananas]


def create_hazards(block_size):
    """Create hazards like fires, rockheads, saws, and spikeheads."""
    # Fires
    fire_positions = [block_size * 7 - 70, block_size * 7 - 35, block_size * 7, block_size * 7 + 35]
    fires = []
    for pos in fire_positions:
        f = Fire(pos, HEIGHT - block_size - 64, 16, 32)
        f.on()
        fires.append(f)

    # RockHeads (vertical traps)
    rockheads = [
        RockHead(7, block_size * 2, 42, 42, 530),
        RockHead(block_size * 3 + 3, 0, 42, 42, 340),
        RockHead(block_size * 7 + 4, -200, 42, 42, 150)
    ]

    # Spikeheads (horizontal traps)
    spikeheads = [
        Spikehead_x(block_size * 37, HEIGHT - (block_size * 2), 54, 52, block_size * 41, block_size * 36),
        Spikehead_x(block_size * 38, HEIGHT - (block_size * 4), 54, 52, block_size * 40, block_size * 37)
    ]

    # Saw (moving hazard)
    saw = Saw((block_size * 11), 0, 38, 42, (WIDTH * 2) - 90, block_size * 11)

    return fires, rockheads, spikeheads, saw


def create_flag(block_size):
    """Create the checkpoint flag."""
    flag = Flag((WIDTH * 5) - (block_size * 4), HEIGHT - (block_size * 2 + 30), 64, 64)
    flag.on()
    return flag


def create_floors(block_size):
    """Create floor and platforms."""
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

    # Custom platform blocks
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

    return [*floor, *floor2, *floor3, *extra_blocks]


# ==============================
#   MAIN GAME LOOP
# ==============================

def main(window):
    clock = pygame.time.Clock()
    background, bg_image = get_background("Purple.png")

    block_size = 96
    player = Player(100, 100, 50, 50)

    font = pygame.font.SysFont("Arial", 64)
    game_over = False

    # === Load Game Objects ===
    fruits = create_fruits(block_size)
    fires, rockheads, spikeheads, saw = create_hazards(block_size)
    flag = create_flag(block_size)
    floors = create_floors(block_size)

    # Combine everything into one list for rendering/collision
    objects = [
        *floors, *fires, *rockheads, *spikeheads,
        saw, *fruits
    ]

    checkpoints = [flag]

    # === Camera Setup ===
    offset_x = 0
    scroll_area_width = 200

    # === Main Game Loop ===
    run = True
    while run:
        clock.tick(FPS)

        # --- Event Handling ---
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                run = False
                break
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_SPACE and player.jump_count < 2:
                    player.jump()

        # --- Update Entities ---
        player.loop(FPS)
        flag.loop()

        for f in fires:
            f.loop()
        for r in rockheads:
            r.loop()
        for s in spikeheads:
            s.loop()
        for fruit in fruits:
            fruit.loop()

        saw.loop()

        # --- Check for Game Over ---
        if player.player_hit >= 2:
            game_over = True

        # --- Movement, Collision, Checkpoints ---
        handle_move(player, objects, checkpoints, flag, *fruits)

        # --- Drawing ---
        draw(window, background, bg_image, player, objects, checkpoints, offset_x)

        if game_over:
            game_over_text = font.render("GAME OVER", True, (161, 3, 252))
            text_rect = game_over_text.get_rect(center=(WIDTH // 2, HEIGHT // 2))
            window.blit(game_over_text, text_rect)
            pygame.display.update()

            # Pause and then quit
            pygame.time.delay(3000)
            run = False
            continue

        # --- Camera Scrolling ---
        if (
            (player.rect.right - offset_x >= WIDTH - scroll_area_width and player.x_vel > 0)
            or (player.rect.left - offset_x <= scroll_area_width and player.x_vel < 0)
        ):
            offset_x += player.x_vel

    pygame.quit()
    quit()


if __name__ == "__main__":
    main(window)
