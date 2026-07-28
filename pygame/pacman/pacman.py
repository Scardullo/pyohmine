"""Pac-Man clone built with pygame."""
import copy
import math

import pygame

from board import boards

pygame.init()

WIDTH, HEIGHT = 900, 950
FPS = 60
CELL_W = WIDTH // 30
CELL_H = (HEIGHT - 50) // 32
LOOKAHEAD = 15  # pixels to peek ahead of a sprite's center when testing for an open turn
PI = math.pi

RIGHT, LEFT, UP, DOWN = 0, 1, 2, 3
DIRECTION_KEYS = {
    pygame.K_RIGHT: RIGHT,
    pygame.K_LEFT: LEFT,
    pygame.K_UP: UP,
    pygame.K_DOWN: DOWN,
}

WALL_COLOR = 'blue'
PLAYER_SPEED = 2
PLAYER_SPAWN = (450, 663, RIGHT)
POWERUP_DURATION = 600  # frames

DOOR_WAYPOINT = (400, 100)   # waypoint eyes head for on their way back to the box
EYES_HOME = (380, 400)       # target once an eaten ghost is back inside the box

screen = pygame.display.set_mode([WIDTH, HEIGHT])
timer = pygame.time.Clock()
font = pygame.font.Font('freesansbold.ttf', 20)
level = copy.deepcopy(boards)


def load_image(path, size=(45, 45)):
    return pygame.transform.scale(pygame.image.load(path), size)


player_images = [load_image(f'assets/player_images/{i}.png') for i in range(1, 5)]
blinky_img = load_image('assets/ghost_images/red.png')
pinky_img = load_image('assets/ghost_images/pink.png')
inky_img = load_image('assets/ghost_images/blue.png')
clyde_img = load_image('assets/ghost_images/orange.png')
spooked_img = load_image('assets/ghost_images/powerup.png')
dead_img = load_image('assets/ghost_images/dead.png')


def near_ghost_box(x, y):
    return 340 < x < 560 and 340 < y < 500


def inside_ghost_box(x, y):
    return 350 < x < 550 and 370 < y < 500


def open_turns(center_x, center_y, direction, door_passable=False, guard_left_edge=True):
    """Which of [right, left, up, down] can a sprite centered here turn into."""
    col = center_x // CELL_W
    if col >= 29 or (guard_left_edge and col <= 0):
        return [True, True, False, False]

    def passable(row, col_):
        value = level[row][col_]
        return value < 3 or (value == 9 and door_passable)

    row = center_y // CELL_H
    turns = [
        passable(row, (center_x + LOOKAHEAD) // CELL_W),   # right
        passable(row, (center_x - LOOKAHEAD) // CELL_W),   # left
        passable((center_y - LOOKAHEAD) // CELL_H, col),   # up
        passable((center_y + LOOKAHEAD) // CELL_H, col),   # down
    ]

    # Near a branch point while moving vertically, also peek a full cell to
    # either side so the turn is offered slightly before the corridor opens.
    if direction in (UP, DOWN) and 12 <= center_y % CELL_H <= 18:
        turns[LEFT] = turns[LEFT] or passable(row, (center_x - CELL_W) // CELL_W)
        turns[RIGHT] = turns[RIGHT] or passable(row, (center_x + CELL_W) // CELL_W)

    return turns


class Ghost:
    """A ghost that chases (or flees) ``self.target`` through the maze.

    Each ghost's personality is two booleans: whether it proactively turns
    toward the target while moving horizontally (``chase_h``) and while
    moving vertically (``chase_v``), rather than only turning when blocked.
    """

    # When the ghost's current direction is blocked, try these directions in
    # order: first the ones that would close the distance to the target,
    # then (as a fallback) whichever is simply open.
    FAVORABLE_ORDER = {RIGHT: (DOWN, UP, LEFT), LEFT: (DOWN, UP, RIGHT),
                        UP: (RIGHT, LEFT, DOWN), DOWN: (RIGHT, LEFT, UP)}
    ANY_ORDER = {RIGHT: (DOWN, UP, LEFT), LEFT: (DOWN, UP, RIGHT),
                 UP: (LEFT, DOWN, RIGHT), DOWN: (UP, LEFT, RIGHT)}
    # Perpendicular directions to consider detouring into when the ghost
    # *could* keep going straight but a chase-minded ghost prefers to cut
    # toward the target instead.
    DETOUR_CHECK = {RIGHT: (DOWN, UP), LEFT: (DOWN, UP), UP: (RIGHT, LEFT), DOWN: (RIGHT, LEFT)}

    def __init__(self, name, x, y, direction, img, chase_axes):
        self.name = name
        self.spawn = (x, y, direction)
        self.img = img
        self.chase_h, self.chase_v = chase_axes
        self.x_pos, self.y_pos, self.direction = x, y, direction
        self.speed = 2
        self.dead = False
        self.in_box = False
        self.turns = [False, False, False, False]
        self.target = (x, y)
        self.hitbox = None

    def reset(self):
        self.x_pos, self.y_pos, self.direction = self.spawn
        self.dead = False

    @property
    def center(self):
        return self.x_pos + 22, self.y_pos + 22

    def update_turns(self):
        cx, cy = self.center
        self.turns = open_turns(cx, cy, self.direction, door_passable=self.in_box or self.dead)
        self.in_box = inside_ghost_box(self.x_pos, self.y_pos)

    def draw(self, powerup, eaten):
        if (not powerup and not self.dead) or (eaten and powerup and not self.dead):
            image = self.img
        elif powerup and not self.dead and not eaten:
            image = spooked_img
        else:
            image = dead_img
        screen.blit(image, (self.x_pos, self.y_pos))
        cx, cy = self.center
        self.hitbox = pygame.rect.Rect((cx - 18, cy - 18), (36, 36))

    def favors(self, direction):
        tx, ty = self.target
        if direction == RIGHT:
            return tx > self.x_pos
        if direction == LEFT:
            return tx < self.x_pos
        if direction == UP:
            return ty < self.y_pos
        return ty > self.y_pos

    def step(self, direction):
        self.direction = direction
        if direction == RIGHT:
            self.x_pos += self.speed
        elif direction == LEFT:
            self.x_pos -= self.speed
        elif direction == UP:
            self.y_pos -= self.speed
        else:
            self.y_pos += self.speed

    def forced_turn(self, blocked_direction):
        """The current direction is blocked; pick the best open alternative."""
        for d in self.FAVORABLE_ORDER[blocked_direction]:
            if self.turns[d] and self.favors(d):
                self.step(d)
                return
        for d in self.ANY_ORDER[blocked_direction]:
            if self.turns[d]:
                self.step(d)
                return

    def move(self, force_chase=False):
        d = self.direction
        chase = force_chase or (self.chase_v if d in (UP, DOWN) else self.chase_h)

        if self.favors(d) and self.turns[d]:
            self.step(d)
        elif not self.turns[d]:
            self.forced_turn(d)
        elif chase:
            for detour in self.DETOUR_CHECK[d]:
                if self.turns[detour] and self.favors(detour):
                    self.step(detour)
                    break
            else:
                self.step(d)
        else:
            self.step(d)

        if self.x_pos < -30:
            self.x_pos = 900


ghosts = [
    Ghost('blinky', 56, 58, RIGHT, blinky_img, chase_axes=(False, False)),
    Ghost('inky', 440, 388, UP, inky_img, chase_axes=(True, False)),
    Ghost('pinky', 440, 438, UP, pinky_img, chase_axes=(False, True)),
    Ghost('clyde', 440, 438, UP, clyde_img, chase_axes=(True, True)),
]
blinky, inky, pinky, clyde = ghosts

player_x, player_y, direction = PLAYER_SPAWN
direction_command = RIGHT
counter = 0
flicker = False
score = 0
lives = 3
powerup = False
power_counter = 0
eaten_ghost = [False, False, False, False]
turns_allowed = [False, False, False, False]
moving = False
startup_counter = 0
game_over = False
game_won = False


def draw_board():
    for i, row in enumerate(level):
        for j, value in enumerate(row):
            cx, cy = j * CELL_W + 0.5 * CELL_W, i * CELL_H + 0.5 * CELL_H
            if value == 1:
                pygame.draw.circle(screen, 'white', (cx, cy), 4)
            elif value == 2 and not flicker:
                pygame.draw.circle(screen, 'white', (cx, cy), 10)
            elif value == 3:
                pygame.draw.line(screen, WALL_COLOR, (cx, i * CELL_H), (cx, i * CELL_H + CELL_H), 3)
            elif value == 4:
                pygame.draw.line(screen, WALL_COLOR, (j * CELL_W, cy), (j * CELL_W + CELL_W, cy), 3)
            elif value == 5:
                pygame.draw.arc(screen, WALL_COLOR,
                                 [(j * CELL_W - CELL_W * 0.4) - 2, cy, CELL_W, CELL_H], 0, PI / 2, 3)
            elif value == 6:
                pygame.draw.arc(screen, WALL_COLOR,
                                 [j * CELL_W + CELL_W * 0.5, cy, CELL_W, CELL_H], PI / 2, PI, 3)
            elif value == 7:
                pygame.draw.arc(screen, WALL_COLOR,
                                 [j * CELL_W + CELL_W * 0.5, i * CELL_H - CELL_H * 0.4, CELL_W, CELL_H],
                                 PI, 3 * PI / 2, 3)
            elif value == 8:
                pygame.draw.arc(screen, WALL_COLOR,
                                 [(j * CELL_W - CELL_W * 0.4) - 2, i * CELL_H - CELL_H * 0.4, CELL_W, CELL_H],
                                 3 * PI / 2, 2 * PI, 3)
            elif value == 9:
                pygame.draw.line(screen, 'white', (j * CELL_W, cy), (j * CELL_W + CELL_W, cy), 3)


def draw_player():
    frame = player_images[counter // 5]
    if direction == RIGHT:
        screen.blit(frame, (player_x, player_y))
    elif direction == LEFT:
        screen.blit(pygame.transform.flip(frame, True, False), (player_x, player_y))
    elif direction == UP:
        screen.blit(pygame.transform.rotate(frame, 90), (player_x, player_y))
    else:
        screen.blit(pygame.transform.rotate(frame, 270), (player_x, player_y))


def draw_message(text, color):
    pygame.draw.rect(screen, 'white', [50, 200, 800, 300], 0, 10)
    pygame.draw.rect(screen, 'dark gray', [70, 220, 760, 260], 0, 10)
    screen.blit(font.render(text, True, color), (100, 300))


def draw_misc():
    screen.blit(font.render(f'Score: {score}', True, 'white'), (10, 920))
    if powerup:
        pygame.draw.circle(screen, 'blue', (140, 930), 15)
    for i in range(lives):
        screen.blit(pygame.transform.scale(player_images[0], (30, 30)), (650 + i * 40, 915))
    if game_over:
        draw_message('Game over! Space bar to restart!', 'red')
    if game_won:
        draw_message('Victory! Space bar to restart!', 'green')


def move_player(x, y):
    if direction == RIGHT and turns_allowed[RIGHT]:
        x += PLAYER_SPEED
    elif direction == LEFT and turns_allowed[LEFT]:
        x -= PLAYER_SPEED
    if direction == UP and turns_allowed[UP]:
        y -= PLAYER_SPEED
    elif direction == DOWN and turns_allowed[DOWN]:
        y += PLAYER_SPEED
    return x, y


def eat_dots():
    global score, powerup, power_counter, eaten_ghost
    if not 0 < player_x < 870:
        return
    row, col = center_y // CELL_H, center_x // CELL_W
    if level[row][col] == 1:
        level[row][col] = 0
        score += 10
    elif level[row][col] == 2:
        level[row][col] = 0
        score += 50
        powerup = True
        power_counter = 0
        eaten_ghost = [False, False, False, False]


def ghost_speed(ghost, eaten):
    if ghost.dead:
        return 4
    if powerup and not eaten:
        return 1
    return 2


def compute_targets():
    """Where each ghost should head next: flee, chase, or return home as eyes."""
    runaway_x = 900 if player_x < 450 else 0
    runaway_y = 900 if player_y < 450 else 0
    flee_targets = [(runaway_x, runaway_y), (runaway_x, player_y), (player_x, runaway_y), (450, 450)]

    targets = []
    for ghost, eaten, flee in zip(ghosts, eaten_ghost, flee_targets):
        if powerup and not ghost.dead and not eaten:
            targets.append(flee)
        elif not ghost.dead:
            target = DOOR_WAYPOINT if near_ghost_box(ghost.x_pos, ghost.y_pos) else (player_x, player_y)
            targets.append(target)
        else:
            targets.append(EYES_HOME)
    return targets


def reset_round():
    """Put the player and ghosts back at their spawn points after a life is lost."""
    global player_x, player_y, direction, direction_command
    global powerup, power_counter, startup_counter, eaten_ghost
    player_x, player_y, direction = PLAYER_SPAWN
    direction_command = direction
    powerup = False
    power_counter = 0
    startup_counter = 0
    eaten_ghost = [False, False, False, False]
    for ghost in ghosts:
        ghost.reset()


def new_game():
    global score, lives, level, game_over, game_won
    score = 0
    lives = 3
    level = copy.deepcopy(boards)
    game_over = False
    game_won = False
    reset_round()


def lose_life():
    global lives, game_over, moving, startup_counter
    startup_counter = 0
    if lives > 0:
        lives -= 1
        reset_round()
    else:
        game_over = True
        moving = False


run = True
while run:
    timer.tick(FPS)

    if counter < 19:
        counter += 1
        if counter > 3:
            flicker = False
    else:
        counter = 0
        flicker = True

    if powerup:
        power_counter += 1
        if power_counter >= POWERUP_DURATION:
            power_counter = 0
            powerup = False
            eaten_ghost = [False, False, False, False]

    if startup_counter < 180 and not game_over and not game_won:
        moving = False
        startup_counter += 1
    else:
        moving = True

    screen.fill('black')
    draw_board()

    center_x, center_y = player_x + 23, player_y + 24
    game_won = not any(1 in row or 2 in row for row in level)

    player_circle = pygame.draw.circle(screen, 'black', (center_x, center_y), 20, 2)
    draw_player()

    for i, ghost in enumerate(ghosts):
        ghost.update_turns()
        ghost.draw(powerup, eaten_ghost[i])

    draw_misc()

    new_targets = compute_targets()
    turns_allowed = open_turns(center_x, center_y, direction, guard_left_edge=False)

    if moving:
        player_x, player_y = move_player(player_x, player_y)
    for i, ghost in enumerate(ghosts):
        ghost.speed = ghost_speed(ghost, eaten_ghost[i])
        if moving:
            ghost.move(force_chase=ghost.dead or ghost.in_box)
        ghost.target = new_targets[i]

    eat_dots()

    if not powerup:
        if any(player_circle.colliderect(g.hitbox) and not g.dead for g in ghosts):
            lose_life()
    else:
        for i, ghost in enumerate(ghosts):
            if ghost.dead or not player_circle.colliderect(ghost.hitbox):
                continue
            if eaten_ghost[i]:
                lose_life()
                break
            ghost.dead = True
            eaten_ghost[i] = True
            score += (2 ** eaten_ghost.count(True)) * 100

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            run = False
        elif event.type == pygame.KEYDOWN:
            if event.key in DIRECTION_KEYS:
                direction_command = DIRECTION_KEYS[event.key]
            elif event.key == pygame.K_SPACE and (game_over or game_won):
                new_game()
        elif event.type == pygame.KEYUP:
            if event.key in DIRECTION_KEYS and DIRECTION_KEYS[event.key] == direction_command:
                direction_command = direction

    for d in range(4):
        if direction_command == d and turns_allowed[d]:
            direction = d

    if player_x > 900:
        player_x = -47
    elif player_x < -50:
        player_x = 897

    for ghost in ghosts:
        if ghost.in_box and ghost.dead:
            ghost.dead = False

    pygame.display.flip()

pygame.quit()
