import pygame
import random
import math
from pygame import mixer

# https://www.youtube.com/watch?v=FfWpgLFMI7w
# Pygame Tutorial for Beginners - Python Game Development Course // freeCodeCamp.org
# !$:/ Ctrl + Alt + L cleans up code   $$!!


# initialize the pygame
pygame.init()
clock = pygame.time.Clock()
# create the screen
screen = pygame.display.set_mode((800, 600))
# Background
background = pygame.image.load('space.png')
# Background sound
mixer.music.load('background2.wav')
mixer.music.play(-1)

# Title and Icon
pygame.display.set_caption("Mars Attacks")
icon = pygame.image.load('spaceship.png')
pygame.display.set_icon(icon)

# player
playerImg = pygame.image.load('ship.png')
playerX = 370
playerY = 480
playerX_change = 0

# enemy
enemyImg = []
enemyX = []
enemyY = []
enemyX_change = []
enemyY_change = []
num_of_enemies = 6

for i in range(num_of_enemies):
    enemyImg.append(pygame.image.load('enemy.png'))
    enemyX.append(random.randint(0, 735))
    enemyY.append(random.randint(50, 100))
    enemyX_change.append(7)
    enemyY_change.append(40)

# bullet   ready state is you cant see the bullet
# bullet fire is bullet is moving
bulletImg = pygame.image.load('bullet.png')
bulletX = 0
bulletY = 480
bulletX_change = 0
bulletY_change = 12
bullet_state = "ready"

# Score


score_value = 0
font = pygame.font.Font('freesansbold.ttf', 32)
textX = 10
textY = 10

over_font = pygame.font.Font('freesansbold.ttf', 64)


def show_score(x, y):
    score = font.render("Score :" + str(score_value), True, (0, 255, 0))
    screen.blit(score, (x, y))


def player(x, y):
    screen.blit(playerImg, (x, y))


def enemy(x, y, i):
    screen.blit(enemyImg[i], (x, y))


def fire_bullet(x, y):
    global bullet_state
    bullet_state = "fire"
    screen.blit(bulletImg, (x + 16, y + 10))


def is_collision(enemyX, enemyY, bulletX, bulletY):
    distance = math.sqrt(
        (math.pow(enemyX - bulletX, 2)) + (+math.pow(enemyY - bulletY, 2)))  # d=√((x_2-x_1)²+(y_2-y_1)²)
    if distance < 27:
        return True
    else:
        return False


def game_over_text():
    over_text = over_font.render("GAME  OVER", True, (0, 255, 255))
    screen.blit(over_text, (185, 250))


# Game Loop
running = True
while running:

    screen.fill((0, 0, 70))  # RGB   0 - 255

    screen.blit(background, (0, 0))

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        # if keystroke is pressed, check whether right or left
        if event.type == pygame.KEYDOWN:  # key is pressed down

            if event.key == pygame.K_LEFT:
                playerX_change = -5
            if event.key == pygame.K_RIGHT:
                playerX_change = 5
            if event.key == pygame.K_SPACE:
                if bullet_state == "ready":  # check to see if bullet is on screen
                    bullet_Sound = mixer.Sound('laser.wav')
                    bullet_Sound.play()
                    bulletX = playerX
                    fire_bullet(playerX, bulletY)

        if event.type == pygame.KEYUP:
            if event.key == pygame.K_LEFT or event.key == pygame.K_RIGHT:
                playerX_change = 0

    # boundaries
    playerX += playerX_change

    if playerX <= 0:
        playerX = 0
    elif playerX >= 736:
        playerX = 736

    # Enemy Movement
    for i in range(num_of_enemies):
        # Game Over
        if enemyY[i] > 440:
            for j in range(num_of_enemies):
                enemyY[j] = 2000
            game_over_text()
            break
        enemyX[i] += enemyX_change[i]
        if enemyX[i] <= 0:
            enemyX_change[i] = 7
            enemyY[i] += enemyY_change[i]
        elif enemyX[i] >= 736:
            enemyX_change[i] = -7
            enemyY[i] += enemyY_change[i]

        # Collision
        collision = is_collision(enemyX[i], enemyY[i], bulletX, bulletY)
        if collision:
            explosion_Sound = mixer.Sound('explosion.wav')
            explosion_Sound.play()
            bulletY = 480
            bullet_state = "ready"
            score_value += 1
            enemyX[i] = random.randint(0, 736)
            enemyY[i] = random.randint(50, 100)

        enemy(enemyX[i], enemyY[i], i)

    # Bullet Movement
    if bulletY <= 0:
        bulletY = 480
        bullet_state = "ready"

    if bullet_state == "fire":
        fire_bullet(bulletX, bulletY)
        bulletY -= bulletY_change

    player(playerX, playerY)
    show_score(textX, textY)
    pygame.display.update()
