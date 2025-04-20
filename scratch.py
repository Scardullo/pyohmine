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

def handle_move(player, objects, checkpoints):
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
    to_check = [collide_left, collide_right, *vertical_collide, chk_left, chk_right]

    for obj in to_check:
        if obj and obj.name == "fire":
            player.make_hit()
    for chk in to_check:
        if chk and chk.name == "flag":
            flag.off(flag)
            
    def update_sprite(self):
        sprite_sheet = "Checkpoint (Flag Idle)(64x64)"
        if self.hit:
            sprite_sheet = "Checkpoint (Flag Out) (64x64)"

        sprites = self.SPRITES[sprite_sheet]
        sprite_index = (self.animation_count //
                        self.ANIMATION_DELAY) % len(sprites)
        self.sprite = sprites[sprite_index]
        self.animation_count += 1
        self.update()