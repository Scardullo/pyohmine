class Spikehead_x(Object):
    ANIMATION_DELAY = 3

    def __init__(self, x, y, width, height, x_right, x_left):
        super().__init__(x, y, width, height, "spikehead_x")
        self.spikehead_x = load_sprite_sheets("Traps", "spikehead", width, height)
        self.image = self.spikehead_x["Blink (54x52)"][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.animation_name = "Blink (54x52)"
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

        if self.rect.x >= self.x_right:
            self.animation_name = 'Right Hit (54x52)'

        if self.rect.x <= self.x_left:
            self.animation_name = 'Left Hit (54x52)'