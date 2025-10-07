class Fruits(Object):
    ANIMATION_DELAY = 3
    SPRITES = load_sprite_sheets("Items", "Fruits", 32, 32)

    def __init__(self, x, y, width, height, animation_name):
        super().__init__(x, y, width, height, "fruits")
        self.fruits = self.SPRITES  # Assuming same size; else, reload with load_sprite_sheets()
        self.animation_name = animation_name  # ← This is the new parameter
        self.image = self.fruits[self.animation_name][0]
        self.mask = pygame.mask.from_surface(self.image)
        self.animation_count = 0
        self.hit = False

    def on(self):
        self.animation_name = animation_name

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
