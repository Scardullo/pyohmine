-- ============================================
-- init.lua - Modern Neovim Setup (Arch / Hyprland safe)
-- ============================================

-- Enable true colors
vim.opt.termguicolors = true

-- Enable line numbers (absolute + relative)
vim.opt.number = true
vim.opt.relativenumber = true

-- Set leader key
vim.g.mapleader = " "

-- ============================================
-- Bootstrap lazy.nvim
-- ============================================
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git", "clone", "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable", lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

-- ============================================
-- Plugins
-- ============================================
require("lazy").setup({

  -- Color schemes
  { "catppuccin/nvim", name = "catppuccin" },
  { "rebelot/kanagawa.nvim" },
  { "morhetz/gruvbox" },
  { "folke/tokyonight.nvim" },
  -- Treesitter
  {
    "nvim-treesitter/nvim-treesitter",
    build = ":TSUpdate",
    config = function()
      require("nvim-treesitter.configs").setup({
        ensure_installed = { "c", "lua", "python", "javascript", "typescript" },
        highlight = { enable = true },
        auto_install = true,
      })
    end
  },

  -- LSP
  { "neovim/nvim-lspconfig" },

  -- Autocompletion
  {
    "hrsh7th/nvim-cmp",
    dependencies = {
      "hrsh7th/cmp-nvim-lsp",
      "hrsh7th/cmp-buffer",
      "hrsh7th/cmp-path",
      "saadparwaiz1/cmp_luasnip",
      "L3MON4D3/LuaSnip",
    },
    config = function()
      local cmp = require("cmp")
      local luasnip = require("luasnip")

      cmp.setup({
        snippet = {
          expand = function(args)
            luasnip.lsp_expand(args.body)
          end,
        },
        mapping = cmp.mapping.preset.insert({
          ["<C-n>"] = cmp.mapping.select_next_item(),
          ["<C-p>"] = cmp.mapping.select_prev_item(),
          ["<CR>"] = cmp.mapping.confirm({ select = true }),
        }),
        sources = cmp.config.sources({
          { name = "nvim_lsp" },
          { name = "luasnip" },
        }, {
          { name = "buffer" },
        }),
      })
    end
  },

  -- Statusline
  {
    "nvim-lualine/lualine.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    config = function()
      require("lualine").setup({
        options = { theme = "auto", section_separators = "", component_separators = "|" }
      })
    end
  },

  -- Hex colors
  {
    "norcalli/nvim-colorizer.lua",
    config = function()
      require("colorizer").setup({ "*" }, { RGB = true, RRGGBB = true, names = true, css = true })
    end
  },

  -- ✅ Indent guides (indent-blankline v3 = ibl)
  {
    "lukas-reineke/indent-blankline.nvim",
    main = "ibl",
    config = function()
      require("ibl").setup({
        scope = { enabled = true },
        indent = { char = "│" },
      })
    end
  },

  -- Git signs
  {
    "lewis6991/gitsigns.nvim",
    config = function()
      require("gitsigns").setup()
    end
  },
})

-- ============================================
-- Colorscheme
-- ============================================
require("tokyonight").setup({
  style = "night",  -- darkest variant
})


vim.cmd.colorscheme("tokyonight")

-- ============================================
-- LSP Setup
-- ============================================
local lspconfig = require("lspconfig")

local function safe_setup(server, opts)
  if lspconfig[server] then
    lspconfig[server].setup(opts or {})
  else
    vim.notify("LSP '" .. server .. "' not found", vim.log.levels.WARN)
  end
end

-- Python
safe_setup("pyright")

-- TypeScript / JavaScript (new name)
safe_setup("ts_ls")

-- ============================================
-- LSP Keymaps
-- ============================================
vim.keymap.set("n", "gd", vim.lsp.buf.definition, { desc = "Go to definition" })
vim.keymap.set("n", "K", vim.lsp.buf.hover, { desc = "Hover info" })
vim.keymap.set("n", "<leader>rn", vim.lsp.buf.rename, { desc = "Rename symbol" })
vim.keymap.set("n", "<leader>ca", vim.lsp.buf.code_action, { desc = "Code action" })

-- ============================================
-- Diagnostics (clean look)
-- ============================================
vim.diagnostic.config({
  signs = false,
  underline = false,
  virtual_text = false,
})
