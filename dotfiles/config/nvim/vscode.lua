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
  { "Mofiqul/vscode.nvim" },
  -- Treesitter
  {
    "nvim-treesitter/nvim-treesitter",
    branch = "main",
    build = ":TSUpdate",
    config = function()
      local parsers = { "c", "lua", "python", "javascript", "typescript" }
      require("nvim-treesitter").install(parsers)
      vim.api.nvim_create_autocmd("FileType", {
        pattern = parsers,
        callback = function() vim.treesitter.start() end,
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
    "catgoose/nvim-colorizer.lua",
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
require("vscode").setup({
    style = "dark",
    transparent = false,
    italic_comments = true,
})
require("vscode").load()
-- ============================================
-- LSP Setup
-- ============================================
-- nvim-lspconfig ships default server configs under lsp/*.lua, which
-- vim.lsp.enable() picks up automatically (see :h lspconfig-nvim-0.11).
vim.lsp.enable({ "pyright", "ts_ls" })

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
