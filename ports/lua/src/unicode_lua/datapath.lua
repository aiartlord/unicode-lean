-- Self-contained bundled-data location.
--
-- The port reads ONLY files inside `ports/lua/data/` at runtime.  This module
-- derives that directory from its own source location so the port stays
-- relocatable and never reaches into the repo-root `data/` tree.

local M = {}

local src = debug.getinfo(1, "S").source
-- `src` looks like "@/abs/.../ports/lua/src/unicode_lua/datapath.lua".
local dir = src:match("^@(.*[/\\])")
if dir == nil then
  error("datapath: cannot determine module directory from source " .. tostring(src))
end

-- From `.../ports/lua/src/unicode_lua/` step up to `.../ports/lua/data/`.
M.data_dir = dir .. "../../data/"

function M.path(name)
  return M.data_dir .. name
end

function M.read(name)
  local handle = assert(io.open(M.path(name), "r"))
  local content = handle:read("*a")
  handle:close()
  return content
end

return M
