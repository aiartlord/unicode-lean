package.path = "src/?.lua;src/?/init.lua;" .. package.path

local M = {}

local function read_file(path)
  local f = assert(io.open(path, "rb"))
  local text = f:read("*a")
  f:close()
  return text
end

local Json = {}
Json.__index = Json

local function new_json(text)
  return setmetatable({ text = text, pos = 1 }, Json)
end

function Json:peek()
  return self.text:sub(self.pos, self.pos)
end

function Json:skip_ws()
  while self:peek():match("%s") do
    self.pos = self.pos + 1
  end
end

function Json:parse_string()
  assert(self:peek() == '"')
  self.pos = self.pos + 1
  local out = {}
  while true do
    local c = self:peek()
    assert(c ~= "", "unterminated string")
    self.pos = self.pos + 1
    if c == '"' then
      return table.concat(out)
    elseif c == "\\" then
      local e = self:peek()
      self.pos = self.pos + 1
      if e == '"' or e == "\\" or e == "/" then
        out[#out + 1] = e
      elseif e == "b" then
        out[#out + 1] = "\b"
      elseif e == "f" then
        out[#out + 1] = "\f"
      elseif e == "n" then
        out[#out + 1] = "\n"
      elseif e == "r" then
        out[#out + 1] = "\r"
      elseif e == "t" then
        out[#out + 1] = "\t"
      else
        error("unsupported escape \\" .. e)
      end
    else
      out[#out + 1] = c
    end
  end
end

function Json:parse_number()
  local start = self.pos
  while self:peek():match("[%d%+%-%.eE]") do
    self.pos = self.pos + 1
  end
  return tonumber(self.text:sub(start, self.pos - 1))
end

function Json:parse_array()
  assert(self:peek() == "[")
  self.pos = self.pos + 1
  local out = {}
  self:skip_ws()
  if self:peek() == "]" then
    self.pos = self.pos + 1
    return out
  end
  while true do
    out[#out + 1] = self:parse_value()
    self:skip_ws()
    local c = self:peek()
    self.pos = self.pos + 1
    if c == "]" then
      return out
    end
    assert(c == ",")
  end
end

function Json:parse_object()
  assert(self:peek() == "{")
  self.pos = self.pos + 1
  local out = {}
  self:skip_ws()
  if self:peek() == "}" then
    self.pos = self.pos + 1
    return out
  end
  while true do
    self:skip_ws()
    local key = self:parse_string()
    self:skip_ws()
    assert(self:peek() == ":")
    self.pos = self.pos + 1
    out[key] = self:parse_value()
    self:skip_ws()
    local c = self:peek()
    self.pos = self.pos + 1
    if c == "}" then
      return out
    end
    assert(c == ",")
  end
end

function Json:parse_value()
  self:skip_ws()
  local c = self:peek()
  if c == '"' then
    return self:parse_string()
  elseif c == "{" then
    return self:parse_object()
  elseif c == "[" then
    return self:parse_array()
  elseif c == "t" and self.text:sub(self.pos, self.pos + 3) == "true" then
    self.pos = self.pos + 4
    return true
  elseif c == "f" and self.text:sub(self.pos, self.pos + 4) == "false" then
    self.pos = self.pos + 5
    return false
  elseif c == "n" and self.text:sub(self.pos, self.pos + 3) == "null" then
    self.pos = self.pos + 4
    return nil
  end
  return self:parse_number()
end

function M.json_file(path)
  return new_json(read_file(path)):parse_value()
end

function M.deep_equal(a, b)
  if a == b then
    return true
  end
  if type(a) ~= type(b) then
    return false
  end
  if type(a) ~= "table" then
    return false
  end
  for k, v in pairs(a) do
    if not M.deep_equal(v, b[k]) then
      return false
    end
  end
  for k, _ in pairs(b) do
    if a[k] == nil then
      return false
    end
  end
  return true
end

function M.assert_equal(actual, expected, label)
  if not M.deep_equal(actual, expected) then
    error((label or "assert_equal") .. " mismatch")
  end
end

function M.assert_includes(list, value, label)
  for _, item in ipairs(list) do
    if item == value then
      return
    end
  end
  error((label or "assert_includes") .. " missing " .. tostring(value))
end

function M.codes(verdict)
  local out = {}
  for _, finding in ipairs(verdict.findings) do
    out[#out + 1] = finding.code
  end
  return out
end

return M
