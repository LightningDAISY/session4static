#! /usr/bin/env luajit

local config = {
	mysql = {
		username = "sorauser",
		password = "password",
		address  = "127.0.0.1",
		port     = 3306,
	},
	session = {
		schemaName = "sora",
		tableName  = "userSession",
		columnName = "sessionId",
		cookieName = "usid",
	},
	modify = {
		jwtSecret  = "xxxxxx",
	},
	log = {
		dir  = "/var/log/session4static",
		error = "error.log",
	},
}

local baseDir = "/var/www/session4static/lib"
traceback = true

package.path =	baseDir .. "/?.lua;" .. package.path

function getTime() return os.time() end
function datetime() return os.date("%Y-%m-%d %H:%M:%S", getTime()) end
function dump(obj)
	local cjson = require "cjson"
	return cjson.encode(obj)
end

function split(str, rep, num)
	local rex = require("rex_pcre")
	local itr = rex.split(str, rep, num)
	local num = 0
	local result = {}
	for val in itr do
		table.insert(result, val)
	end
	return result
end

function appendLog(fname,row)
	local fp = assert(io.open (fname, "a"))
	fp:write(row .. "\n")
	fp:close()
end

function writeErrorLog(str)
	if type(str) == "table" then str = dump(str) end
	local path = config.log.dir .."/" .. config.log.error
	local str  = "[" .. datetime() .. "] " .. str
	appendLog(path, str)
end

function connect()
	local RestyMysql = require "resty.mysql"
	local db, err = RestyMysql:new()
	db:set_timeout(1000)
	db:set_keepalive(10000,1000)
	local ok,err,errcode,sqlstate = db:connect({
		host     = config.mysql.address,
		port     = config.mysql.port,
		user     = config.mysql.username,
		password = config.mysql.password,
		database = config.session.schemaName,
		max_packet_size = 1024 * 1024
	})
	if not ok then return end
	db:query("SET NAMES UTF8")
	return db
end

function escapeSq(str)
	return string.gsub(str, "'", "\\'")
end

function getSessionRecord(sessionId)
	local dbh = connect()
	if not dbh then writeErrorLog("cannot connect") return end
	local sql = "SELECT * FROM " .. config.session.tableName ..
				" WHERE " .. config.session.columnName .. " = '" ..
				escapeSq(sessionId)  .. "'"
	local res,err,errcode,sqlstate = dbh:query(sql)
	if err then errorLog(err) end
	if res and #res > 0 then return result end
end

function getSessionCookie()
	local cookieAll = ngx.req.get_headers()["Cookie"]
	if not cookieAll then return end
	local cookies = split(cookieAll, "\\s*;\\s*")
	for i,cookie in ipairs(cookies) do
		local parts = split(cookie, "\\s*=\\s*", 2)
		if parts[1] == config.session.cookieName then
			return ngx.unescape_uri(parts[2])
		end
	end
end

function getSessionJwt(token)
	local secret = config.modify.jwtSecret
	if not secret then return end
	local jwt = require "resty.jwt"
	local obj = jwt:verify(
		secret,
		token
	)
	if obj.verified then
		return obj.payload
	end
end

function main()
	local sessionId = getSessionCookie()
	if not sessionId then ngx.exit(ngx.HTTP_FORBIDDEN) end
	if config.modify.jwtSecret then
		if getSessionJwt(sessionId) then return end
	else
		if getSessionRecord(sessionId) then return end
	end
	ngx.exit(ngx.HTTP_FORBIDDEN)
end

main()


