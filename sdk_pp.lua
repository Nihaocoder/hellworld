
require 'util.cInputStream'
require 'util.cOutputStream'
local openssl = require('openssl')
local lfSPack = string.pack
local lfSunPack = string.unpack


local pp_pub_key = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjg5Lou5UTuiCd9hZ2h5
OJLYYsXP3RHHtQS8YcQKnzasUdO5l9Bq9Ow6w9qaOl/z5/cxXF408dbb+BcbDud2
q2WIx/HcLz1z4Ym++A7wguvcqM8zNEA5Pb1bF1mKHIb7Khr7Zg0j+qC9uIkXMpUG
U/gouVh1l/6q9vdPwuYTO1O4nAN4G46/KPmoY+FPppeszQEf4Dmj0WXGFL91mrLi
5lo7OIlGFTByrSK0Gj98idxHreOkJCtq5bXmHb7NaFhJ3poC3RsMjAGcEdeuucAI
RC7m/37NBYMab9QVvLwiUz5p5/VB7q9I6c1pnlQ4heLmo66zGfiqup1hZIz23N/T
6QIDAQAB
-----END PUBLIC KEY-----
]]

local pubkeyObj	= openssl.pkey_read(pp_pub_key,true)



-- service inside paras
local SDK_PP_CONSTS = 
{
	app_id 			= 681 ,
	app_key 		= "1e1fdc367ef61e3ad63eab4bdeba33dd",
	url_info 		= "http://passport_i.25pp.com:8080/i",
	--------------------------------------------------------------
	cid				= 10400,
}

SDK_PP_CONSTS.rds_conn_name		= "PPdb/"
SDK_PP_CONSTS.rdst_mid			= "PPdb/uid/"
SDK_PP_CONSTS.rdst_order_flag	= "PPdb/order/orderflag"

PP_ACT = {
	
	auth = 0xAA000022,

}


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_PP_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfPP_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_PP_CONSTS.rdst_mid ..mid
end

local function lfPP_dbSaveAuthInfo(mid,jsonStr)
	local key = lfPP_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- PP session datas
local PP_AUTH_TOKEN_SESSION = {}

local PP_ACTIVE_AUTH 		= 1
local PP_ACTIVE_PAY 		= 1 + PP_ACTIVE_AUTH
local PP_ACTIVE_DRAWBACK 	= 1 + PP_ACTIVE_PAY

local PP_SESSIONS = {
	[PP_ACTIVE_AUTH] 		= {},
	[PP_ACTIVE_PAY]			= {},
	[PP_ACTIVE_DRAWBACK]	= {},
}



local function lfPPSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk PP lfPPSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = PP_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk PP lfPPSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfPPSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk PP lfPPSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = PP_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk PP lfPPSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfPPSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk PP lfPPSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = PP_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk PP lfPPSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- PPtoken验证 start
--------------------------------------------------------------------
-- client send the PP login auth
local function lfPP_authOnRequestFinished(req,resp)
	gLog.debug("i am lfPP_loginOnRequestFinished")
	-- local PPUin = req.PPUin
	-- local session = nil

	-- if PPUin then 
	-- 	session = lfUidGet(PPUin)
	-- end	
	-- --gLog.debug("i am lfPP_loginOnRequestFinished 222",PPUin,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am PP login response page")
	-- end	

end


local function lfPP_authOnPPServerResponse(resp)
	gLog.debug("i am lfPP_authOnPPServerResponse 111")
	local PPUin = resp.PPUin
	gLog.debug("i am lfPP_authOnPPServerResponse 222 ",PPUin)
end	

local function lfPP_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfPP_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfPP_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfPP_authSendResult 333")
    return json
end


local function lfPP_createAuthResponsResult( data )
	local dis = cInputStream:new(data)
	local result = {}

	gLog.debug("i am lfPP_createAuthResponsResult 000", dis)

	result.len 		= dis:getIntUnsign()
	result.commmand = dis:getIntUnsign()
	result.status 	= dis:getIntUnsign()

	gLog.debug("i am lfPP_createAuthResponsResult 111", result.len, result.commmand, result.status)

	if not result.status then
		return nil
	elseif result.status ~= 0 then
		return result
	end

	gLog.debug("i am lfPP_createAuthResponsResult 222")

	result.username = dis:getStr_U()
	result.uid 		= dis:getLongUnsign()
	return result
end

local function lfPP_authOnPPServerData(req,resp,data)
	gLog.debug("i am lfPP_authOnPPServerData",data)
	local session = lfPPSessionGet(PP_ACTIVE_AUTH,req.PPUin)
	if not session or not data then 
		gLog.debug("i am lfPP_authOnPPServerData err 00",session,data)
		return
	end

	-- parse data
	local ret = lfPP_createAuthResponsResult(data)

	-- 向客户端发送结果
	ret = lfPP_authSendResult(session,ret)
	local jsonStr = gJson:encode(ret)

	gLog.debug("i am lfPP_authOnPPServerData fuck 01")
	local PPUin = session.req.PPUin
	gLog.debug("i am lfPP_authOnPPServerData fuck 02")
	-- 将数据存入数据库中(留待login服务器查询)
	if ret.status == 0 and PPUin then
		lfPP_dbSaveAuthInfo(PPUin,jsonStr)
	end	

	gLog.debug("i am lfPP_authOnPPServerData fuck 03")	

	gLog.debug("i am lfPP_authOnPPServerData fuck 04")
end	

local function lfPP_authOnPPServerFinished(req,resp)
	gLog.debug("i am lfPP_authOnPPServerFinished")
	-- 清理session
	lfPPSessionDel(PP_ACTIVE_AUTH,req.PPUin)
end	

local function lfPP_packAuthData(command,token)
	gLog.debug("i am lfPP_packAuthData 000")
	local dos = cOutputStream:new()
	gLog.debug("i am lfPP_packAuthData 111")

	if not command or not token then
		return dos:data('I')
	end

	dos:setIntUnsign(command)
	dos:setStr_A(token,16)
	return dos:data('I')
end
-- 发起向PP客户端的验证请求
local function lfPP_authSendRequestToPPServer(session)
	gLog.debug("i am lfPP_authSendRequestToPPServer")
	local act 			= PP_ACT.auth
	local app_id 		= SDK_PP_CONSTS.app_id
	local app_key 		= SDK_PP_CONSTS.app_key
	local PPUin 		= session.req.PPUin
	local token 		= session.req.token
	-- local sig 			= gUtil.md5lower(""..app_id .. act .. PPUin ..token ..app_key)
	local url 			= SDK_PP_CONSTS.url_info
	
	--url	= string.format("%s?AppId=%d&Act=%d&Uin=%s&Sign=%s&SessionID=%s",url,app_id,act,PPUin,sig,token)
	gLog.debug("PP server request url,data eee",url,bin_data,act)

	local bin_data = lfPP_packAuthData(act,token)
	gLog.debug("===>>",gfHex(bin_data))
	gLog.debug("PP server request url,data xxx",url,bin_data)
	local httpClientRequst = {
		headers = {
			["Content-Type"] = "application/octet-stream",
			["Content-Length"] = #bin_data,
			["Cache-control"] = "no-cache"
		},
		url 			= url,
		method			= "POST",
		PPUin			= PPUin,
		token 			= token,
		body 			= bin_data,
		on_response 	= lfPP_authOnPPServerResponse,
		on_data 		= lfPP_authOnPPServerData,
		on_finished 	= lfPP_authOnPPServerFinished,
	}

	local httpClient 	= gfGetHttpClient()
	session.httpClient = httpClient

	gLog.debug("PP server request fuck",url,bin_data)
	local outReq,err = httpClient:request(httpClientRequst)
	-- gLog.print_r(outReq)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给PP服务器
local function lfPP_authOnRequest(session)
	gLog.debug("i am lfPP_authOnRequest")
	local req = session.req
	local resp = session.resp
	local PPUin = req.headers["uin"] -- PP member id
	local token = req.headers["sessionId"]

	-- __T fake uin and sessionid
	if not PPUin or not token then
		PPUin = "i_am_uin"
		token = "i_am_pptoken"
	end

	token = gBase64.decode( token )

	--token = string.unpack(token,"A16")
	gLog.debug("lfPP_authOnRequest 000 ",PPUin,token,gfHex(token))

	if not PPUin or not token then
		lfPP_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	gLog.debug("lfPP_authOnRequest 001 ",PPUin,token)
	local sessionOrg = lfPPSessionAdd(PP_ACTIVE_AUTH,PPUin,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("PP service sessionOrg err0",PPUin)
	end	

	req.PPUin = PPUin
	req.token = token
	req.on_finished = lfPP_authOnRequestFinished
	gLog.debug("i am lfPP_authOnRequest request, fuck me2")

	-- 此处发起向PP客户端的验证请求
	lfPP_authSendRequestToPPServer(session)

	resp.PPUin = PPUin
	resp.token = token
	--resp.on_response_sent = lfPP_loginOnResponseSend
	gLog.debug("i am lfPP_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- PPtoken验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- PP计费结果 start
--------------------------------------------------------------------
local pp_pay_notify_param_names = 
{
	{"order_id",	false,false}, -- name,isnum,need urldecode
	{"billno",		false,false},
	{"account",		false,true},
	{"amount",		false,false},
	{"status",		true,false},
	{"app_id",		false,false},
	{"uuid",		false,false},
	{"roleid",		false,true},
	{"zone",		false,false},
	-- {"sign",		false},
}
-- PP计费结果合法性验证
function lfPP_payCheckParams(p)
	if not p then
		return false
	end

	gLog.debug("lfPP_payCheckParams 000",p.sign,"\n")
	-- 验证参数
	local pname
	for k,v in pairs(pp_pay_notify_param_names) do
		pname = v[1]
		if not p[pname] then
			gLog.debug("lfPP_payCheckParams 000 err",pname)
			return false
		end

		if v[3] then -- need urlDecode
			p[pname] = gUtil.urldecode_pp(p[pname])
		end

		if v[2] then
			p[pname] = tonumber(p[pname])
		end


	end
	-- gLog.debug("lfPP_payCheckParams 111",p.sign)
	local sign = gUtil.urldecode_pp(p.sign)
	gLog.debug("lfPP_payCheckParams 111",p.sign,"\n")
	sign = gBase64.decode(sign)
	gLog.debug("lfPP_payCheckParams 222",sign,"\n")

	if not sign then
		return false
	end

	gLog.debug("lfPP_payCheckParams 222-222",sign)

  	local jsonstr = pubkeyObj:decrypt(sign)
	gLog.debug("lfPP_payCheckParams 333",jsonstr)

	if not jsonstr then
		return false
	end 

	local json = gJson:decode(jsonstr)
	gLog.debug("lfPP_payCheckParams 444")

	if not json then
		return false
	end

	for k,v in pairs(pp_pay_notify_param_names) do
		if p[v[1]] ~= json[v[1]] then
			gLog.debug("lfPP_payCheckParams 777 failed",v[1],p[v[1]] ,json[v[1]])
			return false
		end
	end
	gLog.debug("lfPP_payCheckParams 999 ok")
	return true
end

local function lfPP_payPPServerNotifyOnData(req,resp,data)
	print("i am lfPP_payPPServerNotifyOnData 000",data)
	local paramStr = data --gUtil.urldecode(data)
	print("i am lfPP_payPPServerNotifyOnData 000-1",paramStr)
	local p = gUtil.parseUrlParams(paramStr)
	print("i am lfPP_payPPServerNotifyOnData 111")

	if not lfPP_payCheckParams(p) then
		return -- 参数检查未通过，直接抛弃
	end	

	print("i am lfPP_payPPServerNotifyOnData 222")

	local order 	= "" .. p.order_id
	local status 	= tonumber(p.status)
	local rmb 		= tonumber(p.amount)
	local c_acc 	= p.account
	local c_accid 	= tonumber(p.uuid)
	local desc 		= p.roleid
	local ext 		= p.roleid
	gLog.debug("i am lfPP_payPPServerNotifyOnData 333",status,rmb)

	local sql_success = -1
	-- TODO:根据结果进行数据处理
	if status == 0 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_PP_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_PP_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfPP_payPPServerNotifyOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_PP_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfPP_payPPServerNotifyOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_PP_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfPP_payPPServerNotifyOnData 666")

	end

	gLog.debug("i am lfPP_payPPServerNotifyOnData 777",sql_success)
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,'success')
    	gLog.debug("=====> success is working")
	else
		gUtil.sendString(resp,200,'fail')
    	gLog.debug("=====> fail is working")
	end

end

-- 来自PP服务器的计费结果
local function lfPP_payPPServerNotifyRequest(session)
	print("i am lfPP_payPPServerNotifyRequest")
	-- gLog.print_r(session)
	local req = session.req
	local resp = session.resp

	req.on_data = lfPP_payPPServerNotifyOnData

	-- print("i am lfPP_payPPServerNotifyRequest 000",req.paramStr)
	-- local paramStr = gUtil.urldecode(req.paramStr)
	-- print("i am lfPP_payPPServerNotifyRequest 000-1",paramStr)
	-- local p = gUtil.parseUrlParams(paramStr)
	-- print("i am lfPP_payPPServerNotifyRequest 111")

	-- if not lfPP_payCheckParams(p) then
	-- 	return -- 参数检查未通过，直接抛弃
	-- end	

	-- print("i am lfPP_payPPServerNotifyRequest 222")

	-- local order 	= "" .. p.order_id
	-- local status 	= tonumber(p.status)
	-- local rmb 		= tonumber(p.amount)
	-- local c_acc 	= p.account
	-- local c_accid 	= tonumber(p.uuid)
	-- local desc 		= p.roleid
	-- local ext 		= p.roleid
	-- gLog.debug("i am lfPP_payPPServerNotifyRequest 333",status,rmb)

	-- local sql_success = -1
	-- -- TODO:根据结果进行数据处理
	-- if status == 0 then
	-- 	-- TODO: save order to mysql db
	-- 	--gfPayInfoInsert(gPayMysqlHandler,SDK_PP_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
	-- 	sql_success = gPay.order_todb(gPayMysqlHandler,SDK_PP_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
	-- 	gLog.debug("i am lfPP_payPPServerNotifyRequest 444")

	-- 	-- 设置redis数据中的标记，通知login服务器过来读取订单数据
	-- 	redisHand:set(SDK_PP_CONSTS.rdst_order_flag,1) 
	-- 	gLog.debug("i am lfPP_payPPServerNotifyRequest 555")
 
	-- else
	-- 	-- TODO: save order to db?
	-- 	sql_success = gPay.order_todb(gPayMysqlHandler,SDK_PP_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

	-- 	gLog.debug("i am lfPP_payPPServerNotifyRequest 666")

	-- end

	-- gLog.debug("i am lfPP_payPPServerNotifyRequest 777",sql_success)
	-- if sql_success == 1 or sql_success == 0 then
	-- 	gUtil.sendString(resp,200,'success')
 --    	gLog.debug("=====> success is working")
	-- else
	-- 	gUtil.sendString(resp,200,'fail')
 --    	gLog.debug("=====> fail is working")
	-- end

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- PP计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- PP退款申请 start
-------------------------------------------------------------------- 
local function lfPP_drawbackOnResponse(resp)
	-- body
end

local function lfPP_drawbackOnData(req,resp,data)
	local json = gJson.decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfPP_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_PP_CONSTS.app_id,order.mid,order.order,SDK_PP_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_PP_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfPP_drawbackOnResponse,
		on_data 		= lfPP_drawbackOnData,
		-- on_finished 	= lfPP_authOnPPServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- PP退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_PP_ACTION_FUNCS = {

	request = {
		["/sdk/pp/auth"] 		= lfPP_authOnRequest,
		["/sdk/pp/paynotifyios"] 	= lfPP_payPPServerNotifyRequest,
	},

	response = {
	},

}

-- name,func table
local serviceData = {
	name = "sdk/pp",
	funcs = SDK_PP_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData