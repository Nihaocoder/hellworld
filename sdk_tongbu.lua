-- service inside paras
local SDK_TONGBU_CONSTS = 
{
	app_id 			= 131004,
	app_key 		= "d2q*MkZn#UJWuDQFd2*4Mkxm@IgVu8QF",
	url_info 		= "http://tgi.tongbu.com/checkv2.aspx",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_TONGBU,
}

SDK_TONGBU_CONSTS.is_debug = TONGBU_SERVICE_IS_DEBUG

SDK_TONGBU_CONSTS.rds_conn_name		= "TONGBUdb/"
SDK_TONGBU_CONSTS.rdst_mid			= "TONGBUdb/mid/"
SDK_TONGBU_CONSTS.rdst_order_flag	= "TONGBUdb/order/orderflag"


local TONGBU_PAY_RESULT = {
	success = gJson:encode({status = "success"}),
	failed = gJson:encode({status = "failed"}),
}

-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_TONGBU_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfTONGBU_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_TONGBU_CONSTS.rdst_mid ..mid
end

local function lfTONGBU_dbSaveAuthInfo(mid,jsonStr)
	local key = lfTONGBU_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- TONGBU session datas
local TONGBU_AUTH_TOKEN_SESSION = {}

local TONGBU_ACTIVE_AUTH 		= 1
local TONGBU_ACTIVE_PAY 		= 1 + TONGBU_ACTIVE_AUTH
local TONGBU_ACTIVE_DRAWBACK 	= 1 + TONGBU_ACTIVE_PAY

local TONGBU_SESSIONS = {
	[TONGBU_ACTIVE_AUTH] 		= {},
	[TONGBU_ACTIVE_PAY]			= {},
	[TONGBU_ACTIVE_DRAWBACK]	= {},
}



local function lfTONGBUSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk TONGBU lfTONGBUSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = TONGBU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk TONGBU lfTONGBUSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfTONGBUSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk TONGBU lfTONGBUSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = TONGBU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk TONGBU lfTONGBUSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfTONGBUSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk TONGBU lfTONGBUSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = TONGBU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk TONGBU lfTONGBUSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- 同步推sessionId验证 start
--------------------------------------------------------------------
-- client send the TONGBU login auth
local function lfTONGBU_authOnRequestFinished(req,resp)
	gLog.debug("i am lfTONGBU_loginOnRequestFinished")
	-- local TONGBU_userID = req.TONGBU_userID
	-- local session = nil

	-- if TONGBU_userID then 
	-- 	session = lfUidGet(TONGBU_userID)
	-- end	
	-- --gLog.debug("i am lfTONGBU_loginOnRequestFinished 222",TONGBU_userID,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am TONGBU login response page")
	-- end	

end


local function lfTONGBU_authOnTONGBUServerResponse(resp)
	gLog.debug("i am lfTONGBU_authOnTONGBUServerResponse 111")
	local TONGBU_userID = resp.TONGBU_userID
	gLog.debug("i am lfTONGBU_authOnTONGBUServerResponse 222 ",TONGBU_userID)
end	

local function lfTONGBU_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfTONGBU_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfTONGBU_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfTONGBU_authSendResult 333")
    return json
end

local function lfTONGBU_authOnTONGBUServerData(req,resp,data)
	gLog.debug("i am lfTONGBU_authOnTONGBUServerData",data)
	local session = lfTONGBUSessionGet(TONGBU_ACTIVE_AUTH,req.TONGBU_userID)


	if not session or not data then 
		gLog.debug("i am lfTONGBU_authOnTONGBUServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	-- local json = gJson:decode(data,nil)
	-- if not json then 
	-- 	gLog.debug("i am lfTONGBU_authOnTONGBUServerData err 01",json,data)
	-- 	return
	-- end	

	local tongbu_ret = tonumber(data)

	if not tongbu_ret then
		lfTONGBU_authSendResult(session,nil)
		return 
	end 

	local json = {
			error_code = tongbu_ret,
	}

	-- 向客户端发送结果
	json = lfTONGBU_authSendResult(session,json)
	gLog.debug("i am lfTONGBU_authOnTONGBUServerData fuck 01")
	local TONGBU_userID = session.req.TONGBU_userID
	gLog.debug("i am lfTONGBU_authOnTONGBUServerData fuck 02",type(TONGBU_userID))
	-- 将数据存入数据库中(留待login服务器查询)
	if json.error_code == tonumber(TONGBU_userID) then
		local jsonStr = gJson:encode(json)
		if jsonStr then
			lfTONGBU_dbSaveAuthInfo(TONGBU_userID,jsonStr)
		gLog.debug("i am lfTONGBU_authOnTONGBUServerData fuck 03")	
		end
	end	

	gLog.debug("i am lfTONGBU_authOnTONGBUServerData fuck 04")
end	

local function lfTONGBU_authOnTONGBUServerFinished(req,resp)
	gLog.debug("i am lfTONGBU_authOnTONGBUServerFinished")

	-- 清理session
	lfTONGBUSessionDel(TONGBU_ACTIVE_AUTH,req.TONGBU_userID)
end	

-- 发起向同步推客户端的验证请求
local function lfTONGBU_authSendRequestToTONGBUServer(session)
	gLog.debug("i am lfTONGBU_authSendRequestToTONGBUServer")
	local TONGBU_userID = session.req.TONGBU_userID
	local sessionId = session.req.sessionId
	--local sig = gUtil.md5lower(sessionId .. "|" .. SDK_TONGBU_CONSTS.app_key)
	local url = string.format("%s?k=%s",SDK_TONGBU_CONSTS.url_info,sessionId)

	gLog.debug("TONGBU server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		TONGBU_userID	= TONGBU_userID,
		on_error 		= nil,
		on_response 	= lfTONGBU_authOnTONGBUServerResponse,
		on_data 		= lfTONGBU_authOnTONGBUServerData,
		on_finished 	= lfTONGBU_authOnTONGBUServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给同步推服务器
local function lfTONGBU_authOnRequest(session)
	gLog.debug("i am lfTONGBU_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp
	local jsonStr = req.headers["json"] 

	local TONGBU_userID,sessionId

	if not jsonStr then
		lfTONGBU_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	local json = gJson:decode(jsonStr)

	TONGBU_userID 	= json.userID
	sessionId 		= json.sessionId

	-- __T
	if not TONGBU_userID then
		TONGBU_userID = "TONGBU_userID"
		sessionId = "sessionId"
	end

	if not TONGBU_userID or not sessionId then
		lfTONGBU_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	gLog.debug("lfTONGBU_authOnRequest 001 ",TONGBU_userID,sessionId)
	local sessionOrg = lfTONGBUSessionAdd(TONGBU_ACTIVE_AUTH,TONGBU_userID,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("TONGBU service sessionOrg err0",TONGBU_userID)
	end	

	req.TONGBU_userID = TONGBU_userID
	req.sessionId = sessionId
	req.on_finished = lfTONGBU_authOnRequestFinished
	gLog.debug("i am lfTONGBU_authOnRequest request, fuck me2")

	-- 此处发起向同步推客户端的验证请求
	lfTONGBU_authSendRequestToTONGBUServer(session)

	resp.TONGBU_userID = TONGBU_userID
	resp.sessionId = sessionId
	--resp.on_response_sent = lfTONGBU_loginOnResponseSend
	gLog.debug("i am lfTONGBU_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- 同步推sessionId验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- 同步推计费结果 start
--------------------------------------------------------------------
-- 同步推计费结果合法性验证
local TONGBU_paynotify_paras = 
{
	["source"] 			= {true,	false,	true},-- need sign,need urldecode,must have
	["trade_no"] 		= {true,	false,	true},
	["amount"] 			= {true,	false,	true},
	["partner"] 		= {true,	false,	true},
	["paydes"] 			= {true,	true,	true},
	["debug"] 			= {true,	false,	true},
	["sign"] 			= {true,	false,	true},
}



-- XIAOMI 计费结果合法性验证
local function lfTONGBU_payCheckParams(p)
	if not p then
		return false
	end
	gLog.debug("lfTONGBU_payCheckParams ___(O_O)_____ 111")

	for k,v in pairs(TONGBU_paynotify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfTONGBU_payCheckParams ___(O_O)_____ xxx",k)
			return false
		end

		if v[2] then
			p[k] = gUtil.urldecode(p[k])
		end
	end

	gLog.debug("lfTONGBU_payCheckParams ___(O_O)_____ 222")

	local strBeforeSign = string.format(
		"source=%s&trade_no=%s&amount=%s&partner=%d&paydes=%s&debug=%s&key=%s",
		p.source, p.trade_no, p.amount, SDK_TONGBU_CONSTS.app_id, p.paydes, p.debug, SDK_TONGBU_CONSTS.app_key)

	gLog.debug("lfTONGBU_payCheckParams ___(O_O)_____ 333",strBeforeSign)

	local sign = gUtil.md5lower(strBeforeSign)
	gLog.debug("lfTONGBU_payCheckParams ___(O_O)_____ 444",sign,p.sign)
	if sign == p.sign then
		return true
	end

	gLog.debug("lfTONGBU_payCheckParams ___(O_O)_____FAILED", p.trade_no,p.paydes)
	return false
end

-- 来自同步推服务器的计费结果
local function lfTONGBU_payTONGBUServerNotifyRequest(session)
	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 000")
	local p = gUtil.parseUrlParams(req.paramStr)
	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 111")

	if not lfTONGBU_payCheckParams(p) then
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 222")
	local order 	= p.trade_no
	local status 	= 1 -- tonumber(p.result)
	local rmb 		= tonumber(p.amount) / 100
	local c_acc 	= ""
	local c_accid 	= 0 -- tonumber(p.mid)
	local desc 		= p.paydes
	local ext 		= p.paydes

	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 333")
	local sql_success = -1
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_TONGBU_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_TONGBU_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_TONGBU_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_TONGBU_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 666")

	end



	gLog.debug("i am lfTONGBU_payTONGBUServerNotifyRequest 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,TONGBU_PAY_RESULT.success)
	end

    gLog.debug("=====> success is working")

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- 同步推计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- 同步推退款申请 start
-------------------------------------------------------------------- 
local function lfTONGBU_drawbackOnResponse(resp)
	-- body
end

local function lfTONGBU_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfTONGBU_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_TONGBU_CONSTS.app_id,order.mid,order.order,SDK_TONGBU_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_TONGBU_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfTONGBU_drawbackOnResponse,
		on_data 		= lfTONGBU_drawbackOnData,
		-- on_finished 	= lfTONGBU_authOnTONGBUServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- 同步推退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_TONGBU_ACTION_FUNCS = {

	request = {
		["/sdk/tongbu/auth"] 		= lfTONGBU_authOnRequest,
		["/sdk/tongbu/paynotify"] 	= lfTONGBU_payTONGBUServerNotifyRequest,
	},

	response = {
		-- ["sdk/tongbu/login"] 	= gfOnRsp_TONGBULogin,
		-- ["sdk/tongbu/exit"] 	= gfOnRsp_TONGBUExit,
		-- ["sdk/tongbu/pay"] 	= gfOnRsp_TONGBUPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/tongbu",
	funcs = SDK_TONGBU_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData