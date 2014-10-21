-- service inside paras
local SDK_DUOKU_CONSTS = 
{
	app_id 			= 1293,
	app_key 		= "d37a5b5989461311fe429a7e3fe05010",
	app_secret 		= "1e918f8667bb68d65370fd16649a1bb1",
	url_info 		= "http://sdk.m.duoku.com/openapi/sdk",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_DUOKU,
}

local DUOKU_PAY_RESULT = {
	success = "SUCCESS",
	failed = "ERROR_SIGN",
}

SDK_DUOKU_CONSTS.rds_conn_name		= "DUOKUdb/"
SDK_DUOKU_CONSTS.rdst_mid			= "DUOKUdb/uid/"
SDK_DUOKU_CONSTS.rdst_order_flag	= "DUOKUdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_DUOKU_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfDUOKU_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_DUOKU_CONSTS.rdst_mid ..mid
end

local function lfDUOKU_dbSaveAuthInfo(mid,jsonStr)
	local key = lfDUOKU_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- DUOKU session datas
local DUOKU_AUTH_TOKEN_SESSION = {}

local DUOKU_ACTIVE_AUTH 		= 1
local DUOKU_ACTIVE_PAY 			= 1 + DUOKU_ACTIVE_AUTH
local DUOKU_ACTIVE_DRAWBACK 	= 1 + DUOKU_ACTIVE_PAY

local DUOKU_SESSIONS = {
	[DUOKU_ACTIVE_AUTH] 		= {},
	[DUOKU_ACTIVE_PAY]			= {},
	[DUOKU_ACTIVE_DRAWBACK]	= {},
}



local function lfDUOKUSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk DUOKU lfDUOKUSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = DUOKU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk DUOKU lfDUOKUSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfDUOKUSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk DUOKU lfDUOKUSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = DUOKU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk DUOKU lfDUOKUSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfDUOKUSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk DUOKU lfDUOKUSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = DUOKU_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk DUOKU lfDUOKUSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


local function lfDUOKU_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfDUOKU_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfDUOKU_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfDUOKU_authSendResult 333")
    return json
end

--------------------------------------------------------------------
-- DUOKU DUOKUjsonStr验证 start
--------------------------------------------------------------------
-- client send the DUOKU login auth
local function lfDUOKU_authOnRequestFinished(req,resp)
	gLog.debug("i am lfDUOKU_loginOnRequestFinished")
	-- local duoku_uid = req.duoku_uid
	-- local session = nil

	-- if duoku_uid then 
	-- 	session = lfUidGet(duoku_uid)
	-- end	
	-- --gLog.debug("i am lfDUOKU_loginOnRequestFinished 222",duoku_uid,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am DUOKU login response page")
	-- end	

end


local function lfDUOKU_authOnDUOKUServerResponse(resp)
	gLog.debug("i am lfDUOKU_authOnDUOKUServerResponse 111")
	local duoku_uid = resp.duoku_uid
	gLog.debug("i am lfDUOKU_authOnDUOKUServerResponse 222 ",duoku_uid)
end	

local function lfDUOKU_authOnDUOKUServerData(req,resp,data)
	gLog.debug("i am lfDUOKU_authOnDUOKUServerData",data)
	local session = lfDUOKUSessionGet(DUOKU_ACTIVE_AUTH,req.duoku_uid)
	if not session or not data then 
		gLog.debug("i am lfDUOKU_authOnDUOKUServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfDUOKU_authOnDUOKUServerData err 01",json,data)
		return
	end	

	session.authdata = json
	gLog.debug("i am lfDUOKU_authOnDUOKUServerData fuck 02")	

end	

local function lfDUOKU_authOnDUOKUServerFinished(req,resp)
	gLog.debug("i am lfDUOKU_authOnDUOKUServerFinished")
	local duoku_uid = req.duoku_uid

	-- do accInfo request
	local session = lfDUOKUSessionGet(DUOKU_ACTIVE_AUTH,duoku_uid) 
	if not session then
		return
	end

	local authdata = session.authdata


	if not authdata or not authdata.error_code then
		lfDUOKU_authSendResult(session,nil)
	else
		-- 获取到的是正确的结果，直接返回给客户端
		lfDUOKU_authSendResult(session,authdata)
		if authdata.error_code == "0" then
			local jsonStr = gJson:encode(authdata)
			if jsonStr then
				lfDUOKU_dbSaveAuthInfo(duoku_uid,jsonStr)
			end
		end
	end
	lfDUOKUSessionDel(DUOKU_ACTIVE_AUTH,duoku_uid) 
end	

-- 发起向DUOKU 客户端的验证请求
local function lfDUOKU_authSendRequestToDUOKUServer(session)
	gLog.debug("i am lfDUOKU_authSendRequestToDUOKUServer")
	local duoku_uid = session.req.duoku_uid
	local duoku_sid = session.req.duoku_sid

	-- make md5 sign
	local str_before_sign = string.format("%d%s%s%s%s",SDK_DUOKU_CONSTS.app_id,SDK_DUOKU_CONSTS.app_key,duoku_uid,duoku_sid,SDK_DUOKU_CONSTS.app_secret)
	local sign = gUtil.md5lower(str_before_sign)

	gLog.debug("i am lfDUOKU_authSendRequestToDUOKUServer",sign,str_before_sign)


	local url_para = string.format("appid=%d&appkey=%s&uid=%s&sessionid=%s&clientsecret=%s",SDK_DUOKU_CONSTS.app_id,SDK_DUOKU_CONSTS.app_key,duoku_uid,duoku_sid,sign)
	local url = string.format("%s/checksession?%s",SDK_DUOKU_CONSTS.url_info,url_para)

	gLog.debug("DUOKU server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		duoku_uid		= duoku_uid,
		authdata 		= nil,
		on_error 		= nil,
		on_response 	= lfDUOKU_authOnDUOKUServerResponse,
		on_data 		= lfDUOKU_authOnDUOKUServerData,
		on_finished 	= lfDUOKU_authOnDUOKUServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		gLog.debug("lfDUOKU_authSendRequestToDUOKUServer err",err)
	end	

end

-- 接收客户端发过来的验证信息，并转发给DUOKU 服务器
local function lfDUOKU_authOnRequest(session)
	gLog.debug("i am lfDUOKU_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp
	local duoku_uid = req.headers["uid"] -- DUOKU  uid
	local duoku_sid = req.headers["sessionid"]

	if not duoku_uid then
		duoku_uid = "duoku_uid"
		duoku_sid = "duoku_sid"
	end


	gLog.debug("lfDUOKU_authOnRequest 001 ",duoku_uid,duoku_sid)

	-- auth data is invalid
	if not duoku_uid or not duoku_sid then
		lfDUOKU_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end
	gLog.debug("lfDUOKU_authOnRequest 001 001")

	local sessionOrg = lfDUOKUSessionAdd(DUOKU_ACTIVE_AUTH,duoku_uid,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("DUOKU service sessionOrg err0",duoku_uid)
	end	

	req.duoku_uid = duoku_uid
	req.duoku_sid = duoku_sid
	req.on_finished = lfDUOKU_authOnRequestFinished
	gLog.debug("i am lfDUOKU_authOnRequest request, fuck me2")

	-- 此处发起向DUOKUjsonStr客户端的验证请求
	lfDUOKU_authSendRequestToDUOKUServer(session)

	resp.duoku_uid = duoku_uid
	resp.duoku_sid = duoku_sid
	--resp.on_response_sent = lfDUOKU_loginOnResponseSend
	gLog.debug("i am lfDUOKU_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- DUOKU DUOKUjsonStr验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- DUOKU 计费结果 start
--------------------------------------------------------------------
local DUOKU_paynotify_paras = 
{
	["amount"] 			= {true,	false,	true},-- need sign,need urldecode,must have
	["cardtype"] 		= {true,	false,	true},
	["orderid"] 		= {true,	false,	true},
	["result"] 			= {true,	false,	true},
	["timetamp"] 		= {true,	false,	true},
	["aid"] 			= {true,	true,	true},
	["client_secret"] 	= {true,	false,	true},
}



-- DUOKU 计费结果合法性验证
local function lfDUOKU_payCheckParams(p)
	if not p then
		return false
	end
	gLog.debug("lfDUOKU_payCheckParams ___(O_O)_____ 111")

	for k,v in pairs(DUOKU_paynotify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfDUOKU_payCheckParams ___(O_O)_____ xxx",k)
			return false
		end

		-- if v[2] then
		-- 	p[k] = gUtil.urldecode(p[k])
		-- end
	end

	--local aid_encode = gUtil.url
	local strBeforeSign = string.format("%s%s%s%s%s%s%s",p.amount,p.cardtype,p.orderid,p.result,p.timetamp,SDK_DUOKU_CONSTS.app_secret,p.aid)
	gLog.debug("lfDUOKU_payCheckParams ___(O_O)_____ 333",strBeforeSign)
	local signature = gUtil.md5lower(strBeforeSign)
	gLog.debug("lfDUOKU_payCheckParams ___(O_O)_____ 444",signature,p.client_secret)


	-- url decode 
	for k,v in pairs(DUOKU_paynotify_paras) do
		if v[2] then
			p[k] = gUtil.urldecode(p[k])
		end
	end


	if signature == p.client_secret then
		return true
	end

	gLog.debug("lfDUOKU_payCheckParams ___(O_O)_____FAILED", p.aid)
	return false
end

-- 来自DUOKU 服务器的计费结果
local function lfDUOKU_payDUOKUServerNotifyRequest(session)
	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 000")
	local p = gUtil.parseUrlParams(req.paramStr)
	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 111")

	if not lfDUOKU_payCheckParams(p) then
		gUtil.sendString(resp,200,DUOKU_PAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 222")
	local order 	= p.orderid
	local status 	= p.result
	local rmb 		= tonumber(p.amount)
	local c_acc 	= ""
	local c_accid 	= tonumber(p.uid)
	local desc 		= p.aid or ""
	local ext 		= p.aid or ""

	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 333")
	local sql_success = -1
	if status == "1" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_DUOKU_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_DUOKU_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_DUOKU_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_DUOKU_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 666")

	end



	gLog.debug("i am lfDUOKU_payDUOKUServerNotifyRequest 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,DUOKU_PAY_RESULT.success)
	end

    gLog.debug("=====> success is working")

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- DUOKU 计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- DUOKU 退款申请 start
-------------------------------------------------------------------- 
local function lfDUOKU_drawbackOnResponse(resp)
	-- body
end

local function lfDUOKU_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfDUOKU_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_DUOKU_CONSTS.app_id,order.mid,order.order,SDK_DUOKU_CONSTS.app_secret)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_DUOKU_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfDUOKU_drawbackOnResponse,
		on_data 		= lfDUOKU_drawbackOnData,
		-- on_finished 	= lfDUOKU_authOnDUOKUServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- DUOKU 退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_DUOKU_ACTION_FUNCS = {

	request = {
		["/sdk/duoku/auth"] 			= lfDUOKU_authOnRequest,
		["/sdk/duoku/paynotify"] 	= lfDUOKU_payDUOKUServerNotifyRequest,
	},

	response = {
		-- ["sdk/DUOKU/login"] 	= gfOnRsp_DUOKULogin,
		-- ["sdk/DUOKU/exit"] 	= gfOnRsp_DUOKUExit,
		-- ["sdk/DUOKU/pay"] 	= gfOnRsp_DUOKUPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/duoku",
	funcs = SDK_DUOKU_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData