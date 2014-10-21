require "lang.sha1"
local xiaomi_sign = hmac_sha1

-- service inside paras
local SDK_XIAOMI_CONSTS = 
{
	app_id 			= 17153,
	app_key 		= "6d545de1-ceae-384f-eff2-51ecf4f07bc0",
	url_info 		= "http://mis.migc.xiaomi.com/api/biz/service",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_XIAOMI,
}


local XIAOMI_PAY_RESULT = {
	success = gJson:encode({errcode = 200}),
	failed = gJson:encode({errcode = 1525}),
}
 



SDK_XIAOMI_CONSTS.rds_conn_name		= "XIAOMIdb/"
SDK_XIAOMI_CONSTS.rdst_mid			= "XIAOMIdb/uid/"
SDK_XIAOMI_CONSTS.rdst_order_flag	= "XIAOMIdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_XIAOMI_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfXIAOMI_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_XIAOMI_CONSTS.rdst_mid ..mid
end

local function lfXIAOMI_dbSaveAuthInfo(mid,jsonStr)
	local key = lfXIAOMI_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- XIAOMI session datas
local XIAOMI_AUTH_TOKEN_SESSION = {}

local XIAOMI_ACTIVE_AUTH 		= 1
local XIAOMI_ACTIVE_PAY 			= 1 + XIAOMI_ACTIVE_AUTH
local XIAOMI_ACTIVE_DRAWBACK 	= 1 + XIAOMI_ACTIVE_PAY

local XIAOMI_SESSIONS = {
	[XIAOMI_ACTIVE_AUTH] 		= {},
	[XIAOMI_ACTIVE_PAY]			= {},
	[XIAOMI_ACTIVE_DRAWBACK]	= {},
}



local function lfXIAOMISessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk XIAOMI lfXIAOMISessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = XIAOMI_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XIAOMI lfXIAOMISessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfXIAOMISessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk XIAOMI lfXIAOMISessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = XIAOMI_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XIAOMI lfXIAOMISessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfXIAOMISessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk XIAOMI lfXIAOMISessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = XIAOMI_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XIAOMI lfXIAOMISessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


local function lfXIAOMI_authSendResult(session,json)
	if not json then 
		json = {
			errcode = 1000,
			errMsg = "未知错误"
		}
	end
	gLog.debug("i am lfXIAOMI_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfXIAOMI_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfXIAOMI_authSendResult 333")
    return json
end

--------------------------------------------------------------------
-- XIAOMI XIAOMIjsonStr验证 start
--------------------------------------------------------------------
-- client send the XIAOMI login auth
local function lfXIAOMI_authOnRequestFinished(req,resp)
	gLog.debug("i am lfXIAOMI_loginOnRequestFinished")
	-- local xiaomi_uid = req.xiaomi_uid
	-- local session = nil

	-- if xiaomi_uid then 
	-- 	session = lfUidGet(xiaomi_uid)
	-- end	
	-- --gLog.debug("i am lfXIAOMI_loginOnRequestFinished 222",xiaomi_uid,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am XIAOMI login response page")
	-- end	

end


local function lfXIAOMI_authOnXIAOMIServerResponse(resp)
	gLog.debug("i am lfXIAOMI_authOnXIAOMIServerResponse 111")
	local xiaomi_uid = resp.xiaomi_uid
	gLog.debug("i am lfXIAOMI_authOnXIAOMIServerResponse 222 ",xiaomi_uid)
end	

local function lfXIAOMI_authOnXIAOMIServerData(req,resp,data)
	gLog.debug("i am lfXIAOMI_authOnXIAOMIServerData",data)
	local session = lfXIAOMISessionGet(XIAOMI_ACTIVE_AUTH,req.xiaomi_uid)
	if not session or not data then 
		gLog.debug("i am lfXIAOMI_authOnXIAOMIServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfXIAOMI_authOnXIAOMIServerData err 01",json,data)
		return
	end	

	session.authdata = json
	gLog.debug("i am lfXIAOMI_authOnXIAOMIServerData fuck 02")	

end	

local function lfXIAOMI_authOnXIAOMIServerFinished(req,resp)
	gLog.debug("i am lfXIAOMI_authOnXIAOMIServerFinished")
	local xiaomi_uid = req.xiaomi_uid

	-- do accInfo request
	local session = lfXIAOMISessionGet(XIAOMI_ACTIVE_AUTH,xiaomi_uid) 
	if not session then
		return
	end

	local authdata = session.authdata


	if not authdata or not authdata.errcode then
		lfXIAOMI_authSendResult(session,nil)
	else
		-- 获取到的是正确的结果，直接返回给客户端
		lfXIAOMI_authSendResult(session,authdata)
		if authdata.errcode == 200 then
			local jsonStr = gJson:encode(authdata)
			if jsonStr then
				lfXIAOMI_dbSaveAuthInfo(xiaomi_uid,jsonStr)
			end
		end
	end
	lfXIAOMISessionDel(XIAOMI_ACTIVE_AUTH,xiaomi_uid) 

	
end	

-- 发起向XIAOMI 客户端的验证请求
local function lfXIAOMI_authSendRequestToXIAOMIServer(session)
	gLog.debug("i am lfXIAOMI_authSendRequestToXIAOMIServer")
	local xiaomi_uid = session.req.xiaomi_uid
	local xiaomi_sid = session.req.xiaomi_sid


	local url_para = string.format("appId=%d&session=%s&uid=%s",SDK_XIAOMI_CONSTS.app_id,xiaomi_sid,xiaomi_uid)
	local sign = xiaomi_sign(SDK_XIAOMI_CONSTS.app_key,url_para)

	url_para = string.format("%s&signature=%s",url_para,sign)

	local url = string.format("%s/verifySession.do?%s",SDK_XIAOMI_CONSTS.url_info,url_para)

	gLog.debug("XIAOMI server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		xiaomi_uid		= xiaomi_uid,
		authdata 		= nil,
		on_error 		= nil,
		on_response 	= lfXIAOMI_authOnXIAOMIServerResponse,
		on_data 		= lfXIAOMI_authOnXIAOMIServerData,
		on_finished 	= lfXIAOMI_authOnXIAOMIServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给XIAOMI 服务器
local function lfXIAOMI_authOnRequest(session)
	gLog.debug("i am lfXIAOMI_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp
	local xiaomi_uid = req.headers["uid"] -- XIAOMI  uid
	local xiaomi_sid = req.headers["sessionId"]

	if not xiaomi_uid then
		xiaomi_uid = "xiaomi_uid"
		xiaomi_sid = "xiaomi_sid"
	end


	gLog.debug("lfXIAOMI_authOnRequest 001 ",xiaomi_uid,xiaomi_sid)

	-- auth data is invalid
	if not xiaomi_uid or not xiaomi_sid then
		lfXIAOMI_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end
	gLog.debug("lfXIAOMI_authOnRequest 001 001")

	local sessionOrg = lfXIAOMISessionAdd(XIAOMI_ACTIVE_AUTH,xiaomi_uid,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("XIAOMI service sessionOrg err0",xiaomi_uid)
	end	

	req.xiaomi_uid = xiaomi_uid
	req.xiaomi_sid = xiaomi_sid
	req.on_finished = lfXIAOMI_authOnRequestFinished
	gLog.debug("i am lfXIAOMI_authOnRequest request, fuck me2")

	-- 此处发起向XIAOMIjsonStr客户端的验证请求
	lfXIAOMI_authSendRequestToXIAOMIServer(session)

	resp.xiaomi_uid = xiaomi_uid
	resp.xiaomi_sid = xiaomi_sid
	--resp.on_response_sent = lfXIAOMI_loginOnResponseSend
	gLog.debug("i am lfXIAOMI_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- XIAOMI XIAOMIjsonStr验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- XIAOMI 计费结果 start
--------------------------------------------------------------------
local XIAOMI_paynotify_paras = 
{
	["appId"] 			= {true,	false,	true},-- need sign,need urldecode,must have
	["cpOrderId"] 		= {true,	false,	true},
	["cpUserInfo"] 		= {true,	true,	true},
	["uid"] 			= {true,	false,	true},
	["orderId"] 		= {true,	false,	true},
	["orderStatus"] 	= {true,	false,	true},
	["payFee"] 			= {true,	false,	true},
	["productCode"] 	= {true,	false,	false},
	["productName"] 	= {true,	true,	false},
	["productCount"] 	= {true,	false,	false},
	["payTime"] 		= {true,	true,	true},
	["signature"] 		= {false,	false,	false},
}



-- XIAOMI 计费结果合法性验证
local function lfXIAOMI_payCheckParams(p)
	if not p then
		return false
	end
	gLog.debug("lfXIAOMI_payCheckParams ___(O_O)_____ 111")

	for k,v in pairs(XIAOMI_paynotify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfXIAOMI_payCheckParams ___(O_O)_____ xxx",k)
			return false
		end
	end


	-- key order
	local keys = {}
	local conf,need_sign,need_decode
	for k,v in pairs(p) do
		conf = XIAOMI_paynotify_paras[k]
		if conf then
			need_sign = conf[1]
			need_decode = conf[2]
		else
			need_sign = true
			need_decode = true
		end

		if need_sign then 
			table.insert(keys,k)
		end

		if need_decode then
			p[k] = gUtil.urldecode_xiaomi(v)
		end
	end

	gUtil.quick_sort(keys,1,#keys,gUtil.string_compare)
	gLog.debug("lfXIAOMI_payCheckParams ___(O_O)_____ 222")

	local strBeforeSign = ""
	local count = 0
	for k,v in pairs(keys) do

		if count > 0 then
			strBeforeSign = string.format("%s&%s=%s",strBeforeSign,v,p[v])
		else
			strBeforeSign = string.format("%s%s=%s",strBeforeSign,v,p[v])
		end
		count = count + 1
	end

	gLog.debug("lfXIAOMI_payCheckParams ___(O_O)_____ 333",strBeforeSign)

	local signature = xiaomi_sign(SDK_XIAOMI_CONSTS.app_key,strBeforeSign)
	gLog.debug("lfXIAOMI_payCheckParams ___(O_O)_____ 444",signature,p.signature)
	if signature == p.signature then
		return true
	end

	gLog.debug("lfXIAOMI_payCheckParams ___(O_O)_____FAILED", p.cpUserInfo)
	return false
end

-- 来自XIAOMI 服务器的计费结果
local function lfXIAOMI_payXIAOMIServerNotifyRequest(session)
	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 000")
	local p = gUtil.parseUrlParams(req.paramStr)
	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 111")

	if not lfXIAOMI_payCheckParams(p) then
		gUtil.sendString(resp,200,XIAOMI_PAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 222")
	local order 	= p.orderId
	local status 	= p.orderStatus
	local rmb 		= tonumber(p.payFee) / 100
	local c_acc 	= ""
	local c_accid 	= tonumber(p.uid)
	local desc 		= p.cpUserInfo
	local ext 		= p.cpUserInfo

	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 333")
	local sql_success = -1
	if status == "TRADE_SUCCESS" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_XIAOMI_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_XIAOMI_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_XIAOMI_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_XIAOMI_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 666")

	end



	gLog.debug("i am lfXIAOMI_payXIAOMIServerNotifyRequest 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,XIAOMI_PAY_RESULT.success)
	end

    gLog.debug("=====> success is working")

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- XIAOMI 计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- XIAOMI 退款申请 start
-------------------------------------------------------------------- 
local function lfXIAOMI_drawbackOnResponse(resp)
	-- body
end

local function lfXIAOMI_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfXIAOMI_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_XIAOMI_CONSTS.app_id,order.mid,order.order,SDK_XIAOMI_CONSTS.app_secret)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_XIAOMI_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfXIAOMI_drawbackOnResponse,
		on_data 		= lfXIAOMI_drawbackOnData,
		-- on_finished 	= lfXIAOMI_authOnXIAOMIServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- XIAOMI 退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_XIAOMI_ACTION_FUNCS = {

	request = {
		["/sdk/xiaomi/auth"] 			= lfXIAOMI_authOnRequest,
		["/sdk/xiaomi/paynotify"] 	= lfXIAOMI_payXIAOMIServerNotifyRequest,
	},

	response = {
		-- ["sdk/xiaomi/login"] 	= gfOnRsp_XIAOMILogin,
		-- ["sdk/xiaomi/exit"] 	= gfOnRsp_XIAOMIExit,
		-- ["sdk/xiaomi/pay"] 	= gfOnRsp_XIAOMIPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/xiaomi",
	funcs = SDK_XIAOMI_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData