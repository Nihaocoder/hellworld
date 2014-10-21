-- service inside paras
local SDK_DJ_CONSTS = 
{
	app_id 			= 414,
	app_key 		= "LNlh1Vjv",
	payment_key 	= "ulyedUEwKMZq",
	url_info 		= "http://connect.d.cn/open/member/info/",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_DJ,
}

SDK_DJ_CONSTS.rds_conn_name		= "djdb/"
SDK_DJ_CONSTS.rdst_mid			= "djdb/mid/"
SDK_DJ_CONSTS.rdst_order_flag	= "djdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_DJ_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfDj_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_DJ_CONSTS.rdst_mid ..mid
end

local function lfDj_dbSaveAuthInfo(mid,jsonStr)
	local key = lfDj_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- dj session datas
local DJ_AUTH_TOKEN_SESSION = {}

local DJ_ACTIVE_AUTH 		= 1
local DJ_ACTIVE_PAY 		= 1 + DJ_ACTIVE_AUTH
local DJ_ACTIVE_DRAWBACK 	= 1 + DJ_ACTIVE_PAY

local DJ_SESSIONS = {
	[DJ_ACTIVE_AUTH] 		= {},
	[DJ_ACTIVE_PAY]			= {},
	[DJ_ACTIVE_DRAWBACK]	= {},
}



local function lfDjSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk downjoy lfDjSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = DJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk downjoy lfDjSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfDjSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk downjoy lfDjSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = DJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk downjoy lfDjSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfDjSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk downjoy lfDjSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = DJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk downjoy lfDjSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- 当乐token验证 start
--------------------------------------------------------------------
-- client send the downjoy login auth
local function lfDj_authOnRequestFinished(req,resp)
	gLog.debug("i am lfDj_loginOnRequestFinished")
	-- local djMemberID = req.djMemberID
	-- local session = nil

	-- if djMemberID then 
	-- 	session = lfUidGet(djMemberID)
	-- end	
	-- --gLog.debug("i am lfDj_loginOnRequestFinished 222",djMemberID,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am downjoy login response page")
	-- end	

end


local function lfDj_authOnDjServerResponse(resp)
	gLog.debug("i am lfDj_authOnDjServerResponse 111")
	local djMemberID = resp.djMemberID
	gLog.debug("i am lfDj_authOnDjServerResponse 222 ",djMemberID)
end	

local function lfDj_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfDj_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfDj_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfDj_authSendResult 333")
    return json
end

local function lfDj_authOnDjServerData(req,resp,data)
	gLog.debug("i am lfDj_authOnDjServerData",data)
	local session = lfDjSessionGet(DJ_ACTIVE_AUTH,req.djMemberID)
	if not session or not data then 
		gLog.debug("i am lfDj_authOnDjServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfDj_authOnDjServerData err 01",json,data)
		return
	end	

	-- 向客户端发送结果
	json = lfDj_authSendResult(session,json)
	gLog.debug("i am lfDj_authOnDjServerData fuck 01")
	local mid = session.req.djMemberID
	gLog.debug("i am lfDj_authOnDjServerData fuck 02")
	-- 将数据存入数据库中(留待login服务器查询)
	if json.error_code == 0 and mid then
		lfDj_dbSaveAuthInfo(mid,data)
	end	
	gLog.debug("i am lfDj_authOnDjServerData fuck 03")	

	gLog.debug("i am lfDj_authOnDjServerData fuck 04")
end	

local function lfDj_authOnDjServerFinished(req,resp)
	gLog.debug("i am lfDj_authOnDjServerFinished")

	-- 清理session
	lfDjSessionDel(DJ_ACTIVE_AUTH,req.djMemberID)
end	

-- 发起向当乐客户端的验证请求
local function lfDj_authSendRequestToDownjoyServer(session)
	gLog.debug("i am lfDj_authSendRequestToDownjoyServer")
	local djMemberID = session.req.djMemberID
	local token = session.req.token
	local sig = gUtil.md5lower(token .. "|" .. SDK_DJ_CONSTS.app_key)
	local url = string.format("%s?app_id=%d&mid=%s&token=%s&sig=%s",SDK_DJ_CONSTS.url_info,SDK_DJ_CONSTS.app_id,djMemberID,token,sig)

	gLog.debug("dj server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		djMemberID		= djMemberID,
		on_error 		= nil,
		on_response 	= lfDj_authOnDjServerResponse,
		on_data 		= lfDj_authOnDjServerData,
		on_finished 	= lfDj_authOnDjServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给当乐服务器
local function lfDj_authOnRequest(session)
	gLog.debug("i am lfDj_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp
	local djMemberID = req.headers["djMemberID"] -- 当乐 member id
	local token = req.headers["token"]
--	gLog.print_r(req)

	if not djMemberID then
		djMemberID = "downjoy_mid"
		token = "token"
	end

	if not djMemberID or not token then
		lfDj_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	gLog.debug("lfDj_authOnRequest 001 ",djMemberID,token)
	local sessionOrg = lfDjSessionAdd(DJ_ACTIVE_AUTH,djMemberID,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("dj service sessionOrg err0",djMemberID)
	end	

	req.djMemberID = djMemberID
	req.token = token
	req.on_finished = lfDj_authOnRequestFinished
	gLog.debug("i am lfDj_authOnRequest request, fuck me2")

	-- 此处发起向当乐客户端的验证请求
	lfDj_authSendRequestToDownjoyServer(session)

	resp.djMemberID = djMemberID
	resp.token = token
	--resp.on_response_sent = lfDj_loginOnResponseSend
	gLog.debug("i am lfDj_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- 当乐token验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- 当乐计费结果 start
--------------------------------------------------------------------
-- 当乐计费结果合法性验证
local function lfDj_payCheckParams(p)
	if not p or not p.result or not p.money or not p.order or not p.mid or not p.time or not p.signature or not p.ext then
		return false
	end
	gLog.debug("lfDj_payCheckParams ___(O_O)_____ 111",p.ext)
	p.ext = gUtil.urldecode(p.ext)
	local strBeforeMd5 = string.format("order=%s&money=%s&mid=%s&time=%s&result=%s&ext=%s&key=%s",p.order,p.money,p.mid,p.time,p.result,p.ext,SDK_DJ_CONSTS.payment_key)
	gLog.debug("lfDj_payCheckParams ___(O_O)_____ 222",p.ext)
	local md5 = gUtil.md5lower(strBeforeMd5)
	gLog.debug("lfDj_payCheckParams ___(O_O)_____ 333")
	if md5 == p.signature then
		p.ext = gUtil.urldecode(p.ext)
		return true
	end

	gLog.debug("lfDj_payCheckParams ___(O_O)_____FAILED", p.ext)
	return false
end

-- 来自当乐服务器的计费结果
local function lfDj_payDjServerNotifyRequest(session)
	gLog.debug("i am lfDj_payDjServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfDj_payDjServerNotifyRequest 000")
	local p = gUtil.parseUrlParams(req.paramStr)
	gLog.debug("i am lfDj_payDjServerNotifyRequest 111")

	if not lfDj_payCheckParams(p) then
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfDj_payDjServerNotifyRequest 222")
	local order 	= p.order
	local status 	= tonumber(p.result)
	local rmb 		= tonumber(p.money)
	local c_acc 	= ""
	local c_accid 	= tonumber(p.mid)
	local desc 		= p.ext
	local ext 		= p.ext

	gLog.debug("i am lfDj_payDjServerNotifyRequest 333")
	local sql_success = -1
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_DJ_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_DJ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfDj_payDjServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_DJ_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfDj_payDjServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_DJ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfDj_payDjServerNotifyRequest 666")

	end



	gLog.debug("i am lfDj_payDjServerNotifyRequest 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,"success")
	end

    gLog.debug("=====> success is working")

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- 当乐计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- 当乐退款申请 start
-------------------------------------------------------------------- 
local function lfDj_drawbackOnResponse(resp)
	-- body
end

local function lfDj_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfDj_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_DJ_CONSTS.app_id,order.mid,order.order,SDK_DJ_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_DJ_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfDj_drawbackOnResponse,
		on_data 		= lfDj_drawbackOnData,
		-- on_finished 	= lfDj_authOnDjServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- 当乐退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_DOWNJOY_ACTION_FUNCS = {

	request = {
		["/sdk/downjoy/auth"] 		= lfDj_authOnRequest,
		["/sdk/downjoy/paynotify"] 	= lfDj_payDjServerNotifyRequest,
	},

	response = {
		-- ["sdk/downjoy/login"] 	= gfOnRsp_djLogin,
		-- ["sdk/downjoy/exit"] 	= gfOnRsp_djExit,
		-- ["sdk/downjoy/pay"] 	= gfOnRsp_djPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/downjoy",
	funcs = SDK_DOWNJOY_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData