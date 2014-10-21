-- service inside paras



local SDK_WDJ_CONSTS = 
{
	app_id 			= "100001043",
	appkey_id 		= "d83e843b2660899c27fc60bb065d511c",
	url_info 		= "https://pay.wandoujia.com/api/uid/check",
	--------------------------------------------------------------
 	file_pubkey   = "service/keys/alipay/alipay_public_key.pem",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_WANDOUJIA,
}

SDK_WDJ_CONSTS.rds_conn_name		= "wandoujiadb/"
SDK_WDJ_CONSTS.rdst_mid				= "wandoujiadb/mid/"
SDK_WDJ_CONSTS.rdst_order_flag		= "wandoujiadb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_WDJ_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfWDJ_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_WDJ_CONSTS.rdst_mid ..mid
end

local function lfWDJ_dbSaveAuthInfo(mid,jsonStr)
	local key = lfWDJ_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- WDJ session datas
local WDJ_AUTH_TOKEN_SESSION = {}

local WDJ_ACTIVE_AUTH 		= 1
local WDJ_ACTIVE_PAY 		= 1 + WDJ_ACTIVE_AUTH
local WDJ_ACTIVE_DRAWBACK 	= 1 + WDJ_ACTIVE_PAY

local WDJ_SESSIONS = {
	[WDJ_ACTIVE_AUTH] 		= {},
	[WDJ_ACTIVE_PAY]			= {},
	[WDJ_ACTIVE_DRAWBACK]	= {},
}



local function lfWDJSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk WDJ lfWDJSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = WDJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk WDJ lfWDJSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfWDJSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk WDJ lfWDJSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = WDJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk WDJ lfWDJSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfWDJSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk WDJ lfWDJSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = WDJ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk WDJ lfWDJSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- 仙果token验证 start
--------------------------------------------------------------------
-- client send the WDJ login auth
local function lfWDJ_authOnRequestFinished(req,resp)
	gLog.debug("i am lfWDJ_authOnRequestFinished")
	-- local WDJMemberID = req.WDJMemberID
	-- local session = nil

	-- if WDJMemberID then 
	-- 	session = lfUidGet(WDJMemberID)
	-- end	
	-- --gLog.debug("i am lfWDJ_loginOnRequestFinished 222",WDJMemberID,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am WDJ login response page")
	-- end	

end


local function lfWDJ_authOnWDJServerResponse(resp)
	gLog.debug("i am lfWDJ_authOnWDJServerResponse 111")
	local WDJMemberID = resp.WDJMemberID
	gLog.debug("i am lfWDJ_authOnWDJServerResponse 222 ",WDJMemberID)
end	

local function lfWDJ_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfWDJ_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfWDJ_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfWDJ_authSendResult 333")
    return json
end

local function lfWDJ_authOnWDJServerData(req,resp,data)
	gLog.debug("i am lfWDJ_authOnWDJServerData",data)
	local uid = req.WDJMemberID

	local session = lfWDJSessionGet(WDJ_ACTIVE_AUTH, uid)
	if not session or not data then 
		gLog.debug("i am lfWDJ_authOnWDJServerData err 00",session,data)
		return
	end
	gLog.debug("i am lfWDJ_authOnWDJServerData .1",uid)

	local error_code = 1
	local error_msg = "token invalid"

	if data == "true" then
		error_code = 0
		error_msg = "ok"
	end

	local json = {
		error_code = error_code,
		error_msg  = error_msg,
	}

	local jsonStr = gJson:encode(json)

	-- 向客户端发送结果
	json = lfWDJ_authSendResult(session,json)
	gLog.debug("i am lfWDJ_authOnWDJServerData fuck 01")

	-- 将数据存入数据库中(留待login服务器查询)
	if json.error_code == 0 and uid then
		lfWDJ_dbSaveAuthInfo(uid, jsonStr)
	end	
	gLog.debug("i am lfWDJ_authOnWDJServerData fuck 03")	

end	

local function lfWDJ_authOnWDJServerFinished(req,resp)
	gLog.debug("i am lfWDJ_authOnWDJServerFinished")

	-- 清理session
	lfWDJSessionDel(WDJ_ACTIVE_AUTH,req.WDJMemberID)
end	

-- 发起向仙果客户端的验证请求
local function lfWDJ_authSendRequestToWDJServer(session)
	gLog.debug("i am lfWDJ_authSendRequestToWDJServer")
	local WDJMemberID = session.req.WDJMemberID
	local token = session.req.token
	local url = string.format("%s?appkey_id=%s&uid=%s&token=%s",
		SDK_WDJ_CONSTS.url_info, SDK_WDJ_CONSTS.appkey_id, WDJMemberID, gUtil.urlencode(token))

	gLog.debug("WDJ server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		WDJMemberID		= WDJMemberID,
		on_error 		= nil,
		on_response 	= lfWDJ_authOnWDJServerResponse,
		on_data 		= lfWDJ_authOnWDJServerData,
		on_finished 	= lfWDJ_authOnWDJServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

local function lfWDJ_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfWDJ_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfWDJ_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfWDJ_authSendResult 333")
    return json
end


-- 接收客户端发过来的验证信息，并转发给仙果服务器
local function lfWDJ_authOnRequest(session)
	gLog.debug("i am lfWDJ_authOnRequest")
	local req = session.req
	local resp = session.resp

	local uid 	= req.headers["uid"] or "wdj_udi"
	local token = req.headers["token"] or "wdj_token"

	gLog.debug("i am lfWDJ_authOnRequest 1",uid, token)
	if not uid then
		return RESULT_CODES.succeed
	end

	gLog.debug("i am lfWDJ_authOnRequest 2",uid, token)

	local sessionOrg = lfWDJSessionAdd(WDJ_ACTIVE_AUTH, uid, session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("WDJ service sessionOrg err0",uid)
	end	

	-- req.uid 		= uid
	req.token 		= token
	req.WDJMemberID = uid
	req.on_finished = lfWDJ_authOnRequestFinished
	gLog.debug("i am lfWDJ_authOnRequest request, fuck me2")

	-- 此处发起向WDJ客户端的验证请求
	lfWDJ_authSendRequestToWDJServer(session)
	resp.uid = uid

	gLog.debug("i am lfWDJ_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- 仙果token验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- 仙果计费结果 start
--------------------------------------------------------------------
-- 仙果计费结果合法性验证

local WDJ_paynotify_paras = 
{
	["CpUserID"] 		= {true,	true,	true},-- need sign,need urldecode,must have
	["CpOrderID"] 		= {true,	true,	true},
	["CpOrderDesc"] 	= {true,	true,	true},
	["CID"] 			= {true,	true,	true},
	["PID"] 			= {true,	true,	true},
	["FID"] 			= {true,	true,	true},
	["TransID"] 		= {true,	true,	true},
	["TransTime"] 		= {true,	true,	true},
	["PerCost"] 		= {true,	true,	true},
	["PayWay"] 			= {false,	true,	true},
	["Statu"] 			= {false,	true,	true},
	["Sign"] 			= {false,	true,	true},
}
local function lfWDJ_payCheckParams(p)
	gLog.debug("lfWDJ_payCheckParams ___(O_O)_____ 000")
	if not p then
		return false
	end

	local para
	for k,v in pairs(WDJ_paynotify_paras) do 

		para = p[k] -- 远端传过来的参数
		if v[3] and not para then -- 必须有的参数
			gLog.error("lfWDJ_payCheckParams err 000, para is nil ",k)
			return false
		end

		if para and v[2] then
			-- 需要做转换
			p[k] =  gUtil.urldecode(para)
		end

	end

	gLog.debug("lfWDJ_payCheckParams ___(O_O)_____ 111",p.CpOrderID)

	-- pin=MD5(UserID + " _ " +OrderID+"_"+PID+"_"+安全码)
	local strBeforeMd5 = string.format("%s%s",SDK_WDJ_CONSTS.app_key,p.CpOrderID)
	gLog.debug("lfWDJ_payCheckParams ___(O_O)_____ 222",strBeforeMd5)

	-- md5签名验证
	local md5 = gUtil.md5upper(strBeforeMd5)
	gLog.debug("lfWDJ_payCheckParams ___(O_O)_____ 333",md5,p.Sign)
	if md5 == p.Sign then
		-- 验证成功
		return true
	end

	-- 验证失败
	gLog.debug("lfWDJ_payCheckParams ___(O_O)_____FAILED", p.CpOrderID)
	return false
end

local function lfWDJ_payWDJServerNotifyOnData( req,resp,data )

	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 000",data)
	local ppp = gUtil.parseUrlParams(data or "")
	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 111",ppp)

	-- if not lfWDJ_payCheckParams(p) then
	-- 	return -- 参数检查未通过，直接抛弃
	-- end	

	local content 	= gUtil.urldecode(ppp.content)
	local sign 	= gUtil.urldecode(ppp.sign)
	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 222", type(content), content)
	local p = gJson:decode(content)
	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 223")

	local order 	= p.orderId
	local status 	= 1
	local rmb 		= tonumber(p.money)
	local c_acc 	= p.buyerId or ""
	local c_accid 	= 0
	local desc 		= p.chargeType --支付类型  ALIPAY：支付宝;SHENZHOUPAY：充值卡;BALANCEPAY：余额;CREDITCARD : 信用卡;DEBITCARD：借记卡
	local ext 		= p.out_trade_no

	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 333",order,ext)
	local sql_success = -1
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_WDJ_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_WDJ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 444",sql_success)

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_WDJ_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 555",SDK_WDJ_CONSTS.rdst_order_flag)
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_WDJ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 666")

	end


	gLog.debug("i am lfWDJ_payWDJServerNotifyOnData 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,"success ")
	else
		gUtil.sendString(resp,200,"fail")
	end

    gLog.debug("=====> success is working")
end


local function lfWDJ_payWDJServerNotifyRequest(session)
	print("i am lfWDJ_payWDJServerNotifyRequest")

	local req = session.req
	req.on_data = lfWDJ_payWDJServerNotifyOnData

	return RESULT_CODES.succeed
end

--------------------------------------------------------------------
-- 仙果计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- 仙果退款申请 start
-------------------------------------------------------------------- 
local function lfWDJ_drawbackOnResponse(resp)
	-- body
end

local function lfWDJ_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfWDJ_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_WDJ_CONSTS.app_id,order.mid,order.order,SDK_WDJ_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_WDJ_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfWDJ_drawbackOnResponse,
		on_data 		= lfWDJ_drawbackOnData,
		-- on_finished 	= lfWDJ_authOnWDJServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- 仙果退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_WDJ_ACTION_FUNCS = {

	request = {
		["/sdk/wandoujia/auth"] 		= lfWDJ_authOnRequest,
		["/sdk/wandoujia/paynotify"] 	= lfWDJ_payWDJServerNotifyRequest,
	},

	response = {
		-- ["sdk/WDJ/login"] 	= gfOnRsp_WDJLogin,
		-- ["sdk/WDJ/exit"] 	= gfOnRsp_WDJExit,
		-- ["sdk/WDJ/pay"] 	= gfOnRsp_WDJPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/wandoujia",
	funcs = SDK_WDJ_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData