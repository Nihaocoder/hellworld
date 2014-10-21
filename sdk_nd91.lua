-- service inside paras
local SDK_ND91_CONSTS = 
{
	android = {
		app_id 			= 105339 ,
		app_key 		= "bf1e8ff0cbe4eb5e8ee05113eb2988d6dd56baf4619fa09a",
	},
	ios = {
		app_id 			= 107359 ,
		app_key 		= "f665a7131d3ae7db2be2cf47af550a36abdadae75df10220",
	},	
	url_info 		= "http://service.sj.91.com/usercenter/AP.aspx",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_91,
}
  
SDK_ND91_CONSTS.rds_conn_name		= "ND91db/"
SDK_ND91_CONSTS.rdst_mid			= "ND91db/uin/"
SDK_ND91_CONSTS.rdst_order_flag		= "ND91db/order/orderflag"

ND91_ACT = {
	
	auth = 4,

}


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_ND91_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)

local function lfND91_getAppInfo(is_ios)
	if is_ios then
		return SDK_ND91_CONSTS.ios.app_id,SDK_ND91_CONSTS.ios.app_key
	end
	return SDK_ND91_CONSTS.android.app_id,SDK_ND91_CONSTS.android.app_key
end

local function lfND91_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_ND91_CONSTS.rdst_mid ..mid
end

local function lfND91_dbSaveAuthInfo(mid,jsonStr)
	local key = lfND91_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- ND91 session datas
local ND91_AUTH_TOKEN_SESSION = {}

local ND91_ACTIVE_AUTH 		= 1
local ND91_ACTIVE_PAY 		= 1 + ND91_ACTIVE_AUTH
local ND91_ACTIVE_DRAWBACK 	= 1 + ND91_ACTIVE_PAY

local ND91_SESSIONS = {
	[ND91_ACTIVE_AUTH] 		= {},
	[ND91_ACTIVE_PAY]			= {},
	[ND91_ACTIVE_DRAWBACK]	= {},
}



local function lfND91SessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk nd91 lfND91SessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = ND91_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk nd91 lfND91SessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfND91SessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk nd91 lfND91SessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = ND91_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk nd91 lfND91SessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfND91SessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk nd91 lfND91SessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = ND91_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk nd91 lfND91SessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- ND91token验证 start
--------------------------------------------------------------------
-- client send the nd91 login auth
local function lfND91_authOnRequestFinished(req,resp)
	gLog.debug("i am lfND91_loginOnRequestFinished")
	local nd91Uin = req.nd91Uin
	local session = nil

	if nd91Uin then 
		session = lfUidGet(nd91Uin)
	end	
	--gLog.debug("i am lfND91_loginOnRequestFinished 222",nd91Uin,session)
	if session then
		-- gUtil.sendSimplePage(session,"login req","i am nd91 login response page")
	end	

end


local function lfND91_authOnND91ServerResponse(resp)
	gLog.debug("i am lfND91_authOnND91ServerResponse 111")
	local nd91Uin = resp.nd91Uin
	gLog.debug("i am lfND91_authOnND91ServerResponse 222 ",nd91Uin)
end	

local function lfND91_authSendResult(session,json)
	if not json then 
		json = {
			ErrorCode = "-1",
			ErrorDesc = "未知错误"
		}
	end
	gLog.debug("i am lfND91_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfND91_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfND91_authSendResult 333")
    return json
end

local function lfND91_authOnND91ServerData(req,resp,data)
	gLog.debug("i am lfND91_authOnND91ServerData",data)
	local session = lfND91SessionGet(ND91_ACTIVE_AUTH,req.nd91Uin)
	if not session or not data then 
		gLog.debug("i am lfND91_authOnND91ServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfND91_authOnND91ServerData err 01",json,data)
		return
	end	

	-- 向客户端发送结果
	json = lfND91_authSendResult(session,json)
	gLog.debug("i am lfND91_authOnND91ServerData fuck 01")
	local nd91Uin = session.req.nd91Uin
	gLog.debug("i am lfND91_authOnND91ServerData fuck 02")
	-- 将数据存入数据库中(留待login服务器查询)
	if json.ErrorCode ==  "1" and nd91Uin then
		lfND91_dbSaveAuthInfo(nd91Uin,data)
	end	
	gLog.debug("i am lfND91_authOnND91ServerData fuck 03")	
	-- 清理session
	-- lfND91SessionDel(ND91_ACTIVE_AUTH,nd91Uin)
	gLog.debug("i am lfND91_authOnND91ServerData fuck 04")
end	

local function lfND91_authOnND91ServerFinished(req,resp)
	gLog.debug("i am lfND91_authOnND91ServerFinished")

	lfND91SessionDel(ND91_ACTIVE_AUTH,req.nd91Uin)
end	

-- 发起向ND91客户端的验证请求
local function lfND91_authSendRequestToNd91Server(session)
	gLog.debug("i am lfND91_authSendRequestToNd91Server")

	local app_id,appkey
	local req

	req = session.req
	if req.is_ios then
		app_id 	= SDK_ND91_CONSTS.ios.app_id
		app_key = SDK_ND91_CONSTS.ios.app_key
	else
		app_id 	= SDK_ND91_CONSTS.android.app_id
		app_key = SDK_ND91_CONSTS.android.app_key
	end

	gLog.debug("i am lfND91_authSendRequestToNd91Server is_ios",req.is_ios)


	local act 			= ND91_ACT.auth
	local nd91Uin 		= session.req.nd91Uin
	local token 		= session.req.token
	local sig 			= gUtil.md5lower(""..app_id .. act .. nd91Uin ..token ..app_key)
	local url 			= SDK_ND91_CONSTS.url_info
	
	url	= string.format("%s?AppId=%d&Act=%d&Uin=%s&Sign=%s&SessionID=%s",url,app_id,act,nd91Uin,sig,token)

	gLog.debug("ND91 server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		nd91Uin			= nd91Uin,
		on_error 		= nil,
		on_response 	= lfND91_authOnND91ServerResponse,
		on_data 		= lfND91_authOnND91ServerData,
		on_finished 	= lfND91_authOnND91ServerFinished,

	}
	local httpClient 	= gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给ND91服务器
local function lfND91_authOnRequest(session)
	gLog.debug("i am lfND91_authOnRequest")
	local req = session.req
	local resp = session.resp
	local nd91Uin = req.headers["uin"] -- ND91 member id
	local token = req.headers["sessionId"]
	local is_ios = req.headers["is_ios"]
	gLog.debug("i am lfND91_authOnRequest is_ios",is_ios,nd91Uin,token)


	-- __T fake uin and sessionid
	if not nd91Uin or not token then
		nd91Uin = "i_am_uin"
		token = "i_am_91sessionid"
	end

	if not nd91Uin or not token then
		lfND91_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	gLog.debug("lfND91_authOnRequest 001 ",nd91Uin,token)
	local sessionOrg = lfND91SessionAdd(ND91_ACTIVE_AUTH,nd91Uin,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("ND91 service sessionOrg err0",nd91Uin)
	end	

	req.nd91Uin = nd91Uin
	req.token = token
	req.is_ios = is_ios
	req.on_finished = lfND91_authOnRequestFinished
	gLog.debug("i am lfND91_authOnRequest request, fuck me2")

	-- 此处发起向ND91客户端的验证请求
	lfND91_authSendRequestToNd91Server(session)

	resp.nd91Uin = nd91Uin
	resp.token = token
	resp.is_ios = is_ios
	--resp.on_response_sent = lfND91_loginOnResponseSend
	gLog.debug("i am lfND91_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- ND91token验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- ND91计费结果 start
--------------------------------------------------------------------

-- 计费结果的各项参数
local nd91_pay_notify_param_names = {
		 "AppId",
		 "Act",
		 "ProductName",
		 "ConsumeStreamId",
		 "CooOrderSerial",
		 "Uin",
		 "GoodsId",
		 "GoodsInfo",
		 "GoodsCount",
		 "OriginalMoney",
		 "OrderMoney",
		 "Note",
		 "PayStatus",
		 "CreateTime",
		 "Sign",
	}
-- ND91计费结果合法性验证
local function lfND91_payCheckParams(p,is_ios)
	if not p then
		return false
	end
	gLog.debug("lfND91_payCheckParams 000")
	-- 验证参数
	for k,v in pairs(nd91_pay_notify_param_names) do
		if not p[v] then
			return false
		end
	end
	gLog.debug("lfND91_payCheckParams 111")
	local app_id,app_key = lfND91_getAppInfo(is_ios)
	gLog.debug("lfND91_payCheckParams 222",app_id,app_key,p["AppId"])

	if p["AppId"] ~= (""..app_id) then
		gLog.debug("lfND91_payCheckParams 999 false",app_id,p["AppId"])
		return false
	end

	if p["Note"] then
		p["Note"] = gUtil.urldecode(p["Note"])
	end


	local strBeforeMd5 = string.format("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			p["AppId"],p["Act"],p["ProductName"],p["ConsumeStreamId"],p["CooOrderSerial"],
			p["Uin"],p["GoodsId"],p["GoodsInfo"],p["GoodsCount"],p["OriginalMoney"],
			p["OrderMoney"],p["Note"],p["PayStatus"],p["CreateTime"],app_key)

	gLog.debug("lfND91_payCheckParams 333",strBeforeMd5)
	local md5 = gUtil.md5lower(strBeforeMd5)

	gLog.debug("lfND91_payCheckParams 444",md5,p["Sign"])

	if md5 == p["Sign"] then
		gLog.debug("lfND91_payCheckParams 555 true")
		return true
	end
	gLog.debug("lfND91_payCheckParams 555 false")
	return false
end

-- 来自ND91服务器的计费结果
local function lfND91_payND91ServerNotifyRequest(session,is_ios)
	gLog.debug("i am lfND91_payND91ServerNotifyRequest")
	-- gLog.print_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfND91_payND91ServerNotifyRequest 000",req.paramStr)
	local paramStr = gUtil.urldecode_91(req.paramStr)
	local p = gUtil.parseUrlParams(paramStr)
	gLog.debug("i am lfND91_payND91ServerNotifyRequest 111")

	if not lfND91_payCheckParams(p,is_ios) then
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfND91_payND91ServerNotifyRequest 222")

	local order 	= p.CooOrderSerial
	local status 	= tonumber(p.PayStatus)
	local rmb 		= tonumber(p.OrderMoney)
	local c_acc 	= ""
	local c_accid 	= tonumber(p.Uin)
	local desc 		= p.Note
	local ext 		= p.Note
	gLog.debug("i am lfND91_payND91ServerNotifyRequest 333",status,rmb)

	local sql_success = -1
	-- TODO:根据结果进行数据处理
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_ND91_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ND91_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfND91_payND91ServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_ND91_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfND91_payND91ServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ND91_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfND91_payND91ServerNotifyRequest 666")

	end

	gLog.debug("i am lfND91_payND91ServerNotifyRequest 777",sql_success)
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,'{"ErrorCode":"1","ErrorDesc":"接收成功"}')
    	gLog.debug("=====> success is working")
	else
		gUtil.sendString(resp,200,'{"ErrorCode":"0","ErrorDesc":"接收失败"}')
    	gLog.debug("=====> failed is working")
	end


	return RESULT_CODES.succeed
end  

local function lfND91_payND91ServerNotifyRequest_android(session)
	return lfND91_payND91ServerNotifyRequest(session , false)
end
local function lfND91_payND91ServerNotifyRequest_ios(session)
	return  lfND91_payND91ServerNotifyRequest(session , true)
end
--------------------------------------------------------------------
-- ND91计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- ND91退款申请 start
-------------------------------------------------------------------- 
local function lfND91_drawbackOnResponse(resp)
	-- body
end

local function lfND91_drawbackOnData(req,resp,data)
	local json = gJson.decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfND91_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_ND91_CONSTS.app_id,order.mid,order.order,SDK_ND91_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_ND91_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfND91_drawbackOnResponse,
		on_data 		= lfND91_drawbackOnData,
		-- on_finished 	= lfND91_authOnND91ServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- ND91退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_ND91_ACTION_FUNCS = {

	request = {
		["/sdk/nd91/auth"] 			= lfND91_authOnRequest,
		["/sdk/nd91/paynotify"] 	= lfND91_payND91ServerNotifyRequest_android,
		["/sdk/nd91/paynotifyios"] 	= lfND91_payND91ServerNotifyRequest_ios,
	},

	response = {
		-- ["sdk/nd91/login"] 	= gfOnRsp_ND91Login,
		-- ["sdk/nd91/exit"] 	= gfOnRsp_ND91Exit,
		-- ["sdk/nd91/pay"] 	= gfOnRsp_ND91Pay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/nd91",
	funcs = SDK_ND91_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData