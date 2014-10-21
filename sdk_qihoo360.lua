-- service inside paras
local SDK_QH360_CONSTS = 
{
	app_id 			= 200695996,
	app_key 		= "e7b075996b9f1b93be54bb2ec57fcced",
	app_secret 		= "49050fcc9e7fdfd05696d09d12ea902a",
	url_info 		= "https://openapi.360.cn",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_QH360,
}
 



SDK_QH360_CONSTS.rds_conn_name		= "QH360db/"
SDK_QH360_CONSTS.rdst_mid			= "QH360db/qh360id/"
SDK_QH360_CONSTS.rdst_order_flag	= "QH360db/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_QH360_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfQH360_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_QH360_CONSTS.rdst_mid ..mid
end

local function lfQH360_dbSaveAuthInfo(mid,jsonStr)
	local key = lfQH360_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- QH360 session datas
local QH360_AUTH_TOKEN_SESSION = {}

local QH360_ACTIVE_AUTH 		= 1
local QH360_ACTIVE_PAY 			= 1 + QH360_ACTIVE_AUTH
local QH360_ACTIVE_DRAWBACK 	= 1 + QH360_ACTIVE_PAY

local QH360_SESSIONS = {
	[QH360_ACTIVE_AUTH] 		= {},
	[QH360_ACTIVE_PAY]			= {},
	[QH360_ACTIVE_DRAWBACK]	= {},
}



local function lfQH360SessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk QH360 lfQH360SessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = QH360_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QH360 lfQH360SessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfQH360SessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk QH360 lfQH360SessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = QH360_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QH360 lfQH360SessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfQH360SessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk QH360 lfQH360SessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = QH360_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QH360 lfQH360SessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


local function lfQH360_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfQH360_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfQH360_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfQH360_authSendResult 333")
    return json
end

--------------------------------------------------------------------
-- QH360 QH360jsonStr获取用户信息 start
--------------------------------------------------------------------
local function lfQH360_accInfoOnRequestFinished(req,resp)
	gLog.debug("i am lfQH360_accInfoOnRequestFinished")

	local session = lfQH360SessionGet(QH360_ACTIVE_AUTH,req.authcode)
	if not session or not session.authdata or not session.authdata.accinfo then
		lfQH360_authSendResult(session,nil)
		if session then
			lfQH360SessionDel(QH360_ACTIVE_AUTH,req.authcode)
		end
		return
	end

	-- 向客户端发送结果
	--json = lfQH360_authSendResult(session,session.authdata)
	gLog.debug("i am lfQH360_accInfoOnRequestFinished fuck 01")
	local accinfo = session.authdata.accinfo
	gLog.debug("i am lfQH360_accInfoOnRequestFinished fuck 02")
	if not accinfo.id then
		lfQH360_authSendResult(session,nil)
		lfQH360SessionDel(QH360_ACTIVE_AUTH,req.authcode)
		return
	end	

	-- 将数据存入数据库中(留待login服务器查询)
	local jsonStr = gJson:encode(session.authdata)
	lfQH360_authSendResult(session,session.authdata)
	gLog.debug("i am lfQH360_accInfoOnRequestFinished before save: ",accinfo.id,jsonStr)
	gLog.debug("i am lfQH360_accInfoOnRequestFinished before save: ",lfQH360_dbSaveAuthInfo(accinfo.id,jsonStr))
	lfQH360SessionDel(QH360_ACTIVE_AUTH,req.authcode)
end


local function lfQH360_accInfoOnQH360ServerResponse(resp)
	local authcode = resp.authcode
	gLog.debug("i am lfQH360_accInfoOnQH360ServerResponse 111 ",authcode)
end	

local function lfQH360_accInfoOnQH360ServerData(req,resp,data)
	gLog.debug("i am lfQH360_accInfoOnQH360ServerData",data)
	local session = lfQH360SessionGet(QH360_ACTIVE_AUTH,req.authcode)
	if not session or not data then 
		gLog.debug("i am lfQH360_accInfoOnQH360ServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if session.authdata then
		session.authdata.accinfo = json
	end
	gLog.debug("i am lfQH360_accInfoOnQH360ServerData",json,data)
end	



-- 发起向QH360 客户端的验证请求
local function lfQH360_accInfoRequestToQH360Server(authcode)
	gLog.debug("i am lfQH360_authSendRequestToQH360Server")
	local session = lfQH360SessionGet(QH360_ACTIVE_AUTH,authcode)

	if not session or not session.authdata then
		return
	end

	local authdata = session.authdata
	local authcode = session.req.authcode
	local url = string.format("%s/user/me.json?access_token=%s&fields=id,name,avatar,sex,area",SDK_QH360_CONSTS.url_info,authdata.access_token)

	gLog.debug("QH360 server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		authcode		= authcode,
		on_error 		= nil,
		on_response 	= lfQH360_accInfoOnQH360ServerResponse,
		on_data 		= lfQH360_accInfoOnQH360ServerData,
		on_finished 	= lfQH360_accInfoOnRequestFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

--------------------------------------------------------------------
-- QH360 QH360jsonStr获取用户信息 end
--------------------------------------------------------------------

--------------------------------------------------------------------
-- QH360 QH360jsonStr验证 start
--------------------------------------------------------------------
-- client send the QH360 login auth
local function lfQH360_authOnRequestFinished(req,resp)
	gLog.debug("i am lfQH360_loginOnRequestFinished")
	-- local authcode = req.authcode
	-- local session = nil

	-- if authcode then 
	-- 	session = lfUidGet(authcode)
	-- end	
	-- --gLog.debug("i am lfQH360_loginOnRequestFinished 222",authcode,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am QH360 login response page")
	-- end	

end


local function lfQH360_authOnQH360ServerResponse(resp)
	gLog.debug("i am lfQH360_authOnQH360ServerResponse 111")
	local authcode = resp.authcode
	gLog.debug("i am lfQH360_authOnQH360ServerResponse 222 ",authcode)
end	

local function lfQH360_authOnQH360ServerData(req,resp,data)
	gLog.debug("i am lfQH360_authOnQH360ServerData",data)
	local session = lfQH360SessionGet(QH360_ACTIVE_AUTH,req.authcode)
	if not session or not data then 
		gLog.debug("i am lfQH360_authOnQH360ServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfQH360_authOnQH360ServerData err 01",json,data)
		return
	end	

	session.authdata = json
	gLog.debug("i am lfQH360_authOnQH360ServerData fuck 02")	

end	

local function lfQH360_authOnQH360ServerFinished(req,resp)
	gLog.debug("i am lfQH360_authOnQH360ServerFinished")
	-- do accInfo request
	local session = lfQH360SessionGet(QH360_ACTIVE_AUTH,req.authcode) 
	if not session then
		return
	elseif not session.authdata then
		lfQH360_authSendResult(session,nil)
		lfQH360SessionDel(QH360_ACTIVE_AUTH,req.authcode) 
		return
	end

	-- 此处发起360账户信息的请求 
	lfQH360_accInfoRequestToQH360Server(req.authcode)	
end	

-- 发起向QH360 客户端的验证请求
local function lfQH360_authSendRequestToQH360Server(session)
	gLog.debug("i am lfQH360_authSendRequestToQH360Server")
	local authcode = session.req.authcode
	local authJson = session.req.authJson
	local url = string.format("grant_type=authorization_code&code=%s&client_id=%s&client_secret=%s&redirect_uri=oob",authcode,SDK_QH360_CONSTS.app_key,SDK_QH360_CONSTS.app_secret)

	--url = gUtil.urlencode(url)

	url = string.format("%s/oauth2/access_token?%s",SDK_QH360_CONSTS.url_info,url)

	gLog.debug("QH360 server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		authcode		= authcode,
		authdata 		= nil,
		on_error 		= nil,
		on_response 	= lfQH360_authOnQH360ServerResponse,
		on_data 		= lfQH360_authOnQH360ServerData,
		on_finished 	= lfQH360_authOnQH360ServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

-- 接收客户端发过来的验证信息，并转发给QH360 服务器
local function lfQH360_authOnRequest(session)
	gLog.debug("i am lfQH360_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp
	local authcode = req.headers["authcode"] -- QH360  member id
	local QH360jsonStr = req.headers["json"]


--	gLog.print_r(req)

	if not authcode then
		authcode = "QH360_mid"
		QH360jsonStr = "QH360jsonStr"
	end
	-- auth data json
	local authJson

	if QH360jsonStr then
		authJson = gJson:decode(QH360jsonStr)
	else
		authJson = nil
	end

	gLog.debug("lfQH360_authOnRequest 001 ",authcode,QH360jsonStr)

	-- auth data is invalid
	if not authcode or not authJson then
		lfQH360_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end
	gLog.debug("lfQH360_authOnRequest 001 001")

	local sessionOrg = lfQH360SessionAdd(QH360_ACTIVE_AUTH,authcode,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("QH360 service sessionOrg err0",authcode)
	end	

	req.authcode = authcode
	req.authJson = authJson
	req.on_finished = lfQH360_authOnRequestFinished
	gLog.debug("i am lfQH360_authOnRequest request, fuck me2")

	-- 此处发起向QH360jsonStr客户端的验证请求
	lfQH360_authSendRequestToQH360Server(session)

	resp.authcode = authcode
	resp.authJson = authJson
	--resp.on_response_sent = lfQH360_loginOnResponseSend
	gLog.debug("i am lfQH360_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- QH360 QH360jsonStr验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- QH360 计费结果 start
--------------------------------------------------------------------
-- QH360 计费结果合法性验证
local function lfQH360_payCheckParams(p)
	if not p or not p.order_id or not p.app_uid or not p.sign then
		return false
	end

	gLog.debug("lfQH360_payCheckParams ___(O_O)_____ 111")

	-- key order
	local keys = {}

	for k,v in pairs(p) do
		if not (k == "sign"  or k == "sign_return") then
			table.insert(keys,k)
		end

		if k == "app_uid" then
			p[k] = gUtil.urldecode(p[k])
		end
	end
	gUtil.quick_sort(keys,1,#keys,gUtil.string_compare)
	gLog.debug("lfQH360_payCheckParams ___(O_O)_____ 222")

	local strBeforeMd5 = ""
	for k,v in pairs(keys) do
		strBeforeMd5 = string.format("%s%s#",strBeforeMd5,p[v])
	end
	strBeforeMd5 = string.format("%s%s",strBeforeMd5,SDK_QH360_CONSTS.app_secret)

	gLog.debug("lfQH360_payCheckParams ___(O_O)_____ 333",strBeforeMd5)

	local md5 = gUtil.md5lower(strBeforeMd5)
	gLog.debug("lfQH360_payCheckParams ___(O_O)_____ 444")
	if md5 == p.sign then
		return true
	end

	gLog.debug("lfQH360_payCheckParams ___(O_O)_____FAILED", p.ext)
	return false
end

-- 来自QH360 服务器的计费结果
local function lfQH360_payQH360ServerNotifyRequest(session)
	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp
	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 000")
	local p = gUtil.parseUrlParams(req.paramStr)
	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 111")

	if not lfQH360_payCheckParams(p) then
		--gUtil.sendString(resp,200,"ok")
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 222")
	local order 	= p.order_id
	local status 	= p.gateway_flag
	local rmb 		= tonumber(p.amount) / 100
	local c_acc 	= ""
	local c_accid 	= tonumber(p.user_id)
	local desc 		= p.app_uid
	local ext 		= p.app_uid

	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 333")
	local sql_success = -1
	if status == "success" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_QH360_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_QH360_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_QH360_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_QH360_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 666")

	end



	gLog.debug("i am lfQH360_payQH360ServerNotifyRequest 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,"ok")
	end

    gLog.debug("=====> success is working")

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- QH360 计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- QH360 退款申请 start
-------------------------------------------------------------------- 
local function lfQH360_drawbackOnResponse(resp)
	-- body
end

local function lfQH360_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfQH360_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_QH360_CONSTS.app_id,order.mid,order.order,SDK_QH360_CONSTS.app_secret)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_QH360_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfQH360_drawbackOnResponse,
		on_data 		= lfQH360_drawbackOnData,
		-- on_finished 	= lfQH360_authOnQH360ServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- QH360 退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_QH360_ACTION_FUNCS = {

	request = {
		["/sdk/qihoo360/auth"] 			= lfQH360_authOnRequest,
		["/sdk/qihoo360/paynotify"] 	= lfQH360_payQH360ServerNotifyRequest,
	},

	response = {
		-- ["sdk/qihoo360/login"] 	= gfOnRsp_QH360Login,
		-- ["sdk/qihoo360/exit"] 	= gfOnRsp_QH360Exit,
		-- ["sdk/qihoo360/pay"] 	= gfOnRsp_QH360Pay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/qihoo360",
	funcs = SDK_QH360_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData