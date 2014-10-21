-- service inside paras
local SDK_UC_CONSTS = 
{
	isDebug			= UC_SERVICE_IS_DEBUG,
	-- cpid 			= 1,
	-- gameid			= 239,
	-- serverid		= 245,
	-- channelid		= 2,
	-- apikey			= "54520eb3c61318c120052da361684207",
	-- url_info 		= "http://sdk.test4.g.uc.cn/ss",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_UC,
}

gLog.debug("SDK_UC_CONSTS.isDebug",SDK_UC_CONSTS.isDebug)
if SDK_UC_CONSTS.isDebug then
	-- 测试环境
	SDK_UC_CONSTS.cpid 			= 1
	SDK_UC_CONSTS.gameid		= 239
	SDK_UC_CONSTS.serverid		= 245
	SDK_UC_CONSTS.channelid		= 2
	SDK_UC_CONSTS.apikey		= "54520eb3c61318c120052da361684207"
	SDK_UC_CONSTS.url_info 		= "http://sdk.test4.g.uc.cn/ss"
	SDK_UC_CONSTS.url_host		= "sdk.test4.g.uc.cn"

else
	-- 正式环境
	SDK_UC_CONSTS.cpid 			= 22504
	SDK_UC_CONSTS.gameid		= 502605
	SDK_UC_CONSTS.serverid		= 1717
	SDK_UC_CONSTS.channelid		= 2
	SDK_UC_CONSTS.apikey		= "6b01111a2c9410852fa2f5f74e06083e"
	SDK_UC_CONSTS.url_info 		= "http://sdk.g.uc.cn/ss"
	SDK_UC_CONSTS.url_host		= "sdk.g.uc.cn"
	-- SDK_UC_CONSTS.url_info 		= "http://119.147.224.158/ss"
	-- SDK_UC_CONSTS.url_host		= "119.147.224.158"
end	

SDK_UC_CONSTS.rds_conn_name		= "ucdb/"
SDK_UC_CONSTS.rdst_ucid			= "ucdb/ucid/"
SDK_UC_CONSTS.rdst_order_flag	= "ucdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_UC_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)






local function lfUC_makeRedisAuthKey(ucid)
	if not ucid or type(ucid) ~= "string" then
		return nil
	end
	return SDK_UC_CONSTS.rdst_ucid ..ucid
end

local function lfUC_dbSaveAuthInfo(ucid,jsonStr)
	local key = lfUC_makeRedisAuthKey(ucid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- UC session datas
local UC_AUTH_TOKEN_SESSION = {}

local UC_ACTIVE_AUTH 		= 1
local UC_ACTIVE_PAY 		= 1 + UC_ACTIVE_AUTH
local UC_ACTIVE_DRAWBACK 	= 1 + UC_ACTIVE_PAY

local UC_SESSIONS = {
	[UC_ACTIVE_AUTH] 		= {},
	[UC_ACTIVE_PAY]			= {},
	[UC_ACTIVE_DRAWBACK]	= {},
}



local function lfUCSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk uc lfUCSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = UC_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk uc lfUCSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfUCSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk uc lfUCSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = UC_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk uc lfUCSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfUCSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk uc lfUCSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = UC_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk uc lfUCSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end

local function lfUC_print_request(sid,desc)
	-- if sid then
	-- 	local session = lfUCSessionGet(UC_ACTIVE_AUTH,sid)
	-- 	gLog.debug("===>>>lfUC_print_request",desc)
	-- 	if session then
	-- 		gLog.print_r(session.req)
	-- 	end
	-- end
end
--------------------------------------------------------------------
-- uc sid 验证 start
--------------------------------------------------------------------
-- client send the uc login auth
local function lfUC_authOnRequestFinished(req,resp)
	gLog.debug("i am lfUC_authOnRequestFinished")
	local sid = req.sid
	local session = nil

	if sid then 
		session = lfUidGet(sid)
	end	
	--gLog.debug("i am lfUC_loginOnRequestFinished 222",sid,session)
	if session then
		-- gUtil.sendSimplePage(session,"login req","i am uc login response page")
	end	

end


local function lfUC_authOnUCServerResponse(resp)
	gLog.debug("i am lfUC_authOnUCServerResponse 111")
	local sid = resp.sid
	gLog.debug("i am lfUC_authOnUCServerResponse 222 ",sid)

	lfUC_print_request(sid,"lfUC_authOnUCServerResponse")
end	

local function lfUC_authSendResult(session,json)
	if not json then 
		json = {
			state = {
				code = 1000,
			}
		}
	end


	local resp = session.resp
	local jsonStr = gJson:encode(json)

	-- gLog.debug("lfUC_authSendResult check session.request")
	-- gLog.print_r(session.req)

    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
    return json
end

local function lfUC_authOnUCServerData(req,resp,data)
	gLog.debug("i am lfUC_authOnUCServerData",data)
	local session = lfUCSessionGet(UC_ACTIVE_AUTH,req.sid)
	if not session or not data then 
		gLog.debug("i am lfUC_authOnUCServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json or not json.state or not json.state.code then 
		gLog.debug("i am lfUC_authOnUCServerData err 01",json,data)
		return
	end	
	gLog.debug("i am lfUC_authOnUCServerData",data,req.sid)

	-- 向客户端发送结果
	json = lfUC_authSendResult(session,json)
	local sid = session.req.sid
	-- 将数据存入数据库中(留待login服务器查询)
	if json.state.code == 1 and sid then
		lfUC_dbSaveAuthInfo(json.data.ucid .. "",data)
	end	
	gLog.debug("i am lfUC_authOnUCServerData end",data)
end	


local function lfUC_authOnUCServerFinished(req,resp)
	gLog.debug("i am lfUC_authOnUCServerFinished")

	lfUCSessionDel(UC_ACTIVE_AUTH,req.sid)
end

-- 发起向UC客户端的验证请求
local function lfUC_authSendRequestToUCServer(session)
	gLog.debug("i am lfUC_authSendRequestToUCServer",session)
	local sid = session.req.sid
	local url = SDK_UC_CONSTS.url_info

	lfUC_print_request(sid,"lfUC_authSendRequestToUCServer 000")

	gLog.debug("UC server request url",url,sid)
	local content = string.format("%dsid=%s%s",SDK_UC_CONSTS.cpid,sid,SDK_UC_CONSTS.apikey)
	gLog.debug("UC server request content",content)
	local sign = gUtil.md5lower(content)

	local reqjson = {
					service = "ucid.user.sidInfo",
					id 		= os.time(),
					game = {
						cpId 		= SDK_UC_CONSTS.cpid,
						gameId		= SDK_UC_CONSTS.gameid,
						channelId 	= SDK_UC_CONSTS.channelid,
						serverId 	= SDK_UC_CONSTS.serverid,
					},

					data = {
						sid = sid,
					},

					sign = sign,
				}
	local jsonstr = gJson:encode(reqjson)
	-- jsonstr = '{"service":"ucid.user.sidInfo","id":1367577917,"game":{"channelId":2,"cpId":1,"gameId":239,"serverId":245},"data":{"sid":"83fa0d40-0622-4bb4-8f75-5053c4b4dd4d113216"},"sign":"70e506ab8c808b3035ad96cc97b14d8a"}'
	gLog.debug("UC server request jsonStr",jsonstr)
	local httpClientRequst = {
		--user_agent		= "girl9server",
		headers = {
			["Content-Type"] 	= "text/html;charset=UTF8",
			-- ["Content-Type"] 	= "application/json",
			["Content-Length"] 	= #jsonstr,
			["Host"]			= SDK_UC_CONSTS.url_host,
			["Cache-control"] 	= "no-cache"
		},
		url 			= url,
		method			= "POST",
		sid				= sid,
		body 			= jsonstr,
		on_response 	= lfUC_authOnUCServerResponse,
		on_data 		= lfUC_authOnUCServerData,
		on_finished 	= lfUC_authOnUCServerFinished,
		on_error		= function(req,resp,err) gLog.debug("uc on error") end,
		-- keep_alive_timeout		= 5.0,
		-- request_header_timeout = 5.0,
		-- timeout = 5.0,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient 		= httpClient

	gLog.debug("=================>UC server request before request")
	-- gLog.print_r(httpClientRequst)
	local outReq,err = httpClient:request(httpClientRequst)
	gLog.debug("=================>UC server request after request",outReq,err)
	-- gLog.print_r(outReq)

	if err then
		-- TODO: 
	end	
	lfUC_print_request(sid,"lfUC_authSendRequestToUCServer 111")
end

-- 接收客户端发过来的验证信息，并转发给UC服务器
local function lfUC_authOnRequest(session)
	gLog.debug("i am lfUC_authOnRequest")
	local req = session.req
	local resp = session.resp
	local sid = req.headers["sid"]

	-- gLog.print_r(req)

	if not sid then
		sid = "tokencontent"
	end

	if not sid then
		lfUC_authSendResult(session,nil)
		return RESULT_CODES.succeed
	end

	gLog.debug("lfUC_authOnRequest 001 ",sid)
	local sessionOrg = lfUCSessionAdd(UC_ACTIVE_AUTH,sid,session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("UC service sessionOrg err0",sid)
	end	

	req.sid = sid
	req.on_finished = lfUC_authOnRequestFinished
	gLog.debug("i am lfUC_authOnRequest request, fuck me2")

	-- 此处发起向uc客户端的验证请求
	lfUC_authSendRequestToUCServer(session)
	resp.sid = sid

	gLog.debug("i am lfUC_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- UCtoken验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- UC计费结果 start
--------------------------------------------------------------------
-- UC计费结果合法性验证
local function lfUC_payCheckParams(p)

	if not p or not p.data or not p.sign then
		return false
	end

	local d = p.data

	if not d.orderId or not d.gameId or not d.serverId or not d.ucid 
	or not d.payWay or not d.amount or not d.callbackInfo or not d.orderStatus 
	or not d.failedDesc then
		return false
	end 

	gLog.debug("lfUC_payCheckParams 000",d.gameId)

	if tonumber(d.gameId) ~= SDK_UC_CONSTS.gameid then
		gLog.warn("lfUC_payCheckParams,invalid request data",d.gameId)
	end

	d.callbackInfo = gUtil.urldecode(d.callbackInfo)

	-- local strBeforeMd5 = string.format("%damount=%fcallbackInfo=%sfailedDesc=%sgameId=%dorderId=%sorderStatus=%spayWay=%dserverId=%d"
	-- ,SDK_UC_CONSTS.cpid,d.amount,)
	local strBeforeMd5 = string.format("%d",SDK_UC_CONSTS.cpid)

	strBeforeMd5 = string.format("%samount=%s",				strBeforeMd5,	d.amount)
	strBeforeMd5 = string.format("%scallbackInfo=%s",		strBeforeMd5,	d.callbackInfo)
	strBeforeMd5 = string.format("%sfailedDesc=%s",			strBeforeMd5,	d.failedDesc)
	strBeforeMd5 = string.format("%sgameId=%s",				strBeforeMd5,	d.gameId)
	strBeforeMd5 = string.format("%sorderId=%s",			strBeforeMd5,	d.orderId)
	strBeforeMd5 = string.format("%sorderStatus=%s",		strBeforeMd5,	d.orderStatus)
	strBeforeMd5 = string.format("%spayWay=%s",				strBeforeMd5,	d.payWay)
	strBeforeMd5 = string.format("%sserverId=%s",			strBeforeMd5,	d.serverId)
	strBeforeMd5 = string.format("%sucid=%s",				strBeforeMd5,	d.ucid)
	strBeforeMd5 = string.format("%s%s",					strBeforeMd5,	SDK_UC_CONSTS.apikey)

	gLog.debug("strBeforeMd5",strBeforeMd5)
	local md5code = gUtil.md5lower(strBeforeMd5)
	gLog.debug("lfUC_payCheckParams 999",md5code,p.sign)
	if md5code == p.sign then
		gLog.debug("lfUC_payCheckParams aaa")
		return true
	end
	gLog.debug("lfUC_payCheckParams aaa")
	return false
end

local function lfUC_payUCServerNotifyOnData(req,resp,data)
	-- body
	gLog.debug("lfUC_payUCServerNotifyOnData ",data)
	local requestJsonStr = data
	local p = gJson:decode(requestJsonStr)

	gLog.debug("lfUC_payUCServerNotifyOnData get json",p)
	if not p or type(p) ~= "table" or not lfUC_payCheckParams(p) then
		local resultStr = "FAILURE"
		gUtil.sendString(resp,200,resultStr)
		return -- 参数检查未通过，直接抛弃
	end	

	print("i am lfUC_payUCServerNotifyOnData 222")
	local d = p.data
	--d.amount = tonumber(d.amount)

	local order 	= d.orderId
	local status 	= d.orderStatus
	local rmb 		= tonumber(d.amount)
	local c_acc 	= ""
	local c_accid 	= tonumber(d.ucid)
	local desc 		= d.callbackInfo
	local ext 		= d.callbackInfo	

	print("i am lfUC_payUCServerNotifyOnData 333")

	-- TODO:根据结果进行数据处理
	local sql_success = -1
	if status == "S" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_UC_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_UC_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfUC_payUCServerNotifyOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_UC_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfUC_payUCServerNotifyOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_UC_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfUC_payUCServerNotifyOnData 666")

	end


	print("i am lfUC_payUCServerNotifyRequest 777")

	local resultStr = "SUCCESS"
	gUtil.sendString(resp,200,resultStr)
    gLog.debug("=====> success is working")
end

-- 来自UC服务器的计费结果
local function lfUC_payUCServerNotifyRequest(session)
	print("i am lfUC_payUCServerNotifyRequest")

	local req = session.req
	req.on_data = lfUC_payUCServerNotifyOnData

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- UC计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- UC退款申请 start
-------------------------------------------------------------------- 
local function lfUC_drawbackOnResponse(resp)
	-- body
end

local function lfUC_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfUC_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_UC_CONSTS.gameid,order.mid,order.order,SDK_UC_CONSTS.apikey)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_UC_CONSTS.gameid,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfUC_drawbackOnResponse,
		on_data 		= lfUC_drawbackOnData,
		-- on_finished 	= lfUC_authOnUCServerFinished,

	}

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end		

end


--------------------------------------------------------------------
-- UC退款申请 end
-------------------------------------------------------------------- 
--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_UC_ACTION_FUNCS = {

	request = {
		["/sdk/uc/auth"] 		= lfUC_authOnRequest,
		["/sdk/uc/paynotify"] 	= lfUC_payUCServerNotifyRequest,
	},

	response = {
	},

}

-- name,func table
local serviceData = {
	name = "sdk/uc",
	funcs = SDK_UC_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData