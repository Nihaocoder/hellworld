-- service inside paras
local SDK_XianGuo_CONSTS = 
{
	app_id 			= 1001,
	app_key 		= "cd9gn2)1#",
	payment_key 	= "ulyedUEwKMZq",
	url_info 		= "http://connect.d.cn/open/member/info/",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_XIANGUO,
}

SDK_XianGuo_CONSTS.rds_conn_name		= "XianGuodb/"
SDK_XianGuo_CONSTS.rdst_mid				= "XianGuodb/mid/"
SDK_XianGuo_CONSTS.rdst_order_flag		= "XianGuodb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_XianGuo_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfXianGuo_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_XianGuo_CONSTS.rdst_mid ..mid
end

local function lfXianGuo_dbSaveAuthInfo(mid,jsonStr)
	local key = lfXianGuo_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- XianGuo session datas
local XianGuo_AUTH_TOKEN_SESSION = {}

local XianGuo_ACTIVE_AUTH 		= 1
local XianGuo_ACTIVE_PAY 		= 1 + XianGuo_ACTIVE_AUTH
local XianGuo_ACTIVE_DRAWBACK 	= 1 + XianGuo_ACTIVE_PAY

local XianGuo_SESSIONS = {
	[XianGuo_ACTIVE_AUTH] 		= {},
	[XianGuo_ACTIVE_PAY]			= {},
	[XianGuo_ACTIVE_DRAWBACK]	= {},
}



local function lfXianGuoSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk XianGuo lfXianGuoSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = XianGuo_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XianGuo lfXianGuoSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfXianGuoSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk XianGuo lfXianGuoSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = XianGuo_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XianGuo lfXianGuoSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfXianGuoSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk XianGuo lfXianGuoSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = XianGuo_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk XianGuo lfXianGuoSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


--------------------------------------------------------------------
-- 仙果token验证 start
--------------------------------------------------------------------
-- client send the XianGuo login auth
local function lfXianGuo_authOnRequestFinished(req,resp)
	gLog.debug("i am lfXianGuo_authOnRequestFinished")
	-- local XianGuoMemberID = req.XianGuoMemberID
	-- local session = nil

	-- if XianGuoMemberID then 
	-- 	session = lfUidGet(XianGuoMemberID)
	-- end	
	-- --gLog.debug("i am lfXianGuo_loginOnRequestFinished 222",XianGuoMemberID,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am XianGuo login response page")
	-- end	

end


local function lfXianGuo_authOnXianGuoServerResponse(resp)
	gLog.debug("i am lfXianGuo_authOnXianGuoServerResponse 111")
	local XianGuoMemberID = resp.XianGuoMemberID
	gLog.debug("i am lfXianGuo_authOnXianGuoServerResponse 222 ",XianGuoMemberID)
end	

local function lfXianGuo_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfXianGuo_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfXianGuo_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfXianGuo_authSendResult 333")
    return json
end

local function lfXianGuo_authOnXianGuoServerData(req,resp,data)
	gLog.debug("i am lfXianGuo_authOnXianGuoServerData",data)
	local session = lfXianGuoSessionGet(XianGuo_ACTIVE_AUTH,req.XianGuoMemberID)
	if not session or not data then 
		gLog.debug("i am lfXianGuo_authOnXianGuoServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfXianGuo_authOnXianGuoServerData err 01",json,data)
		return
	end	

	-- 向客户端发送结果
	json = lfXianGuo_authSendResult(session,json)
	gLog.debug("i am lfXianGuo_authOnXianGuoServerData fuck 01")
	local mid = session.req.XianGuoMemberID
	gLog.debug("i am lfXianGuo_authOnXianGuoServerData fuck 02")
	-- 将数据存入数据库中(留待login服务器查询)
	if json.error_code == 0 and mid then
		lfXianGuo_dbSaveAuthInfo(mid,data)
	end	
	gLog.debug("i am lfXianGuo_authOnXianGuoServerData fuck 03")	

	gLog.debug("i am lfXianGuo_authOnXianGuoServerData fuck 04")
end	

local function lfXianGuo_authOnXianGuoServerFinished(req,resp)
	gLog.debug("i am lfXianGuo_authOnXianGuoServerFinished")

	-- 清理session
	lfXianGuoSessionDel(XianGuo_ACTIVE_AUTH,req.XianGuoMemberID)
end	

-- 发起向仙果客户端的验证请求
local function lfXianGuo_authSendRequestToXianGuoServer(session)
	gLog.debug("i am lfXianGuo_authSendRequestToXianGuoServer")
	local XianGuoMemberID = session.req.XianGuoMemberID
	local token = session.req.token
	local sig = gUtil.md5lower(token .. "|" .. SDK_XianGuo_CONSTS.app_key)
	local url = string.format("%s?app_id=%d&mid=%s&token=%s&sig=%s",SDK_XianGuo_CONSTS.url_info,SDK_XianGuo_CONSTS.app_id,XianGuoMemberID,token,sig)

	gLog.debug("XianGuo server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		XianGuoMemberID		= XianGuoMemberID,
		on_error 		= nil,
		on_response 	= lfXianGuo_authOnXianGuoServerResponse,
		on_data 		= lfXianGuo_authOnXianGuoServerData,
		on_finished 	= lfXianGuo_authOnXianGuoServerFinished,

	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)

	if err then
		-- TODO: 
	end	

end

local function lfXianGuo_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfXianGuo_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfXianGuo_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfXianGuo_authSendResult 333")
    return json
end


-- 接收客户端发过来的验证信息，并转发给仙果服务器
local function lfXianGuo_authOnRequest(session)
	gLog.debug("i am lfXianGuo_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp

	local info_str = req.headers["info"] -- json str
	gLog.debug("i am lfXianGuo_authOnRequest",info_str)
	--info_str= '{"account_id":123456}'
	if not info_str then
		return RESULT_CODES.succeed
	end

	local info = gJson:decode(info_str)
	if not info then
		return RESULT_CODES.succeed
	end


	local ultralisk_uid = info.account_id or "xianguo_uid"
	local ultralisk_sid = info.session or "xianguo_sid"

	gLog.debug("lfXianGuo_authOnRequest 001 ",ultralisk_uid,ultralisk_sid)


	local json = {
		error_code = 0,
		error_msg = "ok",
	}

	lfXianGuo_authSendResult(session,json)
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- 仙果token验证 end
--------------------------------------------------------------------
--------------------------------------------------------------------
-- 仙果计费结果 start
--------------------------------------------------------------------
-- 仙果计费结果合法性验证
local XianGuo_paynotify_paras = 
{
	["UserID"] 			= {true,	true,	true},-- need sign,need urldecode,must have
	["OrderID"] 		= {true,	true,	true},
	["Fee"] 			= {true,	true,	true},
	["Pid"] 			= {true,	true,	true},
	["ConsumerID"] 		= {true,	true,	true},
	["ConsumerName"] 	= {true,	true,	true},
	["ExtraStr"] 		= {true,	true,	true},
	["Status"] 			= {true,	true,	true},
	["Pin"] 			= {false,	true,	true},
}
local function lfXianGuo_payCheckParams(p)
	gLog.debug("lfXianGuo_payCheckParams ___(O_O)_____ 000")
	if not p then
		return false
	end

	local para
	for k,v in pairs(XianGuo_paynotify_paras) do 

		para = p[k] -- 远端传过来的参数
		if v[3] and not para then -- 必须有的参数
			gLog.error("lfXianGuo_payCheckParams err 000, para is nil ",k)
			return false
		end

		if para and v[2] then
			-- 需要做转换
			p[k] =  gUtil.urldecode(para)
		end

	end

	gLog.debug("lfXianGuo_payCheckParams ___(O_O)_____ 111",p.ExtraStr)

	-- pin=MD5(UserID + " _ " +OrderID+"_"+PID+"_"+安全码)
	local strBeforeMd5 = string.format("%s_%s_%s_%s",p.UserID,p.OrderID,p.Pid,SDK_XianGuo_CONSTS.app_key)
	gLog.debug("lfXianGuo_payCheckParams ___(O_O)_____ 222",strBeforeMd5)

	-- md5签名验证
	local md5 = gUtil.md5lower(strBeforeMd5)
	gLog.debug("lfXianGuo_payCheckParams ___(O_O)_____ 333",md5,p.Pin)
	if md5 == p.Pin then
		-- 验证成功
		return true
	end

	-- 验证失败
	gLog.debug("lfXianGuo_payCheckParams ___(O_O)_____FAILED", p.ExtraStr)
	return false
end

local function lfXianGuo_payXianGuoServerNotifyOnData( req,resp,data )

	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 000",data)
	local p = gUtil.parseUrlParams(data or "")
	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 111",p)

	if not lfXianGuo_payCheckParams(p) then
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 222")
	local order 	= p.OrderID
	local status 	= tonumber(p.Status)
	local rmb 		= tonumber(p.Fee) / 100
	local c_acc 	= p.UserID or ""
	local c_accid 	= 0
	local desc 		= p.ExtraStr
	local ext 		= p.ExtraStr

	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 333")
	local sql_success = -1
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_XianGuo_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_XianGuo_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_XianGuo_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_XianGuo_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 666")

	end



	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyOnData 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,"ok")
	else
		gUtil.sendString(resp,200,"failed")
	end

    gLog.debug("=====> success is working")
end


-- 来自仙果服务器的计费结果
local function lfXianGuo_payXianGuoServerNotifyRequest(session)
	gLog.debug("i am lfXianGuo_payXianGuoServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp

	req.on_data = lfXianGuo_payXianGuoServerNotifyOnData


	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- 仙果计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- 仙果退款申请 start
-------------------------------------------------------------------- 
local function lfXianGuo_drawbackOnResponse(resp)
	-- body
end

local function lfXianGuo_drawbackOnData(req,resp,data)
	local json = gJson:decode(data)

	if json.error_code == 0 then
		-- 成功
	else
		-- 失败	
	end

end

function gfXianGuo_drawbackRequest(order)
	local httpClient = gfGetHttpClient()
	local sigSrc = string.format("app_id=%d&mid=%s&order_no=%s&key=%s",SDK_XianGuo_CONSTS.app_id,order.mid,order.order,SDK_XianGuo_CONSTS.payment_key)
	local sig = gUtil.md5lower(sigStr)
	local url = string.format("app_id=%d&mid=%s&order_no=%s&sig=%s",SDK_XianGuo_CONSTS.app_id,order.mid,order.order,sig)

	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		order 			= order,
		--on_error 		= nil,
		on_response 	= lfXianGuo_drawbackOnResponse,
		on_data 		= lfXianGuo_drawbackOnData,
		-- on_finished 	= lfXianGuo_authOnXianGuoServerFinished,

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
local SDK_XianGuo_ACTION_FUNCS = {

	request = {
		["/sdk/xianguo/auth"] 		= lfXianGuo_authOnRequest,
		["/sdk/xianguo/paynotify"] 	= lfXianGuo_payXianGuoServerNotifyRequest,
	},

	response = {
		-- ["sdk/XianGuo/login"] 	= gfOnRsp_XianGuoLogin,
		-- ["sdk/XianGuo/exit"] 	= gfOnRsp_XianGuoExit,
		-- ["sdk/XianGuo/pay"] 	= gfOnRsp_XianGuoPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/XianGuo",
	funcs = SDK_XianGuo_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData