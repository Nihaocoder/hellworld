local xml_tool = require "util/xmlParser"



-- service inside paras
 local SDK_QQ_CONSTS = 
 {
 	app_id 			= 1101239975,
 	appkey_id 		= "HzxG3jFRipddeYFm",
 	url_info 		= "https://graph.qq.com/user/get_user_info",
 	cid				= CHANNEL_ID_QQ,
 }

-- local QQ_PAY_RESULT = {
-- 	success = "success",
-- 	failed = "failed",
-- }

local QQ_CONST = {
	file_sign_bin = "service/temp/qq_sign_bin.txt",
 	file_content  = "service/temp/qq_content.txt",
 	file_pubkey   = "service/keys/qq/qq_public_key.pem",
}

SDK_QQ_CONSTS.rds_conn_name		= "qqdb/"
SDK_QQ_CONSTS.rdst_mid			= "qqdb/mid/"
SDK_QQ_CONSTS.rdst_order_flag	= "qqdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_QQ_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfQQ_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_QQ_CONSTS.rdst_mid ..mid
end

local function lfQQ_dbSaveAuthInfo(mid,jsonStr)
	local key = lfQQ_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	gLog.debug("i am lfQQ_dbSaveAuthInfo ....... ",key,jsonStr)
	return redisHand:set(key, jsonStr)
end 

-- QQ session datas
local QQ_AUTH_TOKEN_SESSION = {}

local QQ_ACTIVE_AUTH 		= 1
local QQ_ACTIVE_PAY 			= 1 + QQ_ACTIVE_AUTH
local QQ_ACTIVE_DRAWBACK 	= 1 + QQ_ACTIVE_PAY

local QQ_SESSIONS = {
	[QQ_ACTIVE_AUTH] 		= {},
	[QQ_ACTIVE_PAY]			= {},
	[QQ_ACTIVE_DRAWBACK]	= {},
}



local function lfQQSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk QQ lfQQSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = QQ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QQ lfQQSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfQQSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk QQ lfQQSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = QQ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QQ lfQQSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfQQSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk QQ lfQQSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = QQ_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk QQ lfQQSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


local function lfQQ_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfQQ_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfQQ_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfQQ_authSendResult 333")
    return json
end

local function lfQQ_authOnRequestFinished(req,resp)
	gLog.debug("i am lfQQ_authOnRequestFinished")
	-- local QQMemberID = req.QQMemberID
	-- local session = nil

	-- if QQMemberID then 
	-- 	session = lfUidGet(QQMemberID)
	-- end	
	-- --gLog.debug("i am lfQQ_loginOnRequestFinished 222",QQMemberID,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am QQ login response page")
	-- end	
end

local function lfQQ_authOnQQServerResponse(resp)
	gLog.debug("i am lfQQ_authOnQQServerResponse 111")
	local QQMemberID = resp.QQMemberID
	gLog.debug("i am lfQQ_authOnQQServerResponse 222 ", QQMemberID)
end	

local function lfQQ_authOnQQServerData(req,resp,data)
	gLog.debug("i am lfQQ_authOnQQServerData",data)
	local uid = req.QQMemberID

	local session = lfQQSessionGet(QQ_ACTIVE_AUTH, uid)
	if not session or not data then 
		gLog.debug("i am lfQQ_authOnQQServerData err 00",session,data)
		return
	end
	gLog.debug("i am lfQQ_authOnQQServerData .1",uid)

	local qqjson = gJson:decode(data)
	local error_code = 1
	local error_msg = "qq open server return result invalid";

	if qqjson and qqjson.msg then
		 error_msg = qqjson.msg
	end

	if qqjson and 0==qqjson.ret then
		error_code = 0
	end


	local json = {
		error_code = error_code,
		error_msg  = error_msg,
	}

	local jsonStr = gJson:encode(json)

	gLog.debug("i am lfQQ_authOnQQServerData .1",jsonStr)
	-- 向客户端发送结果
	json = lfQQ_authSendResult(session,json)
	gLog.debug("i am lfQQ_authOnQQServerData fuck 01")

	-- 将数据存入数据库中(留待login服务器查询)
	if json.error_code == 0 and uid then
		lfQQ_dbSaveAuthInfo(uid, jsonStr)
	end	
	gLog.debug("i am lfQQ_authOnQQServerData fuck 03")	

end	


local function lfQQ_authOnQQServerFinished(req,resp)
	gLog.debug("i am lfQQ_authOnQQServerFinished")

	-- 清理session
	lfQQSessionDel(QQ_ACTIVE_AUTH,req.QQMemberID)
end	

local function lfQQ_authSendRequestToQQServer(session)
	gLog.debug("i am lfQQ_authSendRequestToQQServer")
	local QQMemberID = session.req.QQMemberID
	local token = session.req.token
	local url = string.format("%s?openid=%s&oauth_consumer_key=%s&access_token=%s",
		SDK_QQ_CONSTS.url_info, gUtil.urlencode(QQMemberID), gUtil.urlencode(SDK_QQ_CONSTS.app_id), gUtil.urlencode(token))

	gLog.debug("QQ server request url",url)
	local httpClientRequst = {
		url 			= url,
		method			= "GET",
		QQMemberID		= QQMemberID,
		on_error 		= nil,
		on_response 	= lfQQ_authOnQQServerResponse,
		on_data 		= lfQQ_authOnQQServerData,
		on_finished 	= lfQQ_authOnQQServerFinished,
	}
	local httpClient = gfGetHttpClient()
	session.httpClient = httpClient

	local outReq,err = httpClient:request(httpClientRequst)
	if err then
		-- TODO: 
	end	
end

-- 接收客户端发过来的验证信息，并转发给QQ 服务器
local function lfQQ_authOnRequest(session)
	gLog.debug("i am lfQQ_authOnRequest")

	local req = session.req
	local resp = session.resp

	local uid = req.headers["openid"] or "qquid"
	local token = req.headers["access_token"] or "qqtoken"

	if not uid  then
		return RESULT_CODES.succeed
	end

	gLog.debug("i am lfQQ_authOnRequest 2",uid, token)

	local sessionOrg = lfQQSessionAdd(QQ_ACTIVE_AUTH, uid, session) -- 将本次的session暂存下来

	if sessionOrg then
		-- 残留session的警告
		gLog.debug("QQ service sessionOrg err0",uid)
	end	

	-- req.uid 		= uid
	req.token 		= token
	req.QQMemberID  = uid
	req.on_finished = lfQQ_authOnRequestFinished
	gLog.debug("i am lfQQ_authOnRequest request, fuck me2")

	-- 此处发起向QQ客户端的验证请求
	lfQQ_authSendRequestToQQServer(session)
	resp.uid = uid

	gLog.debug("i am lfQQ_authOnRequest, fuck me3")

	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- QQ QQjsonStr验证 end
--------------------------------------------------------------------

function lfQQ_payExtParse(ext)
	gLog.debug("i am lfQQ_payExtParse 111")

	if not ext then
		return "",0
	end

	local v = gUtil.split(ext,"_")

	local account_id = v[1] or "0"
	local server_index = v[2] or "0"
	local sub_cid = 0

	if v[3] then
		sub_cid = tonumber(v[3]) or 0
	end

	ext = account_id .. "|" .. server_index
	return ext,sub_cid
end
--------------------------------------------------------------------
-- QQ 计费结果 start
--------------------------------------------------------------------

function lfQQ_payVerifySign(sign,content,file_title)
  local sign_base64_decode = gBase64.decode(sign) 
  local content_decode = gUtil.urldecode(content) 

  gLog.debug("i am lfQQ_payVerifySign 000")
  local file_sign_bin = string.format("service/temp/%s_sign_bin.txt",file_title)
  local file_content = string.format("service/temp/%s_content.txt",file_title)

  -- out bin sgin to file
  gUtil.out_to_file(file_sign_bin,sign_base64_decode)
  -- out content to file
  gUtil.out_to_file(file_content,content_decode)

  local cmd = string.format("openssl dgst -verify %s -signature %s %s",QQ_CONST.file_pubkey,file_sign_bin,file_content)
  ret = os.execute(cmd)
  -- os.execute("ls -la service/temp")

  cmd = string.format("rm %s %s",file_sign_bin,file_content)
  os.execute(cmd)
  -- os.execute("ls -la service/temp")
  -- os.execute("pwd")

  -- os.execute(QQ_CONST.cmd2) 
  if ret == 0 then
    return true
  end
  
  return false
end

local QQ_notify_paras = 
{
	["buyer_email"] 			= {true,	false,	false},-- need sign,need urldecode,must have
	["payment_type"] 			= {true,	false,	false},
	["is_total_fee_adjust"] 	= {true,	false,	false},
	["discount"] 				= {true,	false,	false},
	["out_trade_no"] 			= {true,	false,	true},
	["total_fee"] 				= {true,	false,	true},
	["quantity"] 				= {true,	false,	false},
	["gmt_create"] 				= {true,	false,	false},
	["trade_no"] 				= {true,	false,	true},
	["trade_status"] 			= {true,	false,	true},
	["partner"] 				= {true,	false,	false},
	["seller_email"] 			= {true,	false,	false},
	["gmt_payment"] 			= {true,	false,	false},
	["subject"] 				= {true,	false,	false},
	["buyer_id"] 				= {true,	false,	false},
	["use_coupon"] 				= {true,	false,	false},
	["seller_id"] 				= {true,	false,	false},
}


-- QQ 计费结果合法性验证
local function lfQQ_payCheckParams(p)
	if not p or not p.sign or not p.notify_data then
			gLog.debug("lfQQ_payCheckParams ___(O_O)_____ 000")
		return false
	end


	gLog.debug("lfQQ_payCheckParams ___(O_O)_____ 111")

	for k,v in pairs(QQ__notify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfQQ_payCheckParams ___(O_O)_____ xxx",k)
			return false
		end

		if v[2] then
			p[k] = gUtil.urldecode(p[k][1])
		end
	end
	gLog.debug("lfQQ_payCheckParams ___(O_O)_____ 222")
	local file_title = p.trade_no .. ""
	if lfQQ_payVerifySign(p.sign,"notify_data="..p.notify_data,file_title) == true then
		return true
	end

	gLog.debug("lfQQ_payCheckParams ___(O_O)_____FAILED")
	return false
end


local function lfQQ_payData2Paras(data)
	local src_paras = gUtil.parseUrlParams(data)
	gLog.debug("i am lfQQ_payData2Paras 000",src_paras,"\n")

	if not src_paras or not src_paras.sign or not src_paras.notify_data then
		return nil
	end

	gLog.debug("i am lfQQ_payData2Paras 111")
	for k,v in pairs(src_paras) do
		src_paras[k] = gUtil.urldecode(v)
	end

	gLog.debug("i am lfQQ_payData2Paras 222")
	local p_xml = xml_tool.xmlparse(src_paras.notify_data)

	if not p_xml or not p_xml["notify"] then
		return nil
	end
	p_xml = p_xml["notify"]
	-- gLog.print_r(p_xml)

	-- gLog.debug()

	local p = {}
	for k,v in pairs(p_xml) do
		if v[1] then
			p[k] = v[1]
		end
	end
	gLog.debug("i am lfQQ_payData2Paras 333")

	p.sign = src_paras.sign
	p.sign_type = src_paras.sign_type
	p.notify_data = src_paras.notify_data
	-- gLog.print_r(p)
	gLog.debug("i am lfQQ_payData2Paras 444")

	return p
end	


local function lfQQ_payOnData(req,resp,data)

	gLog.debug("i am lfQQ_payOnData 000",data,"\n")

	if not data then
		gUtil.sendString(resp,200,QQ_PAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end
	
	local p = lfQQ_payData2Paras(data)
	if not lfQQ_payCheckParams(p) then
		gUtil.sendString(resp,200,QQ_PAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfQQ_payOnData 222",p.trade_status)
	local order 	= p.trade_no or ""
	local status 	= p.trade_status or ""
	local rmb 		= tonumber(p.total_fee)
	local c_acc 	= p.buyer_email or ""
	local desc 		= p.out_trade_no or ""
	local ext 		= p.out_trade_no or ""
	local sub_cid	= 0

	--  do ex 
	c_acc = c_acc .. "," .. (p.buyer_id or "")
	ext,sub_cid = lfQQ_payExtParse(ext)
	local c_accid = sub_cid


	gLog.debug("i am lfQQ_payOnData 333")
	local sql_success = -1
	if status == "WAIT_BUYER_PAY" then
		gUtil.sendString(resp,200,QQ_PAY_RESULT.success)
		return
	elseif status == "TRADE_SUCCESS" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_QQ_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_QQ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfQQ_payOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_QQ_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfQQ_payOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_QQ_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfQQ_payOnData 666")

	end



	gLog.debug("i am lfQQ_payOnData 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,QQ_PAY_RESULT.success)
	else
		gUtil.sendString(resp,200,QQ_PAY_RESULT.failed)
	end

    gLog.debug("=====> ul  success is working")
end

-- 来自QQ 服务器的计费结果
local function lfQQ_payServerNotifyRequest(session)
	gLog.debug("i am lfQQ_payServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp

	req.on_data = lfQQ_payOnData

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- QQ alipay 计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_QQ_ACTION_FUNCS = {

	request = {
		["/sdk/qq/auth"] 		= lfQQ_authOnRequest,
		["/sdk/qq/paynotify"] 	= lfQQ_payServerNotifyRequest,

	},

	response = {
		-- ["sdk/QQ/login"] 	= gfOnRsp_QQLogin,
		-- ["sdk/QQ/exit"] 	= gfOnRsp_QQExit,
		-- ["sdk/QQ/pay"] 	= gfOnRsp_QQPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/qq",
	funcs = SDK_QQ_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData
