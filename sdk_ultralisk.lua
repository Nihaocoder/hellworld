local xml_tool = require "util/xmlParser"


local ALIPAY_CONST = {
	file_sign_bin = "service/temp/alipay_sign_bin.txt",
 	file_content  = "service/temp/alipay_content.txt",
 	file_pubkey   = "service/keys/alipay/alipay_public_key.pem",
}

local SHENZHOUFU_CONST = 
{
	app_id = 183659,
	app_pri_key = "ultralisk2013girl9",
	app_des_key = "/V3maASwRZI=",
}


 ALIPAY_CONST.cmd = string.format("openssl dgst -verify %s -signature %s %s",ALIPAY_CONST.file_pubkey,ALIPAY_CONST.file_sign_bin,ALIPAY_CONST.file_content)
 ALIPAY_CONST.cmd2 = string.format("rm %s %s",ALIPAY_CONST.file_sign_bin,ALIPAY_CONST.file_content)


gLog.debug(ALIPAY_CONST.cmd)


-- service inside paras
local SDK_ULTRALISK_CONSTS = 
{
	app_id 			= 1293,
	app_key 		= "d37a5b5989461311fe429a7e3fe05010",
	app_secret 		= "1e918f8667bb68d65370fd16649a1bb1",
	url_info 		= "http://sdk.m.ULTRALISK.com/openapi/sdk",
	--------------------------------------------------------------
	cid				= CHANNEL_ID_ULTRALISK,
}

local ULTRALISK_PAY_ALIPAY_RESULT = {
	success = "success",
	failed = "failed",
}

local ULTRALISK_PAY_SHENZHOUFU_RESULT = {
	success = "success",
	failed = "failed",
}

SDK_ULTRALISK_CONSTS.rds_conn_name		= "ULTRALISKdb/"
SDK_ULTRALISK_CONSTS.rdst_mid			= "ULTRALISKdb/uid/"
SDK_ULTRALISK_CONSTS.rdst_order_flag	= "ULTRALISKdb/order/orderflag"


-- redis handler
local redisHand = gRedisMgr:handlerGet(SDK_ULTRALISK_CONSTS.rds_conn_name,GLOBLE_REDIS_CONF.default_ip,GLOBLE_REDIS_CONF.default_port,GLOBLE_REDIS_CONF.default_pass)



local function lfULTRALISK_makeRedisAuthKey(mid)
	if not mid or type(mid) ~= "string" then
		return nil
	end
	return SDK_ULTRALISK_CONSTS.rdst_mid ..mid
end

local function lfULTRALISK_dbSaveAuthInfo(mid,jsonStr)
	local key = lfULTRALISK_makeRedisAuthKey(mid)
	if not key then
		return nil
	end
	return redisHand:set(key,jsonStr)
end 

-- ULTRALISK session datas
local ULTRALISK_AUTH_TOKEN_SESSION = {}

local ULTRALISK_ACTIVE_AUTH 		= 1
local ULTRALISK_ACTIVE_PAY 			= 1 + ULTRALISK_ACTIVE_AUTH
local ULTRALISK_ACTIVE_DRAWBACK 	= 1 + ULTRALISK_ACTIVE_PAY

local ULTRALISK_SESSIONS = {
	[ULTRALISK_ACTIVE_AUTH] 		= {},
	[ULTRALISK_ACTIVE_PAY]			= {},
	[ULTRALISK_ACTIVE_DRAWBACK]	= {},
}



local function lfULTRALISKSessionAdd(active,key,session)
	if not active or not key or not session then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionAdd: invalid para ",active,key,session)
		return nil
	end	

	local sessionTable = ULTRALISK_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionAdd: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = session
	return result	
end	

local function lfULTRALISKSessionGet(active,key)
	if not active or not key then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionGet: invalid para ",active,key)
		return nil
	end	

	local sessionTable = ULTRALISK_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionGet: unknow active ",active)
		return nil
	end

	return sessionTable[key]
end

local function lfULTRALISKSessionDel(active,key)
	if not active or not key then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionDel: invalid para ",active,key)
		return nil
	end	

	local sessionTable = ULTRALISK_SESSIONS[active]
	if not sessionTable then
		gLog.warn("sdk ULTRALISK lfULTRALISKSessionDel: unknow active ",active)
		return nil
	end

	local result = sessionTable[key]
	sessionTable[key] = nil
	return result
end


local function lfULTRALISK_authSendResult(session,json)
	if not json then 
		json = {
			error_code = 1000,
			error_msg = "未知错误"
		}
	end
	gLog.debug("i am lfULTRALISK_authSendResult 111")

	local resp = session.resp
	local jsonStr = gJson:encode(json)
	gLog.debug("i am lfULTRALISK_authSendResult 222",jsonStr)
    resp:set_status(200)
	resp:set_header('Content-Type', 'text/html;charset=UTF8')
	resp:set_header('Content-Length', #jsonStr)
	resp:set_header('rmbinfo', gPay.getYbExchangeJsonString())
	resp:set_body(jsonStr)
	resp:send()  
	gLog.debug("i am lfULTRALISK_authSendResult 333")
    return json
end

--------------------------------------------------------------------
-- ULTRALISK ULTRALISKjsonStr验证 start
--------------------------------------------------------------------
-- client send the ULTRALISK login auth
local function lfULTRALISK_authOnRequestFinished(req,resp)
	gLog.debug("i am lfULTRALISK_loginOnRequestFinished")
	-- local ultralisk_uid = req.ultralisk_uid
	-- local session = nil

	-- if ultralisk_uid then 
	-- 	session = lfUidGet(ultralisk_uid)
	-- end	
	-- --gLog.debug("i am lfULTRALISK_loginOnRequestFinished 222",ultralisk_uid,session)
	-- if session then
	-- 	-- gUtil.sendSimplePage(session,"login req","i am ULTRALISK login response page")
	-- end	


end


local function lfULTRALISK_authOnULTRALISKServerResponse(resp)
	gLog.debug("i am lfULTRALISK_authOnULTRALISKServerResponse 111")
	local ultralisk_uid = resp.ultralisk_uid
	gLog.debug("i am lfULTRALISK_authOnULTRALISKServerResponse 222 ",ultralisk_uid)
end	

local function lfULTRALISK_authOnULTRALISKServerData(req,resp,data)
	gLog.debug("i am lfULTRALISK_authOnULTRALISKServerData",data)
	local session = lfULTRALISKSessionGet(ULTRALISK_ACTIVE_AUTH,req.ultralisk_uid)
	if not session or not data then 
		gLog.debug("i am lfULTRALISK_authOnULTRALISKServerData err 00",session,data)
		return
	end
	-- JSON 解析 
	local json = gJson:decode(data,nil)
	if not json then 
		gLog.debug("i am lfULTRALISK_authOnULTRALISKServerData err 01",json,data)
		return
	end	

	session.authdata = json
	gLog.debug("i am lfULTRALISK_authOnULTRALISKServerData fuck 02")	

end	

local function lfULTRALISK_authOnULTRALISKServerFinished(req,resp)
	gLog.debug("i am lfULTRALISK_authOnULTRALISKServerFinished")
	local ultralisk_uid = req.ultralisk_uid

	-- do accInfo request
	local session = lfULTRALISKSessionGet(ULTRALISK_ACTIVE_AUTH,ultralisk_uid) 
	if not session then
		return
	end

	local authdata = session.authdata


	if not authdata or not authdata.error_code then
		lfULTRALISK_authSendResult(session,nil)
	else
		-- 获取到的是正确的结果，直接返回给客户端
		lfULTRALISK_authSendResult(session,authdata)
		if authdata.error_code == "0" then
			local jsonStr = gJson:encode(authdata)
			if jsonStr then
				lfULTRALISK_dbSaveAuthInfo(ultralisk_uid,jsonStr)
			end
		end
	end
	lfULTRALISKSessionDel(ULTRALISK_ACTIVE_AUTH,ultralisk_uid) 
end	

-- 发起向ULTRALISK 客户端的验证请求
local function lfULTRALISK_authSendRequestToULTRALISKServer(session)
	gLog.debug("i am lfULTRALISK_authSendRequestToULTRALISKServer")
	-- local ultralisk_uid = session.req.ultralisk_uid
	-- local ultralisk_sid = session.req.ultralisk_sid

	-- -- make md5 sign
	-- local str_before_sign = string.format("%d%s%s%s%s",SDK_ULTRALISK_CONSTS.app_id,SDK_ULTRALISK_CONSTS.app_key,ultralisk_uid,ultralisk_sid,SDK_ULTRALISK_CONSTS.app_secret)
	-- local sign = gUtil.md5lower(str_before_sign)

	-- gLog.debug("i am lfULTRALISK_authSendRequestToULTRALISKServer",sign,str_before_sign)


	-- local url_para = string.format("appid=%d&appkey=%s&uid=%s&sessionid=%s&clientsecret=%s",SDK_ULTRALISK_CONSTS.app_id,SDK_ULTRALISK_CONSTS.app_key,ultralisk_uid,ultralisk_sid,sign)
	-- local url = string.format("%s/checksession?%s",SDK_ULTRALISK_CONSTS.url_info,url_para)

	-- gLog.debug("ULTRALISK server request url",url)
	-- local httpClientRequst = {
	-- 	url 			= url,
	-- 	method			= "GET",
	-- 	ultralisk_uid	= ultralisk_uid,
	-- 	authdata 		= nil,
	-- 	on_error 		= nil,
	-- 	on_response 	= lfULTRALISK_authOnULTRALISKServerResponse,
	-- 	on_data 		= lfULTRALISK_authOnULTRALISKServerData,
	-- 	on_finished 	= lfULTRALISK_authOnULTRALISKServerFinished,

	-- }
	-- local httpClient = gfGetHttpClient()
	-- session.httpClient = httpClient

	-- local outReq,err = httpClient:request(httpClientRequst)

	-- if err then
	-- 	gLog.debug("lfULTRALISK_authSendRequestToULTRALISKServer err",err)
	-- end	

end

-- 接收客户端发过来的验证信息，并转发给ULTRALISK 服务器
local function lfULTRALISK_authOnRequest(session)
	gLog.debug("i am lfULTRALISK_authOnRequest")
	-- if true then
	-- 	return RESULT_CODES.succeed
	-- end
	local req = session.req
	local resp = session.resp

	local info_str = req.headers["info"] -- json str
	gLog.debug("i am lfULTRALISK_authOnRequest",info_str)
	--info_str= '{"account_id":123456}'
	if not info_str then
		return RESULT_CODES.succeed
	end

	local info = gJson:decode(info_str)
	if not info then
		return RESULT_CODES.succeed
	end


	local ultralisk_uid = info.account_id or "ultralisk_uid"
	local ultralisk_sid = info.session or "ultralisk_sid"

	gLog.debug("lfULTRALISK_authOnRequest 001 ",ultralisk_uid,ultralisk_sid)


	local json = {
		error_code = 0,
		error_msg = "ok",
	}

	lfULTRALISK_authSendResult(session,json)

	-- auth data is invalid
	-- if not ultralisk_uid or not ultralisk_sid then
	-- 	lfULTRALISK_authSendResult(session,nil)
	-- 	return RESULT_CODES.succeed
	-- end
	-- gLog.debug("lfULTRALISK_authOnRequest 001 001")

	-- local sessionOrg = lfULTRALISKSessionAdd(ULTRALISK_ACTIVE_AUTH,ultralisk_uid,session) -- 将本次的session暂存下来

	-- if sessionOrg then
	-- 	-- 残留session的警告
	-- 	gLog.debug("ULTRALISK service sessionOrg err0",ultralisk_uid)
	-- end	

	-- req.ultralisk_uid = ultralisk_uid
	-- req.ultralisk_sid = ultralisk_sid
	-- req.on_finished = lfULTRALISK_authOnRequestFinished
	-- gLog.debug("i am lfULTRALISK_authOnRequest request, fuck me2")

	-- -- 此处发起向ULTRALISKjsonStr客户端的验证请求
	-- --lfULTRALISK_authSendRequestToULTRALISKServer(session)

	-- resp.ultralisk_uid = ultralisk_uid
	-- resp.ultralisk_sid = ultralisk_sid
	-- resp.on_response_sent = lfULTRALISK_loginOnResponseSend
	-- gLog.debug("i am lfULTRALISK_authOnRequest, fuck me3")
	return RESULT_CODES.succeed
end  
--------------------------------------------------------------------
-- ULTRALISK ULTRALISKjsonStr验证 end
--------------------------------------------------------------------

function lfULTRALISK_payExtParse(ext)
	gLog.debug("i am lfULTRALISK_payExtParse 111")

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
-- ULTRALISK alipay 计费结果 start
--------------------------------------------------------------------

function lfULTRALISK_payAlipayVerifySign(sign,content,file_title)
  local sign_base64_decode = gBase64.decode(sign) 
  local content_decode = gUtil.urldecode(content) 

  gLog.debug("i am lfULTRALISK_payAlipayVerifySign 000")
  local file_sign_bin = string.format("service/temp/%s_sign_bin.txt",file_title)
  local file_content = string.format("service/temp/%s_content.txt",file_title)

  -- out bin sgin to file
  gUtil.out_to_file(file_sign_bin,sign_base64_decode)
  -- out content to file
  gUtil.out_to_file(file_content,content_decode)

  local cmd = string.format("openssl dgst -verify %s -signature %s %s",ALIPAY_CONST.file_pubkey,file_sign_bin,file_content)
  ret = os.execute(cmd)
  -- os.execute("ls -la service/temp")

  cmd = string.format("rm %s %s",file_sign_bin,file_content)
  os.execute(cmd)
  -- os.execute("ls -la service/temp")
  -- os.execute("pwd")

  -- os.execute(ALIPAY_CONST.cmd2) 
  if ret == 0 then
    return true
  end
  
  return false
end

local ULTRALISK_alipay_notify_paras = 
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


-- ULTRALISK 计费结果合法性验证
local function lfULTRALISK_payAlipayCheckParams(p)
	if not p or not p.sign or not p.notify_data then
			gLog.debug("lfULTRALISK_payAlipayCheckParams ___(O_O)_____ 000")
		return false
	end


	gLog.debug("lfULTRALISK_payAlipayCheckParams ___(O_O)_____ 111")

	for k,v in pairs(ULTRALISK_alipay_notify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfULTRALISK_payAlipayCheckParams ___(O_O)_____ xxx",k)
			return false
		end

		if v[2] then
			p[k] = gUtil.urldecode(p[k][1])
		end
	end
	gLog.debug("lfULTRALISK_payAlipayCheckParams ___(O_O)_____ 222")
	local file_title = p.trade_no .. ""
	if lfULTRALISK_payAlipayVerifySign(p.sign,"notify_data="..p.notify_data,file_title) == true then
		return true
	end

	gLog.debug("lfULTRALISK_payAlipayCheckParams ___(O_O)_____FAILED")
	return false
end


local function lfULTRALISK_payAlipayData2Paras(data)
	local src_paras = gUtil.parseUrlParams(data)
	gLog.debug("i am lfULTRALISK_payAlipayData2Paras 000",src_paras,"\n")

	if not src_paras or not src_paras.sign or not src_paras.notify_data then
		return nil
	end

	gLog.debug("i am lfULTRALISK_payAlipayData2Paras 111")
	for k,v in pairs(src_paras) do
		src_paras[k] = gUtil.urldecode(v)
	end

	gLog.debug("i am lfULTRALISK_payAlipayData2Paras 222")
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
	gLog.debug("i am lfULTRALISK_payAlipayData2Paras 333")

	p.sign = src_paras.sign
	p.sign_type = src_paras.sign_type
	p.notify_data = src_paras.notify_data
	-- gLog.print_r(p)
	gLog.debug("i am lfULTRALISK_payAlipayData2Paras 444")

	return p
end	


local function lfULTRALISK_payAlipayOnData(req,resp,data)

	gLog.debug("i am lfULTRALISK_payAlipayOnData 000",data,"\n")

	if not data then
		gUtil.sendString(resp,200,ULTRALISK_PAY_ALIPAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end
	
	local p = lfULTRALISK_payAlipayData2Paras(data)
	if not lfULTRALISK_payAlipayCheckParams(p) then
		gUtil.sendString(resp,200,ULTRALISK_PAY_ALIPAY_RESULT.failed)
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfULTRALISK_payAlipayOnData 222",p.trade_status)
	local order 	= p.trade_no or ""
	local status 	= p.trade_status or ""
	local rmb 		= tonumber(p.total_fee)
	local c_acc 	= p.buyer_email or ""
	local desc 		= p.out_trade_no or ""
	local ext 		= p.out_trade_no or ""
	local sub_cid	= 0

	-- alipay do ex 
	c_acc = c_acc .. "," .. (p.buyer_id or "")
	ext,sub_cid = lfULTRALISK_payExtParse(ext)
	local c_accid = sub_cid


	gLog.debug("i am lfULTRALISK_payAlipayOnData 333")
	local sql_success = -1
	if status == "WAIT_BUYER_PAY" then
		gUtil.sendString(resp,200,ULTRALISK_PAY_ALIPAY_RESULT.success)
		return
	elseif status == "TRADE_SUCCESS" then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfULTRALISK_payAlipayOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_ULTRALISK_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfULTRALISK_payAlipayOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfULTRALISK_payAlipayOnData 666")

	end



	gLog.debug("i am lfULTRALISK_payAlipayOnData 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,ULTRALISK_PAY_ALIPAY_RESULT.success)
	else
		gUtil.sendString(resp,200,ULTRALISK_PAY_ALIPAY_RESULT.failed)
	end

    gLog.debug("=====> ul alipay success is working")
end

-- 来自ULTRALISK 服务器的计费结果
local function lfULTRALISK_payAlipayServerNotifyRequest(session)
	gLog.debug("i am lfULTRALISK_payAlipayServerNotifyRequest")
	-- gLog.gLog.debug_r(session)
	local req = session.req
	local resp = session.resp

	req.on_data = lfULTRALISK_payAlipayOnData

	return RESULT_CODES.succeed
end  

--------------------------------------------------------------------
-- ULTRALISK alipay 计费结果 end
-------------------------------------------------------------------- 

--------------------------------------------------------------------
-- ULTRALISK 神州付 计费结果 start
--------------------------------------------------------------------

local ULTRALISK_shenzhoufu_notify_paras = 
{
	["version"] 		= {true,	true,	true},-- need sign,need urldecode,must have
	["merId"] 			= {true,	true,	true},
	["payMoney"] 		= {true,	true,	true},
	["orderId"] 		= {true,	true,	true},
	["payResult"] 		= {true,	true,	true},
	["privateField"] 	= {true,	true,	true},
	["payDetails"] 		= {true,	true,	true},
	["md5String"] 		= {true,	true,	true},
	["signString"] 		= {true,	true,	true},
}


-- ULTRALISK 计费结果合法性验证
local function lfULTRALISK_payShenzhoufuCheckParams(p)
	if not p then
			gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ 000")
		return false
	end


	gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ 111")

	for k,v in pairs(ULTRALISK_shenzhoufu_notify_paras) do
		if v[3] and not p[k] then
			gLog.error("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ xxx",k)
			return false
		end

		if v[2] then
			p[k] = gUtil.urldecode(p[k])
		end
	end
	gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ 222")
	local str_before_sign = string.format("%s%s%s%s%s%s%s%s", p.version, p.merId, p.payMoney, p.orderId, p.payResult, p.privateField,p.payDetails,SHENZHOUFU_CONST.app_pri_key)
	gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ 222")

	local sign = gUtil.md5lower(str_before_sign)
	gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____ 333",sign,p.md5String,str_before_sign)
	if sign == p.md5String then
		return true
	end

	gLog.debug("lfULTRALISK_payShenzhoufuCheckParams ___(O_O)_____FAILED")
	return false
end

local function lfULTRALISK_payShenzhoufuServerOnData(req,resp,data)
	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData",data)

	if not data then
		return
	end

	-- 拆分参数
	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 000")
	local p = gUtil.parseUrlParams(data)
	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 111")

	if not lfULTRALISK_payShenzhoufuCheckParams(p) then
		return -- 参数检查未通过，直接抛弃
	end	

	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 222")
	local order 	= p.orderId
	local status 	= tonumber(p.payResult)
	local rmb 		= tonumber(p.payMoney) / 100
	local c_acc 	= ""
	--local c_accid 	= 0
	local desc 		= p.privateField
	local ext 		= p.privateField
	local sub_cid	= 0

	-- do ex 
	ext,sub_cid = lfULTRALISK_payExtParse(ext)
	local c_accid = sub_cid


	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 333")
	if status == 1 then
		-- TODO: save order to mysql db
		--gfPayInfoInsert(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,p.CooOrderSerial,OrderMoney,p.Note)
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.succed)
		gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 444")

		-- 设置redis数据中的标记，通知login服务器过来读取订单数据
		redisHand:set(SDK_ULTRALISK_CONSTS.rdst_order_flag,1) 
		gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 555")
 
	else
		-- TODO: save order to db?
		sql_success = gPay.order_todb(gPayMysqlHandler,SDK_ULTRALISK_CONSTS.cid,c_acc,c_accid,order,rmb,desc,ext,RECHARGE_CODES.failed)

		gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 666")

	end



	gLog.debug("i am lfULTRALISK_payShenzhoufuServerOnData 777")
	if sql_success == 1 or sql_success == 0 then
		gUtil.sendString(resp,200,p.orderId)
		gLog.debug("=====> ul shenzhoufu success is working",p.orderId)
	else
		gUtil.sendString(resp,200,ULTRALISK_PAY_SHENZHOUFU_RESULT.failed)
		gLog.debug("=====> ul shenzhoufu faild is working",ULTRALISK_PAY_SHENZHOUFU_RESULT.failed)
	end




end

-- 神州付付费结果通知入口
local function lfULTRALISK_payShenzhoufuServerNotifyRequest(session)
	gLog.debug("i am lfULTRALISK_payShenzhoufuServerNotifyRequest")
	local req = session.req
	local resp = session.resp

	req.on_data = lfULTRALISK_payShenzhoufuServerOnData
	return RESULT_CODES.succeed

end

--------------------------------------------------------------------
-- ULTRALISK 神州付 计费结果 end
--------------------------------------------------------------------


--------------------------------------------------------------------
-- service data
--------------------------------------------------------------------
local SDK_ULTRALISK_ACTION_FUNCS = {

	request = {
		["/sdk/ultralisk/auth"] 				= lfULTRALISK_authOnRequest,
		["/sdk/ultralisk/alipay/paynotify"] 	= lfULTRALISK_payAlipayServerNotifyRequest,
		["/sdk/ultralisk/shenzhoufu/paynotify"] = lfULTRALISK_payShenzhoufuServerNotifyRequest,

	},

	response = {
		-- ["sdk/ultralisk/login"] 	= gfOnRsp_ULTRALISKLogin,
		-- ["sdk/ultralisk/exit"] 	= gfOnRsp_ULTRALISKExit,
		-- ["sdk/ultralisk/pay"] 	= gfOnRsp_ULTRALISKPay,
	},

}

-- name,func table
local serviceData = {
	name = "sdk/ultralisk",
	funcs = SDK_ULTRALISK_ACTION_FUNCS,
}

gLog.info(string.format("[%s] service on",serviceData.name))
return serviceData