package com.ces.xarch.helps.web.filter;
/**
 * <p>Copyright:Copyright(c) 2013</p>
 * <p>Company:上海中信信息发展股份有限公司</p>
 * <p>包名:com.ces.xarch.helps.web.filter</p>
 * <p>文件名:XssFilter.java</p>
 * <p>类更新历史信息</p>
 * @todo Reamy(杨木江 yangmujiang@sohu.com) 创建于 2013-02-20 16:16:20
 */

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;

/**
 * 跨站脚本攻击过滤类.
 * <p>描述:过滤跨站脚本攻击</p>
 * <p>Company:上海中信信息发展股份有限公司</p>
 * @author Reamy(杨木江 yangmujiang@sohu.com)222
 * @date 2013-02-20  16:16:20
 * @version 1.0.2013.0220
 */
public class XssFilter implements Filter {
	private String errorPage = null;
	private int errorCode = 405;
	private String errorMessage = "请求不合法";
	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 * @author Reamy(杨木江 yangmujiang@sohu.com)
	 * @date 2013-02-20 16:16:20
	 */
	public void destroy() {}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 * @author Reamy(杨木江 yangmujiang@sohu.com)
	 * @date 2013-02-20 16:16:20
	 */
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest)request;
		HttpServletResponse httpResponse = (HttpServletResponse)response;
		HttpServletRequest req = (HttpServletRequest) request;

		Map<String, String[]> parameters = httpRequest.getParameterMap();
        for (String key : parameters.keySet()) {
            if (StringUtils.isNotBlank(key)) {
                String[] values = parameters.get(key);
                for (int i = 0; i < values.length; i++) {
                    if (StringUtils.isNotBlank(values[i])) {
	                    encode(values[i]);
                    }
                }
            }
        }

		String uri = req.getRequestURI();
		String queryString = httpRequest.getQueryString();
		// 如果请求中含有跨站脚本则跳转到错误页面，否则继续请求
		if (queryString != null && !"".equals(queryString)) {
			String temp = htmlEncodeNew(queryString);

			String[] keywords = { "master", "truncate", "insert", "select", "delete", "update", "declare", "alert",
	                "create", "drop"};
	        // 判断是否包含非法字符
	        for (String keyword : keywords) {
	            if (temp.toLowerCase().contains(keyword)) {
	            	RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
					dispatcher.forward(request, response);
	            }
	        }

			if (!temp.equals(queryString)) {
				if (errorPage != null && !"".equals(errorPage)) {
					// 设置错误响应代码
					httpResponse.setStatus(errorCode);

					// 跳转到错误页面
					RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
					dispatcher.forward(request, response);
				} else {
					// 直接返回错误响应信息
					httpResponse.sendError(errorCode, errorMessage);
				}
				return;
			}
			if(temp.toLowerCase().contains("alert")||temp.toLowerCase().contains("prompt")){
				RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
				dispatcher.forward(request, response);
				return;
			}
		}
		if (queryString != null && !"".equals(queryString)) {
			encode(queryString);
		}
		// 校验是否存在SQL注入信息
        if(uri.contains("/services/")){
            if(uri.contains("script")||uri.contains("alert")){
                if (errorPage != null && !"".equals(errorPage)) {
                    // 设置错误响应代码
                    httpResponse.setStatus(errorCode);

                    // 跳转到错误页面
                    RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
                    dispatcher.forward(request, response);
                } else {
                    // 直接返回错误响应信息
                    httpResponse.sendError(errorCode, errorMessage);
                }
                return;
            }
        }
        Enumeration<?> params = req.getParameterNames();
        String paramN = null;
        while (params.hasMoreElements()) {
            paramN = (String) params.nextElement();
            if(paramN.equals("UI")){
                continue;
            }
            // 针对xss对参数名称进行修改成功注入问题
            String paramVale = req.getParameter(paramN);
            if(uri.toLowerCase().endsWith(".jsp") || uri.toLowerCase().endsWith(".html")){
                Boolean checkstatus = checkSQLInject(paramN, uri);
                if(checkstatus){
                    httpResponse.setStatus(errorCode);
                    // 跳转到错误页面
                    RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
                    dispatcher.forward(request, response);
                    return;
                }
            }
            if (!paramN.toLowerCase().contains("password")) {
                //System.out.println("传参为：" + paramN + "==" + paramVale);
            }
            // 校验是否存在SQL注入信息
            boolean status = false;
            if (uri.contains("start.check") || uri.contains("/appmanage/") || uri.contains("editing-editor!save.json"))
            {
                status = false;
            }else{
                status = checkSQLInject(paramVale, uri);
            }
            if(status){
                if (errorPage != null && !"".equals(errorPage)) {
                    // 设置错误响应代码
                    httpResponse.setStatus(errorCode);

                    // 跳转到错误页面
                    RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
                    dispatcher.forward(request, response);
                } else {
                    // 直接返回错误响应信息
                    httpResponse.sendError(errorCode, errorMessage);
                }
                return;
            }
        }
		filterChain.doFilter(request, response);
	}

	private String htmlEncodeNew(String str) {
		str = str.replaceAll("<([/\\w]*)>", "&lt;$1&gt;");
		return str;
	}

	public boolean checkSQLInject(String str, String url) {
		if (com.cesgroup.core.util.StringUtils.isEmpty(str)) {
			return false;// 如果传入空串则认为不存在非法字符
		}
		if(!url.toLowerCase().endsWith("view.jsp")&&!url.toLowerCase().endsWith("nonsupport.jsp")&&(url.toLowerCase().endsWith(".jsp")|| url.toLowerCase().endsWith(".html"))){//" 打断url  导致追加事件
			//示例/archive/cfg-resource/coral40/views/component/bu ttonbrowsepaging/browsepaging.jsp?componentVersionId=4028098158e143110158e1905d2a000e17370%22%3bconfirm(1)%2f%2f442mjz4go&isDeptPush=0&constructDetailId=8a7a 54f55cc9d782015cc9e90ed6000d&assembleType=3&menuId=4028a8655707721901570856d940 004a&menuCode=SF&topComVersionId=4028b9814a5b1279014a5b27e74f0019&tableId=8a7a5 44260fcddf50160fe76a57609d9&componentVersionId=8a7a54f55b6027f0015b60a836bb0300 &menuId=4028a8655707721901570856d940004a&moduleId=8a7a54f55b6027f0015b6090ca140 000&masterGridDivId=LTS_8a7a54f55b6027f0015b6090ca140000_1294&dataId=8a8bb01b75 f3009c0175f3c4fd741e40
			if ( str.contains("%22") || str.contains("script") || str.contains("javascript") || str.contains("eval") || str.contains("alert(") || str.contains("window[")|| str.contains("onmouseover")||str.contains("onfocus") || str.contains("@import") || str.contains(":alert") || str.contains(".source") || str.contains("new Function(") || str.contains("<iframe") || str.contains("<IMG") || str.contains("<img") || str.contains("||") || str.contains("+") || str.contains("Content-Type:") || str.contains("content-type:") || str.contains("<A") || str.contains("<a")) {
				return true;
			}
		}else{
			// 判断黑名单
			String[] inj_stra = {"'","@java.","@org.a","runtime.exec","<script>","script%","</script>","confirm(","alert(", "<img"};
			str = str.toLowerCase(); // sql不区分大小写
			for (int i = 0; i < inj_stra.length; i++) {
				if (str.indexOf(inj_stra[i]) >= 0 ) {
					return true;
				}
			}
		}
		//检查是否包含${ } 关键字，导致页面可以弹出异常信息
		return checkContainScript(str, url);
	}
	/**
	 *
	 * @param str
	 * @param url
	 * @return
	 */
	private Boolean checkContainScript(String str, String url) {
		Map<String, String> setMap  = new HashMap<String, String>();
		setMap.put("${", "}");
		//orgnl
		setMap.put("%23{", "}");
		setMap.put("#{", "}");
		//必须包含双重才会被拦截的注入
		setMap.put("select", "from");
		setMap.put("update", "from");
		setMap.put("delete", "from");
		setMap.put("drop", "table");
		setMap.put("insert", "value");
		//setMap.put("%24%7B","%7D");
		if(str.equals("${idSuffix}")){
			return false;
		}
		for(String key:setMap.keySet()){//keySet获取map集合key的集合  然后在遍历key即可
			String value = setMap.get(key).toString();//
			//System.out.println("key:"+key+" vlaue:"+value);
			if(str.contains(key) && str.contains(value)){
				return true;
			}
		}
		return false;
	}
	/* (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 * @author Reamy(杨木江 yangmujiang@sohu.com)
	 * @date 2013-02-20 16:16:20
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	/**
	 * 输入过滤
	 * @param str
	 * @return
	 */
	private String encode(String str) {
		if (StringUtils.isBlank(str)) {
			return str;
		}

		htmlEncode(str);
		return str;
    }

	/**
	 * 检验输入
	 * @param str
	 * @return
	 */
	private String htmlEncode(String str) {
		String temp = str.replaceAll("<([/\\w]*)>", "&lt;$1&gt;");
		if (!temp.equals(str)) {
            throw new RuntimeException("包含非法字符");
		}
		str = str.replaceAll("<([/\\w]*)>", "&lt;$1&gt;");
		return str;
	}
}

