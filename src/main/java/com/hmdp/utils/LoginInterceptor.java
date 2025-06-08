package com.hmdp.utils;


import com.hmdp.dto.UserDTO;
import com.hmdp.entity.User;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginInterceptor implements HandlerInterceptor {

    /**
     * 此方法的作用是在请求进入到Controller进行拦截，有返回值
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // 1 获取session
        HttpSession session = request.getSession();
        // 2 获取用户
        Object user = session.getAttribute("user");

        // 3 判断用户
        if (user==null) {
            response.setStatus(401);
            return false;
        }
        // 4  存储用户
        UserHolder.saveUser((UserDTO) user);
        // 5 放行
        return true;
    }

    /**
     * 该方法是在ModelAndView返回给前端渲染后执行
     * @param request
     * @param response
     * @param handler
     * @param ex
     * @throws Exception
     */

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
       UserHolder.removeUser();
    }
}
